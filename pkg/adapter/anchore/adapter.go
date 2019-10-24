package anchore

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	log "github.com/sirupsen/logrus"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/anchore/harbor-scanner-adapter/pkg/adapter"
	"github.com/anchore/harbor-scanner-adapter/pkg/adapter/anchore/client"
	"github.com/anchore/harbor-scanner-adapter/pkg/model/anchore"
	"github.com/anchore/harbor-scanner-adapter/pkg/model/harbor"
)

const (
	DescriptionFormatString = "Description unavailable.\nVendor-specific CVSS v3/v2 Scores: %.1f/%.1f.\nNVD CVSS v3/v2 Scores: %.1f/%.1f (Score of -1.0 means data unavailable).\nFor more detail see link."
	DigestRegex             = "^sha256:[a-zA-Z0-9]{64}"
)

type HarborScannerAdapter struct {
	ClientConfiguration *client.ClientConfig
}

// NewScanner constructs new HarborScannerAdapter with the given Config.
func NewScanner(cfg *client.ClientConfig) (adapter.ScannerAdapter, error) {
	if cfg == nil {
		return nil, errors.New("anchore client configuration must not be nil")
	}
	return &HarborScannerAdapter{
		ClientConfiguration: cfg,
	}, nil
}

// Create a scan id from the input image properties
func GenerateScanId(repository string, digest string) (string, error) {
	scanId := base64.URLEncoding.EncodeToString([]byte(fmt.Sprintf(`%s@%s`, repository, digest)))
	return scanId, nil
}

func ScanIdToRegistryDigest(scanId string) (string, string, error) {
	unsplit, err := base64.URLEncoding.DecodeString(scanId)
	if err != nil {
		return "", "", fmt.Errorf("invalid scanID")
	}

	parts := strings.Split(string(unsplit), "@")
	if len(parts) != 2 {
		return "", "", fmt.Errorf("invalid scanID")
	}

	if matched, err := regexp.Match(DigestRegex, []byte(parts[1])); (!matched) || err != nil {
		//Handle issue with split parts if the latter part doesn't match a digest format
		if err != nil {
			return "", "", err
		} else {
			return "", "", fmt.Errorf("invalid digest format")
		}
	}
	log.WithFields(log.Fields{"input": scanId, "repository": parts[0], "digest": parts[1]}).Debug("parsed scanId")
	return parts[0], parts[1], nil
}

func ScanToAnchoreRequest(req harbor.ScanRequest) (*anchore.ImageScanRequest, error) {
	fakeTag := req.Artifact.Digest[7:] // Map the digest to a tag name for anchore since anchore requires a tag

	var registryHostPort, err = client.ExtractRegistryFromUrl(req.Registry.URL)
	if err != nil {
		return nil, err
	}

	tagPullString := fmt.Sprintf("%s/%s:%s", registryHostPort, req.Artifact.Repository, fakeTag)
	digestPullString := fmt.Sprintf("%s/%s@%s", registryHostPort, req.Artifact.Repository, req.Artifact.Digest)

	var anchoreReq = &anchore.ImageScanRequest{
		Source: anchore.ImageSource{
			DigestSource: anchore.DigestSource{
				PullString:                digestPullString,
				Tag:                       tagPullString,
				CreationTimestampOverride: nowISOFormat(),
			},
		},
		ImageType:   "docker",
		Annotations: nil,
	}

	return anchoreReq, nil
}

// Returns the username and password from an authorizatino header input value (Harbor sends a single value
// The expected authorization value is of format "Basic b64(username:password)"
func GetUsernamePassword(authorizationInput string) (string, string, error) {
	var authzValue string
	components := strings.Split(strings.TrimSpace(authorizationInput), " ")
	if len(components) == 2 {
		//Expected case: {<scheme>, <value>}
		if strings.ToLower(components[0]) != "basic" {
			return "", "", fmt.Errorf("unsupported authorization type %v", components[0])
		}
		authzValue = components[1]

	} else {
		//Assume just the value
		authzValue = components[0]
	}

	decoded, err := base64.StdEncoding.DecodeString(authzValue)
	if err != nil {
		return "", "", err
	}
	parts := strings.SplitN(string(decoded), ":", 2)
	return parts[0], parts[1], nil

}

// Add credentials to Anchore for authorizing the image fetch
func (s *HarborScannerAdapter) EnsureRegistryCredentials(registry string, repository string, username string, password string) error {
	// New method, using client
	resp, body, errs := client.AddRegistryCredential(s.ClientConfiguration, registry, repository, username, password)
	if errs != nil {
		log.WithField("errs", errs).Error("could not execute request to anchore api to add registry credential")
		return errs[0]
	}

	if resp.StatusCode == http.StatusInternalServerError || resp.StatusCode == http.StatusConflict {
		var anchoreError = anchore.Error{}
		err := json.Unmarshal(body, &anchoreError)
		if err != nil {
			log.Errorf("got error %v trying unmarshal anchore api error response into an anchore error object", err)
			return err
		}

		// Check if a PUT is needed
		if anchoreError.Message == "registry already exists in DB" {
			log.WithField("msg", anchoreError.Message).Debug("updating registry credential since one already exists")

			// Do update
			resp, body, errs = client.UpdateRegistryCredential(s.ClientConfiguration, registry, repository, username, password)
			if errs != nil {
				log.WithField("errs", errs).Error("could not execute request to anchore api to update registry credential")
				return errs[0]
			}
			if resp.StatusCode != http.StatusOK {
				log.WithFields(log.Fields{"errorMessage": anchoreError.Message, "registry": registry, "repository": repository}).Error("unexpected response from anchore api. credential update not successful")
				return fmt.Errorf("unexpected response on registry credential update from anchore api: %v", resp.StatusCode)
			}
		} else {
			log.WithFields(log.Fields{"errorMessage": anchoreError.Message, "registry": registry, "repository": repository}).Error("unexpected response from anchore api. could not determine if update action is appropriate")
			return fmt.Errorf("unexpected response from anchore api")
		}
	} else if resp.StatusCode != http.StatusOK {
		// More handling
		log.Error("unexpected error response from anchore adding registry credential")
		return fmt.Errorf("failed to add credential got response code %v", resp.StatusCode)
	}

	log.Debug("successfully added registry credential to anchore")
	return nil
}

func (s *HarborScannerAdapter) Scan(req harbor.ScanRequest) (harbor.ScanResponse, error) {
	scanId, err := GenerateScanId(req.Artifact.Repository, req.Artifact.Digest)
	if err != nil {
		return harbor.ScanResponse{}, err
	}

	var registry string
	registry, err = client.ExtractRegistryFromUrl(req.Registry.URL)
	if err != nil {
		return harbor.ScanResponse{}, err
	}

	if req.Registry.Authorization != "" {
		username, password, err2 := GetUsernamePassword(req.Registry.Authorization)
		if err2 != nil {
			return harbor.ScanResponse{}, err2
		}

		// Add the credentials for the repository to be scanned
		err = s.EnsureRegistryCredentials(registry, req.Artifact.Repository, username, password)
		if err != nil {
			return harbor.ScanResponse{}, err
		}
	}
	// Convert and submit the scan request
	anchoreScanRequest, err := ScanToAnchoreRequest(req)
	if err != nil {
		return harbor.ScanResponse{}, err
	}

	err = client.AnalyzeImage(s.ClientConfiguration, *anchoreScanRequest)
	if err != nil {
		log.Error("Could not submit image for analysis ", err)
		return harbor.ScanResponse{}, err
	}

	// All ok, so return the scan Id to lookup results
	return harbor.ScanResponse{
		ID: scanId,
	}, nil
}

// update method and parameter passed in
func (s *HarborScannerAdapter) GetHarborVulnerabilityReport(scanId string, includeDescriptions bool) (harbor.VulnerabilityReport, error) {

	log.Info("scanId: ", scanId)
	if scanId == "" {
		return harbor.VulnerabilityReport{}, errors.New("no scanId")
	}

	repository, digest, err := ScanIdToRegistryDigest(scanId)
	if err != nil {
		return harbor.VulnerabilityReport{}, err
	} else {
		log.WithFields(log.Fields{"repository": repository, "digest": digest}).Info("getting harbor vulnerability report")
	}

	anchoreVulnResponse, err := s.GetAnchoreVulnReport(digest)
	if err != nil {
		log.Error("error from vulnerability report api call to anchore")
		return harbor.VulnerabilityReport{}, err
	}

	vulnDescriptionMap := make(map[string]string)

	if includeDescriptions {
		// Get vulnerability id/group mappings for getting additional metadata
		// remove duplicates where vuln can have multiple matches
		uniqVulnIdNamespacePairs := make(map[anchore.NamespacedVulnerability]bool)
		for _, v := range anchoreVulnResponse.Vulnerabilities {
			vulnId := anchore.NamespacedVulnerability{
				ID:          v.VulnerabilityID,
				Namespace:   v.FeedGroup,
				Description: "",
			}

			// Check cache
			cachedDescription, ok := GetCachedVulnDescription(vulnId)
			if ok {
				// Found in cache, add to the final map
				vulnDescriptionMap[vulnId.ID] = cachedDescription
			} else {
				// Not in cache, pass to lookup array
				uniqVulnIdNamespacePairs[vulnId] = true
			}
		}

		// Convert the map into an array for downstream
		vulns := make([]anchore.NamespacedVulnerability, len(uniqVulnIdNamespacePairs))
		i := 0
		for v := range uniqVulnIdNamespacePairs {
			vulns[i] = v
			i++
		}

		// Add the descriptions in
		start := time.Now()
		err = client.GetVulnerabilityDescriptions(s.ClientConfiguration, &vulns)
		if err != nil {
			//Return without desc
			log.Printf("could not get vulnerability metadata for populating descriptions due to error %v", err)
		}

		// Pivot to a map for next call
		for _, desc := range vulns {
			vulnDescriptionMap[desc.ID] = desc.Description

			// Add to the cache
			CacheVulnDescription(desc)
		}

		descriptionTime := time.Now().Sub(start)
		log.WithFields(log.Fields{"duration": descriptionTime}).Debug("time to get descriptions")
	} else {
		log.Debug("Skipping vuln description merge, as dictated by configuration")
	}

	return s.ToHarborScanResult(repository, anchoreVulnResponse, vulnDescriptionMap)
}

func (s *HarborScannerAdapter) GetAnchoreVulnReport(digest string) (anchore.ImageVulnerabilityReport, error) {
	log.WithField("digest", digest).Debug("checking vulnerability report cache")
	anchoreVulnResponse, ok := GetCachedVulnReport(digest)
	if ok {
		log.Debug("found report in cache")
		return anchoreVulnResponse, nil
	} else {
		log.Debug("no report in cache, generating")
	}

	img, err := client.GetImage(s.ClientConfiguration, digest)
	if err != nil {
		return anchore.ImageVulnerabilityReport{}, err
	}
	if len(img) == 0 {
		// Unusual case, should be 404, but just in case to ensure correct array access
		return anchore.ImageVulnerabilityReport{}, fmt.Errorf("not found")
	} else {
		switch img[0].AnalysisStatus {
		case "analyzed":
			log.Debug("found analyzed image")
		case "analysis_failed":
			log.Debug("failed analysis")
			return anchore.ImageVulnerabilityReport{}, fmt.Errorf("scan failed")
		default:
			log.Debug("Pending analysis")
			return anchore.ImageVulnerabilityReport{}, fmt.Errorf("analysis pending")
		}
	}

	report, err := client.GetImageVulnerabilities(s.ClientConfiguration, digest, s.ClientConfiguration.FilterVendorIgnoredVulns)
	if err == nil {
		log.Debug("caching result report")
		CacheVulnReport(digest, report)
	}

	return report, err
}

// update method and parameter passed in
func (s *HarborScannerAdapter) GetRawVulnerabilityReport(scanId string) (harbor.RawReport, error) {
	log.Info("Getting raw report for scanId: ", scanId)
	if scanId == "" {
		return harbor.VulnerabilityReport{}, errors.New("no ScanId")
	}

	repository, digest, err := ScanIdToRegistryDigest(scanId)
	if err != nil {
		return harbor.VulnerabilityReport{}, err
	} else {
		log.WithFields(log.Fields{"repository": repository, "digest": digest}).Info("getting raw vulnerability report")
	}

	return s.GetAnchoreVulnReport(digest)
}

//Convert the Anchore vuln to a harbor description
func ToHarborDescription(anchoreVuln *anchore.Vulnerability) (string, error) {
	var CVSSv3 float64
	var CVSSv2 float64
	var vendorCVSSv3 float64
	var vendorCVSSv2 float64

	for _, nvd := range anchoreVuln.NvdData {
		if nvd.CVSSv3Score.BaseScore > CVSSv3 {
			CVSSv3 = nvd.CVSSv3Score.BaseScore
		}

		if nvd.CVSSv2Score.BaseScore > CVSSv2 {
			CVSSv2 = nvd.CVSSv2Score.BaseScore
		}
	}

	for _, vnd := range anchoreVuln.VendorData {
		if vnd.CVSSv3Score.BaseScore > vendorCVSSv3 {
			vendorCVSSv3 = vnd.CVSSv3Score.BaseScore
		}

		if vnd.CVSSv2Score.BaseScore > vendorCVSSv2 {
			vendorCVSSv2 = vnd.CVSSv2Score.BaseScore
		}
	}

	return fmt.Sprintf(DescriptionFormatString, vendorCVSSv3, vendorCVSSv2, CVSSv3, CVSSv2), nil
}

func (s *HarborScannerAdapter) ToHarborScanResult(repo string, srs anchore.ImageVulnerabilityReport, vulnDescriptions map[string]string) (harbor.VulnerabilityReport, error) {
	var vulnerabilities = make([]harbor.VulnerableItem, len(srs.Vulnerabilities))
	var maxSev = harbor.SevNone
	var sev harbor.Severity
	var err error
	//
	for i, v := range srs.Vulnerabilities {
		sev = harbor.ToHarborSeverity(v.Severity)
		description, ok := vulnDescriptions[v.VulnerabilityID]

		if !ok || description == "" {
			description, err = ToHarborDescription(&v)
			if err != nil {
				log.Printf("could not format harbor description from vuln cvss data %v", err)
			}
		}

		if description == "" {
			description = "unavailable. see link"
		}

		vulnerabilities[i] = harbor.VulnerableItem{
			ID:          v.VulnerabilityID,
			Severity:    sev,
			Pkg:         v.PkgName,
			Version:     v.InstalledVersion,
			Links:       []string{v.URL},
			Fixed:       v.Fix,
			Description: description,
		}

		if vulnerabilities[i].Fixed == "None" {
			// In Anchore API this means there is no fix available. Zero it here
			vulnerabilities[i].Fixed = ""
		}

		if sev > maxSev {
			maxSev = sev
		}
	}

	return harbor.VulnerabilityReport{
		GeneratedAt: time.Now(),
		Artifact: harbor.Artifact{
			Repository: repo,
			Digest:     srs.ImageDigest,
		},
		Scanner:         adapter.AdapterMetadata.Scanner,
		Severity:        maxSev,
		Vulnerabilities: vulnerabilities, //VulnNamespace listing
	}, nil
}

func nowISOFormat() string {
	t := time.Now()
	return t.UTC().Format(time.RFC3339)
}

func (s *HarborScannerAdapter) GetMetadata() (harbor.ScannerAdapterMetadata, error) {
	adapterMeta := adapter.AdapterMetadata

	var feedsUpdated time.Time
	feedsUpdated, err := client.GetVulnDbUpdateTime(s.ClientConfiguration)
	if err != nil {
		log.WithField("err", err).Error("could not get vulnerability db update time")
		return harbor.ScannerAdapterMetadata{}, err
		//adapterMeta.Properties[adapter.HarborMetadataVulnDbUpdateKey] = ""
	} else {
		log.WithField("db_update_timestamp", feedsUpdated).Debug("vulnerability DB update timestamp retrieved")
		adapterMeta.Properties[adapter.HarborMetadataVulnDbUpdateKey] = feedsUpdated.Format(time.RFC3339)
	}

	return adapterMeta, nil
}
