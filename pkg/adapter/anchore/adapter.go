package anchore

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"regexp"
	"strings"
	"time"

	log "github.com/sirupsen/logrus"

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
	Configuration *AdapterConfig
}

// Compute the key for the item
func cacheKeyForVuln(v *anchore.NamespacedVulnerability) string {
	if v != nil {
		return fmt.Sprintf("%v/%v", v.Namespace, v.ID)
	} else {
		return ""
	}
}

// NewScannerAdapter constructs new HarborScannerAdapter with the given Config.
func NewScannerAdapter(cfg *AdapterConfig) (adapter.ScannerAdapter, error) {
	err := InitCaches(cfg.CacheConfig)
	if err != nil {
		log.Errorf("could not initialized caches as configuration requested: %s", err)
		return nil, err
	}
	return &HarborScannerAdapter{cfg}, nil
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
		// Handle issue with split parts if the latter part doesn't match a digest format
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
	tag := req.Artifact.Digest[7:] // Map the digest to a tag name for anchore since anchore requires a tag
	if req.Artifact.Tag != "" {
		tag = req.Artifact.Tag
	}

	registryHostPort, err := client.ExtractRegistryFromUrl(req.Registry.URL)
	if err != nil {
		return nil, err
	}

	tagPullString := fmt.Sprintf("%s/%s:%s", registryHostPort, req.Artifact.Repository, tag)
	digestPullString := fmt.Sprintf("%s/%s@%s", registryHostPort, req.Artifact.Repository, req.Artifact.Digest)

	anchoreReq := &anchore.ImageScanRequest{
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
		// Expected case: {<scheme>, <value>}
		if strings.ToLower(components[0]) != "basic" {
			return "", "", fmt.Errorf("unsupported authorization type %v", components[0])
		}
		authzValue = components[1]

	} else {
		// Assume just the value
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
func (s *HarborScannerAdapter) EnsureRegistryCredentials(
	registryUrl string,
	repository string,
	username string,
	password string,
) error {
	// New method, using client
	resp, body, errs := client.AddRegistryCredential(
		&s.Configuration.AnchoreClientConfig,
		registryUrl,
		repository,
		username,
		password,
		s.Configuration.RegistryTLSVerify,
		s.Configuration.RegistryValidateCreds,
	)
	if errs != nil {
		log.WithField("errs", errs).Error("could not execute request to anchore api to add registry credential")
		return errs[0]
	}

	if resp.StatusCode == http.StatusInternalServerError || resp.StatusCode == http.StatusConflict {
		anchoreError := anchore.Error{}
		err := json.Unmarshal(body, &anchoreError)
		if err != nil {
			log.Errorf("got error %v trying unmarshal anchore api error response into an anchore error object", err)
			return err
		}

		// Check if a PUT is needed
		if anchoreError.Message == "registry already exists in DB" {
			log.WithField("msg", anchoreError.Message).Debug("updating registry credential since one already exists")

			// Do update
			resp, body, errs = client.UpdateRegistryCredential(
				&s.Configuration.AnchoreClientConfig,
				registryUrl,
				repository,
				username,
				password,
				s.Configuration.RegistryTLSVerify,
				s.Configuration.RegistryValidateCreds,
			)
			if errs != nil {
				log.WithField("errs", errs).Error("could not execute request to anchore api to update registry credential")
				return errs[0]
			}
			if resp.StatusCode != http.StatusOK {
				log.WithFields(log.Fields{"errorMessage": anchoreError.Message, "registry": registryUrl, "repository": repository}).
					Error("unexpected response from anchore api. credential update not successful")
				return fmt.Errorf("unexpected response on registry credential update from anchore api: %v", resp.StatusCode)
			}
		} else {
			log.WithFields(log.Fields{"errorMessage": anchoreError.Message, "registry": registryUrl, "repository": repository}).Error("unexpected response from anchore api. could not determine if update action is appropriate")
			return fmt.Errorf("unexpected response from anchore api")
		}
	} else if resp.StatusCode != http.StatusOK {
		// More handling
		log.WithFields(log.Fields{"receivedResponse": string(body), "receivedStatusCode": resp.StatusCode}).Error("unexpected error response from anchore adding registry credential")
		return fmt.Errorf("failed to add valid credentials to anchore for registry")
	}

	log.Debug("successfully added registry credential to anchore")
	return nil
}

func (s *HarborScannerAdapter) Scan(req harbor.ScanRequest) (harbor.ScanResponse, error) {
	scanId, err := GenerateScanId(req.Artifact.Repository, req.Artifact.Digest)
	if err != nil {
		return harbor.ScanResponse{}, err
	}

	if !s.Configuration.UseAnchoreConfiguredCreds && req.Registry.Authorization != "" {
		username, password, err2 := GetUsernamePassword(req.Registry.Authorization)
		if err2 != nil {
			return harbor.ScanResponse{}, err2
		}

		// Add the credentials for the repository to be scanned
		err = s.EnsureRegistryCredentials(req.Registry.URL, req.Artifact.Repository, username, password)
		if err != nil {
			return harbor.ScanResponse{}, err
		}
	} else {
		if s.Configuration.UseAnchoreConfiguredCreds {
			log.Info("Skipping adding Harbor authz token to Anchore due to adapter configuration")
		} else {
			log.Info("Skipping adding Harbor authz token to Anchore due to no token provided in request")
		}
	}

	// Convert and submit the scan request
	anchoreScanRequest, err := ScanToAnchoreRequest(req)
	if err != nil {
		return harbor.ScanResponse{}, err
	}

	err = client.AnalyzeImage(&s.Configuration.AnchoreClientConfig, *anchoreScanRequest)
	if err != nil {
		log.Error("Could not submit image for analysis ", err)
		return harbor.ScanResponse{}, err
	}

	// All ok, so return the scan Id to lookup results
	return harbor.ScanResponse{
		ID: scanId,
	}, nil
}

// If not ready yet, return empty result
func (s *HarborScannerAdapter) GetHarborVulnerabilityReport(
	scanId string,
	includeDescriptions bool,
) (*harbor.VulnerabilityReport, error) {
	imageRepository, imageDigest, err := ScanIdToRegistryDigest(scanId)
	if err != nil {
		return nil, err
	}

	imageState, err := GetImageState(imageDigest, &s.Configuration.AnchoreClientConfig)
	if err != nil {
		return nil, err
	}
	if imageState != Analyzed {
		return &harbor.VulnerabilityReport{}, fmt.Errorf("analysis not complete")
	}

	result, ok := resultStore.PopResult(scanId)

	if ok {
		log.Debug("Found result in cache")
		log.Debug("Result Complete?: ", result.IsComplete)
		log.Debug("Result Error?: ", result.Error)
		if result.IsComplete {
			return result.Result, result.Error
		} else {
			return nil, fmt.Errorf("result not ready")
		}
	} else {
		fn := func() (*harbor.VulnerabilityReport, error) {
			rep, err := BuildHarborVulnerabilityReport(imageRepository, imageDigest, includeDescriptions, &s.Configuration.AnchoreClientConfig, s.Configuration.FilterVendorIgnoredVulns)
			if err != nil {
				return nil, err
			}

			log.Debug("Got report from BuildHarborVulnerabilityReport for scanId: ", scanId)
			return &rep, err
		}

		requestResult := resultStore.RequestResult(scanId, fn)
		if requestResult.Error != nil {
			return nil, requestResult.Error
		}
		return requestResult.Result, nil
	}
}

type ImageState int64

const (
	NotFound       ImageState = 0
	AnalysisFailed ImageState = 1
	Analyzing      ImageState = 2
	Analyzed       ImageState = 3
)

func GetImageState(imageDigest string, clientConfig *client.ClientConfig) (ImageState, error) {
	log.WithField("digest", imageDigest).Debug("checking vulnerability report cache")
	_, ok := ReportCache.Get(imageDigest)
	if ok {
		log.WithField("digest", imageDigest).Debug("found report in cache")
		return Analyzed, nil
	} else {
		log.WithField("digest", imageDigest).Debug("no report in cache, generating")
	}

	img, err := client.GetImage(clientConfig, imageDigest)
	if err != nil {
		return NotFound, err
	}
	if len(img) == 0 {
		// Unusual case, should be 404, but just in case to ensure correct array access
		return NotFound, fmt.Errorf("not found")
	}

	switch img[0].AnalysisStatus {
	case "analyzed":
		log.Debug("found analyzed image")
		return Analyzed, nil
	case "analysis_failed":
		log.Debug("analysis failed")
		return AnalysisFailed, nil
	case "analyzing":
		log.Debug("analysis pending")
		return Analyzing, nil
	case "not_analyzed":
		log.Debug("analysis pending")
		return Analyzing, nil
	default:
		state := img[0].AnalysisStatus
		log.Debugf("unknown analysis state %s", state)
		return NotFound, fmt.Errorf("unknown analysis state %s", state)
	}
}

// Construct the harbor report type from an assumed-analyzed image
func BuildHarborVulnerabilityReport(
	imageRepository string,
	imageDigest string,
	includeDescriptions bool,
	clientConfig *client.ClientConfig,
	filterVendorIgnoredVulns bool,
) (harbor.VulnerabilityReport, error) {
	if imageRepository == "" || imageDigest == "" {
		return harbor.VulnerabilityReport{}, errors.New("no repository or digest provided to build vuln report for")
	} else {
		log.WithFields(log.Fields{"repository": imageRepository, "digest": imageDigest}).Info("getting harbor vulnerability report")
	}

	anchoreVulnResponse, err := GetAnchoreVulnReport(imageDigest, clientConfig, filterVendorIgnoredVulns)
	if err != nil {
		log.Error("error from vulnerability report api call to Anchore")
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
			cachedDescription, ok := DescriptionCache.Get(cacheKeyForVuln(&vulnId))
			if ok {
				// Found in cache, add to the final map
				vulnDescriptionMap[vulnId.ID] = cachedDescription.(string)
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
		err = client.GetVulnerabilityDescriptions(clientConfig, &vulns)
		if err != nil {
			// Return without desc
			log.WithField("err", err).Warn("could not get vulnerability metadata for populating descriptions due to error")
		}

		// Pivot to a map for next call
		for _, desc := range vulns {
			vulnDescriptionMap[desc.ID] = desc.Description

			// Add to the cache
			DescriptionCache.Add(cacheKeyForVuln(&desc), desc.Description)
		}

		descriptionTime := time.Since(start)
		log.WithFields(log.Fields{"duration": descriptionTime}).Debug("time to get descriptions")
	} else {
		log.Debug("Skipping vuln description merge, as dictated by configuration")
	}

	log.Debug("Finished Building Report!!")
	return ToHarborScanResult(imageRepository, anchoreVulnResponse, vulnDescriptionMap)
}

func GetAnchoreVulnReport(
	digest string,
	clientConfig *client.ClientConfig,
	filterVendorIgnoredVulns bool,
) (anchore.ImageVulnerabilityReport, error) {
	imageState, err := GetImageState(digest, clientConfig)
	if err != nil {
		return anchore.ImageVulnerabilityReport{}, err
	}

	// Handle nice error messages
	switch imageState {
	case Analyzed:
		log.Debug("found analyzed image")
		// Continue
	case AnalysisFailed:
		log.Debug("analysis failed")
		return anchore.ImageVulnerabilityReport{}, fmt.Errorf("analysis failed")
	case Analyzing:
		log.Debug("analysis pending")
		return anchore.ImageVulnerabilityReport{}, fmt.Errorf("analysis pending")
	default:
		log.Debug("analysis incomplete but unknown state")
		return anchore.ImageVulnerabilityReport{}, fmt.Errorf("analysis in unknown state")
	}

	report, err := client.GetImageVulnerabilities(clientConfig, digest, filterVendorIgnoredVulns)
	if err == nil {
		log.WithField("digest", digest).Debug("caching result report")
		ReportCache.Add(digest, report)
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

	return GetAnchoreVulnReport(digest, &s.Configuration.AnchoreClientConfig, s.Configuration.FullVulnerabilityDescriptions)
}

// Convert the Anchore vuln to a harbor description
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

func ToHarborScanResult(
	repo string,
	srs anchore.ImageVulnerabilityReport,
	vulnDescriptions map[string]string,
) (harbor.VulnerabilityReport, error) {
	vulnerabilities := make([]harbor.VulnerableItem, len(srs.Vulnerabilities))
	maxSev := harbor.SevNone
	var sev harbor.Severity
	var err error
	var description string
	var ok bool

	for i, v := range srs.Vulnerabilities {
		sev = harbor.ToHarborSeverity(v.Severity)

		if vulnDescriptions != nil {
			description, ok = vulnDescriptions[v.VulnerabilityID]
		} else {
			// Fall thru if no descriptions available
			description = ""
			ok = false
		}

		if !ok || description == "" {
			description, err = ToHarborDescription(&v)
			if err != nil {
				log.WithField("err", err).Warn("could not format harbor description from vuln cvss data")
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
		Vulnerabilities: vulnerabilities, // VulnNamespace listing
	}, nil
}

func nowISOFormat() string {
	t := time.Now()
	return t.UTC().Format(time.RFC3339)
}

func (s *HarborScannerAdapter) GetMetadata() (harbor.ScannerAdapterMetadata, error) {
	adapterMeta := adapter.AdapterMetadata
	var err error
	var feedsUpdated time.Time

	if cached, ok := UpdateTimestampCache.Get("db"); ok {
		feedsUpdated = cached.(time.Time)
	} else {
		feedsUpdated, err = client.GetVulnDbUpdateTime(&s.Configuration.AnchoreClientConfig)
		if err != nil {
			log.WithField("err", err).Error("could not get vulnerability db update time")
			return harbor.ScannerAdapterMetadata{}, err
		}
	}

	// Cache result
	UpdateTimestampCache.Add("db", feedsUpdated)

	log.WithField("db_update_timestamp", feedsUpdated).Debug("vulnerability DB update timestamp retrieved")
	adapterMeta.Properties[adapter.HarborMetadataVulnDbUpdateKey] = feedsUpdated.Format(time.RFC3339)
	return adapterMeta, nil
}
