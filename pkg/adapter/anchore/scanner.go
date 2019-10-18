package anchore

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	log "github.com/sirupsen/logrus"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/anchore/harbor-scanner-adapter/pkg/adapter"
	"github.com/anchore/harbor-scanner-adapter/pkg/model/anchore"
	"github.com/anchore/harbor-scanner-adapter/pkg/model/harbor"
	"github.com/parnurzeal/gorequest"
)

const (
	DescriptionFormatString = "Description unavailable. \nVendor-specific CVSS v3/v2 Scores: %.1f/%.1f. \nNVD CVSS v3/v2 Scores: %.1f/%.1f (Score of -1.0 means data unavailable).\nFor more detail see link: %v"
)

type imageScanner struct {
	ClientConfiguration *ClientConfig
}

// NewScanner constructs new ScannerAdapter with the given Config.
func NewScanner(cfg *ClientConfig) (adapter.ScannerAdapter, error) {
	if cfg == nil {
		return nil, errors.New("anchore client configuration must not be nil")
	}
	return &imageScanner{
		ClientConfiguration: cfg,
	}, nil
}

func GenerateScanId(registry string, repository string, digest string, tag string) (string, error) {
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
	return parts[0], parts[1], nil
}

func ScanToAnchoreRequest(req harbor.ScanRequest) (*anchore.AnchoreImageScanRequest, error) {
	fakeTag := req.Artifact.Digest[7:] // Map the digest to a tag name for anchore since anchore requires a tag

	var registryHostPort, err = ExtractRegistryFromUrl(req.Registry.URL)
	if err != nil {
		return nil, err
	}

	tagPullString := fmt.Sprintf("%s/%s:%s", registryHostPort, req.Artifact.Repository, fakeTag)
	digestPullString := fmt.Sprintf("%s/%s@%s", registryHostPort, req.Artifact.Repository, req.Artifact.Digest)

	var anchoreReq = &anchore.AnchoreImageScanRequest{
		Source: anchore.AnchoreImageSource{
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

func ExtractRegistryFromUrl(url string) (string, error) {
	registryURLComponents := strings.Split(url, "://")

	if len(registryURLComponents) == 1 {
		// No scheme, just use the value (e.g. url = "docker.io"
		return registryURLComponents[0], nil
	} else if len(registryURLComponents) > 1 {
		// Had a scheme, e.g url = "http://docker.io"
		return registryURLComponents[1], nil
	}

	return "", fmt.Errorf("invalid registry url format, cannot extract hostname:port")

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
func (s *imageScanner) AnchoreAddCreds(registry string, repository string, username string, password string) error {
	timeout := time.Duration(s.ClientConfiguration.TimeoutSeconds) * time.Second
	request := gorequest.New().SetBasicAuth(s.ClientConfiguration.Username, s.ClientConfiguration.Password)
	var registryName = fmt.Sprintf("%s/%s", strings.TrimSpace(registry), repository)
	var registryAddUrl = s.ClientConfiguration.Endpoint + "/v1/registries"
	var registryUpdateUrl = s.ClientConfiguration.Endpoint + "/v1/registries/" + url.PathEscape(registryName)
	var payload = fmt.Sprintf(`{"registry": "%s", "registry_user": "%s", "registry_pass": "%v", "registry_verify": false}`, registryName, username, password)

	resp, body, errs := request.Post(registryAddUrl).Set("Content-Type", "application/json").Timeout(timeout).Send(payload).End()
	log.Println("Anchore credential-add Response: ", body)
	if resp.StatusCode != http.StatusOK || errs != nil {

		// Handle retry with PUT instead. Detect if registry has creds already. Yes, should be 409, but currently is a 500
		if resp.StatusCode == http.StatusInternalServerError {

			var anchoreError = &anchore.AnchoreError{}
			err := json.Unmarshal([]byte(body), &anchoreError)
			if err != nil {
				log.Printf("Got error %v trying unmarshall anchore api error response into an anchore error object", err)
				return errs[0]
			}

			// Check if a PUT is needed
			if strings.Index(anchoreError.Message, "registry already exists") >= 0 {
				log.Printf("Updating %v, body: %v", registryUpdateUrl, payload)

				//Use PUT instead of POST
				log.Printf("Updating creds that already exist for this repo")
				resp, body, errs := request.Put(registryUpdateUrl).Set("Content-Type", "application/json").Timeout(timeout).Send(payload).End()
				log.Println("Anchore credential-add Response: ", body)
				if resp.StatusCode != http.StatusOK || errs != nil {
					log.Printf("Error updating credenials in anchore %v", errs)
					return fmt.Errorf("could not update registry credential in anchore")
				} else {
					//success on update
					return nil
				}
			}

		} else {
			return fmt.Errorf("could not update registry credential in anchore")
		}
	}

	//Success on add
	return nil
}

func (s *imageScanner) Scan(req harbor.ScanRequest) (harbor.ScanResponse, error) {
	scanId, err := GenerateScanId(req.Registry.URL, req.Artifact.Repository, req.Artifact.Digest, "")
	if err != nil {
		return harbor.ScanResponse{}, err
	}

	var registry string
	registry, err = ExtractRegistryFromUrl(req.Registry.URL)
	username, password, err2 := GetUsernamePassword(req.Registry.Authorization)
	if err2 != nil {
		return harbor.ScanResponse{}, err2
	}

	err = s.AnchoreAddCreds(registry, req.Artifact.Repository, username, password)
	if err != nil {
		return harbor.ScanResponse{}, err
	}

	anchoreScanRequest, err := ScanToAnchoreRequest(req)
	if err != nil {
		return harbor.ScanResponse{}, err
	}

	var scannerAPI = s.ClientConfiguration.Endpoint + "/v1/images"
	log.Printf("anchore-engine add image URL: %s", scannerAPI)

	timeout := time.Duration(s.ClientConfiguration.TimeoutSeconds) * time.Second
	var data anchore.AnchoreImages

	request := gorequest.New().SetBasicAuth(s.ClientConfiguration.Username, s.ClientConfiguration.Password)
	resp, body, errs := request.Post(scannerAPI).Type("json").Param("autosubscribe", "false").Send(anchoreScanRequest).Timeout(timeout).End()

	if errs != nil && len(errs) > 0 {
		log.Println("error sending scan request to anchore api", errs)
		return harbor.ScanResponse{}, nil
	}
	var sendBody []byte
	_, err = resp.Request.Body.Read(sendBody)

	log.Println("Response: ", body)
	if resp.StatusCode != http.StatusOK {
		log.Println("Could not submit image for analysis: ", body)
		return harbor.ScanResponse{}, fmt.Errorf("submission failure")
	}

	err = json.Unmarshal([]byte(body), &data)
	if err != nil {
		log.Printf("Failed response: ")
	}
	checkStatusStruct(resp, errs)

	log.Println("scan target (imageDigest): ", data[0].Digest)

	return harbor.ScanResponse{
		ID: scanId,
	}, nil
}

// update method and parameter passed in
func (s *imageScanner) GetHarborVulnerabilityReport(scanId string, includeDescriptions bool) (harbor.VulnerabilityReport, error) {

	log.Println("scanId: ", scanId)
	if scanId == "" {
		return harbor.VulnerabilityReport{}, errors.New("no ScanId")
	}

	repository, digest, err := ScanIdToRegistryDigest(scanId)
	if err != nil {
		return harbor.VulnerabilityReport{}, err
	}

	anchoreVulnResponse, err := s.GetAnchoreVulnReport(digest)
	if err != nil {
		return harbor.VulnerabilityReport{}, err
	}
	vulnDescriptionMap := make(map[string]string)

	if includeDescriptions {
		// Get vulnerability id/group mappings for getting additional metadata
		// remove duplicates where vuln can have multiple matches
		uniqVulnIdNamespacePairs := make(map[VulnNamespaceDescription]bool)
		for _, v := range anchoreVulnResponse.Vulnerabilities {
			uniqVulnIdNamespacePairs[VulnNamespaceDescription{
				id:          v.VulnerabilityID,
				namespace:   v.FeedGroup,
				description: "",
			}] = true
		}

		// Convert the map into an array for downstream
		vulns := make([]VulnNamespaceDescription, len(uniqVulnIdNamespacePairs))
		i := 0
		for v := range uniqVulnIdNamespacePairs {
			vulns[i] = v
			i++
		}

		// Add the descriptions in
		start := time.Now()
		err = GetVulnerabilityDescriptions(s.ClientConfiguration, &vulns)
		if err != nil {
			//Return without desc
			log.Printf("could not get vulnerability metadata for populating descriptions due to error %v", err)
		}

		log.Debugf("description list %v", vulns)

		// Pivot to a map for next call
		for _, desc := range vulns {
			vulnDescriptionMap[desc.id] = desc.description
		}
		log.Debugf("description map %v", vulnDescriptionMap)

		descriptionTime := time.Now().Sub(start)
		log.WithFields(log.Fields{"duration": descriptionTime}).Debug("time to get descriptions")
	} else {
		log.Debug("Skipping vuln description merge, as dictated by configuration")
	}

	return s.ToHarborScanResult(repository, anchoreVulnResponse, vulnDescriptionMap)
}

func (s *imageScanner) GetAnchoreVulnReport(digest string) (anchore.ScanResult, error) {
	return GetImageVulnerabilities(s.ClientConfiguration, digest, s.ClientConfiguration.FilterVendorIgnoredVulns)
}

// update method and parameter passed in
func (s *imageScanner) GetRawVulnerabilityReport(scanId string) (harbor.RawReport, error) {
	log.Println("Getting raw report for scanId: ", scanId)
	if scanId == "" {
		return harbor.VulnerabilityReport{}, errors.New("no ScanId")
	}

	_, digest, err := ScanIdToRegistryDigest(scanId)
	if err != nil {
		return harbor.VulnerabilityReport{}, err
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

	return fmt.Sprintf(DescriptionFormatString, vendorCVSSv3, vendorCVSSv2, CVSSv3, CVSSv2, anchoreVuln.URL), nil
}

func (s *imageScanner) ToHarborScanResult(repo string, srs anchore.ScanResult, vulnDescriptions map[string]string) (harbor.VulnerabilityReport, error) {
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

func checkStatusStruct(resp gorequest.Response, errs []error) {
	if errs != nil {
		if resp != nil {
			log.WithFields(log.Fields{"status": resp.Status, "statusCode": resp.StatusCode, "errs": errs}).Error("error response from anchore")
		} else {
			log.WithFields(log.Fields{"resp": "nil", "errs": errs}).Error("error response from anchore")
		}
	}
}

func nowISOFormat() string {
	t := time.Now()
	return t.UTC().Format(time.RFC3339)
}

func (s *imageScanner) GetMetadata() (harbor.ScannerAdapterMetadata, error) {
	adapterMeta := adapter.AdapterMetadata

	var feedsUpdated time.Time
	feedsUpdated, err := s.GetVulnDbUpdateTime()
	if err != nil {
		log.Printf("Could not verify vulnerability db update time due to error: %v", err)
		//return harbor.ScannerAdapterMetadata{}, err
		adapterMeta.Properties[adapter.HarborMetadataVulnDbUpdateKey] = ""
	} else {
		log.Printf("Db updated at %v", feedsUpdated)
		adapterMeta.Properties[adapter.HarborMetadataVulnDbUpdateKey] = feedsUpdated.Format(time.RFC3339)
	}

	return adapterMeta, nil
}

func (s *imageScanner) GetVulnDbUpdateTime() (time.Time, error) {
	request := gorequest.New().SetBasicAuth(s.ClientConfiguration.Username, s.ClientConfiguration.Password)
	timeout := time.Duration(s.ClientConfiguration.TimeoutSeconds) * time.Second
	resp, body, errs := request.Get(s.ClientConfiguration.Endpoint + "/v1/system/feeds").Timeout(timeout).End()
	if errs != nil {
		return time.Time{}, errs[0]
	}
	checkStatusStruct(resp, errs)

	feedsResp := anchore.FeedStatuses{}

	err := json.Unmarshal([]byte(body), &feedsResp)
	if err != nil {
		return time.Time{}, err
	}

	if len(feedsResp) > 0 {
		var newestSync = time.Time{}

		for _, feed := range feedsResp {
			for _, group := range feed.Groups {
				ts := group.LastSync
				if ts != "" {

					//Adjust the time to ensure it has trailing Z for UTC
					if ts[len(ts)-1] != 'Z' {
						ts = ts + "Z"
					}
					t, err := StringToTime(ts)
					if err != nil {
						return newestSync, err
					}
					if t.After(newestSync) {
						newestSync = t
					}
				}
			}
		}
		return newestSync, nil
	}

	return time.Time{}, nil
}

func StringToTime(timestampString string) (time.Time, error) {
	t, err := time.Parse(time.RFC3339Nano, timestampString)
	if err != nil {
		// Try without nano
		t, err = time.Parse(time.RFC3339, timestampString)
		if err != nil {
			return time.Time{}, err
		}

		return t, nil
	}
	return t, nil
}
