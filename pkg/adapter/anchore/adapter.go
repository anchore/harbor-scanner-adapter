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
	}
	return ""
}

// NewScannerAdapter constructs new HarborScannerAdapter with the given Config.
func NewScannerAdapter(cfg *AdapterConfig) (adapter.ScannerAdapter, error) {
	err := InitCaches(cfg.CacheConfig)
	if err != nil {
		log.WithFields(log.Fields{"err": err, "config": cfg.CacheConfig}).
			Errorf("could not initialized caches as configuration requested")
		return nil, err
	}
	return &HarborScannerAdapter{cfg}, nil
}

// GenerateScanID Create a scan id from the input image properties
func GenerateScanID(repository string, digest string) (string, error) {
	scanID := base64.URLEncoding.EncodeToString([]byte(fmt.Sprintf(`%s@%s`, repository, digest)))
	return scanID, nil
}

// ScanIDToRegistryDigest Inverse of GenerateScanId, gets the image components from the input ID
func ScanIDToRegistryDigest(scanID string) (string, string, error) {
	unsplit, err := base64.URLEncoding.DecodeString(scanID)
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
		}
		return "", "", fmt.Errorf("invalid digest format")
	}
	log.WithFields(log.Fields{"scanId": scanID, "repository": parts[0], "imageDigest": parts[1]}).Debug("parsed scanId")
	return parts[0], parts[1], nil
}

func ScanToAnchoreRequest(req harbor.ScanRequest) (*anchore.ImageScanRequest, error) {
	tag := req.Artifact.Digest[7:] // Map the digest to a tag name for anchore since anchore requires a tag
	if req.Artifact.Tag != "" {
		tag = req.Artifact.Tag
	}

	registryHostPort, err := client.ExtractRegistryFromURL(req.Registry.URL)
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

// GetUsernamePassword Returns the username and password from an authorizatino header input value (Harbor sends a single value
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

// EnsureRegistryCredentials Add credentials to Anchore for authorizing the image fetch
func (s *HarborScannerAdapter) EnsureRegistryCredentials(
	registryURL string,
	repository string,
	username string,
	password string,
) error {
	// New method, using client
	resp, body, errs := client.AddRegistryCredential(
		&s.Configuration.AnchoreClientConfig,
		registryURL,
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
			log.WithField("msg", anchoreError.Message).
				Debug("updating registry credential since one already exists but may be expired")

			// Do update
			resp, _, errs = client.UpdateRegistryCredential(
				&s.Configuration.AnchoreClientConfig,
				registryURL,
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
				log.WithFields(log.Fields{"ErrorMessage": anchoreError.Message, "Registry": registryURL, "repository": repository}).
					Error("unexpected response from anchore api. credential update not successful")
				return fmt.Errorf("unexpected response on registry credential update from anchore api: %v", resp.StatusCode)
			}
		} else {
			log.WithFields(log.Fields{"errorMessage": anchoreError.Message, "registry": registryURL, "repository": repository}).Error("unexpected response from anchore api could not determine if update action is appropriate for registry credentials")
			return fmt.Errorf("unexpected response from anchore api could not determine if update action is appropriate for registry credentials")
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
	scanID, err := GenerateScanID(req.Artifact.Repository, req.Artifact.Digest)
	if err != nil {
		log.Errorf("error encountered generating ScanId from Harbor scan request: %s", err)
		return harbor.ScanResponse{}, err
	}

	log.WithFields(log.Fields{"scanId": scanID, "repository": req.Artifact.Repository, "artifactDigest": req.Artifact.Digest, "artifactTag": req.Artifact.Tag}).
		Debug("generated ScanId")

	// Convert and submit the scan request
	anchoreScanRequest, err := ScanToAnchoreRequest(req)
	if err != nil {
		return harbor.ScanResponse{}, err
	}

	asyncCreateScan := func() (bool, error) {
		tokenLength := len(req.Registry.Authorization)

		if s.Configuration.UseAnchoreConfiguredCreds {
			log.WithFields(log.Fields{"scanId": scanID, "UseAnchoreConfiguredCredentials": s.Configuration.UseAnchoreConfiguredCreds, "ScanRequestTokenLength": tokenLength}).
				Debug("Skipping adding Harbor authz token to Anchore due to adapter configuration")
		} else {
			if req.Registry.Authorization == "" {
				log.WithFields(log.Fields{"scanId": scanID, "UseAnchoreConfiguredCredentials": s.Configuration.UseAnchoreConfiguredCreds, "ScanRequestTokenLength": tokenLength}).Debug("Skipping adding Harbor authz token to Anchore due to no token provided in request")
			} else {
				log.WithFields(log.Fields{"scanId": scanID, "UseAnchoreConfiguredCredentials": s.Configuration.UseAnchoreConfiguredCreds}).Debug("ensuring Anchore deployment has credentials for retrieving the image to scan")
				username, password, err2 := GetUsernamePassword(req.Registry.Authorization)
				if err2 != nil {
					log.WithFields(log.Fields{"scanId": scanID, "UseAnchoreConfiguredCredentials": s.Configuration.UseAnchoreConfiguredCreds}).Error("could not extract credentials for image pull access from the scan request authorization field")
					return false, err2
				}

				// Add the credentials for the repository to be scanned
				err = s.EnsureRegistryCredentials(req.Registry.URL, req.Artifact.Repository, username, password)
				if err != nil {
					log.WithFields(log.Fields{"scanId": scanID}).Error("failed ensuring that Anchore has authorized access to pull the image from Harbor")
					return false, err
				}
			}
		}

		err = client.AnalyzeImage(&s.Configuration.AnchoreClientConfig, *anchoreScanRequest)
		if err != nil {
			log.Error("Could not submit image for analysis ", err)
			return false, err
		}
		return true, nil
	}
	resultStore.RequestCreateScan(scanID, asyncCreateScan)

	log.WithFields(log.Fields{"scanId": scanID, "repository": req.Artifact.Repository, "artifactDigest": req.Artifact.Digest, "artifactTag": req.Artifact.Tag}).
		Info("scan successfully initiated against Anchore")
	// All ok, so return the scanId to lookup results
	return harbor.ScanResponse{
		ID: scanID,
	}, nil
}

// GetHarborVulnerabilityReport Return a vulnerability report in Harbor format if available for the requested ScanId. If not ready yet, returns empty result.
func (s *HarborScannerAdapter) GetHarborVulnerabilityReport(
	scanID string,
	includeDescriptions bool,
) (*harbor.VulnerabilityReport, error) {
	imageRepository, imageDigest, err := ScanIDToRegistryDigest(scanID)
	if err != nil {
		return nil, err
	}

	result, ok := resultStore.PopResult(scanID)
	log.WithFields(log.Fields{"scanId": scanID, "resultRecordFound": ok}).Debug("checked result store for scan Id result")
	if !ok {
		// No result found, so only continue if the image is in Anchore Enterprise and analyzed. This can happen if the adapter was restarted during a scan.
		log.WithFields(log.Fields{"scanId": scanID, "resultRecordFound": ok}).
			Info("no result found in store checking image is analyzed in Anchore Enterprise")
	}

	if !result.ScanCreated {
		log.WithFields(log.Fields{"scanId": scanID, "scanCreated": result.ScanCreated, "resultIsComplete": result.IsComplete, "resultError": result.Error}).
			Debug("scan not created yet")
		if result.Error != nil {
			return nil, result.Error
		}
		return nil, fmt.Errorf("create scan not ready")
	}

	if !result.AnalysisComplete {
		log.WithFields(log.Fields{"scanId": scanID, "errors": result.Error}).Debug("checking image analysis state in Anchore Enterprise")
		if result.Error != nil {
			if result.Error.Error() == "image not found" || result.Error.Error() == "analysis failed" {
				log.WithFields(log.Fields{"error": result.Error}).Error("image analysis failed or image not found in Anchore Enterprise")

				// Mark the Raw result as errored too to fail fast
				rawScanID := fmt.Sprintf("%s-raw", scanID)
				rawResult, ok := resultStore.PopResult(rawScanID)
				if ok {
					log.WithFields(log.Fields{"scanId": scanID, "rawScanId": rawScanID}).Debug("marking raw result as errored since analysis failed or image not found")
					rawResult.Error = result.Error
					rawResult.IsComplete = true
					resultStore.SafeUpdateResult(rawScanID, rawResult)
				}

				return nil, result.Error
			}
		}
		imageAnalsisFn := func() (bool, error) {
			return IsImageAnalysed(imageDigest, scanID, &s.Configuration.AnchoreClientConfig)
		}
		resultStore.RequestAnalysisStatus(scanID, imageAnalsisFn)
		return nil, fmt.Errorf("result not ready")
	}

	if result.ReportBuildInProgress {
		log.WithFields(log.Fields{"scanId": scanID, "resultIsComplete": result.IsComplete, "resultError": result.Error}).
			Debug("checked result store for scan Id result")
		if result.IsComplete {
			return result.Result, result.Error
		}
		return nil, fmt.Errorf("result not ready")
	}

	fn := func() (*harbor.VulnerabilityReport, error) {
		rep, err := BuildHarborVulnerabilityReport(
			scanID,
			imageRepository,
			imageDigest,
			includeDescriptions,
			&s.Configuration.AnchoreClientConfig,
			s.Configuration.FilterVendorIgnoredVulns,
		)
		if err != nil {
			return nil, err
		}

		log.Debug("Got report from BuildHarborVulnerabilityReport for scanId: ", scanID)
		return &rep, err
	}

	log.WithField("scanId", scanID).Info("begin building vulnerability report")
	requestResult := resultStore.RequestResult(scanID, fn)
	if requestResult.Error != nil {
		return nil, requestResult.Error
	}
	return requestResult.Result, nil
}

type ImageState int64

const (
	NotFound       ImageState = 0
	AnalysisFailed ImageState = 1
	Analyzing      ImageState = 2
	Analyzed       ImageState = 3
)

func IsImageAnalysed(imageDigest, scanID string, clientConfig *client.Config) (bool, error) {
	imageState, err := GetImageState(imageDigest, clientConfig)
	if err != nil {
		return false, err
	}

	log.WithFields(log.Fields{"scanId": scanID, "imageState": imageState, "imageDigest": imageDigest}).
		Debug("image analysis state check")

	switch imageState {
	case Analyzed:
		log.WithFields(log.Fields{"scanId": scanID, "imageState": imageState, "imageDigest": imageDigest}).
			Debug("found analyzed image")
		return true, nil
	case AnalysisFailed:
		log.WithFields(log.Fields{"scanId": scanID, "imageState": imageState, "imageDigest": imageDigest}).
			Debug("analysis failed")
		return false, fmt.Errorf("analysis failed")
	case Analyzing:
		log.WithFields(log.Fields{"scanId": scanID, "imageState": imageState, "imageDigest": imageDigest}).
			Debug("analysis pending")
		return false, fmt.Errorf("analysis pending")
	default:
		log.WithFields(log.Fields{"scanId": scanID, "imageState": imageState, "imageDigest": imageDigest}).
			Debug("analysis incomplete but unknown state")
		return false, fmt.Errorf("analysis in unknown state")
	}
}

func GetImageState(imageDigest string, clientConfig *client.Config) (ImageState, error) {
	log.WithField("imageDigest", imageDigest).Debug("checking vulnerability report cache")
	_, ok := ReportCache.Get(imageDigest)
	if ok {
		log.WithField("imageDigest", imageDigest).Debug("found report in cache")
		return Analyzed, nil
	}
	log.WithField("imageDigest", imageDigest).Debug("no report in cache, generating")

	img, err := client.GetImage(clientConfig, imageDigest, 0)
	if err != nil {
		return NotFound, err
	}

	log.WithFields(log.Fields{"imageDigest": imageDigest, "analysis_status": img.AnalysisStatus}).
		Debug("image analysis status")
	switch img.AnalysisStatus {
	case "analyzed":
		return Analyzed, nil
	case "analysis_failed":
		return AnalysisFailed, nil
	case "analyzing":
		return Analyzing, nil
	case "not_analyzed":
		return Analyzing, nil
	default:
		state := img.AnalysisStatus
		log.Debugf("unknown analysis state %s", state)
		return NotFound, fmt.Errorf("unknown analysis state %s", state)
	}
}

// BuildHarborVulnerabilityReport Construct the harbor-formatted vulnerability report from an analyzed image in Anchore
func BuildHarborVulnerabilityReport(
	scanID string,
	imageRepository string,
	imageDigest string,
	includeDescriptions bool,
	clientConfig *client.Config,
	filterVendorIgnoredVulns bool,
) (harbor.VulnerabilityReport, error) {
	if imageRepository == "" || imageDigest == "" {
		return harbor.VulnerabilityReport{}, errors.New("no repository or digest provided to build vuln report for")
	}
	log.WithFields(log.Fields{"repository": imageRepository, "imageDigest": imageDigest}).
		Debug("getting harbor vulnerability report")

	start := time.Now()
	anchoreVulnResponse, err := GetAnchoreVulnReport(scanID, imageDigest, clientConfig, filterVendorIgnoredVulns)
	if err != nil {
		log.WithFields(log.Fields{"repository": imageRepository, "imageDigest": imageDigest}).
			Error("error from vulnerability report api call to Anchore")
		return harbor.VulnerabilityReport{}, err
	}

	vulnListingTime := time.Since(start)
	log.WithFields(log.Fields{"repository": imageRepository, "imageDigest": imageDigest, "vulnerabilityListApiCallDuration": vulnListingTime}).
		Debug("time to get vulnerability listing")

	vulnDescriptionMap := make(map[string]string)

	if includeDescriptions {
		// Get vulnerability id/group mappings for getting additional metadata
		// remove duplicates where vuln can have multiple matches
		uniqVulnIDNamespacePairs := make(map[anchore.NamespacedVulnerability]bool)
		for _, v := range anchoreVulnResponse.Vulnerabilities {
			vulnID := anchore.NamespacedVulnerability{
				ID:          v.VulnerabilityID,
				Namespace:   v.FeedGroup,
				Description: "",
			}

			// Check cache
			cachedDescription, ok := DescriptionCache.Get(cacheKeyForVuln(&vulnID))
			if ok {
				// Found in cache, add to the final map
				vulnDescriptionMap[vulnID.ID] = cachedDescription.(string)
			} else {
				// Not in cache, pass to lookup array
				uniqVulnIDNamespacePairs[vulnID] = true
			}
		}

		// Convert the map into an array for downstream
		vulns := make([]anchore.NamespacedVulnerability, len(uniqVulnIDNamespacePairs))
		i := 0
		for v := range uniqVulnIDNamespacePairs {
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
		log.WithFields(log.Fields{"repository": imageRepository, "imageDigest": imageDigest, "vulnerabilityDescriptionConstructionDuration": descriptionTime}).
			Debug("time to get descriptions")
	} else {
		log.Debug("Skipping vuln description merge, as dictated by configuration")
	}

	log.WithFields(log.Fields{"repository": imageRepository, "imageDigest": imageDigest}).
		Debug("finished fetching Anchore data to construct scan result")
	return ToHarborScanResult(imageRepository, anchoreVulnResponse, vulnDescriptionMap)
}

func GetAnchoreVulnReport(
	scanID string,
	digest string,
	clientConfig *client.Config,
	filterVendorIgnoredVulns bool,
) (anchore.ImageVulnerabilityReport, error) {
	report, err := client.GetImageVulnerabilities(clientConfig, digest, filterVendorIgnoredVulns, 0)
	if err == nil {
		log.WithFields(log.Fields{"scanID": scanID, "imageDigest": digest}).Debug("caching result report")
		ReportCache.Add(digest, report)
	} else {
		log.WithFields(log.Fields{"scanID": scanID, "imageDigest": digest, "error": err}).Debug("Error getting image vulnerabilities")
	}

	return report, err
}

// GetRawVulnerabilityReport Get an adapter-native (Anchore) formatted vulnerability report for the requested ScanId
func (s *HarborScannerAdapter) GetRawVulnerabilityReport(scanID string) (harbor.RawReport, error) {
	if scanID == "" {
		return harbor.VulnerabilityReport{}, errors.New("no ScanId")
	}

	repository, digest, err := ScanIDToRegistryDigest(scanID)
	if err != nil {
		return harbor.VulnerabilityReport{}, err
	}

	rawScanID := fmt.Sprintf("%s-raw", scanID) // Used to store just the raw report results in the rawResult store
	rawResult, _ := resultStore.PopResult(rawScanID)
	result, resultFound := resultStore.GetResult(scanID)

	// If there is no entry in the cache for the base scanID (harbor formatted report) and the raw ScanCreated is false
	// then the original create scan request was unsuccessful, likely due to the image being unable to be added to Anchore
	// so we need to fail fast.
	if !resultFound && !rawResult.ScanCreated {
		log.WithFields(log.Fields{"scanId": scanID}).Debug("scan creation failed, no result found in store for scanId")
		return nil, fmt.Errorf("create scan unsuccessful")
	}

	// Check Scan has been created for the non-report report. This ensures the image is in Anchore Enterprise and submitted for analysis.
	if !rawResult.ScanCreated && !result.ScanCreated {
		log.WithFields(log.Fields{"scanId": rawScanID, "scanCreated": result.ScanCreated, "resultIsComplete": result.IsComplete, "resultError": result.Error}).
			Debug("scan not created yet")
		if rawResult.Error != nil {
			return nil, result.Error
		}
		// If the original scan contains an eror then return as this indicates the image is not in Anchore Enterprise
		if result.Error != nil {
			return nil, result.Error
		}
		return nil, fmt.Errorf("create scan not ready")
	}

	if !rawResult.AnalysisComplete {
		log.WithFields(log.Fields{"scanId": rawScanID, "errors": result.Error}).Debug("checking image analysis state in Anchore Enterprise")
		if rawResult.Error != nil {
			if rawResult.Error.Error() == "image not found" || rawResult.Error.Error() == "analysis failed" {
				log.WithFields(log.Fields{"error": rawResult.Error}).Error("image analysis failed or image not found in Anchore Enterprise")
				return nil, result.Error
			}
		}
		imageAnalsisFn := func() (bool, error) {
			return IsImageAnalysed(digest, rawScanID, &s.Configuration.AnchoreClientConfig)
		}
		resultStore.RequestAnalysisStatus(rawScanID, imageAnalsisFn)
		return nil, fmt.Errorf("result not ready")
	}

	if rawResult.ReportBuildInProgress {
		log.WithFields(log.Fields{"scanId": rawScanID, "resultIsComplete": rawResult.IsComplete, "resultError": rawResult.Error}).
			Debug("checked result store for scan Id result")
		if rawResult.IsComplete {
			return rawResult.RawResult, rawResult.Error
		}
		return nil, fmt.Errorf("result not ready")
	}

	rawReportFn := func() (*anchore.ImageVulnerabilityReport, error) {
		log.WithFields(log.Fields{"repository": repository, "imageDigest": digest, "scanId": rawScanID}).
			Info("Getting raw Anchore-formatted vulnerability report")
		rep, err := GetAnchoreVulnReport(
			rawScanID,
			digest,
			&s.Configuration.AnchoreClientConfig,
			s.Configuration.FullVulnerabilityDescriptions,
		)
		if err != nil {
			return nil, err
		}
		return &rep, err
	}

	requestResult := resultStore.RequestRawResult(rawScanID, rawReportFn)
	if requestResult.Error != nil {
		return nil, requestResult.Error
	}
	return requestResult.Result, nil
}

// ToHarborDescription Convert the Anchore Vulnerability record to a harbor description string
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

	// Disable RawReportMimeType if not enabled
	if !s.Configuration.EnableRawMimeType {
		adapterMeta.Capabilities[0].ProducesMIMETypes = []string{adapter.HarborVulnReportv1MimeType}
	}

	var err error
	var feedsUpdated time.Time

	if cached, ok := UpdateTimestampCache.Get("db"); ok {
		feedsUpdated = cached.(time.Time)
	} else {
		feedsUpdated, err = client.GetVulnDBUpdateTime(&s.Configuration.AnchoreClientConfig)
		if err != nil {
			log.WithField("err", err).Error("could not get vulnerability db update time")
			return harbor.ScannerAdapterMetadata{}, err
		}
	}

	// Cache result
	UpdateTimestampCache.Add("db", feedsUpdated)

	log.WithField("VulnerabilityDbUpdateTimestamp", feedsUpdated).Debug("vulnerability DB update timestamp retrieved")
	adapterMeta.Properties[adapter.HarborMetadataVulnDBUpdateKey] = feedsUpdated.Format(time.RFC3339)
	return adapterMeta, nil
}
