package client

import (
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"net/url"
	"path"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/parnurzeal/gorequest"
	log "github.com/sirupsen/logrus"

	"github.com/anchore/harbor-scanner-adapter/pkg/adapter/anchore/credential"
	"github.com/anchore/harbor-scanner-adapter/pkg/model/anchore"
)

const (
	CHUNKSIZE                               = 100
	NVDFEEDGROUP                            = "nvdv2:cves"
	RegistryCredentialUpdateRequestTemplate = `{"registry": "%v", "registry_user": "%v", "registry_pass": "%v", "registry_verify": %v, "registry_type": "docker_v2"}` // #nosec G101
	AddImageURL                             = "/images"
	GetImageURLTemplate                     = "/images/%s"
	GetImageVulnerabilitiesURLTemplate      = "/images/%s/vuln/all"
	QueryVulnerabilitiesURLTemplate         = "/query/vulnerabilities"
	RegistriesCollectionURL                 = "/registries"
	RegistryCredentialUpdateURLTemplate     = "/registries/%s" // #nosec G101
	FeedsURL                                = "/system/feeds"
	VersionURL                              = "/version"
)

var apiVersion = "v2" // Defaults to v2 but will switch to v1 if v2 API is not supported

type Config struct {
	Endpoint       string
	Username       string
	Password       string
	TimeoutSeconds int
	TLSVerify      bool
}

func getNewRequest(clientConfiguration *Config) *gorequest.SuperAgent {
	passwordConfig := clientConfiguration.Password
	credenitalLoader := credential.CreateCredentialLoader(passwordConfig)
	clientConfiguration.Password = credenitalLoader.LoadFromCredentialStore(passwordConfig)

	timeout := time.Duration(clientConfiguration.TimeoutSeconds) * time.Second
	return gorequest.New().
		TLSClientConfig(&tls.Config{InsecureSkipVerify: clientConfiguration.TLSVerify}).
		SetBasicAuth(clientConfiguration.Username, clientConfiguration.Password).
		Timeout(timeout) // #nosec G402
}

func AnalyzeImage(clientConfiguration *Config, analyzeRequest anchore.ImageScanRequest) error {
	log.WithFields(log.Fields{"request": analyzeRequest}).Info("requesting image analysis")

	request := getNewRequest(clientConfiguration)

	reqURL, err := buildURLWithAPIVersion(*clientConfiguration, AddImageURL, nil)
	if err != nil {
		return err
	}

	var apiCompatibleRequest interface{}
	if apiVersion == "v1" {
		apiCompatibleRequest = anchore.ImageScanRequestV1{
			Source: anchore.ImageSourceV1{
				DigestSource: anchore.DigestSourceV1{
					PullString:                analyzeRequest.Source.DigestSource.PullString,
					Tag:                       analyzeRequest.Source.DigestSource.Tag,
					CreationTimestampOverride: analyzeRequest.Source.DigestSource.CreationTimestampOverride,
				},
			},
			ImageType:   analyzeRequest.ImageType,
			Annotations: analyzeRequest.Annotations,
		}
	} else {
		apiCompatibleRequest = analyzeRequest
	}

	log.WithFields(log.Fields{"method": "post", "url": reqURL}).Debug("sending request to anchore api")
	// call API get the full report until "analysis_status" = "analyzed"
	resp, body, errs := sendRequest(
		clientConfiguration,
		request.Post(reqURL).Set("Content-Type", "application/json").Send(apiCompatibleRequest),
	)
	if errs != nil {
		log.Errorf("could not contact anchore api")
		return errs[0]
	}
	if resp.StatusCode != 200 {
		log.WithFields(log.Fields{"body": string(body), "request": reqURL}).Debug("response from anchore api")
		return fmt.Errorf("request failed with status %v: %v", resp.StatusCode, string(body))
	}
	return nil
}

// Updates the Description fields in the input array of Description objects
func GetVulnerabilityDescriptions(clientConfiguration *Config, vulns *[]anchore.NamespacedVulnerability) error {
	var vulnListing anchore.VulnerabilityQueryResults

	// Sort and get namespaces for efficient lookups
	less := func(i, j int) bool {
		return (*vulns)[i].Namespace < (*vulns)[j].Namespace
	}

	sort.Slice(*vulns, less)

	// Used chunked fetch to get full listing, adding in the nvdv2 Namespace for extra coverage
	count := len(*vulns)
	if count == 0 {
		// Nothing to do
		return nil
	}

	for i := 0; i < count/CHUNKSIZE+1; i++ {
		start, end := getVulnProcessingChunks(count, i, CHUNKSIZE)

		vulnIDs := make([]string, end-start)
		namespaces := make(map[string]bool)

		if start < 0 || end > count+1 {
			log.WithFields(log.Fields{"start": start, "end": end}).
				Error("vulnerability description chunking returned out-of-bounds indexes. this should not happen")
			return fmt.Errorf("error generating vulnerability descriptions")
		}

		chunkToProcess := (*vulns)[start:end]
		log.WithFields(log.Fields{"total": count, "start": start, "end": end, "size": len(chunkToProcess)}).
			Trace("processing chunk of the vuln list")
		for i, v := range chunkToProcess {
			vulnIDs[i] = v.ID
			namespaces[v.Namespace] = true
		}

		// Ensure nvdv2 is set
		namespaces[NVDFEEDGROUP] = true

		// Construct Namespace filter
		namespaceNames := make([]string, len(namespaces))
		i := 0
		for v := range namespaces {
			namespaceNames[i] = v
			i++
		}

		// Split the input array into map[string][]string where key is the Namespace
		// Then query the system for a single Namespace and populate the result fields
		qryResults, errs := QueryVulnerabilityRecords(clientConfiguration, vulnIDs, namespaceNames)
		if errs != nil {
			log.WithField("errs", errs).Debug("error getting vuln records")
			return errs[0]
		}

		vulnListing.Vulnerabilities = append(vulnListing.Vulnerabilities, qryResults.Vulnerabilities...)
		vulnListing.ReturnedCount += qryResults.ReturnedCount
	}

	vulnDescriptionMap := make(map[string]map[string]string)

	// Build a map of vuln ID => map[string]string w/namespaces as 2nd layer key
	for _, result := range vulnListing.Vulnerabilities {
		if found, ok := vulnDescriptionMap[result.ID]; ok {
			found[result.Namespace] = result.Description
		} else {
			vulnDescriptionMap[result.ID] = map[string]string{
				result.Namespace: result.Description,
			}
		}
	}

	var foundDescription string

	// Update the Description for each input entry
	for i, vulnRecord := range *vulns {
		foundDescription = ""

		// update each with rules
		rec, ok := vulnDescriptionMap[vulnRecord.ID]
		if !ok {
			log.WithFields(log.Fields{"vulnerabilityId": vulnRecord.ID, "namespace": vulnRecord.Namespace}).
				Debug("no vulnerability record in anchore api vulnerability metadata query results")
			continue
		}
		if ns, ok := rec[vulnRecord.Namespace]; ok && ns != "" {
			foundDescription = ns
		} else if vulnRecord.Namespace != NVDFEEDGROUP {
			// No record in Namespace, try nvdv2
			if nvdDesc, ok := rec[NVDFEEDGROUP]; ok {
				foundDescription = nvdDesc
			}
		}

		if foundDescription == "" {
			log.WithField("vulnerabilityId", vulnRecord.ID).Trace("no description found for vulnerability")
		} else {
			if vulnRecord.Description == "" {
				log.WithField("vulnerabilityId", vulnRecord.ID).Trace("updating vulnerability description in response report")
				vulnRecord.Description = foundDescription
			} else {
				log.WithField("vulnerabilityId", vulnRecord.ID).Trace("vulnerability already has description, skipping update")
			}
		}

		(*vulns)[i] = vulnRecord
	}

	// Clean exit
	return nil
}

// Simple query that handles pagination and returns the results
func QueryVulnerabilityRecords(
	clientConfiguration *Config,
	ids []string,
	namespaces []string,
) (anchore.VulnerabilityQueryResults, []error) {
	var page string
	var vulnListing anchore.VulnerabilityQueryResults
	var vulnPage anchore.VulnerabilityQueryResults
	var start, end, pageStart, pageEnd time.Time

	vulnIDsStr := strings.Join(ids, ",")
	namespaceStr := strings.Join(namespaces, ",")

	request := getNewRequest(clientConfiguration)
	morePages := true

	start = time.Now()
	reqURL, err := buildURLWithAPIVersion(*clientConfiguration, QueryVulnerabilitiesURLTemplate, nil)
	if err != nil {
		return vulnListing, []error{err}
	}

	for morePages {
		pageStart = time.Now()

		req := request.Get(reqURL).Param("id", vulnIDsStr).Param("namespace", namespaceStr)
		if page != "" {
			req = req.Param("page", page)
		}

		resp, body, errs := sendRequest(clientConfiguration, req)
		if errs != nil {
			return vulnListing, errs
		}
		if resp.StatusCode == 200 {
			err := json.Unmarshal(body, &vulnPage)
			if err != nil {
				return vulnListing, []error{fmt.Errorf("failed getting vulnerability metadata")}
			}

			if vulnPage.NextPage != "" {
				morePages = true
				page = vulnPage.NextPage
				log.WithField("nextPage", vulnPage.NextPage).Debug("more pages found")
			} else {
				log.Debug("no more pages of results")
				morePages = false
				page = ""
			}

			vulnListing.Vulnerabilities = append(vulnListing.Vulnerabilities, vulnPage.Vulnerabilities...)

			// Merge the counts so the response to caller looks like the result of a single call
			vulnListing.ReturnedCount += vulnPage.ReturnedCount
		} else {
			log.WithFields(log.Fields{"status": resp.StatusCode, "body": string(body), "url": resp.Request.URL}).Errorf("got non 200 response from server for vuln query")
			return vulnListing, []error{fmt.Errorf("error response from server")}
		}

		pageEnd = time.Now()
		duration := pageEnd.Sub(pageStart)
		log.Debugf("querying took %v seconds", duration)
	}
	end = time.Now()
	duration := end.Sub(start)

	log.Debugf("Returning merged result of %v records", vulnListing.ReturnedCount)
	log.Debugf("querying took %v seconds", duration)

	return vulnListing, nil
}

// Return indexes for the requested chunk in the range to use for slices, the 2nd value is the open-set end (e.g. last index + 1)
func getVulnProcessingChunks(itemCount, chunkToGet, chunkSize int) (int, int) {
	last := itemCount
	cs := float64(chunkSize)
	if chunkToGet*chunkSize < itemCount {
		return chunkToGet * chunkSize, int(math.Min(float64(chunkToGet+1)*cs, float64(last)))
	}
	// Out of range
	return -1, -1
}

// Retrieve the vulnerabilities
func GetImageVulnerabilities(
	clientConfiguration *Config,
	digest string,
	filterIgnored bool,
	retryCount int,
) (anchore.ImageVulnerabilityReport, error) {
	log.WithFields(log.Fields{"digest": digest, "filterIgnored": filterIgnored}).Debug("retrieving scan result for image")

	var imageVulnerabilityReport anchore.ImageVulnerabilityReport

	reqURL, err := buildURLWithAPIVersion(*clientConfiguration, GetImageVulnerabilitiesURLTemplate, []interface{}{digest})
	if err != nil {
		return imageVulnerabilityReport, err
	}

	request := getNewRequest(clientConfiguration)
	resp, body, errs := sendRequest(
		clientConfiguration,
		request.Get(reqURL).Param("vendor_only", strconv.FormatBool(filterIgnored)),
	)
	if errs != nil {
		return imageVulnerabilityReport, errs[0]
	}

	if resp.StatusCode == 200 {
		if apiVersion == "v1" {
			var imageVulnerabilityReportV1 anchore.ImageVulnerabilityReportV1
			err := json.Unmarshal(body, &imageVulnerabilityReportV1)
			if err != nil {
				return anchore.ImageVulnerabilityReport(imageVulnerabilityReportV1), err
			}
			log.Debug("returning v1 image vulnerability report")
			return anchore.ImageVulnerabilityReport(imageVulnerabilityReportV1), nil
		}
		err := json.Unmarshal(body, &imageVulnerabilityReport)
		if err != nil {
			return imageVulnerabilityReport, err
		}
		return imageVulnerabilityReport, nil
	}
	if resp.StatusCode == 404 {
		log.WithFields(log.Fields{"digest": digest}).
			Debug("Received 404 getting Image vulnerabilities from Anchore, image not found in Anchore")

		// TODO Make the retry count configurable and backoff retries
		// Anchore returns 404 if the image is not found, retry up to 5 times
		// This is to handle the case where the image is still being submitted for analysis
		// and the image is not yet available in the Anchore DB
		if retryCount < 5 {
			log.WithFields(log.Fields{"digest": digest, "retryCount": retryCount}).
				Debug("retrying get image vulnerabilities")
			time.Sleep(5 * time.Second)
			return GetImageVulnerabilities(clientConfiguration, digest, filterIgnored, retryCount+1)
		}

		return imageVulnerabilityReport, fmt.Errorf("not found")
	}
	return imageVulnerabilityReport, fmt.Errorf("error response from anchore api")
}

func GetImage(clientConfiguration *Config, digest string, retryCount int) (anchore.Image, error) {
	log.WithFields(log.Fields{"digest": digest}).Debug("retrieving anchore state for image")

	var image anchore.Image
	request := getNewRequest(clientConfiguration)

	reqURL, err := buildURLWithAPIVersion(*clientConfiguration, GetImageURLTemplate, []interface{}{digest})
	if err != nil {
		return image, err
	}

	log.WithFields(log.Fields{"method": "get", "url": reqURL}).Debug("sending request to anchore api")
	// call API get the full report until "analysis_status" = "analyzed"
	resp, body, errs := sendRequest(clientConfiguration, request.Get(reqURL))
	if errs != nil {
		log.Errorf("could not contact anchore api")
		return image, errs[0]
	}

	if resp.StatusCode == 404 {
		log.WithFields(log.Fields{"digest": digest}).
			Debug("Received 404 getting Image from Anchore, image not found in Anchore")

		// TODO Make the retry count configurable and backoff retries
		// Anchore returns 404 if the image is not found, retry up to 5 times
		// This is to handle the case where the image is still being submitted for analysis
		// and the image is not yet available in the Anchore DB
		if retryCount < 5 {
			log.WithFields(log.Fields{"digest": digest, "retryCount": retryCount}).
				Debug("retrying image status check")
			time.Sleep(5 * time.Second)
			return GetImage(clientConfiguration, digest, retryCount+1)
		}

		return image, fmt.Errorf("image not found")
	}

	if apiVersion == "v1" {
		var imageList anchore.ImageListV1
		err = json.Unmarshal(body, &imageList)
		if err != nil {
			log.Errorf("unmarshall anchore api response")
			return image, err
		}
		if len(imageList) == 0 {
			// Unusual case, should be 404, but just in case to ensure correct array access
			return image, fmt.Errorf("not found")
		}
		if len(imageList) > 1 {
			log.WithFields(log.Fields{"imageDigest": digest, "imageCount": len(imageList)}).
				Warn("image status check returned more than one expected record. using the first")
		}
		image = anchore.Image{
			Digest:         imageList[0].Digest,
			AnalysisStatus: imageList[0].AnalysisStatus,
		}
		return image, nil
	}

	err = json.Unmarshal(body, &image)
	if err != nil {
		log.Errorf("unmarshall anchore api response")
		return image, err
	}

	return image, nil
}

func GetVulnDBUpdateTime(clientConfiguration *Config) (time.Time, error) {
	request := getNewRequest(clientConfiguration)
	reqURL, err := buildURLWithAPIVersion(*clientConfiguration, FeedsURL, nil)
	if err != nil {
		return time.Time{}, err
	}

	_, body, errs := sendRequest(clientConfiguration, request.Get(reqURL))
	if errs != nil {
		return time.Time{}, errs[0]
	}
	feedsResp := anchore.FeedStatuses{}

	err = json.Unmarshal(body, &feedsResp)
	if err != nil {
		return time.Time{}, err
	}

	if len(feedsResp) > 0 {
		newestSync := time.Time{}

		for _, feed := range feedsResp {
			for _, group := range feed.Groups {
				ts := group.LastSync
				if ts != "" {
					// Adjust the time to ensure it has trailing Z for UTC
					if ts[len(ts)-1] != 'Z' {
						ts += "Z"
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

// Get a time.Time version of a string
func StringToTime(timestampString string) (time.Time, error) {
	t, err := time.Parse(time.RFC3339Nano, timestampString)
	if err != nil {
		// Try without nano format
		t, err = time.Parse(time.RFC3339, timestampString)
		if err != nil {
			return time.Time{}, err
		}

		return t, nil
	}
	return t, nil
}

// Process the registry URL to return only the hostname and port as docker pull strings support
func ExtractRegistryFromURL(registryURL string) (string, error) {
	u, err := url.Parse(registryURL)
	if err != nil {
		return "", err
	}

	if u.Host != "" {
		return u.Host, nil
	}
	return "", fmt.Errorf("no host portion found in the input url. must be a full url with scheme")
}

// Return the registry credential entry as anchore will use it. This is the registry url minus the scheme + / + repository name
func RegistryNameFromRepo(registryURL string, repository string) (string, error) {
	reg, err := ExtractRegistryFromURL(registryURL)
	if err != nil {
		return "", err
	}

	return fmt.Sprintf("%v/%v", reg, repository), nil
}

// Build the request URL
func buildURL(config Config, requestPathTemplate string, args []interface{}) (string, error) {
	u, err := url.Parse(config.Endpoint)
	if err != nil {
		return "", err
	}

	u.Path = path.Join(u.Path, fmt.Sprintf(requestPathTemplate, args...))
	return u.String(), nil
}

// Build the request URL with API Version
func buildURLWithAPIVersion(config Config, requestPathTemplate string, args []interface{}) (string, error) {
	u, err := url.Parse(config.Endpoint)
	if err != nil {
		return "", err
	}

	u.Path = path.Join(u.Path, apiVersion, fmt.Sprintf(requestPathTemplate, args...))
	return u.String(), nil
}

// Add a new registry credential to anchore
func AddRegistryCredential(
	clientConfiguration *Config,
	registryURL string,
	repository string,
	username string,
	password string,
	registryTLSVerify bool,
	validateCreds bool,
) (gorequest.Response, []byte, []error) {
	request := getNewRequest(clientConfiguration)
	registryName, err := RegistryNameFromRepo(registryURL, repository)
	if err != nil {
		return nil, nil, []error{err}
	}

	registryAddURL, err := buildURLWithAPIVersion(*clientConfiguration, RegistriesCollectionURL, nil)
	if err != nil {
		return nil, nil, []error{err}
	}

	payload := fmt.Sprintf(RegistryCredentialUpdateRequestTemplate, registryName, username, password, registryTLSVerify)

	return sendRequest(
		clientConfiguration,
		request.Post(registryAddURL).
			Set("Content-Type", "application/json").
			Param("validate", strconv.FormatBool(validateCreds)).
			Send(payload),
	)
}

// Update an existing credential record
func UpdateRegistryCredential(
	clientConfiguration *Config,
	registryURL string,
	repository string,
	username string,
	password string,
	registryTLSVerify bool,
	validateCreds bool,
) (gorequest.Response, []byte, []error) {
	request := getNewRequest(clientConfiguration)
	registryName, err := RegistryNameFromRepo(registryURL, repository)
	if err != nil {
		log.WithField("err", err).Error("cannot update pull credential due to registryUrl name construction failing")
		return nil, nil, []error{err}
	}

	req, err := buildURLWithAPIVersion(*clientConfiguration, RegistryCredentialUpdateURLTemplate, []interface{}{registryName})
	if err != nil {
		return nil, nil, []error{err}
	}

	payload := fmt.Sprintf(RegistryCredentialUpdateRequestTemplate, registryName, username, password, registryTLSVerify)

	return sendRequest(
		clientConfiguration,
		request.Put(req).
			Set("Content-Type", "application/json").
			Param("validate", strconv.FormatBool(validateCreds)).
			Send(payload),
	)
}

func logResponse(resp gorequest.Response, body []byte, errs []error) (gorequest.Response, []byte, []error) {
	if errs != nil {
		if resp != nil {
			log.WithFields(log.Fields{"status": resp.Status, "statusCode": resp.StatusCode, "errs": errs}).
				Error("error response from anchore")
		} else {
			log.WithFields(log.Fields{"resp": "nil", "errs": errs}).Error("error response from anchore")
		}
	} else {
		log.WithFields(log.Fields{
			"requestURL":    resp.Request.URL,
			"requestMethod": resp.Request.Method,
			"statusCode":    resp.StatusCode,
			"contentLength": resp.ContentLength,
			"status":        resp.Status,
			"contentType":   resp.Header.Get("Content-Type"),
		}).Debug("anchore API response")
		log.WithFields(log.Fields{"statusCode": resp.StatusCode, "body": string(body)}).Trace("anchore API response content")
	}

	return resp, body, errs
}

type AnchoreVersion struct {
	API struct {
		Version string `json:"version"`
	} `json:"api"`
	DB struct {
		SchemaVersion string `json:"schema_version"`
	} `json:"db"`
	Service struct {
		Version string `json:"version"`
	} `json:"service"`
}

func getAPIVersion(clientConfiguration *Config) (string, error) {
	log.Debug("checking anchore API version")
	request := getNewRequest(clientConfiguration)
	reqURL, err := buildURL(*clientConfiguration, VersionURL, nil)
	if err != nil {
		return "", err
	}
	resp, _, errs := sendRequest(clientConfiguration, request.Get(reqURL))
	if errs != nil {
		return "", errs[0]
	}
	if resp.StatusCode != 200 {
		return "", fmt.Errorf("error response from anchore api: %+v", resp.StatusCode)
	}
	bodyContent, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("failed to read Anchore API version: %w", err)
	}
	ver := AnchoreVersion{}
	err = json.Unmarshal(bodyContent, &ver)
	if err != nil {
		return "", fmt.Errorf("failed to unmarshal Anchore API version: %w", err)
	}
	log.WithFields(log.Fields{"api": ver.API.Version, "db": ver.DB.SchemaVersion, "enterprise": ver.Service.Version}).
		Debug("discovered anchore versions in use")
	if ver.API.Version == "2" {
		return "v2", nil
	}
	// Default to v1 if we can't determine the version as 4.X does not include api version in the /version API response
	return "v1", nil
}

// Wrapper for sending a request to anchore
// Logs the response and handles switching the Anchore API version if required
func sendRequest(clientConfiguration *Config, req *gorequest.SuperAgent) (gorequest.Response, []byte, []error) {
	t := time.Now()
	log.WithFields(log.Fields{
		"URL":                 req.Url,
		"method":              req.Method,
		"Anchore API Version": apiVersion,
	}).Debug("sending request")
	resp, body, errs := req.EndBytes()
	log.WithField("duration", time.Since(t)).Debug("api call duration")
	// If we get a 404 try to determine the running API version and switch to that
	if resp != nil && resp.StatusCode == 404 {
		var err error
		prevAPIVersion := apiVersion
		apiVersion, err = getAPIVersion(clientConfiguration)
		if err != nil {
			log.WithField("err", err).Error("error getting Anchore API version")
		}
		// If the API version has changed try the request again with the new API version
		if prevAPIVersion != apiVersion {
			log.WithFields(log.Fields{"prevAPIVersion": prevAPIVersion, "apiVersion": apiVersion}).
				Info("Anchore API version changed trying request again")
			req.Url = strings.Replace(
				req.Url,
				strings.Join([]string{clientConfiguration.Endpoint, prevAPIVersion}, "/"),
				strings.Join([]string{clientConfiguration.Endpoint, apiVersion}, "/"),
				1,
			)
			return sendRequest(clientConfiguration, req)
		}
	}
	return logResponse(resp, body, errs)
}
