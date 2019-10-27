package client

import (
	"crypto/tls"
	"encoding/json"
	"fmt"
	"github.com/anchore/harbor-scanner-adapter/pkg/model/anchore"
	"github.com/parnurzeal/gorequest"
	log "github.com/sirupsen/logrus"
	"math"
	"net/url"
	"path"
	"sort"
	"strconv"
	"strings"
	"time"
)

const (
	CHUNKSIZE                               = 100
	NVDFEEDGROUP                            = "nvdv2:cves"
	RegistryCredentialUpdateRequestTemplate = `{"registry": "%v", "registry_user": "%v", "registry_pass": "%v", "registry_verify": %v, "registry_type": "docker_v2"}`
	AddImageURL                             = "/v1/images"
	GetImageURLTemplate                     = "/v1/images/%s"
	GetImageVulnerabilitiesURLTemplate      = "/v1/images/%s/vuln/all"
	QueryVulnerabilitiesURLTemplate         = "/v1/query/vulnerabilities"
	RegistriesCollectionURL                 = "/v1/registries"
	RegistryCredentialUpdateURLTemplate     = "/v1/registries/%s"
	FeedsURL                                = "/v1/system/feeds"
)

type ClientConfig struct {
	Endpoint       string
	Username       string
	Password       string
	TimeoutSeconds int
	TLSVerify      bool
}

func getNewRequest(clientConfiguration *ClientConfig) *gorequest.SuperAgent {
	timeout := time.Duration(clientConfiguration.TimeoutSeconds) * time.Second
	return gorequest.New().TLSClientConfig(&tls.Config{InsecureSkipVerify: clientConfiguration.TLSVerify}).SetBasicAuth(clientConfiguration.Username, clientConfiguration.Password).Timeout(timeout)
}

// Handle error responses generically
func unmarshalError(body []byte, response gorequest.Response) (anchore.Error, error) {
	result := anchore.Error{}

	if response != nil && response.Header.Get("Content-Type") == "application/problem+json" {
		// Try to unmarshal a json problem and map to anchore error
		jsonError := anchore.ApplicationJsonError{}
		err := json.Unmarshal(body, &jsonError)
		if err != nil {
			return anchore.Error{}, err
		}
		result.Message = jsonError.Title
		result.HttpCode = response.StatusCode
		result.Detail["title"] = jsonError.Title
		result.Detail["detail"] = jsonError.Detail
		result.Detail["type"] = jsonError.Type
		result.Detail["instance"] = jsonError.Instance
		result.Detail["status"] = jsonError.Status
		return result, nil
	} else if body != nil && len(body) > 0 {
		// Try to unmarshal an anchore error
		err := json.Unmarshal(body, &result)
		if err != nil {
			// Do a very raw decode
			if response != nil {
				result.Message = string(body)
				result.HttpCode = response.StatusCode
			} else {
				return result, err
			}
		}
		return result, nil
	} else {
		return result, fmt.Errorf("nothing to unmarshal")
	}
}

func AnalyzeImage(clientConfiguration *ClientConfig, analyzeRequest anchore.ImageScanRequest) error {
	log.WithFields(log.Fields{"request": analyzeRequest}).Info("requesting image analysis")

	request := getNewRequest(clientConfiguration)

	reqUrl, err := buildUrl(*clientConfiguration, AddImageURL, nil)
	if err != nil {
		return err
	}

	log.WithFields(log.Fields{"method": "post", "url": reqUrl}).Debug("sending request to anchore api")
	// call API get the full report until "analysis_status" = "analyzed"
	resp, _, errs := request.Post(reqUrl).Set("Content-Type", "application/json").Send(analyzeRequest).EndBytes()
	checkStatusStruct(resp, errs)
	if errs != nil {
		log.Errorf("could not contact anchore api")
		return errs[0]
	}
	if resp.StatusCode != 200 {
		return fmt.Errorf("request failed with status %v", resp.StatusCode)
	}
	return nil
}

// Updates the Description fields in the input array of Description objects
func GetVulnerabilityDescriptions(clientConfiguration *ClientConfig, vulns *[]anchore.NamespacedVulnerability) error {
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

		vulnIds := make([]string, end-start)
		namespaces := make(map[string]bool)

		if start < 0 || end > count+1 {
			log.WithFields(log.Fields{"start": start, "end": end}).Error("vulnerabiilty description chunking returned out-of-bounds indexes. this should not happen")
			return fmt.Errorf("error generating vulnerability descriptions")
		}

		chunkToProcess := (*vulns)[start:end]
		log.WithFields(log.Fields{"total": count, "start": start, "end": end, "size": len(chunkToProcess)}).Debug("processing chunk of the vuln list")
		for i, v := range chunkToProcess {
			vulnIds[i] = v.ID
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

		//Split the input array into map[string][]string where key is the Namespace
		//Then query the system for a single Namespace and populate the result fields
		qryResults, errs := QueryVulnerabilityRecords(clientConfiguration, vulnIds, namespaceNames)
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
		if rec, ok := vulnDescriptionMap[vulnRecord.ID]; !ok {
			log.WithFields(log.Fields{"ID": vulnRecord.ID, "Namespace": vulnRecord.Namespace}).Debug("warning: could not find vuln record in anchore api results for querying vuln descriptions")
			continue
		} else {

			if ns, ok := rec[vulnRecord.Namespace]; ok && ns != "" {
				foundDescription = ns
			} else if vulnRecord.Namespace != NVDFEEDGROUP {
				// No record in Namespace, try nvdv2
				if nvdDesc, ok := rec[NVDFEEDGROUP]; ok {
					foundDescription = nvdDesc
				}
			}

			if foundDescription == "" {
				log.Debugf("no Description found for ID %v", vulnRecord.ID)
			} else {
				if vulnRecord.Description == "" {
					log.Debugf("updating vuln Description for %v", vulnRecord.ID)
					vulnRecord.Description = foundDescription
				} else {
					log.Debugf("vuln already has Description, skipping update")
				}
			}
		}

		(*vulns)[i] = vulnRecord
	}

	// Clean exit
	return nil
}

// Simple query that handles pagination and returns the results
func QueryVulnerabilityRecords(clientConfiguration *ClientConfig, ids []string, namespaces []string) (anchore.VulnerabilityQueryResults, []error) {
	var page string
	var vulnListing anchore.VulnerabilityQueryResults
	var vulnPage anchore.VulnerabilityQueryResults
	var start, end, pageStart, pageEnd time.Time

	vulnIdsStr := strings.Join(ids, ",")
	namespaceStr := strings.Join(namespaces, ",")

	request := getNewRequest(clientConfiguration)
	more_pages := true

	start = time.Now()
	reqUrl, err := buildUrl(*clientConfiguration, QueryVulnerabilitiesURLTemplate, nil)
	if err != nil {
		return vulnListing, []error{err}
	}

	for more_pages {
		pageStart = time.Now()

		req := request.Get(reqUrl).Param("id", vulnIdsStr).Param("namespace", namespaceStr)
		if page != "" {
			log.Debug("getting page ", page)
			req = req.Param("page", page)
		}

		log.WithFields(log.Fields{"id": vulnIdsStr, "namespace": namespaceStr, "page": page}).Debugf("vulnerability query parameters")
		resp, body, errs := req.EndBytes()

		if errs != nil {
			return vulnListing, errs
		} else {

			if resp.StatusCode == 200 {
				err := json.Unmarshal(body, &vulnPage)
				if err != nil {
					return vulnListing, []error{fmt.Errorf("failed getting vulnerability metadata")}
				}

				if vulnPage.NextPage != "" {
					more_pages = true
					page = vulnPage.NextPage
					log.WithField("nextPage", vulnPage.NextPage).Debug("more pages found")
				} else {
					log.Debug("no more pages of results")
					more_pages = false
					page = ""
				}

				vulnListing.Vulnerabilities = append(vulnListing.Vulnerabilities, vulnPage.Vulnerabilities...)

				// Merge the counts so the response to caller looks like the result of a single call
				vulnListing.ReturnedCount += vulnPage.ReturnedCount
			} else {
				log.WithFields(log.Fields{"status": resp.StatusCode}).Errorf("got non 200 response from server for vuln query: %s", body)
				return vulnListing, []error{fmt.Errorf("error response from server")}
			}
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
	} else {
		// Out of range
		return -1, -1
	}
}

// Retrieve the vulnerabilities
func GetImageVulnerabilities(clientConfiguration *ClientConfig, digest string, filterIgnored bool) (anchore.ImageVulnerabilityReport, error) {
	log.WithFields(log.Fields{"digest": digest, "filterIgnored": filterIgnored}).Debug("retrieving scan result for image")

	var imageVulnerabilityReport anchore.ImageVulnerabilityReport

	reqUrl, err := buildUrl(*clientConfiguration, GetImageVulnerabilitiesURLTemplate, []interface{}{digest})
	if err != nil {
		return imageVulnerabilityReport, err
	}

	request := getNewRequest(clientConfiguration)
	resp, body, errs := request.Get(reqUrl).Param("vendor_only", strconv.FormatBool(filterIgnored)).EndBytes()
	if errs != nil {
		return imageVulnerabilityReport, errs[0]
	}

	if resp.StatusCode == 200 {
		err := json.Unmarshal(body, &imageVulnerabilityReport)
		if err != nil {
			return imageVulnerabilityReport, err
		}
		return imageVulnerabilityReport, nil
	} else {
		return imageVulnerabilityReport, fmt.Errorf("error response from anchore api")
	}

}

func GetImage(clientConfiguration *ClientConfig, digest string) (anchore.ImageList, error) {
	log.WithFields(log.Fields{"digest": digest}).Debug("retrieving anchore state for image")

	var imageList anchore.ImageList
	request := getNewRequest(clientConfiguration)

	reqUrl, err := buildUrl(*clientConfiguration, GetImageURLTemplate, []interface{}{digest})
	if err != nil {
		return imageList, err
	}

	log.WithFields(log.Fields{"method": "get", "url": reqUrl}).Debug("sending request to anchore api")
	// call API get the full report until "analysis_status" = "analyzed"
	resp, body, errs := request.Get(reqUrl).EndBytes()
	checkStatusStruct(resp, errs)
	if errs != nil {
		log.Errorf("could not contact anchore api")
		return imageList, errs[0]
	}
	err = json.Unmarshal(body, &imageList)
	if err != nil {
		log.Errorf("unmarshall anchore api response")
		return imageList, err
	}

	return imageList, nil
}

func GetVulnDbUpdateTime(clientConfiguration *ClientConfig) (time.Time, error) {
	request := getNewRequest(clientConfiguration)
	reqUrl, err := buildUrl(*clientConfiguration, FeedsURL, nil)
	if err != nil {
		return time.Time{}, err
	}

	resp, body, errs := request.Get(reqUrl).EndBytes()
	if errs != nil {
		return time.Time{}, errs[0]
	}
	checkStatusStruct(resp, errs)

	feedsResp := anchore.FeedStatuses{}

	err = json.Unmarshal(body, &feedsResp)
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
func ExtractRegistryFromUrl(registryUrl string) (string, error) {
	u, err := url.Parse(registryUrl)
	if err != nil {
		return "", err
	}

	if u.Host != "" {
		return u.Host, nil
	} else {
		return "", fmt.Errorf("no host portion found in the input url. must be a full url with scheme")
	}
}

// Return the registry credential entry as anchore will use it. This is the registry url minus the scheme + / + repository name
func RegistryNameFromRepo(registryUrl string, repository string) (string, error) {
	u, err := url.Parse(registryUrl)
	if err != nil {
		return "", err
	}

	u.Path = repository
	return u.String(), nil
}

// Build the request URL
func buildUrl(config ClientConfig, requestPathTemplate string, args []interface{}) (string, error) {
	u, err := url.Parse(config.Endpoint)
	if err != nil {
		return "", err
	}

	u.Path = path.Join(u.Path, fmt.Sprintf(requestPathTemplate, args...))
	return u.String(), nil
}

// Add a new registry credential to anchore
func AddRegistryCredential(clientConfiguration *ClientConfig, registry string, repository string, username string, password string, registryTLSVerify bool, validateCreds bool) (gorequest.Response, []byte, []error) {
	request := getNewRequest(clientConfiguration)
	registryName, err := RegistryNameFromRepo(registry, repository)
	if err != nil {
		return nil, nil, []error{err}
	}

	registryAddUrl, err := buildUrl(*clientConfiguration, RegistriesCollectionURL, nil)
	if err != nil {
		return nil, nil, []error{err}
	}

	var payload = fmt.Sprintf(RegistryCredentialUpdateRequestTemplate, registryName, username, password, registryTLSVerify)

	return request.Post(registryAddUrl).Set("Content-Type", "application/json").Param("validate", strconv.FormatBool(validateCreds)).Send(payload).EndBytes()
}

// Update an existing credential record
func UpdateRegistryCredential(clientConfiguration *ClientConfig, registry string, repository string, username string, password string, registryTLSVerify bool, validateCreds bool) (gorequest.Response, []byte, []error) {
	request := getNewRequest(clientConfiguration)
	registryName, err := RegistryNameFromRepo(registry, repository)
	if err != nil {
		log.WithField("err", err).Error("cannot update pull credential due to registry name construction failing")
		return nil, nil, []error{err}
	}

	u, err := url.Parse(clientConfiguration.Endpoint)
	if err != nil {
		return nil, nil, []error{err}
	}

	u.Path = path.Join(u.Path, fmt.Sprintf(RegistryCredentialUpdateURLTemplate, url.PathEscape(registryName)))

	var payload = fmt.Sprintf(RegistryCredentialUpdateRequestTemplate, registryName, username, password, registryTLSVerify)

	log.Debug("Updating creds that already exist for this repo")
	return request.Put(u.String()).Set("Content-Type", "application/json").Param("validate", strconv.FormatBool(validateCreds)).Send(payload).EndBytes()
}

func checkStatusStruct(resp gorequest.Response, errs []error) {
	if errs != nil {
		if resp != nil {
			log.WithFields(log.Fields{"status": resp.Status, "statusCode": resp.StatusCode, "errs": errs}).Error("error response from anchore")
		} else {
			log.WithFields(log.Fields{"resp": "nil", "errs": errs}).Error("error response from anchore")
		}
	} else {
		log.WithFields(log.Fields{"status": resp.StatusCode}).Debug("got response")
	}
}
