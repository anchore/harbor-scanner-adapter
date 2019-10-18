package anchore

import (
	"encoding/json"
	"fmt"
	"github.com/anchore/harbor-scanner-adapter/pkg/model/anchore"
	"github.com/parnurzeal/gorequest"
	log "github.com/sirupsen/logrus"
	"math"
	"sort"
	"strings"
	"time"
)

const (
	CHUNKSIZE = 100
	NVDFEEDGROUP = "nvdv2:cves"
)

type VulnNamespaceDescription struct {
	id string
	namespace string
	description string
}


// Updates the description fields in the input array of description objects
func GetVulnerabilityDescriptions(clientConfiguration *ClientConfig, vulns *[]VulnNamespaceDescription) error {
	var vulnListing anchore.VulnerabilityQueryResults

	// Sort and get namespaces for efficient lookups
	less := func(i, j int) bool {
		return (*vulns)[i].namespace < (*vulns)[j].namespace
	}

	sort.Slice(*vulns, less)

	// Used chunked fetch to get full listing, adding in the nvdv2 namespace for extra coverage
	count := len(*vulns)

	for i := 0; i < count / CHUNKSIZE + 1; i++ {
		start, end := getVulnProcessingChunks(count, i, CHUNKSIZE)

		vulnIds := make([]string, end-start)
		namespaces := make(map[string]bool)

		chunkToProcess := (*vulns)[start:end]
		log.WithFields(log.Fields{"total": count, "start": start, "end": end, "size": len(chunkToProcess)}).Debug("processing chunk of the vuln list")
		for i, v := range chunkToProcess {
			vulnIds[i] = v.id
			namespaces[v.namespace] = true
		}

		// Ensure nvdv2 is set
		namespaces[NVDFEEDGROUP] = true

		// Construct namespace filter
		namespaceNames := make([]string, len(namespaces))
		i := 0
		for v := range namespaces {
			namespaceNames[i] = v
			i++
		}

		//Split the input array into map[string][]string where key is the namespace
		//Then query the system for a single namespace and populate the result fields
		qryResults, errs := QueryVulnerabilityRecords(clientConfiguration, vulnIds, namespaceNames)
		if errs != nil {
			log.Debugf("error getting vuln records ", errs)
			return errs[0]

		}

		vulnListing.Vulnerabilities = append(vulnListing.Vulnerabilities, qryResults.Vulnerabilities...)
		vulnListing.ReturnedCount += qryResults.ReturnedCount
	}

	log.Debug("building description -> namespace map")

	vulnDescriptionMap := make(map[string]map[string]string)

	// Build a map of vuln ID => map[string]string w/namespaces as 2nd layer key
	for _, result := range vulnListing.Vulnerabilities {
		if found, ok := vulnDescriptionMap[result.ID]; ok {
			found[result.Namespace] = result.Description
		} else {
			vulnDescriptionMap[result.ID] = map[string]string {
				result.Namespace: result.Description,
			}
		}
	}

	var foundDescription string

	log.Debug("merging description results")

	// Update the description for each input entry
	for i, vulnRecord := range *vulns {
		log.Debugf("processing %v for description update", vulnRecord.id)

		foundDescription = ""

		// update each with rules
		if rec, ok := vulnDescriptionMap[vulnRecord.id]; ! ok {
			log.WithFields(log.Fields{"id": vulnRecord.id, "namespace": vulnRecord.namespace}).Debug("warning: could not find vuln record in anchore api results for querying vuln descriptions")
			continue
		} else {

			if ns, ok := rec[vulnRecord.namespace]; ok && ns != "" {
				foundDescription = ns
				log.Debugf("description found in ns %v", vulnRecord.namespace)
			} else if vulnRecord.namespace != NVDFEEDGROUP {
				// No record in namespace, try nvdv2
				if nvdDesc, ok := rec[NVDFEEDGROUP]; ok {
					log.Debugf("Updating %v description to value from namespace %v -> %v", vulnRecord.id, NVDFEEDGROUP, nvdDesc)
					foundDescription = nvdDesc
				}
			}

			if foundDescription == "" {
				log.Debugf("no description found for id %v", vulnRecord.id)
			} else {
				if vulnRecord.description == "" {
					log.Debugf("updating vuln description for %v", vulnRecord.id)
					vulnRecord.description = foundDescription
				} else {
					log.Debugf("vuln already has description, skipping update")
				}
			}
		}

		(*vulns)[i] = vulnRecord
	}

	// Clean exit
	return nil
}

// Simple query that handles pagination and returns the results
func QueryVulnerabilityRecords(clientConfiguration *ClientConfig, ids []string, namespaces []string) (anchore.VulnerabilityQueryResults, []error){
	var page string
	var vulnListing anchore.VulnerabilityQueryResults
	var vulnPage anchore.VulnerabilityQueryResults
	var start, end, pageStart, pageEnd time.Time

	vulnIdsStr := strings.Join(ids, ",")
	namespaceStr := strings.Join(namespaces, ",")

	timeout := time.Duration(clientConfiguration.TimeoutSeconds) * time.Second
	request := gorequest.New().SetBasicAuth(clientConfiguration.Username, clientConfiguration.Password)
	more_pages := true

	start = time.Now()

	for more_pages {
		pageStart = time.Now()

		req := request.Get(clientConfiguration.Endpoint+"/v1/query/vulnerabilities").Param("id", vulnIdsStr).Param("namespace", namespaceStr).Timeout(timeout)
		if page != "" {
			log.Debug("getting page ", page)
			req = req.Param("page", page)
		}

		log.WithFields(log.Fields{"id": vulnIdsStr, "namespace": namespaceStr, "page": page}).Debugf("vulnerability query parameters")
		resp, body, errs := req.End()

		if errs != nil {
			return vulnListing, errs
		} else {

			if resp.StatusCode == 200 {
				err := json.Unmarshal([]byte(body), &vulnPage)
				if err != nil {
					return vulnListing, []error{fmt.Errorf("failed getting vulnerability metadata")}
				}

				if vulnPage.NextPage != "" {
					more_pages = true
					page = vulnPage.NextPage
				} else {
					more_pages = false
					page = ""
				}

				vulnListing.Vulnerabilities = append(vulnListing.Vulnerabilities, vulnPage.Vulnerabilities...)

				// Merge the counts so the response to caller looks like the result of a single call
				vulnListing.ReturnedCount += vulnPage.ReturnedCount
			} else {
				log.Warnf("got non 200 response from server for vuln query: %v", body)
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
	if chunkToGet * chunkSize < itemCount {
		return chunkToGet * chunkSize, int(math.Min(float64(chunkToGet + 1) * cs, float64(last)))
	} else {
		// Out of range
		return -1, -1
	}
}

// Retrieve the vulnerabilities
func GetImageVulnerabilities(clientConfiguration *ClientConfig, digest string, filterIgnored bool) (anchore.ScanResult, error) {
	log.Println("Retrieving scan result for digest ", digest)

	var ScanResultdata anchore.ScanResult
	var tempscandata anchore.AnchoreImages
	timeout := time.Duration(clientConfiguration.TimeoutSeconds) * time.Second

	request := gorequest.New().SetBasicAuth(clientConfiguration.Username, clientConfiguration.Password)

	// call API get the full report until "analysis_status" = "analyzed"
	resp, _, errs := request.Get(clientConfiguration.Endpoint + "/v1/images/" + digest).Timeout(timeout).EndStruct(&tempscandata)
	checkStatusStruct(resp, errs)
	if errs != nil {
		log.Errorf("could not contact anchore api")
		return anchore.ScanResult{}, fmt.Errorf("connection error")
	}

	switch tempscandata[0].AnalysisStatus {
	case "analysis_failed":
		//to do: define return result once it failed
		log.Println("analysis_status = analysis_failed")
		return anchore.ScanResult{}, fmt.Errorf("scan failed")
	case "analyzed":
		anchoreUrl := fmt.Sprintf("%v/v1/images/%v/vuln/all?vendor_only=%v", clientConfiguration.Endpoint, digest, filterIgnored)
		log.Println("checking vulns for image at: ", anchoreUrl)
		resp, _, errs = request.Get(anchoreUrl).Timeout(60 * time.Second).EndStruct(&ScanResultdata)
		checkStatusStruct(resp, errs)
		return ScanResultdata, nil
	default:
		//Includes the "not_analyzed" state
		log.Println("Anchore analysis not complete return empty")
		return anchore.ScanResult{}, fmt.Errorf("analysis pending")
	}
}

