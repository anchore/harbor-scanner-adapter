package v1

import (
	"encoding/json"
	"fmt"
	"github.com/anchore/harbor-scanner-adapter/pkg/adapter"
	"github.com/anchore/harbor-scanner-adapter/pkg/model/harbor"
	"github.com/gorilla/mux"
	log "github.com/sirupsen/logrus"
	"net/http"
	"strings"
)

type APIHandler struct {
	scanner adapter.ScannerAdapter
	config  adapter.ServiceConfig
}

func NewAPIHandler(scanner adapter.ScannerAdapter, cfg adapter.ServiceConfig) *APIHandler {
	return &APIHandler{
		scanner: scanner,
		config:  cfg,
	}
}

// Middleware function, which will be called for each request
func (h *APIHandler) AuthenticationMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if h.config.ApiKey == "" {
			next.ServeHTTP(w, r)
			return
		}

		authzHeader := r.Header.Get("Authorization")
		if authzHeader != "" {
			authzHeader = strings.TrimSpace(authzHeader)
			comps := strings.Split(authzHeader, " ")
			if len(comps) == 2 && comps[0] == "Bearer" && comps[1] == h.config.ApiKey {
				log.Debug("authenticated request with api key")
				next.ServeHTTP(w, r)
				return
			}
		}
		// Write an error and stop the handler chain
		http.Error(w, "Forbidden", http.StatusForbidden)
	})
}

func (h *APIHandler) CreateScan(res http.ResponseWriter, req *http.Request) {
	scanRequest := harbor.ScanRequest{}
	err := json.NewDecoder(req.Body).Decode(&scanRequest)
	if err != nil {
		log.WithField("err", err).Errorf("failed decoding scan request")
		http.Error(res, "Bad request", 400)
		return
	}

	scanResponse, err := h.scanner.Scan(scanRequest)
	if err != nil {
		log.WithField("err", err).Errorf("failed executing the scan request")
		http.Error(res, "Internal Server Error", 500)
		return
	}

	res.WriteHeader(http.StatusAccepted)

	res.Header().Set("Content-Type", "application/json")
	err = json.NewEncoder(res).Encode(scanResponse)
	if err != nil {
		log.WithField("err", err).Errorf("failed encoding the scan response")
		http.Error(res, "Internal Server Error", 500)
		return
	}
}

func (h *APIHandler) GetScanReport(res http.ResponseWriter, req *http.Request) {
	vars := mux.Vars(req)
	scanId, _ := vars["scanId"]

	requestedTypes := req.Header["Accept"]
	numTypes := len(requestedTypes)
	var requestedType string
	var report interface{}
	var err error

	if numTypes > 1 {
		log.Info("No support for multiple types per request, yet")
	} else if numTypes == 0 {
		requestedType = adapter.HarborVulnReportv1MimeType
	} else if requestedTypes[0] == adapter.HarborVulnReportv1MimeType || requestedTypes[0] == adapter.RawVulnReportMimeType {
		requestedType = requestedTypes[0]
	}

	log.Info("Requested report %v", requestedType)

	switch requestedType {
	case adapter.HarborVulnReportv1MimeType:
		report, err = h.GetHarborVulnerabilityReport(scanId, h.config.FullVulnerabilityDescriptions)
	case adapter.RawVulnReportMimeType:
		report, err = h.GetRawScanReport(scanId)
	default:
		http.Error(res, "Unsupported mime type", http.StatusBadRequest)
	}

	if err != nil {
		res.Header().Set("Content-Type", "application/json")

		if err.Error() == "scan failed" {
			log.Println("Scan failed")
			http.Error(res, fmt.Sprintf(`"message": "scan failed"}`), http.StatusNotFound)
		} else if err.Error() == "Not Found" {
			log.Println("Not found")
			http.Error(res, fmt.Sprintf(`"message": "not found"}`), http.StatusNotFound)
		} else if err.Error() == "analysis pending" {
			log.Println("Pending")
			res.Header().Set("Location", req.URL.String())
			http.Error(res, fmt.Sprintf(`"message": "scan pending"}`), http.StatusFound)
		} else {
			http.Error(res, "Internal Error", http.StatusInternalServerError)
		}
		return
	}

	res.Header().Set("Content-Type", requestedType)
	err = json.NewEncoder(res).Encode(report)
	return
}

func (h *APIHandler) GetHarborVulnerabilityReport(scanId string, includeFullDescriptions bool) (harbor.VulnerabilityReport, error) {
	return h.scanner.GetHarborVulnerabilityReport(scanId, includeFullDescriptions)
}

func (h *APIHandler) GetRawScanReport(scanId string) (harbor.RawReport, error) {
	return h.scanner.GetRawVulnerabilityReport(scanId)
}

// Return metadata about the adapter service itself as well as the upstream service
// it proxies (Anchore Engine or Enterprise).
func (h *APIHandler) GetMetadata(res http.ResponseWriter, req *http.Request) {
	res.Header().Set("Content-Type", "application/json")

	resp, err := h.scanner.GetMetadata()
	if err != nil {
		log.WithField("err", err).Error("error returning metadata")
		http.Error(res, "Internal Server Error", 500)
		return
	}

	res.Header().Set("Content-Type", "application/vnd.scanner.adapter.metadata+json")
	err = json.NewEncoder(res).Encode(resp)
	if err != nil {
		log.WithField("err", err).Error("error json encoding the response")
		http.Error(res, "Internal Server Error serializing json response", 500)
		return
	}
	return
}
