package v1

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	"github.com/anchore/harbor-scanner-adapter/pkg/adapter"
	"github.com/anchore/harbor-scanner-adapter/pkg/adapter/anchore"
	"github.com/anchore/harbor-scanner-adapter/pkg/model/harbor"
	"github.com/gorilla/mux"
	log "github.com/sirupsen/logrus"
)

const (
	AcceptHeader                  = "Accept"
	ContentTypeHeader             = "Content-Type"
	AuthorizationHeader           = "Authorization"
	BearerTokenPrefix             = "bearer"
	AllMimeTypes                  = "*/*"
	JSONRequestMimeType           = "application/json"
	HarborVulnReportv1MimeType    = "application/vnd.scanner.adapter.vuln.report.harbor+json; version=1.0"
	RawVulnReportMimeType         = "application/vnd.scanner.adapter.vuln.report.raw+json"
	DockerImageMimeType           = "application/vnd.docker.distribution.manifest.v2+json"
	OciImageMimeType              = "application/vnd.oci.image.manifest.v1+json"
	HarborMetadataVulnDbUpdateKey = "harbor.scanner-adapter/vulnerability-database-updated-at"
	HarborMetadataScannerTypeKey  = "harbor.scanner-adapter/scanner-type"
	AdapterType                   = "os-package-vulnerability"
	ScanRequestMimeType           = "application/vnd.scanner.adapter.scan.request+json; version=1.0"
	ScanResponseMimeType          = "application/vnd.scanner.adapter.scan.response+json; version=1.0"
	MetadataResponseMimeType      = "application/vnd.scanner.adapter.metadata+json; version=1.0"
	ErrorResponseMimeType         = "application/vnd.scanner.adapter.error+json; version=1.0"
)

type APIHandler struct {
	scanner adapter.ScannerAdapter
	config  anchore.AdapterConfig
}

func NewAPIHandler(scanner adapter.ScannerAdapter, cfg anchore.AdapterConfig) *APIHandler {
	return &APIHandler{
		scanner: scanner,
		config:  cfg,
	}
}

func getRequestBearerToken(r *http.Request) string {
	authzHeader := r.Header.Get(AuthorizationHeader)
	if authzHeader != "" {
		authzHeader = strings.TrimSpace(authzHeader)
		comps := strings.Split(authzHeader, " ")
		if len(comps) == 2 && strings.ToLower(comps[0]) == BearerTokenPrefix {
			return comps[1]
		}
	}
	return ""
}

func isAuthenticated(apiKey string, r *http.Request) bool {
	return apiKey == "" || apiKey == getRequestBearerToken(r)
}

// Middleware function, which will be called for each request
func (h *APIHandler) AuthenticationMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if isAuthenticated(h.config.ApiKey, r) {
			next.ServeHTTP(w, r)
		} else {
			// Write an error and stop the handler chain
			SendErrorResponse(&w, "unauthorized", http.StatusUnauthorized)
			return
		}
	})
}

// Simple logger middleware to log requests
func (h *APIHandler) LoggerMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		log.WithFields(log.Fields{
			"accept":       r.Header.Get(AcceptHeader),
			"method":       r.Method,
			"content-type": r.Header.Get(ContentTypeHeader),
			"url":          r.URL.String()}).Info("handling request")
		next.ServeHTTP(w, r)
	})
}

func UnmarshallScanRequest(req *http.Request) (harbor.ScanRequest, error) {
	scanRequest := harbor.ScanRequest{}
	acceptHeader := req.Header.Get(AcceptHeader)
	requestType := req.Header.Get(ContentTypeHeader)

	// Check if content type is unexpected but specified
	if requestType != "" && requestType != ScanRequestMimeType && requestType != JSONRequestMimeType {
		return scanRequest, fmt.Errorf("invalid content type: %v", requestType)
	}

	// Strict checking if accept specifies a type not supported
	if acceptHeader != "" && acceptHeader != ScanResponseMimeType && acceptHeader != AllMimeTypes {
		return scanRequest, fmt.Errorf("unsupported media type")
	}

	err := json.NewDecoder(req.Body).Decode(&scanRequest)
	if err != nil {
		log.WithField("err", err).Errorf("failed decoding scan request")
		return scanRequest, fmt.Errorf("bad request")
	}

	return scanRequest, nil
}

func ValidateScanRequest(req *harbor.ScanRequest) error {
	if req.Registry.URL == "" {
		return fmt.Errorf("invalid registry url")
	}

	if req.Artifact.Digest == "" {
		return fmt.Errorf("emtpy digest")
	}

	if req.Artifact.Repository == "" {
		return fmt.Errorf("empty repository")
	}

	return nil
}

func (h *APIHandler) CreateScan(res http.ResponseWriter, req *http.Request) {
	scanRequest, err := UnmarshallScanRequest(req)
	if err != nil {
		SendErrorResponse(&res, err.Error(), 400)
		return
	}

	err = ValidateScanRequest(&scanRequest)
	if err != nil {
		log.WithField("err", err).Errorf("failed validating scan request")
		SendErrorResponse(&res, err.Error(), 400)
		return
	}

	logRequest := scanRequest
	logRequest.Registry.Authorization = "[REDACTED]"
	redacted, err := json.Marshal(logRequest)
	if err == nil {
		log.WithField("request", string(redacted)).Debug("scan request")
	}

	scanResponse, err := h.scanner.Scan(scanRequest)
	if err != nil {
		log.WithField("err", err).Errorf("failed executing the scan request")
		SendErrorResponse(&res, err.Error(), 500)
		return
	}

	log.WithField("scanId", scanResponse.ID).Info("success creating scan")
	res.WriteHeader(http.StatusAccepted)
	res.Header().Set(ContentTypeHeader, ScanResponseMimeType)
	err = json.NewEncoder(res).Encode(scanResponse)
	if err != nil {
		log.WithField("err", err).Errorf("failed encoding the scan response")
		SendErrorResponse(&res, err.Error(), 500)
	}
	return
}

func (h *APIHandler) GetScanReport(res http.ResponseWriter, req *http.Request) {
	vars := mux.Vars(req)
	scanId, _ := vars["scanId"]

	requestedTypes := req.Header[AcceptHeader]
	numTypes := len(requestedTypes)
	var requestedType string
	var report interface{}
	var err error

	if numTypes > 1 {
		log.Info("No support for multiple types per request, yet")
	} else if numTypes == 0 || requestedTypes[0] == AllMimeTypes || requestedTypes[0] == "" {
		// Default if no Accept set or set to */* then return the harbor report
		requestedType = HarborVulnReportv1MimeType
	} else if requestedTypes[0] == HarborVulnReportv1MimeType || requestedTypes[0] == RawVulnReportMimeType {
		requestedType = requestedTypes[0]
	}

	switch requestedType {
	case HarborVulnReportv1MimeType:
		report, err = h.GetHarborVulnerabilityReport(scanId, h.config.FullVulnerabilityDescriptions)
	case RawVulnReportMimeType:
		report, err = h.GetRawScanReport(scanId)
	default:
		log.Error("invalid requested report type")
		SendErrorResponse(&res, "unsupported media tyep", http.StatusBadRequest)
		return
	}

	if err != nil {
		if err.Error() == "scan failed" {
			log.Error("Scan failed")
			SendErrorResponse(&res, "scan failed", http.StatusNotFound)
		} else if err.Error() == "Not Found" {
			log.Error("not found")
			SendErrorResponse(&res, "no scan found for scanId", http.StatusNotFound)
		} else if err.Error() == "analysis pending" {
			log.Info("valid scanId, but scan not complete")
			res.Header().Set("Location", req.URL.String())
			SendErrorResponse(&res, "scan pending", http.StatusFound)
		} else {
			log.Error("unknown internal error")
			SendErrorResponse(&res, err.Error(), http.StatusInternalServerError)
		}
		return
	}

	res.Header().Set(ContentTypeHeader, requestedType)
	err = json.NewEncoder(res).Encode(report)
	if err != nil {
		log.WithField("err", err).Error("failed encoding the scan response")
		SendErrorResponse(&res, err.Error(), 500)
	}
	return
}

func (h *APIHandler) GetHarborVulnerabilityReport(scanId string, includeFullDescriptions bool) (harbor.VulnerabilityReport, error) {
	return h.scanner.GetHarborVulnerabilityReport(scanId, includeFullDescriptions)
}

func (h *APIHandler) GetRawScanReport(scanId string) (harbor.RawReport, error) {
	return h.scanner.GetRawVulnerabilityReport(scanId)
}

func ValidateMetadataRequest(req *http.Request) error {
	acceptHeader := req.Header.Get(AcceptHeader)
	if acceptHeader != "" && acceptHeader != AllMimeTypes && acceptHeader != MetadataResponseMimeType {
		return fmt.Errorf("unsupported media type")
	}
	return nil
}

// Return metadata about the adapter service itself as well as the upstream service
// it proxies (Anchore Engine or Enterprise).
func (h *APIHandler) GetMetadata(res http.ResponseWriter, req *http.Request) {
	err := ValidateMetadataRequest(req)
	if err != nil {
		log.WithField("err", err).Error("invalid metadata request")
		SendErrorResponse(&res, "invalid request", http.StatusBadRequest)
		return
	}

	resp, err := h.scanner.GetMetadata()
	if err != nil {
		log.WithField("err", err).Error("error returning metadata")
		SendErrorResponse(&res, err.Error(), http.StatusInternalServerError)
		return
	}

	SendJsonResponse(&res, resp, MetadataResponseMimeType)
}

func SendJsonResponse(res *http.ResponseWriter, obj interface{}, contentType string) {
	log.Info("sending json response")
	(*res).Header().Set(ContentTypeHeader, contentType)
	err := json.NewEncoder(*res).Encode(obj)
	if err != nil {
		log.WithField("err", err).Error("error json encoding the response")
		SendErrorResponse(res, "error encoding response object", http.StatusInternalServerError)
	}
	return
}

func SendErrorResponse(res *http.ResponseWriter, message string, code int) {
	log.WithFields(log.Fields{"message": message, "code": code}).Error("returning error response")
	resp := *res
	resp.Header().Set(ContentTypeHeader, ErrorResponseMimeType)
	errResp := harbor.ErrorResponse{Error: harbor.Error{Message: message}}
	resp.WriteHeader(code)
	err := json.NewEncoder(resp).Encode(errResp)
	if err != nil {
		log.Error("failed marshalling response in json using text/plain")
		// Return text format
		resp.Header().Set(ContentTypeHeader, "text/plain")
		http.Error(resp, message, code)
	}
	return
}
