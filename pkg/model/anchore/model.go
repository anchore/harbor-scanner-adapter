// Models for the Anchore Engine API. These are shared with the Enterprise API, so the client works with both.
package anchore

// A vulnerability listing from GET /v1/image/<Digest>/vuln/all
type ScanResult struct {
	ImageDigest     string          `json:"imageDigest"`
	Vulnerabilities []Vulnerability `json:"Vulnerabilities"`
}

type Vulnerability struct {
	VulnerabilityID  string       `json:"vuln"`
	PkgName          string       `json:"package_name"`
	InstalledVersion string       `json:"package_version"`
	Package_type     string       `json:"package_type"`
	Package          string       `json:"package"`
	URL              string       `json:"url"`
	Fix              string       `json:"fix"`
	Severity         string       `json:"severity"`
	Feed             string       `json:"feed"`
	FeedGroup        string       `json:"feed_group"`
	PackageCPE       string       `json:"package_cpe"`
	PackagePath      string       `json:"package_path"`
	NvdData          []NvdObject  `json:"nvd_data"`
	VendorData       []VendorData `json:"vendor_data"`
}

type NvdObject struct {
	Id          string    `json:"id"`
	CVSSv2Score CVSSScore `json:"cvss_v2"`
	CVSSv3Score CVSSScore `json:"cvss_v3"`
}

type CVSSScore struct {
	BaseScore           float64 `json:"base_score"`
	ExploitabilityScore float64 `json:"exploitability_score"`
	ImpactScore         float64 `json:"impact_score"`
}

type VendorData struct {
	Id          string    `json:"id"`
	CVSSv2Score CVSSScore `json:"cvss_v2"`
	CVSSv3Score CVSSScore `json:"cvss_v3"`
}

// An image status result from GET /v1/images/<Digest>
type AnchoreImage struct {
	Digest         string `json:"imageDigest"`
	AnalysisStatus string `json:"analysis_status"`
}

type AnchoreImages []AnchoreImage

type FeedGroup struct {
	Name        string `json:"name"`
	CreatedAt   string `json:"created_at"`
	LastSync    string `json:"last_sync"`
	RecordCount int64  `json:"record_count"`
}

type FeedStatus struct {
	Name         string      `json:"name"`
	CreatedAt    string      `json:"created_at"`
	UpdatedAt    string      `json:"updated_at"`
	Groups       []FeedGroup `json:"groups"`
	LastFullSync string      `json:"last_full_sync"`
}

type FeedStatuses []FeedStatus

type DigestSource struct {
	PullString                string `json:"pullstring"`
	Tag                       string `json:"tag"`
	CreationTimestampOverride string `json:"creation_timestamp_override"`
}

// Models for requesting analysis via the POST /v1/images call
type AnchoreImageSource struct {
	DigestSource DigestSource `json:"digest"`
}

type AnchoreImageScanRequest struct {
	Source      AnchoreImageSource `json:"source"`
	ImageType   string             `json:"image_type"`
	Annotations map[string]string  `json:"annotations,omitempty"`
}

type AnchoreError struct {
	Detail   map[string]interface{} `json:"detail"`
	HttpCode int                    `json:"httpcode"`
	Message  string                 `json:"message"`
}

type NamespacedVulnerability struct {
	ID          string `json:"id"`
	Namespace   string `json:"namespace"`
	Description string `json:"description"`
	// Omits other fields for now, since they are unused
}

type VulnerabilityQueryResults struct {
	Page            string                    `json:"page"`
	NextPage        string                    `json:"next_page"`
	ReturnedCount   int                       `json:"returned_count"`
	Vulnerabilities []NamespacedVulnerability `json:"vulnerabilities"`
}
