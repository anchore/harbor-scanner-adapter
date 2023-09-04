package anchore

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"testing"
	"time"

	"github.com/anchore/harbor-scanner-adapter/pkg/adapter/anchore/client"
	"github.com/anchore/harbor-scanner-adapter/pkg/model/anchore"
)

func TestStringToTime(t *testing.T) {
	var s time.Time
	var err error

	s, err = client.StringToTime("2019-10-02T18:23:16Z")
	t.Logf("Time: %v Error: %v", s, err)
	if err != nil {
		t.Error(err)
	}
	if s.Year() != 2019 || s.Month() != 10 || s.Day() != 2 || s.Hour() != 18 || s.Minute() != 23 || s.Second() != 16 ||
		s.Location() != time.UTC {
		t.Error("incorrect time")
	}

	s, err = client.StringToTime("2019-10-02T07:57:46.185519Z")
	t.Logf("Time: %v Error: %v", s, err)
	if err != nil {
		t.Error(err)
	}
	if s.Year() != 2019 || s.Month() != 10 || s.Day() != 2 || s.Hour() != 7 || s.Minute() != 57 || s.Second() != 46 ||
		s.Location() != time.UTC {
		t.Error("incorrect time")
	}
}

func TestGetUsernamePassword(t *testing.T) {
	header1 := fmt.Sprintf("Basic %v", base64.StdEncoding.EncodeToString([]byte("foo:bar")))
	header2 := fmt.Sprintf("basic %v", base64.StdEncoding.EncodeToString([]byte("foo:bar")))

	headerValues := []string{
		header1,
		header2,
	}

	for _, header := range headerValues {
		usr, pass, err := GetUsernamePassword(header)
		if err != nil {
			t.Error(err)
		}

		if usr != "foo" || pass != "bar" {
			t.Error("Did not decode expected foo:bar result: ", usr, " : ", pass)
		}
	}
}

func TestScanIdToRegistryDigest(t *testing.T) {
	inputs := [][]string{
		{
			"test:5000",
			"/project1/repo1/image",
			"sha256:4214707ec3ec157f9566258710e274824a0b6a8e34051bd081d9192900d06647",
			"true",
		},
		{"test", "/project1/repo1/image", "sha256:4214707ec3ec157f9566258710e274824a0b6a8e34051bd081d9192900d06647", "true"},
		{
			"test.com:5000",
			"/project1/repo1/image",
			"sha256:4214707ec3ec157f9566258710e274824a0b6a8e34051bd081d9192900d06647",
			"true",
		},
		{
			"something.test.com:5000",
			"/project1/repo1/image",
			"sha256:4214707ec3ec157f9566258710e274824a0b6a8e34051bd081d9192900d06647",
			"true",
		},
		{"test:5000", "/project1/repo1/image", "4214707ec3ec157f9566258710e274824a0b6a8e34051bd081d9192900d06647", "false"},
		{"test:5000", "/project1/repo1/image", "sha256:", "false"},
	}

	for _, v := range inputs {
		generated, err := GenerateScanId(v[1], v[2])
		if err != nil {
			t.Errorf("failed: %v", err)
		}

		if repo, dig, err := ScanIdToRegistryDigest(generated); (err == nil) != (v[3] == "true") {
			t.Errorf("Failed test. Repo=%v, Digest=%v err=%v", repo, dig, err)
		}

	}
}

func TestToHarborDescription(t *testing.T) {
	raw := `{
		"feed": "nvdv2",
		"feed_group": "nvdv2:cves",
		"fix": "None",
		"nvd_data": [
			{
				"cvss_v2": {
					"base_score": 4.3,
					"exploitability_score": 8.6,
					"impact_score": 2.9
				},
				"cvss_v3": {
					"base_score": -1.0,
					"exploitability_score": -1.0,
					"impact_score": -1.0
				},
				"id": "CVE-2014-3146"
			}
		],
		"package": "lxml-3.2.1",
		"package_cpe": "cpe:/a:-:lxml:3.2.1:-:~~~python~~",
		"package_cpe23": "cpe:2.3:a:-:lxml:3.2.1:-:-:-:-:-:-:~~~python~~",
		"package_name": "lxml",
		"package_path": "/usr/lib64/python2.7/site-packages/lxml",
		"package_type": "python",
		"package_version": "3.2.1",
		"severity": "Medium",
		"url": "https://nvd.nist.gov/vuln/detail/CVE-2014-3146",
		"vendor_data": [],
		"vuln": "CVE-2014-3146"
		}`

	var vuln anchore.Vulnerability
	err := json.Unmarshal([]byte(raw), &vuln)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("%v", vuln)

	description, err := ToHarborDescription(&vuln)
	if err != nil {
		t.Fatal(err)
	}
	t.Log("Generated description: ", description)

	anchoreVuln := anchore.Vulnerability{
		VulnerabilityID: "CVE-123",
		VendorData: []anchore.VendorData{
			{
				ID: "CVE-123",
				CVSSv2Score: anchore.CVSSScore{
					BaseScore:           1.0,
					ExploitabilityScore: 1.0,
					ImpactScore:         1.0,
				},
				CVSSv3Score: anchore.CVSSScore{
					BaseScore:           2.0,
					ExploitabilityScore: 2.0,
					ImpactScore:         2.0,
				},
			},
		},
		NvdData: []anchore.NvdObject{
			{
				ID: "CVE-123",
				CVSSv2Score: anchore.CVSSScore{
					BaseScore:           1.0,
					ExploitabilityScore: 1.0,
					ImpactScore:         1.0,
				},
				CVSSv3Score: anchore.CVSSScore{
					BaseScore:           2.1,
					ExploitabilityScore: 2.1,
					ImpactScore:         2.1,
				},
			},
		},
		URL: "https://nvd.nist.gov/vuln/detail/CVE-2018-20650",
	}

	desc, err := ToHarborDescription(&anchoreVuln)
	if err != nil {
		t.Fatal(err)
	}
	t.Log("Description: ", desc)

	// Empty scores
	anchoreVuln2 := anchore.Vulnerability{
		VulnerabilityID: "CVE-123",
		VendorData:      []anchore.VendorData{},
		NvdData:         []anchore.NvdObject{},
		URL:             "https://nvd.nist.gov/vuln/detail/CVE-2018-20650",
	}

	desc2, err2 := ToHarborDescription(&anchoreVuln2)
	if err2 != nil {
		t.Fatal(err2)
	}
	t.Log("Description (empty): ", desc2)
}
