package anchore

import (
	"encoding/base64"
	"github.com/anchore/harbor-scanner-adapter/pkg/model/anchore"
	"math/rand"
	"testing"
	"time"
)

// Db update cache tests
func TestCacheDBUpdate(t *testing.T) {
	defer FlushDbUpdateCache()
	testT := time.Now()
	CacheDBUpdate(testT)

	if dbUpdateCached.IsZero() {
		t.Fatal("not cached")
	}
}

func TestGetCachedDbUpdateTime(t *testing.T) {
	defer FlushDbUpdateCache()

	_, ok := GetCachedDbUpdateTime()
	if ok {
		t.Fatal("Found cached db time, but no value should be found")
	}

	testT := time.Now()
	CacheDBUpdate(testT)

	if t2, ok := GetCachedDbUpdateTime(); !ok {
		t.Fatal("not cached")
	} else {
		if t2 != testT {
			t.Fatal("wrong ts cached")
		}
	}
}

func TestFlushDBUpdateCache(t *testing.T) {
	defer FlushDbUpdateCache()
	testT := time.Now()
	CacheDBUpdate(testT)
	foundT, ok := GetCachedDbUpdateTime()
	if !ok || foundT != testT {
		t.Fail()
	}
	FlushDbUpdateCache()
	_, ok = GetCachedDbUpdateTime()
	if ok {
		t.Fail()
	}
}

// Vuln description cache tests
func TestGetCachedVulnDescription(t *testing.T) {
	defer FlushVulnDescriptionCache()
	desc1 := anchore.NamespacedVulnerability{
		ID:          "cve123",
		Namespace:   "debian:8",
		Description: "some description worth noting",
	}

	desc2 := anchore.NamespacedVulnerability{
		ID:          "cve123",
		Namespace:   "debian:8",
		Description: "",
	}

	CacheVulnDescription(desc1)
	if vulnDescriptionCache.Len() != 1 {
		t.Fatal("cache length is not one", vulnDescriptionCache.Len())
	}

	r, ok := GetCachedVulnDescription(desc2)
	if !ok {
		t.Fatal("not found, should have been found")
	}

	if r != desc1.Description {
		t.Fatal("wrong result:", r)
	}
}

func TestCacheVulnDescription(t *testing.T) {
	defer FlushVulnDescriptionCache()
	desc1 := anchore.NamespacedVulnerability{
		ID:          "cve123",
		Namespace:   "debian:8",
		Description: "some description worth noting",
	}

	CacheVulnDescription(desc1)

	FlushVulnDescriptionCache()

	_, ok := GetCachedVulnDescription(desc1)
	if ok {
		t.Fatal("should not get value after flush")
	}

}

func TestCacheVulnDescriptionTimeout(t *testing.T) {
	t.SkipNow()
	defer FlushVulnDescriptionCache()
	desc1 := anchore.NamespacedVulnerability{
		ID:          "cve123",
		Namespace:   "debian:8",
		Description: "some description worth noting",
	}

	CacheVulnDescription(desc1)
	sleepDuration := time.Second * (DefaultVulnReportCacheTimeoutSeconds + 1)
	t.Log("Sleeping to test ttl: ", DefaultVulnReportCacheTimeoutSeconds+1)
	time.Sleep(sleepDuration)

	_, ok := GetCachedVulnDescription(anchore.NamespacedVulnerability{
		ID:          "cve123",
		Namespace:   "debian:8",
		Description: "",
	})
	if ok {
		t.Fatal("should not get value after timeout")
	}
	if vulnDescriptionCache.Len() > 0 {
		t.Fatal("should not have any cached entries after ttl + request")
	}

}

// Test for manual checks of memory usage for various sizes of data
func TestVulnDescriptionCacheSize(t *testing.T) {
	t.SkipNow()
	var tmp = make([]byte, 1000)

	for i := 0; i < 10000; i++ {
		_, err := rand.Read(tmp)
		if err != nil {
			t.Fatal(err)
		}

		desc := base64.StdEncoding.EncodeToString(tmp)

		CacheVulnDescription(anchore.NamespacedVulnerability{
			ID:          "cve-" + string(i),
			Namespace:   "debian:9",
			Description: desc,
		})
	}

}

// Vuln report cache tests
func TestGetCachedVulnReport(t *testing.T) {
	defer FlushVulnReportCache()

	CacheVulnReport("digest123", anchore.ImageVulnerabilityReport{
		ImageDigest:     "digest123",
		Vulnerabilities: nil,
	})

	if vulnReportCache.Len() != 1 {
		t.Fatal("cache length is not one", vulnReportCache.Len())
	}

	r, ok := GetCachedVulnReport("digest123")
	if !ok {
		t.Fatal("not found, should have been found")
	}

	if r.ImageDigest != "digest123" {
		t.Fatal("wrong result:", r)
	}
}

func TestCacheVulnReport(t *testing.T) {
	defer FlushVulnReportCache()

	CacheVulnReport("digest123", anchore.ImageVulnerabilityReport{
		ImageDigest:     "digest123",
		Vulnerabilities: nil,
	})

	FlushVulnReportCache()

	_, ok := GetCachedVulnReport("digest123")
	if ok {
		t.Fatal("should not get value after flush")
	}

}
