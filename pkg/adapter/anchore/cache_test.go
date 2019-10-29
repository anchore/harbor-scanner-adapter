package anchore

import (
	"encoding/base64"
	"github.com/anchore/harbor-scanner-adapter/pkg/model/anchore"
	"math/rand"
	"testing"
	"time"
)

// Db update cache tests
func TestUpdateTimestmapCache(t *testing.T) {
	err := InitCaches(DefaultCacheConfig)
	if err != nil {
		t.Fatal(err)
	}

	defer UpdateTimestampCache.Flush()
	testT := time.Now()
	UpdateTimestampCache.Add("db", testT)

	if UpdateTimestampCache.Cache.Len() == 0 {
		t.Fatal("not cached")
	}

	if _, ok := UpdateTimestampCache.Get("db"); !ok {
		t.Fatal("not cached")
	}
}

func TestGetCachedDbUpdateTime(t *testing.T) {
	err := InitCaches(DefaultCacheConfig)
	if err != nil {
		t.Fatal(err)
	}
	defer UpdateTimestampCache.Flush()

	_, ok := UpdateTimestampCache.Get("db")
	if ok {
		t.Fatal("Found cached db time, but no value should be found")
	}

	testT := time.Now()
	UpdateTimestampCache.Add("db", testT)

	if t2, ok := UpdateTimestampCache.Get("db"); !ok {
		t.Fatal("not cached")
	} else {
		if t2 != testT {
			t.Fatal("wrong ts cached")
		}
	}
}

func TestFlushDBUpdateCache(t *testing.T) {
	err := InitCaches(DefaultCacheConfig)
	if err != nil {
		t.Fatal(err)
	}
	defer UpdateTimestampCache.Flush()
	testT := time.Now()
	UpdateTimestampCache.Add("db", testT)
	foundT, ok := UpdateTimestampCache.Get("db")
	if !ok || foundT != testT {
		t.Fail()
	}
	UpdateTimestampCache.Flush()
	_, ok = UpdateTimestampCache.Get("db")
	if ok {
		t.Fail()
	}
}

// Vuln description cache tests
func TestGetCachedVulnDescription(t *testing.T) {
	err := InitCaches(DefaultCacheConfig)
	if err != nil {
		t.Fatal(err)
	}
	defer DescriptionCache.Flush()
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

	DescriptionCache.Add(desc1.ID, desc1.Description)
	if DescriptionCache.Cache.Len() != 1 {
		t.Fatal("cache length is not one", DescriptionCache.Cache.Len())
	}

	r, ok := DescriptionCache.Get(desc2.ID)
	if !ok {
		t.Fatal("not found, should have been found")
	}

	if r != desc1.Description {
		t.Fatal("wrong result:", r)
	}
}

func TestCacheVulnDescription(t *testing.T) {
	err := InitCaches(DefaultCacheConfig)
	if err != nil {
		t.Fatal(err)
	}
	defer DescriptionCache.Flush()
	desc1 := anchore.NamespacedVulnerability{
		ID:          "cve123",
		Namespace:   "debian:8",
		Description: "some description worth noting",
	}

	DescriptionCache.Add(desc1.ID, desc1.Description)

	DescriptionCache.Flush()

	_, ok := DescriptionCache.Get(desc1.ID)
	if ok {
		t.Fatal("should not get value after flush")
	}

}

func TestCacheVulnDescriptionTimeout(t *testing.T) {
	t.SkipNow()
	err := InitCaches(DefaultCacheConfig)
	testTTL := time.Duration(3 * time.Second)
	DescriptionCache.TTL = testTTL
	if err != nil {
		t.Fatal(err)
	}
	defer DescriptionCache.Flush()
	desc1 := anchore.NamespacedVulnerability{
		ID:          "cve123",
		Namespace:   "debian:8",
		Description: "some description worth noting",
	}

	DescriptionCache.Add("cve123", desc1)
	sleepDuration := (testTTL + 1)
	t.Log("Sleeping to test ttl: ", testTTL+1)
	time.Sleep(sleepDuration)

	_, ok := DescriptionCache.Get("cve123")
	if ok {
		t.Fatal("should not get value after timeout")
	}
	if DescriptionCache.Cache.Len() > 0 {
		t.Fatal("should not have any cached entries after ttl + request")
	}

}

// Test for manual checks of memory usage for various sizes of data
func TestVulnDescriptionCacheSize(t *testing.T) {
	t.SkipNow()
	err := InitCaches(DefaultCacheConfig)
	if err != nil {
		t.Fatal(err)
	}
	var tmp = make([]byte, 1000)

	for i := 0; i < 10000; i++ {
		_, err := rand.Read(tmp)
		if err != nil {
			t.Fatal(err)
		}

		desc := base64.StdEncoding.EncodeToString(tmp)

		DescriptionCache.Add("id"+string(i), anchore.NamespacedVulnerability{
			ID:          "cve-" + string(i),
			Namespace:   "debian:9",
			Description: desc,
		})
	}

}

// Vuln report cache tests
func TestGetCachedVulnReport(t *testing.T) {
	err := InitCaches(DefaultCacheConfig)
	if err != nil {
		t.Fatal(err)
	}
	defer ReportCache.Flush()

	ReportCache.Add("digest123", anchore.ImageVulnerabilityReport{
		ImageDigest:     "digest123",
		Vulnerabilities: nil,
	})

	t.Log("TTL: ", ReportCache.TTL)
	if ReportCache.Cache.Len() != 1 {
		t.Fatal("cache length is not one", ReportCache.Cache.Len())
	}

	r, ok := ReportCache.Get("digest123")
	if !ok {
		t.Fatal("not found, should have been found")
	}

	if r.(anchore.ImageVulnerabilityReport).ImageDigest != "digest123" {
		t.Fatal("wrong result:", r)
	}
}

func TestCacheVulnReport(t *testing.T) {
	err := InitCaches(DefaultCacheConfig)
	if err != nil {
		t.Fatal(err)
	}
	defer ReportCache.Flush()

	ReportCache.Add("digest123", anchore.ImageVulnerabilityReport{
		ImageDigest:     "digest123",
		Vulnerabilities: nil,
	})

	ReportCache.Flush()

	_, ok := ReportCache.Get("digest123")
	if ok {
		t.Fatal("should not get value after flush")
	}
}
