package anchore

import (
	"fmt"
	"github.com/anchore/harbor-scanner-adapter/pkg/model/anchore"
	"github.com/golang/groupcache/lru"
	log "github.com/sirupsen/logrus"
	"sync"
	"time"
)

const (
	DbUpdateCacheTimeoutSeconds    = 60
	VulnReportCacheTimeoutSeconds  = 180
	DescriptionCacheTimeoutSeconds = 60 * 60 * 24
)

type TimestampedEntry struct {
	CachedAt time.Time
	Object interface{}
}

// Description cache for storing vuln descriptions, only keep 10k entries
var vulnDescriptionCache = lru.New(10000)
var vulnCacheLock = sync.Mutex{}

// Cached db update, subject to ttl
var dbUpdateCached = time.Time{}
var dbUpdateCachedAt = time.Time{}
var dbUpdateCacheLock = sync.Mutex{}

// Cached vuln reports from Anchore backend. Keep a small ttl, mostly used for repeated requests for different mime types (e.g. caller
// requests the harbor format then the raw format, adapter can cache result between those calls (seconds)
var vulnReportCache = lru.New(100)
var vulnReportCacheLock = sync.Mutex{}

// Get a vuln report from the cache. If present ok bool = true, false otherwise
func GetCachedVulnReport(digest string) (anchore.ImageVulnerabilityReport, bool) {
	vulnReportCacheLock.Lock()
	defer vulnReportCacheLock.Unlock()

	entry, ok := vulnReportCache.Get(digest)
	if ok {
		age := time.Since(entry.(TimestampedEntry).CachedAt)
		// Check the time
		if age > VulnReportCacheTimeoutSeconds * time.Second {
			// expired, remove
			log.WithFields(log.Fields{"age":age, "digest": digest}).Debug("expired entry")
			vulnReportCache.Remove(digest)
		} else {
			log.WithFields(log.Fields{"age":age, "digest": digest}).Debug("cache hit")
			// ok, return
			return entry.(TimestampedEntry).Object.(anchore.ImageVulnerabilityReport), true
		}
	}
	return anchore.ImageVulnerabilityReport{}, false
}

// Cache a vuln report
func CacheVulnReport(digest string, report anchore.ImageVulnerabilityReport) {
	vulnReportCacheLock.Lock()
	defer vulnReportCacheLock.Unlock()
	vulnReportCache.Add(digest, TimestampedEntry{
		CachedAt: time.Now(),
		Object:   report,
	})
}

// Drop the cache
func FlushVulnReportCache() {
	vulnReportCacheLock.Lock()
	defer vulnReportCacheLock.Unlock()
	vulnReportCache.Clear()
}

// Compute the key for the item
func cacheKeyForVuln(v *anchore.NamespacedVulnerability) string {
	if v != nil {
		return fmt.Sprintf("%v/%v", v.Namespace, v.ID)
	} else {
		return ""
	}
}

// Drop the cache
func FlushVulnDescriptionCache() {
	vulnCacheLock.Lock()
	defer vulnCacheLock.Unlock()
	vulnDescriptionCache.Clear()
}

func GetCachedVulnDescription(v anchore.NamespacedVulnerability) (string, bool) {
	vulnCacheLock.Lock()
	defer vulnCacheLock.Unlock()
	key := cacheKeyForVuln(&v)

	if key != "" {
		entry, ok := vulnDescriptionCache.Get(key)
		if ok {
			// Check the time
			age := time.Since(entry.(TimestampedEntry).CachedAt)
			if age > DescriptionCacheTimeoutSeconds * time.Second {
				// expired, remove
				log.WithFields(log.Fields{"age": age, "key": key}).Info("vuln description expired entry")
				vulnDescriptionCache.Remove(key)
			} else {
				log.WithField("key", key).Debug("vuln description cache hit")
				// ok, return
				return entry.(TimestampedEntry).Object.(string), ok
			}
		}
	}
	return "", false
}

func CacheVulnDescription(v anchore.NamespacedVulnerability) {
	vulnCacheLock.Lock()
	defer vulnCacheLock.Unlock()
	key := cacheKeyForVuln(&v)
	if key != "" {
		vulnDescriptionCache.Add(key, TimestampedEntry{
			CachedAt: time.Now(),
			Object:   v.Description,
		})
	}
}

// Drop the cache
func FlushDbUpdateCache() {
	dbUpdateCacheLock.Lock()
	defer dbUpdateCacheLock.Unlock()
	dbUpdateCachedAt = time.Time{}
	dbUpdateCached = time.Time{}
}

func CacheDBUpdate(dbTime time.Time) {
	dbUpdateCacheLock.Lock()
	defer dbUpdateCacheLock.Unlock()
	dbUpdateCached = dbTime
	dbUpdateCachedAt = time.Now()
}

func GetCachedDbUpdateTime() (time.Time, bool) {
	dbUpdateCacheLock.Lock()
	defer dbUpdateCacheLock.Unlock()

	if dbUpdateCachedAt.IsZero() || dbUpdateCached.IsZero() {
		log.Debug("dbUpdateTime cache miss, no value to return")
		return dbUpdateCached, false
	}
	age := time.Since(dbUpdateCachedAt)

	if age > DbUpdateCacheTimeoutSeconds * time.Second {
		log.WithField("age", age).Info("dbUpdateTime expired cache for db update timestamp")
		return dbUpdateCached, false
	} else {
		log.Info("dbUpdateTime cache hit")
		return dbUpdateCached, true

	}
}