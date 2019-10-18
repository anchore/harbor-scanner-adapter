package anchore
//
//import (
//	"fmt"
//	"github.com/golang/groupcache/lru"
//	"net/http/fcgi"
//	"sync"
//)
//
//// Some caches for performance
//
//// Description cache for storing vuln descriptions, only keep 10k entries
//var vulnDescriptionCache = lru.New(10000)
//var vulnCacheLock = sync.Mutex{}
//
//// Cached db update, subject to ttl
//var dbUpdateCached = ""
//var dbUpdateCacheLock = sync.Mutex{}
//
//// Cached vuln reports from Anchore backend. Keep a small ttl, mostly used for repeated requests for different mime types (e.g. caller
//// requests the harbor format then the raw format, adapter can cache result between those calls (seconds)
//var vulnReportCache = lru.New(1000)
//var vulnReportCacheLock = sync.Mutex{}
//
//func GetVulnDescriptionsWithCache(config ClientConfig, vulnIds []string) (map[string]string, error) {
//	vulns := make(map[string]string)
//	var remainingVulns []string
//
//	vulnCacheLock.Lock()
//
//	//Find any from cache
//	for _, v := range vulnIds {
//		if found, ok := vulnDescriptionCache.Get(v); ok {
//			vulns[v] = found.(string) // It's a string, so ok
//		} else {
//			remainingVulns = append(remainingVulns, v)
//		}
//	}
//
//	// Unlock?
//	vulnCacheLock.Unlock()
//
//	fetched, err := GetVulnerabilityDescriptions(config, remainingVulns)
//
//	vulnCacheLock.Lock()
//	for k := range fetched {
//		// Cache the entry
//		vulnDescriptionCache.Add(k, fetched[k])
//	}
//
//	defer vulnCacheLock.Unlock()
//	return vulns, nil
//}
//
