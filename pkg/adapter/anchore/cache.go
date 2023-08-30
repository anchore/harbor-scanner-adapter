package anchore

import (
	"sync"
	"time"

	"github.com/golang/groupcache/lru"
	log "github.com/sirupsen/logrus"
)

// A simple struct to track the cache time for the entry as well as the value itself
type TimestampedEntry struct {
	CachedAt time.Time
	Object   interface{}
}

type CacheConfiguration struct {
	VulnDescriptionCacheEnabled  bool
	VulnDescriptionCacheMaxCount int
	VulnDescriptionCacheTTL      int
	DbUpdateCacheEnabled         bool
	DbUpdatedCacheTTL            int
	VulnReportCacheEnabled       bool
	VulnReportCacheMaxCount      int
	VulnReportCacheTTL           int
}

type ConcurrentCache interface {
	Add(key string, obj interface{}) error
	Get(key string) (interface{}, bool)
	Flush() error
}

type LockingTTLCache struct {
	Cache   *lru.Cache    // The data store, stores TimestampedEntry values
	Lock    sync.Mutex    // Lock for concurrency
	TTL     time.Duration // TTL for values
	Enabled bool          // If true, use the cache, else always bypass
}

// Cache for vulnerability description text since those must be retrieved from the Anchore APIs separately
// This can be removed if/when the Anchore API vulnerability response includes descriptions directly
var DescriptionCache *LockingTTLCache

// Cache for the vulnerability response from the Anchore API
var ReportCache *LockingTTLCache

// Cache for storing vuln db update timestamps to minimize the calls to get the db timestamp since it isn't part of
// the vulnerability response
var UpdateTimestampCache *LockingTTLCache

func NewCache(enabled bool, size int, ttl int) *LockingTTLCache {
	if !enabled {
		size = 0
	}
	return &LockingTTLCache{
		Cache:   lru.New(size),
		Lock:    sync.Mutex{},
		TTL:     time.Duration(ttl) * time.Second,
		Enabled: enabled,
	}
}

func (c *LockingTTLCache) Get(key string) (interface{}, bool) {
	if c.Enabled {
		c.Lock.Lock()
		defer c.Lock.Unlock()
		if entry, ok := c.Cache.Get(key); ok {
			// Check the time
			age := time.Since(entry.(TimestampedEntry).CachedAt)
			if age > c.TTL {
				// expired, remove
				log.WithFields(log.Fields{"age": age, "key": key, "ttl": c.TTL}).Trace("expired cache entry")
				c.Cache.Remove(key)
			} else {
				log.WithFields(log.Fields{"age": age, "key": key, "ttl": c.TTL}).Trace("valid cache entry")
				// ok, return
				return entry.(TimestampedEntry).Object, true
			}
		}
	}
	return nil, false
}

// Cache a vuln report
func (c *LockingTTLCache) Add(key string, obj interface{}) {
	if c.Enabled {
		c.Lock.Lock()
		defer c.Lock.Unlock()
		c.Cache.Add(key, TimestampedEntry{
			CachedAt: time.Now(),
			Object:   obj,
		})
	}
}

// Drop the cache
func (c *LockingTTLCache) Flush() {
	c.Lock.Lock()
	defer c.Lock.Unlock()
	c.Cache.Clear()
}

func InitCaches(configuration CacheConfiguration) error {
	log.WithField("config", configuration).Info("initializing caches")
	DescriptionCache = NewCache(
		configuration.VulnDescriptionCacheEnabled,
		configuration.VulnDescriptionCacheMaxCount,
		configuration.VulnDescriptionCacheTTL,
	)
	ReportCache = NewCache(
		configuration.VulnReportCacheEnabled,
		configuration.VulnReportCacheMaxCount,
		configuration.VulnReportCacheTTL,
	)
	UpdateTimestampCache = NewCache(configuration.DbUpdateCacheEnabled, 1, configuration.DbUpdatedCacheTTL)
	return nil
}
