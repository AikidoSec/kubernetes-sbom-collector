package controllers

import (
	"sync"
	"time"

	stereoscopeImage "github.com/anchore/stereoscope/pkg/image"
)

const (
	nodePlatformCacheSize = 5000
	nodePlatformCacheTTL  = time.Hour
)

type nodePlatformEntry struct {
	platform  *stereoscopeImage.Platform
	expiresAt time.Time
}

// nodePlatformCache caches the platform of the nodes, keyed by node name. The zero value is ready to use.
type nodePlatformCache struct {
	mu      sync.Mutex
	entries map[string]nodePlatformEntry
}

func (c *nodePlatformCache) Get(nodeName string) (*stereoscopeImage.Platform, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()

	entry, ok := c.entries[nodeName]
	if !ok || time.Now().After(entry.expiresAt) {
		return nil, false
	}

	return entry.platform, true
}

// Add caches the node platform. Since Add only runs on a cache miss, it also removes the expired entries.
// New entries are not cached while the cache is full.
func (c *nodePlatformCache) Add(nodeName string, platform *stereoscopeImage.Platform) {
	c.mu.Lock()
	defer c.mu.Unlock()

	now := time.Now()
	for name, entry := range c.entries {
		if now.After(entry.expiresAt) {
			delete(c.entries, name)
		}
	}

	if len(c.entries) >= nodePlatformCacheSize {
		return
	}

	if c.entries == nil {
		c.entries = make(map[string]nodePlatformEntry)
	}

	c.entries[nodeName] = nodePlatformEntry{platform: platform, expiresAt: now.Add(nodePlatformCacheTTL)}
}
