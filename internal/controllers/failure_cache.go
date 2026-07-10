package controllers

import (
	"sync"
	"time"

	"aikidoSec.kubernetes-sbom-collector/pkg/models"
)

// imageFailureCache records images that have recently failed to be processed0
type imageFailureCache struct {
	cooldown   time.Duration
	maxEntries int
	mu         sync.Mutex
	entries    map[string]time.Time
}

func newImageFailureCache(cooldown time.Duration, maxEntries int) *imageFailureCache {
	return &imageFailureCache{
		cooldown:   cooldown,
		maxEntries: maxEntries,
		entries:    make(map[string]time.Time),
	}
}

func (c *imageFailureCache) key(img models.ImageReference) string {
	return img.ShorthandName() + "@" + img.Digest
}

// inCooldown reports whether the image failed within the cooldown window
func (c *imageFailureCache) inCooldown(img models.ImageReference) bool {
	c.mu.Lock()
	defer c.mu.Unlock()

	key := c.key(img)
	failedAt, ok := c.entries[key]
	if !ok {
		return false
	}
	if time.Since(failedAt) >= c.cooldown {
		delete(c.entries, key)
		return false
	}
	return true
}

// record marks the image as failed now
func (c *imageFailureCache) record(img models.ImageReference) {
	c.mu.Lock()
	defer c.mu.Unlock()

	now := time.Now()
	for k, failedAt := range c.entries {
		if now.Sub(failedAt) >= c.cooldown {
			delete(c.entries, k)
		}
	}

	key := c.key(img)

	// Bound memory: if still at capacity after pruning expired entries, evict the oldest.
	if _, exists := c.entries[key]; !exists && len(c.entries) >= c.maxEntries {
		var oldestKey string
		var oldestAt time.Time
		for k, failedAt := range c.entries {
			if oldestKey == "" || failedAt.Before(oldestAt) {
				oldestKey, oldestAt = k, failedAt
			}
		}
		delete(c.entries, oldestKey)
	}

	c.entries[key] = now
}
