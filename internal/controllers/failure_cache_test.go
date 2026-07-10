package controllers

import (
	"testing"
	"time"

	"aikidoSec.kubernetes-sbom-collector/pkg/models"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func testImage(repo, digest string) models.ImageReference {
	return models.ImageReference{
		ShorthandRepository: repo,
		Digest:              digest,
	}
}

func TestImageFailureCache(t *testing.T) {
	t.Run("record puts image in cooldown", func(t *testing.T) {
		c := newImageFailureCache(5*time.Minute, 100)
		img := testImage("library/nginx", "sha256:abc")

		require.False(t, c.inCooldown(img), "unseen image should not be in cooldown")

		c.record(img)

		assert.True(t, c.inCooldown(img))
	})

	t.Run("cooldown expires and is pruned on read", func(t *testing.T) {
		c := newImageFailureCache(5*time.Minute, 100)
		img := testImage("library/nginx", "sha256:abc")

		c.record(img)
		// Simulate the cooldown having elapsed.
		c.entries[c.key(img)] = time.Now().Add(-6 * time.Minute)

		assert.False(t, c.inCooldown(img))
		_, ok := c.entries[c.key(img)]
		assert.False(t, ok, "expired entry should be pruned on read")
	})

	t.Run("distinct images tracked independently", func(t *testing.T) {
		c := newImageFailureCache(5*time.Minute, 100)
		recorded := testImage("library/nginx", "sha256:aaa")
		sameRepoOtherDigest := testImage("library/nginx", "sha256:bbb")
		otherRepoSameDigest := testImage("library/redis", "sha256:aaa")

		c.record(recorded)

		assert.True(t, c.inCooldown(recorded))
		assert.False(t, c.inCooldown(sameRepoOtherDigest))
		assert.False(t, c.inCooldown(otherRepoSameDigest))
	})

	t.Run("record prunes expired entries", func(t *testing.T) {
		c := newImageFailureCache(5*time.Minute, 100)
		stale := testImage("library/old", "sha256:111")
		fresh := testImage("library/new", "sha256:222")

		c.record(stale)
		c.entries[c.key(stale)] = time.Now().Add(-time.Hour)

		c.record(fresh)

		_, ok := c.entries[c.key(stale)]
		assert.False(t, ok, "stale entry should be pruned when recording a new failure")
		assert.True(t, c.inCooldown(fresh))
	})

	t.Run("evicts oldest when full", func(t *testing.T) {
		c := newImageFailureCache(5*time.Minute, 3)

		base := time.Now()
		filled := []models.ImageReference{
			testImage("library/a", "sha256:a"),
			testImage("library/b", "sha256:b"),
			testImage("library/c", "sha256:c"),
		}
		for i, img := range filled {
			c.record(img)
			// Space out the timestamps so "a" is the oldest and "c" the newest.
			c.entries[c.key(img)] = base.Add(time.Duration(i) * time.Second)
		}
		require.Len(t, c.entries, 3)

		// Recording a new image at capacity must evict the oldest entry, not grow the cache.
		newImg := testImage("library/d", "sha256:d")
		c.record(newImg)

		assert.Len(t, c.entries, 3)
		assert.False(t, c.inCooldown(filled[0]), "oldest entry should have been evicted")
		assert.True(t, c.inCooldown(filled[1]))
		assert.True(t, c.inCooldown(filled[2]))
		assert.True(t, c.inCooldown(newImg))
	})

	t.Run("re-recording existing does not evict", func(t *testing.T) {
		c := newImageFailureCache(5*time.Minute, 2)
		a := testImage("library/a", "sha256:a")
		b := testImage("library/b", "sha256:b")

		c.record(a)
		c.record(b)
		require.Len(t, c.entries, 2)

		// Re-recording an already-tracked image should refresh it, not evict the other entry.
		c.record(a)

		assert.Len(t, c.entries, 2)
		assert.True(t, c.inCooldown(a))
		assert.True(t, c.inCooldown(b))
	})
}
