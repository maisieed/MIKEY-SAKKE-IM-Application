package main

import (
	"bytes"
	"sync"
	"time"
)

// ReplayCache stores parameters required to prevent replay attacks.
type ReplayCache struct {
	clockSkew time.Duration // The clock skew (seconds).
	tick      *time.Ticker  // Channel that will deliver ticks when replay cache should be reset.
	mutex     sync.Mutex    // Mutex to handle replayCache.
	cache     [][]byte      // List of successfully authenticated messages received since last tick.
}

// resetReplayCache resets the replay cache every clock skew period.
// This must be called as a Goroutine.
func (replayCache *ReplayCache) resetReplayCache() {
	for {
		<-replayCache.tick.C
		// If new clock skew period, reset replay cache.
		replayCache.mutex.Lock()
		replayCache.cache = [][]byte{}
		replayCache.mutex.Unlock()
	}
}

// isInReplayCache checks if the given message is currently in the replay cache.
// Returns true if in the replay cache, else false.
func (replayCache *ReplayCache) isInReplayCache(message []byte) (found bool) {
	replayCache.mutex.Lock()
	for _, existingMessage := range replayCache.cache {
		if bytes.Equal(message, existingMessage) {
			found = true
		}
	}
	replayCache.mutex.Unlock()
	return
}

// addToReplayCache adds the given message to the replay cache.
func (replayCache *ReplayCache) addToReplayCache(message []byte) {
	replayCache.mutex.Lock()
	replayCache.cache = append(replayCache.cache, message)
	replayCache.mutex.Unlock()
}
