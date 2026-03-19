package proxy

import (
	"sync"
	"time"
)

// rateLimitTracker stores the sliding window timestamps for a single [Server/Tool] pair.
type rateLimitTracker struct {
	timestamps []time.Time
}

var (
	rateLimitMutex sync.Mutex
	rateLimits     = make(map[string]*rateLimitTracker)
)

// Allow checks if a given tool on a server has exceeded its rate limit.
// It uses a simple sliding window algorithm. Returns true if allowed, false if rejected.
func Allow(server, tool string, max int, window time.Duration) bool {
	if max <= 0 {
		return true // rate limiting disabled natively if max is 0
	}

	key := server + ":" + tool
	now := time.Now()
	cutoff := now.Add(-window)

	rateLimitMutex.Lock()
	defer rateLimitMutex.Unlock()

	tracker, exists := rateLimits[key]
	if !exists {
		tracker = &rateLimitTracker{timestamps: make([]time.Time, 0, max)}
		rateLimits[key] = tracker
	}

	// Filter out expired timestamps
	validTimestampCount := 0
	for _, t := range tracker.timestamps {
		if t.After(cutoff) {
			tracker.timestamps[validTimestampCount] = t
			validTimestampCount++
		}
	}
	tracker.timestamps = tracker.timestamps[:validTimestampCount]

	if len(tracker.timestamps) >= max {
		return false
	}

	// Allowed! Log the timestamp.
	tracker.timestamps = append(tracker.timestamps, now)
	return true
}
