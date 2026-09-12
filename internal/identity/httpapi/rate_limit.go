package httpapi

import (
	"sync"
	"time"
)

type rateLimit struct {
	maximum int
	window  time.Duration
}

type rateWindow struct {
	startedAt time.Time
	count     int
}

type fixedWindowLimiter struct {
	mutex       sync.Mutex
	limit       rateLimit
	maximumKeys int
	windows     map[string]rateWindow
}

func newFixedWindowLimiter(limit rateLimit) *fixedWindowLimiter {
	return &fixedWindowLimiter{
		limit:       limit,
		maximumKeys: 10_000,
		windows:     make(map[string]rateWindow),
	}
}

func (limiter *fixedWindowLimiter) allow(key string, now time.Time) (bool, time.Duration) {
	limiter.mutex.Lock()
	defer limiter.mutex.Unlock()

	window, exists := limiter.windows[key]
	if !exists || now.Sub(window.startedAt) >= limiter.limit.window {
		if !exists && len(limiter.windows) >= limiter.maximumKeys {
			limiter.removeExpired(now)
			if len(limiter.windows) >= limiter.maximumKeys {
				return false, limiter.limit.window
			}
		}
		limiter.windows[key] = rateWindow{startedAt: now, count: 1}
		return true, 0
	}
	if window.count >= limiter.limit.maximum {
		return false, limiter.limit.window - now.Sub(window.startedAt)
	}
	window.count++
	limiter.windows[key] = window
	return true, 0
}

func (limiter *fixedWindowLimiter) removeExpired(now time.Time) {
	for key, window := range limiter.windows {
		if now.Sub(window.startedAt) >= limiter.limit.window {
			delete(limiter.windows, key)
		}
	}
}
