package proxy

import "sync/atomic"

// IsPaused is the global atomic circuit breaker controlling all autonomous proxy traffic.
var IsPaused atomic.Bool
