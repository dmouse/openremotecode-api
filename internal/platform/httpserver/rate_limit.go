package httpserver

import (
	"container/list"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
)

// defaultRateLimitCapacity bounds the clients one limiter tracks. At roughly a hundred
// bytes an entry this caps each limiter near one megabyte, however many addresses a
// caller rotates through.
const defaultRateLimitCapacity = 10_000

// RateLimiter is a fixed-window limiter keyed by client network (see RateLimitKey).
//
// Memory is bounded. Entries are kept in the order their windows started, so expired
// windows are swept from the front on every call at amortized constant cost. When the
// table is still full, the oldest window is evicted rather than the new client refused:
// refusing would let anyone controlling enough addresses lock every other client out.
// Eviction only hands the evicted client a fresh window, which is no more than a caller
// with that many addresses already has.
type RateLimiter struct {
	mutex    sync.Mutex
	maximum  int
	window   time.Duration
	capacity int
	entries  map[string]*list.Element
	order    *list.List
}

type rateEntry struct {
	key       string
	startedAt time.Time
	count     int
}

func NewRateLimiter(maximum int, window time.Duration) *RateLimiter {
	return newRateLimiter(maximum, window, defaultRateLimitCapacity)
}

func newRateLimiter(maximum int, window time.Duration, capacity int) *RateLimiter {
	return &RateLimiter{
		maximum:  maximum,
		window:   window,
		capacity: capacity,
		entries:  make(map[string]*list.Element),
		order:    list.New(),
	}
}

// Allow counts one request for key and reports whether it is within the limit, and if
// not, how long until the key's window ends.
func (limiter *RateLimiter) Allow(key string, now time.Time) (bool, time.Duration) {
	limiter.mutex.Lock()
	defer limiter.mutex.Unlock()
	limiter.removeExpired(now)

	if element, exists := limiter.entries[key]; exists {
		entry := element.Value.(*rateEntry)
		if now.Sub(entry.startedAt) >= limiter.window {
			entry.startedAt, entry.count = now, 1
			limiter.order.MoveToBack(element)
			return true, 0
		}
		if entry.count >= limiter.maximum {
			return false, limiter.window - now.Sub(entry.startedAt)
		}
		entry.count++
		return true, 0
	}
	for len(limiter.entries) >= limiter.capacity {
		limiter.remove(limiter.order.Front())
	}
	limiter.entries[key] = limiter.order.PushBack(&rateEntry{key: key, startedAt: now, count: 1})
	return true, 0
}

func (limiter *RateLimiter) removeExpired(now time.Time) {
	for element := limiter.order.Front(); element != nil; element = limiter.order.Front() {
		if now.Sub(element.Value.(*rateEntry).startedAt) < limiter.window {
			return
		}
		limiter.remove(element)
	}
}

func (limiter *RateLimiter) remove(element *list.Element) {
	delete(limiter.entries, element.Value.(*rateEntry).key)
	limiter.order.Remove(element)
}

// RateLimitKey is the key a request is rate limited under: its client address, with an
// IPv6 address reduced to its /64. A single IPv6 host is routinely assigned a whole /64,
// so keying by full address would give it billions of independent budgets.
func RateLimitKey(request *http.Request, trustedProxies []*net.IPNet) string {
	address := ClientAddress(request, trustedProxies)
	ip := net.ParseIP(address)
	if ip == nil || ip.To4() != nil {
		return address
	}
	return (&net.IPNet{IP: ip.Mask(net.CIDRMask(64, 128)), Mask: net.CIDRMask(64, 128)}).String()
}

// ClientAddress returns the request's client IP. X-Forwarded-For is honoured only when the
// direct peer is a configured trusted proxy, and then only up to the first address that is
// not itself a trusted proxy, reading from the right; anything malformed falls back to the peer.
func ClientAddress(request *http.Request, trustedProxies []*net.IPNet) string {
	peer := remoteHost(request.RemoteAddr)
	peerIP := net.ParseIP(peer)
	if peerIP == nil || !ipInNetworks(peerIP, trustedProxies) {
		return peer
	}
	forwardedFor := request.Header.Values("X-Forwarded-For")
	if len(forwardedFor) != 1 {
		return peer
	}
	addresses := strings.Split(forwardedFor[0], ",")
	for index := len(addresses) - 1; index >= 0; index-- {
		address := strings.TrimSpace(addresses[index])
		ip := net.ParseIP(address)
		if ip == nil {
			return peer
		}
		if !ipInNetworks(ip, trustedProxies) {
			return address
		}
	}
	return peer
}

func remoteHost(address string) string {
	host, _, err := net.SplitHostPort(address)
	if err == nil {
		return host
	}
	return address
}

func ipInNetworks(ip net.IP, networks []*net.IPNet) bool {
	for _, network := range networks {
		if network.Contains(ip) {
			return true
		}
	}
	return false
}
