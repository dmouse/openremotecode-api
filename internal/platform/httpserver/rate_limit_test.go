package httpserver

import (
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestRateLimiterEnforcesFixedWindows(t *testing.T) {
	limiter := NewRateLimiter(2, time.Minute)
	now := time.Date(2026, 9, 24, 12, 0, 0, 0, time.UTC)
	for range 2 {
		if allowed, _ := limiter.Allow("client", now); !allowed {
			t.Fatal("request within the limit was refused")
		}
	}
	allowed, retryAfter := limiter.Allow("client", now.Add(20*time.Second))
	if allowed || retryAfter != 40*time.Second {
		t.Fatalf("over-limit request = %v, retry after %v; want refused, 40s", allowed, retryAfter)
	}
	if allowed, _ := limiter.Allow("other", now); !allowed {
		t.Fatal("one client's budget affected another")
	}
	if allowed, _ := limiter.Allow("client", now.Add(time.Minute)); !allowed {
		t.Fatal("a new window did not reset the count")
	}
}

// Filling the table must never lock out a client it has not seen: that is the
// global denial of service a capacity refusal would hand to anyone with enough addresses.
func TestRateLimiterEvictsOldestInsteadOfRefusingNewClients(t *testing.T) {
	limiter := newRateLimiter(1, time.Minute, 3)
	now := time.Date(2026, 9, 24, 12, 0, 0, 0, time.UTC)
	for index := range 3 {
		limiter.Allow(fmt.Sprintf("flood-%d", index), now.Add(time.Duration(index)*time.Second))
	}
	if allowed, _ := limiter.Allow("legitimate", now.Add(5*time.Second)); !allowed {
		t.Fatal("a new client was refused because the table was full")
	}
	if len(limiter.entries) != 3 || limiter.order.Len() != 3 {
		t.Fatalf("limiter grew past its capacity: %d entries", len(limiter.entries))
	}
	if _, kept := limiter.entries["flood-0"]; kept {
		t.Fatal("the oldest window was not the one evicted")
	}
	if allowed, _ := limiter.Allow("flood-2", now.Add(6*time.Second)); allowed {
		t.Fatal("eviction reset a client that was not evicted")
	}
}

func TestRateLimiterSweepsExpiredWindows(t *testing.T) {
	limiter := NewRateLimiter(1, time.Minute)
	now := time.Date(2026, 9, 24, 12, 0, 0, 0, time.UTC)
	for index := range 100 {
		limiter.Allow(fmt.Sprintf("client-%d", index), now)
	}
	limiter.Allow("late", now.Add(time.Minute))
	if len(limiter.entries) != 1 || limiter.order.Len() != 1 {
		t.Fatalf("expired windows were retained: %d entries", len(limiter.entries))
	}
}

func TestRateLimitKeyGroupsIPv6ByPrefix(t *testing.T) {
	key := func(remote string) string {
		request := httptest.NewRequest(http.MethodPost, "/", nil)
		request.RemoteAddr = remote
		return RateLimitKey(request, nil)
	}
	if first, second := key("[2001:db8:1:2::1]:1234"), key("[2001:db8:1:2:ffff::9]:1234"); first != second {
		t.Fatalf("one /64 produced two keys: %q, %q", first, second)
	}
	if first, second := key("[2001:db8:1:2::1]:1234"), key("[2001:db8:1:3::1]:1234"); first == second {
		t.Fatal("different /64 networks shared a key")
	}
	if got := key("192.0.2.10:1234"); got != "192.0.2.10" {
		t.Fatalf("IPv4 key = %q, want the full address", got)
	}
	if got := key("[::ffff:192.0.2.10]:1234"); got != "::ffff:192.0.2.10" && got != "192.0.2.10" {
		t.Fatalf("IPv4-mapped key = %q, want the IPv4 address", got)
	}
}

func TestClientAddressTrustsOnlyConfiguredProxies(t *testing.T) {
	_, trustedProxy, err := net.ParseCIDR("10.0.0.0/8")
	if err != nil {
		t.Fatalf("parse trusted proxy: %v", err)
	}
	request := httptest.NewRequest(http.MethodPost, "/v1/auth/login", nil)
	request.RemoteAddr = "192.0.2.10:1234"
	request.Header.Set("X-Forwarded-For", "198.51.100.7")
	if address := ClientAddress(request, []*net.IPNet{trustedProxy}); address != "192.0.2.10" {
		t.Fatalf("untrusted peer spoofed client address as %q", address)
	}

	request.RemoteAddr = "10.0.0.4:1234"
	request.Header.Set("X-Forwarded-For", "198.51.100.7, 10.0.0.3")
	if address := ClientAddress(request, []*net.IPNet{trustedProxy}); address != "198.51.100.7" {
		t.Fatalf("expected forwarded client address, got %q", address)
	}
}
