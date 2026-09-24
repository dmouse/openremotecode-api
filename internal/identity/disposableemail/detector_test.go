package disposableemail

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

type fakeChecker struct {
	domain string
	closed atomic.Bool
}

func (checker *fakeChecker) IsDisposable(email string) bool {
	return strings.HasSuffix(email, "@"+checker.domain)
}

func (checker *fakeChecker) Close() error {
	checker.closed.Store(true)
	return nil
}

func quietLogger() *slog.Logger { return slog.New(slog.NewTextHandler(io.Discard, nil)) }

func waitFor(t *testing.T, condition func() bool) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for !condition() {
		if time.Now().After(deadline) {
			t.Fatal("condition was not met in time")
		}
		time.Sleep(time.Millisecond)
	}
}

func TestDetectorAnswersFalseUntilTheListLoads(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	release := make(chan struct{})
	detector := start(ctx, quietLogger(), time.Millisecond, func() (checker, error) {
		<-release
		return &fakeChecker{domain: "burner.test"}, nil
	})

	if detector.IsDisposable("someone@burner.test") {
		t.Fatal("a detector with no list must not reject anyone")
	}
	close(release)
	waitFor(t, func() bool { return detector.IsDisposable("someone@burner.test") })
	if detector.IsDisposable("someone@example.com") {
		t.Fatal("an ordinary domain was reported as disposable")
	}
}

func TestDetectorRetriesUntilTheListLoads(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var attempts atomic.Int32
	detector := start(ctx, quietLogger(), time.Millisecond, func() (checker, error) {
		if attempts.Add(1) < 3 {
			return nil, errors.New("download failed")
		}
		return &fakeChecker{domain: "burner.test"}, nil
	})

	waitFor(t, func() bool { return detector.IsDisposable("someone@burner.test") })
	if attempts.Load() != 3 {
		t.Fatalf("attempts = %d, want 3", attempts.Load())
	}
}

func TestDetectorReleasesTheCheckerWhenTheContextEnds(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	instance := &fakeChecker{domain: "burner.test"}
	detector := start(ctx, quietLogger(), time.Millisecond, func() (checker, error) {
		return instance, nil
	})
	waitFor(t, func() bool { return detector.IsDisposable("someone@burner.test") })

	cancel()

	waitFor(t, instance.closed.Load)
	waitFor(t, func() bool { return !detector.IsDisposable("someone@burner.test") })
}

func TestDetectorStopsRetryingWhenTheContextEnds(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	var attempts atomic.Int32
	start(ctx, quietLogger(), time.Hour, func() (checker, error) {
		attempts.Add(1)
		return nil, errors.New("download failed")
	})
	waitFor(t, func() bool { return attempts.Load() == 1 })

	// The hour-long retry delay must not keep the loop alive past shutdown.
	cancel()
	time.Sleep(20 * time.Millisecond)
	if attempts.Load() != 1 {
		t.Fatalf("attempts after cancel = %d, want 1", attempts.Load())
	}
}
