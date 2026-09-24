// Package disposableemail adapts github.com/rezmoss/go-is-disposable-email to the
// identity module's DisposableEmailDetector.
//
// The library does not embed its domain list. It downloads a compiled list over HTTPS
// on first use, caches it in a directory, and refreshes it on an interval. That makes
// it a third-party runtime dependency of what is otherwise a self-contained service,
// so this adapter never lets it gate anything: the list loads in the background, a
// detector with no list answers "not disposable", and a failed load is retried with
// backoff. Registration therefore degrades to unfiltered, never to unavailable, and
// readiness does not depend on it. See docs/adr/0016-disposable-email-filter.md.
package disposableemail

import (
	"context"
	"fmt"
	"log/slog"
	"sync/atomic"
	"time"

	disposable "github.com/rezmoss/go-is-disposable-email"
)

const (
	initialRetryDelay = 30 * time.Second
	maximumRetryDelay = 15 * time.Minute
	// downloadTimeout bounds one fetch of a list of roughly 450 KB. The library's own
	// default is thirty seconds, which is long for a background retry loop.
	downloadTimeout = 10 * time.Second
	refreshInterval = 24 * time.Hour
)

// Config selects where the list comes from and which domains are exempt from it.
// The zero value uses the library's defaults: its published GitHub release and a
// cache under os.UserCacheDir.
type Config struct {
	// CacheDir must be writable. The production container has a read-only root
	// filesystem, so deployments point this at a tmpfs mount.
	CacheDir string
	// DataURL overrides the list location so a deployment can self-host a reviewed
	// copy instead of trusting the upstream release feed. It must be HTTPS.
	DataURL string
	// AllowDomains are never reported as disposable, including their subdomains,
	// whatever the list says. It is the operator's remedy for a false positive.
	AllowDomains []string
}

// checker is the part of *disposable.Checker the detector uses, so the load, retry,
// and shutdown behavior can be tested without downloading anything.
type checker interface {
	IsDisposable(emailOrDomain string) bool
	Close() error
}

type loadedChecker struct{ checker }

// Detector implements identity.DisposableEmailDetector. It is safe for concurrent use.
type Detector struct {
	loaded atomic.Pointer[loadedChecker]
}

// Start returns immediately. The list loads on a background goroutine that stops, and
// releases the library's refresh worker, when ctx is cancelled.
func Start(ctx context.Context, config Config, logger *slog.Logger) *Detector {
	return start(ctx, logger, initialRetryDelay, func() (checker, error) {
		return open(config, logger)
	})
}

func start(
	ctx context.Context,
	logger *slog.Logger,
	retryDelay time.Duration,
	open func() (checker, error),
) *Detector {
	detector := &Detector{}
	go detector.run(ctx, logger, retryDelay, open)
	return detector
}

// IsDisposable answers false until the list has loaded: an unavailable filter must not
// turn into a registration outage.
func (detector *Detector) IsDisposable(email string) bool {
	loaded := detector.loaded.Load()
	return loaded != nil && loaded.IsDisposable(email)
}

func (detector *Detector) run(
	ctx context.Context,
	logger *slog.Logger,
	retryDelay time.Duration,
	open func() (checker, error),
) {
	for {
		instance, err := open()
		if err == nil {
			detector.loaded.Store(&loadedChecker{instance})
			<-ctx.Done()
			detector.loaded.Store(nil)
			_ = instance.Close()
			return
		}
		logger.Warn(
			"disposable email list unavailable; registration is not filtered until it loads",
			"error", err,
			"retry_in", retryDelay.String(),
		)
		timer := time.NewTimer(retryDelay)
		select {
		case <-ctx.Done():
			timer.Stop()
			return
		case <-timer.C:
		}
		retryDelay = min(retryDelay*2, maximumRetryDelay)
	}
}

func open(config Config, logger *slog.Logger) (checker, error) {
	options := []disposable.Option{
		disposable.WithHTTPTimeout(downloadTimeout),
		disposable.WithAutoRefresh(refreshInterval),
		disposable.WithCustomAllowlist(config.AllowDomains...),
		disposable.WithLogger(slogPrinter{logger}),
	}
	if config.CacheDir != "" {
		options = append(options, disposable.WithCacheDir(config.CacheDir))
	}
	if config.DataURL != "" {
		options = append(options, disposable.WithDataURL(config.DataURL))
	}
	instance, err := disposable.New(options...)
	if err != nil {
		return nil, err
	}
	logger.Info("disposable email list loaded", "domains", instance.Stats().BlocklistCount)
	return instance, nil
}

// slogPrinter routes the library's diagnostics, which name only its cache path, its
// download URL, and list sizes, into the server's structured log.
type slogPrinter struct{ logger *slog.Logger }

func (printer slogPrinter) Printf(format string, values ...any) {
	printer.logger.Info(fmt.Sprintf(format, values...), "component", "disposable-email")
}
