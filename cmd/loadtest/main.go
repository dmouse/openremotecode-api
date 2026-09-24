// Command loadtest drives a running server with simulated connector/phone pairs through the
// real admission path and the authenticated relay, and reports connect success, round-trip
// latency, throughput, disconnects, server CPU and memory, and PostgreSQL transaction rate.
//
// It seeds accounts, sessions, devices, connectors and trust directly into the database with
// credentials it generates, so it must only ever point at a disposable database: it refuses a
// non-loopback database host. The server must trust 127.0.0.1 as a proxy
// (TRUSTED_PROXY_CIDRS=127.0.0.1/32) so each pair is rate limited as its own client.
//
// Envelopes carry random ciphertext. The relay never decrypts, so this is its real work; the
// peers' HPKE cost is deliberately not part of the measurement.
package main

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	connectorspostgres "opencode-remote/server/internal/connectors/postgres"
	identitypostgres "opencode-remote/server/internal/identity/postgres"
	"opencode-remote/server/internal/platform/database"

	"github.com/gorilla/websocket"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

const (
	suite           = "HPKE-Auth-P256-HKDF-SHA256-AES-256-GCM"
	relayProtocol   = "opencode-remote.v1"
	protocolVersion = 2
	deviceCookie    = "opencode_remote_device" // development cookie name
)

type config struct {
	api         string
	databaseURL string
	pairs       int
	rate        float64
	size        int
	duration    time.Duration
	ramp        time.Duration
	serverPID   int
	label       string
}

func main() {
	var cfg config
	flag.StringVar(&cfg.api, "api", "http://127.0.0.1:18080", "server base URL")
	flag.StringVar(&cfg.databaseURL, "database-url", "", "disposable PostgreSQL the server uses (seeded directly)")
	flag.IntVar(&cfg.pairs, "pairs", 100, "connector/phone pairs, each its own account")
	flag.Float64Var(&cfg.rate, "rate", 1, "envelopes per second each phone sends (echoed back by its connector)")
	flag.IntVar(&cfg.size, "size", 1024, "ciphertext bytes per envelope")
	flag.DurationVar(&cfg.duration, "duration", time.Minute, "steady-state measurement time (keep under the 5-minute lease)")
	flag.DurationVar(&cfg.ramp, "ramp", 20*time.Second, "time over which pairs connect")
	flag.IntVar(&cfg.serverPID, "server-pid", 0, "server process to sample CPU and memory from (optional)")
	flag.StringVar(&cfg.label, "label", "", "name for this run in the output")
	flag.Parse()
	if err := run(cfg); err != nil {
		log.Fatal(err)
	}
}

func run(cfg config) error {
	if cfg.duration >= 4*time.Minute+30*time.Second {
		return errors.New("duration must stay under the 5-minute relay authorization lease")
	}
	if err := requireLoopbackDatabase(cfg.databaseURL); err != nil {
		return err
	}
	db, pool, err := database.Open(cfg.databaseURL)
	if err != nil {
		return err
	}
	defer pool.Close()

	run := strconv.FormatInt(time.Now().UnixNano()%1_000_000, 36)
	log.Printf("seeding %d pairs (run %s)", cfg.pairs, run)
	pairs, err := seed(db, run, cfg.pairs)
	if err != nil {
		return fmt.Errorf("seed: %w", err)
	}

	ciphertext := base64.RawURLEncoding.EncodeToString(randomBytes(cfg.size))
	encapsulated := base64.RawURLEncoding.EncodeToString(randomBytes(65))
	stats := newStats()
	stop := make(chan struct{})
	var steady atomic.Bool

	log.Printf("connecting %d pairs over %s", cfg.pairs, cfg.ramp)
	// settled counts pairs that are ready or have failed; running tracks the goroutines, which
	// keep sending until stop is closed.
	var settled, running sync.WaitGroup
	interval := cfg.ramp / time.Duration(max(1, cfg.pairs))
	connectStart := time.Now()
	for index := range pairs {
		settled.Add(1)
		running.Add(1)
		go func(p *pair) {
			defer running.Done()
			p.run(cfg, stats, ciphertext, encapsulated, stop, &steady, settled.Done)
		}(pairs[index])
		time.Sleep(interval)
	}
	settled.Wait()
	connectTime := time.Since(connectStart)
	ready := 0
	for _, p := range pairs {
		if p.ready.Load() {
			ready++
		}
	}
	log.Printf("%d/%d pairs ready after %s; measuring for %s", ready, cfg.pairs, connectTime.Round(time.Millisecond), cfg.duration)

	startTx, _ := transactions(db)
	sampler := startSampler(cfg.serverPID)
	stats.resetWindow()
	steady.Store(true)
	windowStart := time.Now()
	time.Sleep(cfg.duration)
	steady.Store(false)
	window := time.Since(windowStart)
	endTx, _ := transactions(db)
	serverUsage := sampler.stop()
	close(stop)
	running.Wait()

	report(cfg, stats, ready, window, float64(endTx-startTx)/window.Seconds(), serverUsage)
	return nil
}

// ---- seeding -----------------------------------------------------------------------------

type identity struct {
	Version   int    `json:"version"`
	Suite     string `json:"suite"`
	KeyID     string `json:"keyId"`
	PublicKey string `json:"publicKey"`
}

type pair struct {
	index               int
	fakeIP              string
	deviceID            string
	accessToken         string
	deviceCredential    string
	connectorCredential string
	device, connector   identity
	ready               atomic.Bool
}

func seed(db *gorm.DB, run string, count int) ([]*pair, error) {
	now := time.Now().UTC()
	expires := now.Add(24 * time.Hour)
	passwordHash := "loadtest-no-password"
	var (
		users      []identitypostgres.UserModel
		sessions   []identitypostgres.SessionModel
		devices    []connectorspostgres.DeviceModel
		connectors []connectorspostgres.ConnectorModel
		trusts     []connectorspostgres.TrustModel
		pairs      []*pair
	)
	for index := range count {
		suffix := fmt.Sprintf("%s_%06d", run, index)
		userID, sessionID := "usr_loadtest_"+suffix, "asn_loadtest_"+suffix
		deviceID, connectorID := "dev_loadtest_"+suffix, "con_loadtest_"+suffix
		p := &pair{
			index: index, fakeIP: fmt.Sprintf("198.18.%d.%d", index/250, index%250+1), deviceID: deviceID,
			accessToken: token("ora_"), deviceCredential: token("ord_"), connectorCredential: token("orc_"),
			device: newIdentity(), connector: newIdentity(),
		}
		pairs = append(pairs, p)
		verified := now
		users = append(users, identitypostgres.UserModel{ID: userID, Email: suffix + "@loadtest.invalid",
			NormalizedEmail: suffix + "@loadtest.invalid", PasswordHash: &passwordHash, Status: "active",
			EmailVerifiedAt: &verified, CreatedAt: now})
		sessions = append(sessions, identitypostgres.SessionModel{ID: sessionID, UserID: userID,
			AccessTokenHash: hash(p.accessToken), AccessTokenExpiresAt: now.Add(2 * time.Hour),
			RefreshExpiresAt: expires, ClientName: "loadtest", CreatedAt: now, LastRefreshedAt: now})
		devices = append(devices, connectorspostgres.DeviceModel{ID: deviceID, UserID: userID, Name: "Load phone",
			IdentityVersion: 1, IdentitySuite: suite, KeyID: p.device.KeyID, PublicKey: p.device.PublicKey,
			CredentialHash: hash(p.deviceCredential), CredentialExpiresAt: &expires, CreatedAt: now, ActivatedAt: &verified})
		connectors = append(connectors, connectorspostgres.ConnectorModel{ID: connectorID, UserID: userID, Name: "Load connector",
			IdentityVersion: 1, IdentitySuite: suite, KeyID: p.connector.KeyID, PublicKey: p.connector.PublicKey,
			CredentialHash: hash(p.connectorCredential), CredentialExpiresAt: &expires, CreatedAt: now})
		trusts = append(trusts, connectorspostgres.TrustModel{UserID: userID, DeviceID: deviceID, ConnectorID: connectorID, CreatedAt: now})
	}
	return pairs, db.Transaction(func(tx *gorm.DB) error {
		for _, batch := range []any{&users, &sessions, &devices, &connectors, &trusts} {
			if err := tx.Omit(clause.Associations).CreateInBatches(batch, 500).Error; err != nil {
				return err
			}
		}
		return nil
	})
}

func newIdentity() identity {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		panic(err)
	}
	public := elliptic.Marshal(elliptic.P256(), key.X, key.Y) //nolint:staticcheck // uncompressed point is the wire format
	digest := sha256.Sum256(public)
	return identity{Version: 1, Suite: suite, KeyID: base64.RawURLEncoding.EncodeToString(digest[:]),
		PublicKey: base64.RawURLEncoding.EncodeToString(public)}
}

func token(prefix string) string {
	return prefix + base64.RawURLEncoding.EncodeToString(randomBytes(32))
}
func hash(value string) []byte { digest := sha256.Sum256([]byte(value)); return digest[:] }
func randomBytes(size int) []byte {
	value := make([]byte, size)
	if _, err := rand.Read(value); err != nil {
		panic(err)
	}
	return value
}

func requireLoopbackDatabase(databaseURL string) error {
	parsed, err := url.Parse(databaseURL)
	if err != nil || parsed.Hostname() == "" {
		return errors.New("-database-url must be a postgres:// URL")
	}
	if ip := net.ParseIP(parsed.Hostname()); parsed.Hostname() != "localhost" && (ip == nil || !ip.IsLoopback()) {
		return errors.New("refusing to seed a non-loopback database: point -database-url at a disposable local instance")
	}
	return nil
}

// ---- one pair ----------------------------------------------------------------------------

type envelope struct {
	ProtocolVersion int    `json:"protocolVersion"`
	Type            string `json:"type"`
	MessageID       string `json:"messageId"`
	SenderKeyID     string `json:"senderKeyId"`
	RecipientKeyID  string `json:"recipientKeyId"`
	Epoch           string `json:"epoch"`
	Sequence        uint64 `json:"sequence"`
	ExpiresAt       int64  `json:"expiresAt"`
	Suite           string `json:"suite"`
	EncapsulatedKey string `json:"encapsulatedKey"`
	Ciphertext      string `json:"ciphertext"`
}

func (p *pair) run(cfg config, stats *stats, ciphertext, encapsulated string, stop <-chan struct{}, steady *atomic.Bool, settle func()) {
	var settleOnce sync.Once
	settled := func() { settleOnce.Do(settle) }
	defer settled()
	started := time.Now()
	connector, err := p.connect(cfg.api, "connector", map[string]any{
		"protocolVersion": protocolVersion, "type": "connector.hello", "pluginVersion": "loadtest",
		"identity": p.connector, "nonce": nonce(), "capabilities": []string{"session.list"},
	})
	if err != nil {
		stats.connectFailure(err)
		return
	}
	defer connector.Close()
	phone, err := p.connect(cfg.api, "client", map[string]any{
		"protocolVersion": protocolVersion, "type": "client.hello", "identity": p.device, "nonce": nonce(),
	})
	if err != nil {
		stats.connectFailure(err)
		return
	}
	defer phone.Close()

	// The phone may send only once the relay has told it the connector is present.
	peerSeen := make(chan struct{})
	var pending sync.Map // messageId -> send time
	epoch := base64.RawURLEncoding.EncodeToString(randomBytes(32))
	done := make(chan struct{})
	var closeOnce sync.Once
	finish := func() { closeOnce.Do(func() { close(done) }) }

	go func() { // connector: echo every envelope back to the phone
		defer finish()
		var sequence uint64
		for {
			_, message, err := connector.ReadMessage()
			if err != nil {
				stats.disconnect("connector", err, steady.Load())
				return
			}
			var incoming envelope
			if json.Unmarshal(message, &incoming) != nil || incoming.Type != "relay.envelope" {
				continue
			}
			sequence++
			incoming.SenderKeyID, incoming.RecipientKeyID, incoming.Sequence = p.connector.KeyID, p.device.KeyID, sequence
			incoming.ExpiresAt = time.Now().Add(time.Minute).UnixMilli()
			if err := connector.WriteJSON(incoming); err != nil {
				stats.disconnect("connector", err, steady.Load())
				return
			}
		}
	}()
	go func() { // phone: record round trips
		defer finish()
		seen := false
		for {
			_, message, err := phone.ReadMessage()
			if err != nil {
				stats.disconnect("phone", err, steady.Load())
				return
			}
			var incoming struct {
				Type      string `json:"type"`
				MessageID string `json:"messageId"`
			}
			if json.Unmarshal(message, &incoming) != nil {
				continue
			}
			switch incoming.Type {
			case "connector.hello":
				if !seen {
					seen = true
					close(peerSeen)
				}
			case "relay.envelope":
				if sent, ok := pending.LoadAndDelete(incoming.MessageID); ok {
					stats.roundTrip(time.Since(sent.(time.Time)), steady.Load())
				}
			}
		}
	}()

	select {
	case <-peerSeen:
	case <-done:
		stats.connectFailure(errors.New("relay closed before the peer appeared"))
		return
	case <-time.After(15 * time.Second):
		stats.connectFailure(errors.New("peer hello not received"))
		return
	}
	p.ready.Store(true)
	stats.connected(time.Since(started))
	settled()

	ticker := time.NewTicker(time.Duration(float64(time.Second) / cfg.rate))
	defer ticker.Stop()
	var sequence uint64
	for {
		select {
		case <-stop:
			return
		case <-done:
			return
		case <-ticker.C:
			sequence++
			id := uuid()
			pending.Store(id, time.Now())
			err := phone.WriteJSON(envelope{ProtocolVersion: protocolVersion, Type: "relay.envelope", MessageID: id,
				SenderKeyID: p.device.KeyID, RecipientKeyID: p.connector.KeyID, Epoch: epoch, Sequence: sequence,
				ExpiresAt: time.Now().Add(time.Minute).UnixMilli(), Suite: suite, EncapsulatedKey: encapsulated, Ciphertext: ciphertext})
			if err != nil {
				return
			}
			stats.sent(steady.Load())
		}
	}
}

// connect obtains a single-use ticket over the HTTP API and opens an authenticated relay
// socket with it, then sends the role's hello and waits for relay.ready.
func (p *pair) connect(api, role string, hello map[string]any) (*websocket.Conn, error) {
	body, credential := []byte(`{}`), p.connectorCredential
	if role == "client" {
		body, credential = []byte(`{"deviceId":"`+p.deviceID+`"}`), p.accessToken
	}
	request, _ := http.NewRequest(http.MethodPost, api+"/v1/relay/tickets", bytes.NewReader(body))
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Authorization", "Bearer "+credential)
	request.Header.Set("X-Forwarded-For", p.fakeIP)
	if role == "client" {
		request.AddCookie(&http.Cookie{Name: deviceCookie, Value: p.deviceCredential})
	}
	response, err := httpClient.Do(request)
	if err != nil {
		return nil, fmt.Errorf("%s ticket: %w", role, err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusCreated {
		detail, _ := io.ReadAll(io.LimitReader(response.Body, 200))
		return nil, fmt.Errorf("%s ticket: HTTP %d %s", role, response.StatusCode, strings.TrimSpace(string(detail)))
	}
	var ticket struct {
		Ticket string `json:"ticket"`
	}
	if err := json.NewDecoder(response.Body).Decode(&ticket); err != nil {
		return nil, fmt.Errorf("%s ticket: %w", role, err)
	}
	dialer := websocket.Dialer{HandshakeTimeout: 10 * time.Second,
		Subprotocols: []string{relayProtocol, "ticket." + ticket.Ticket}}
	socket, _, err := dialer.Dial("ws"+strings.TrimPrefix(api, "http")+"/v1/relay", nil)
	if err != nil {
		return nil, fmt.Errorf("%s dial: %w", role, err)
	}
	if err := socket.WriteJSON(hello); err != nil {
		socket.Close()
		return nil, fmt.Errorf("%s hello: %w", role, err)
	}
	_ = socket.SetReadDeadline(time.Now().Add(10 * time.Second))
	var ready struct {
		Type string `json:"type"`
	}
	if err := socket.ReadJSON(&ready); err != nil || ready.Type != "relay.ready" {
		socket.Close()
		return nil, fmt.Errorf("%s ready: %v (%q)", role, err, ready.Type)
	}
	_ = socket.SetReadDeadline(time.Time{})
	return socket, nil
}

var httpClient = &http.Client{Timeout: 15 * time.Second, Transport: &http.Transport{MaxIdleConnsPerHost: 256}}

func nonce() string { return base64.RawURLEncoding.EncodeToString(randomBytes(16)) }

func uuid() string {
	value := randomBytes(16)
	value[6] = value[6]&0x0f | 0x40
	value[8] = value[8]&0x3f | 0x80
	return fmt.Sprintf("%x-%x-%x-%x-%x", value[0:4], value[4:6], value[6:8], value[8:10], value[10:16])
}

// ---- measurement -------------------------------------------------------------------------

type stats struct {
	mutex           sync.Mutex
	connectLatency  []time.Duration
	connectErrors   map[string]int
	roundTrips      []time.Duration
	sentInWindow    int
	disconnects     map[string]int
	disconnectCount int
}

func newStats() *stats {
	return &stats{connectErrors: map[string]int{}, disconnects: map[string]int{}}
}

func (s *stats) connected(latency time.Duration) {
	s.mutex.Lock()
	s.connectLatency = append(s.connectLatency, latency)
	s.mutex.Unlock()
}

func (s *stats) connectFailure(err error) {
	s.mutex.Lock()
	s.connectErrors[truncate(err.Error(), 90)]++
	s.mutex.Unlock()
}

func (s *stats) roundTrip(latency time.Duration, inWindow bool) {
	if !inWindow {
		return
	}
	s.mutex.Lock()
	s.roundTrips = append(s.roundTrips, latency)
	s.mutex.Unlock()
}

func (s *stats) sent(inWindow bool) {
	if !inWindow {
		return
	}
	s.mutex.Lock()
	s.sentInWindow++
	s.mutex.Unlock()
}

// disconnect counts sockets the server closed during the measurement window. Closures after
// the window are the harness shutting down and are not counted.
func (s *stats) disconnect(side string, err error, inWindow bool) {
	if !inWindow {
		return
	}
	var reason string
	var closeErr *websocket.CloseError
	switch {
	case errors.As(err, &closeErr):
		reason = fmt.Sprintf("server closed the socket (code %d)", closeErr.Code)
	case errors.Is(err, net.ErrClosed):
		// The harness closed this side because its partner socket dropped first.
		reason = "closed after its partner dropped"
	default:
		reason = "read error"
	}
	s.mutex.Lock()
	s.disconnects[side+": "+truncate(reason, 60)]++
	s.disconnectCount++
	s.mutex.Unlock()
}

func (s *stats) resetWindow() {
	s.mutex.Lock()
	s.roundTrips, s.sentInWindow = nil, 0
	s.mutex.Unlock()
}

func truncate(value string, limit int) string {
	if len(value) <= limit {
		return value
	}
	return value[:limit] + "…"
}

type usage struct {
	cpuCores   float64
	maxRSSMiB  float64
	maxThreads int
	sampled    bool
}

type sampler struct {
	pid     int
	stopped chan struct{}
	result  chan usage
}

func startSampler(pid int) *sampler {
	s := &sampler{pid: pid, stopped: make(chan struct{}), result: make(chan usage, 1)}
	go func() {
		if pid == 0 {
			<-s.stopped
			s.result <- usage{}
			return
		}
		ticks := float64(100) // USER_HZ on Linux
		startCPU, _ := processCPU(pid)
		start := time.Now()
		var peak usage
		ticker := time.NewTicker(time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				rss, threads := processMemory(pid)
				peak.maxRSSMiB = max(peak.maxRSSMiB, rss)
				peak.maxThreads = max(peak.maxThreads, threads)
			case <-s.stopped:
				endCPU, _ := processCPU(pid)
				peak.cpuCores = float64(endCPU-startCPU) / ticks / time.Since(start).Seconds()
				peak.sampled = true
				s.result <- peak
				return
			}
		}
	}()
	return s
}

func (s *sampler) stop() usage { close(s.stopped); return <-s.result }

func processCPU(pid int) (int64, error) {
	raw, err := os.ReadFile(fmt.Sprintf("/proc/%d/stat", pid))
	if err != nil {
		return 0, err
	}
	fields := strings.Fields(string(raw[bytes.LastIndexByte(raw, ')')+2:]))
	user, _ := strconv.ParseInt(fields[11], 10, 64)
	system, _ := strconv.ParseInt(fields[12], 10, 64)
	return user + system, nil
}

func processMemory(pid int) (float64, int) {
	raw, err := os.ReadFile(fmt.Sprintf("/proc/%d/status", pid))
	if err != nil {
		return 0, 0
	}
	var rss float64
	var threads int
	for _, line := range strings.Split(string(raw), "\n") {
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		switch fields[0] {
		case "VmRSS:":
			kib, _ := strconv.ParseFloat(fields[1], 64)
			rss = kib / 1024
		case "Threads:":
			threads, _ = strconv.Atoi(fields[1])
		}
	}
	return rss, threads
}

func transactions(db *gorm.DB) (int64, error) {
	var total int64
	err := db.Raw("SELECT xact_commit + xact_rollback FROM pg_stat_database WHERE datname = current_database()").Scan(&total).Error
	return total, err
}

func percentile(sorted []time.Duration, fraction float64) time.Duration {
	if len(sorted) == 0 {
		return 0
	}
	return sorted[min(len(sorted)-1, int(fraction*float64(len(sorted))))]
}

func report(cfg config, s *stats, ready int, window time.Duration, txPerSecond float64, server usage) {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	slices.Sort(s.connectLatency)
	slices.Sort(s.roundTrips)
	lost := s.sentInWindow - len(s.roundTrips)
	fmt.Printf("\n== %s: %d pairs (%d sockets), %.1f msg/s per phone, %d B ciphertext, %s window ==\n",
		cfg.label, cfg.pairs, 2*cfg.pairs, cfg.rate, cfg.size, window.Round(time.Second))
	fmt.Printf("connect:     %d/%d ready  p50 %s  p95 %s  p99 %s  max %s\n", ready, cfg.pairs,
		ms(percentile(s.connectLatency, .5)), ms(percentile(s.connectLatency, .95)),
		ms(percentile(s.connectLatency, .99)), ms(percentile(s.connectLatency, 1)))
	for reason, count := range s.connectErrors {
		fmt.Printf("  connect failure x%d: %s\n", count, reason)
	}
	fmt.Printf("round trip:  %d sent, %d returned (%d in flight or lost)  p50 %s  p95 %s  p99 %s  max %s\n",
		s.sentInWindow, len(s.roundTrips), lost,
		ms(percentile(s.roundTrips, .5)), ms(percentile(s.roundTrips, .95)),
		ms(percentile(s.roundTrips, .99)), ms(percentile(s.roundTrips, 1)))
	fmt.Printf("throughput:  %.0f envelopes/s relayed (each round trip is two)\n", 2*float64(len(s.roundTrips))/window.Seconds())
	fmt.Printf("disconnects: %d during the window\n", s.disconnectCount)
	for reason, count := range s.disconnects {
		fmt.Printf("  x%d %s\n", count, reason)
	}
	fmt.Printf("postgres:    %.0f transactions/s\n", txPerSecond)
	if server.sampled {
		fmt.Printf("server:      %.2f CPU cores, peak RSS %.0f MiB, peak threads %d\n", server.cpuCores, server.maxRSSMiB, server.maxThreads)
	}
	summary, _ := json.Marshal(map[string]any{
		"label": cfg.label, "pairs": cfg.pairs, "rate": cfg.rate, "size": cfg.size, "ready": ready,
		"connectP95ms": ms64(percentile(s.connectLatency, .95)), "rttP50ms": ms64(percentile(s.roundTrips, .5)),
		"rttP99ms": ms64(percentile(s.roundTrips, .99)), "sent": s.sentInWindow, "returned": len(s.roundTrips),
		"disconnects": s.disconnectCount, "pgTxPerSec": int(txPerSecond), "cpuCores": server.cpuCores, "rssMiB": int(server.maxRSSMiB),
	})
	fmt.Printf("summary %s\n", summary)
}

func ms(value time.Duration) string { return fmt.Sprintf("%.1fms", ms64(value)) }
func ms64(value time.Duration) float64 {
	return float64(value.Microseconds()) / 1000
}
