package main

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Avicted/dialtone/internal/channel"
	"github.com/Avicted/dialtone/internal/config"
	"github.com/Avicted/dialtone/internal/device"
	"github.com/Avicted/dialtone/internal/message"
	"github.com/Avicted/dialtone/internal/serverinvite"
	"github.com/Avicted/dialtone/internal/storage"
	"github.com/Avicted/dialtone/internal/user"
)

// ---------------------------------------------------------------------------
// Stub repositories – satisfy interfaces, never called during wiring.
// ---------------------------------------------------------------------------

type stubUserRepo struct{}

func (stubUserRepo) Create(context.Context, user.User) error             { return nil }
func (stubUserRepo) GetByID(context.Context, user.ID) (user.User, error) { return user.User{}, nil }
func (stubUserRepo) GetByUsernameHash(context.Context, string) (user.User, error) {
	return user.User{}, nil
}
func (stubUserRepo) Count(context.Context) (int, error)                   { return 0, nil }
func (stubUserRepo) UpsertProfile(context.Context, user.Profile) error    { return nil }
func (stubUserRepo) ListProfiles(context.Context) ([]user.Profile, error) { return nil, nil }
func (stubUserRepo) UpsertDirectoryKeyEnvelope(context.Context, user.DirectoryKeyEnvelope) error {
	return nil
}
func (stubUserRepo) GetDirectoryKeyEnvelope(context.Context, string) (user.DirectoryKeyEnvelope, error) {
	return user.DirectoryKeyEnvelope{}, nil
}

type stubDeviceRepo struct{}

func (stubDeviceRepo) Create(context.Context, device.Device) error { return nil }
func (stubDeviceRepo) GetByID(context.Context, device.ID) (device.Device, error) {
	return device.Device{}, nil
}
func (stubDeviceRepo) GetByUserAndPublicKey(context.Context, user.ID, string) (device.Device, error) {
	return device.Device{}, nil
}
func (stubDeviceRepo) ListByUser(context.Context, user.ID) ([]device.Device, error) { return nil, nil }
func (stubDeviceRepo) ListAll(context.Context) ([]device.Device, error)             { return nil, nil }
func (stubDeviceRepo) UpdateLastSeen(context.Context, device.ID, time.Time) error   { return nil }

type stubChannelRepo struct{}

func (stubChannelRepo) CreateChannel(context.Context, channel.Channel) error { return nil }
func (stubChannelRepo) GetChannel(context.Context, channel.ID) (channel.Channel, error) {
	return channel.Channel{}, nil
}
func (stubChannelRepo) ListChannels(context.Context) ([]channel.Channel, error)     { return nil, nil }
func (stubChannelRepo) UpdateChannelName(context.Context, channel.ID, string) error { return nil }
func (stubChannelRepo) DeleteChannel(context.Context, channel.ID) error             { return nil }
func (stubChannelRepo) SaveMessage(context.Context, channel.Message) error          { return nil }
func (stubChannelRepo) ListRecentMessages(context.Context, channel.ID, int) ([]channel.Message, error) {
	return nil, nil
}
func (stubChannelRepo) UpsertKeyEnvelope(context.Context, channel.KeyEnvelope) error { return nil }
func (stubChannelRepo) GetKeyEnvelope(context.Context, channel.ID, device.ID) (channel.KeyEnvelope, error) {
	return channel.KeyEnvelope{}, nil
}

type stubBroadcastRepo struct{}

func (stubBroadcastRepo) Save(context.Context, message.BroadcastMessage) error { return nil }
func (stubBroadcastRepo) ListRecent(context.Context, int) ([]message.BroadcastMessage, error) {
	return nil, nil
}

type stubInviteRepo struct{}

func (stubInviteRepo) Create(context.Context, serverinvite.Invite) error { return nil }
func (stubInviteRepo) Consume(context.Context, string, user.ID, time.Time) (serverinvite.Invite, error) {
	return serverinvite.Invite{}, nil
}

// ---------------------------------------------------------------------------
// stubStore wraps the stubs into a storage.Store.
// ---------------------------------------------------------------------------

type stubStore struct {
	migrateErr error
	closeErr   error
	closed     bool
}

func newStubStore() *stubStore                               { return &stubStore{} }
func (s *stubStore) Close(context.Context) error             { s.closed = true; return s.closeErr }
func (s *stubStore) Migrate(context.Context) error           { return s.migrateErr }
func (s *stubStore) Users() user.Repository                  { return stubUserRepo{} }
func (s *stubStore) Devices() device.Repository              { return stubDeviceRepo{} }
func (s *stubStore) Broadcasts() message.BroadcastRepository { return stubBroadcastRepo{} }
func (s *stubStore) Channels() channel.Repository            { return stubChannelRepo{} }
func (s *stubStore) ServerInvites() serverinvite.Repository  { return stubInviteRepo{} }

// Compile-time check.
var _ storage.Store = (*stubStore)(nil)

// ---------------------------------------------------------------------------
// Helper: pick a free port and return a listen address.
// ---------------------------------------------------------------------------

func freeAddr(t *testing.T) string {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen for free port: %v", err)
	}
	addr := l.Addr().String()
	l.Close()
	return addr
}

// validCfg returns a config that passes validation using a free port.
func validCfg(t *testing.T) config.Config {
	t.Helper()
	return config.Config{
		ListenAddr:     freeAddr(t),
		DBURL:          "postgres://stub",
		UsernamePepper: "pepper",
		AdminToken:     "admin-token",
	}
}

// ---------------------------------------------------------------------------
// healthHandler tests
// ---------------------------------------------------------------------------

func TestHealthHandler_ReturnsOK(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/health", nil)
	rec := httptest.NewRecorder()

	healthHandler(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusOK)
	}
	if body := rec.Body.String(); body != "ok" {
		t.Fatalf("body = %q, want %q", body, "ok")
	}
}

func TestHealthHandler_AllMethods(t *testing.T) {
	for _, m := range []string{
		http.MethodGet, http.MethodPost, http.MethodPut,
		http.MethodDelete, http.MethodHead, http.MethodPatch,
	} {
		t.Run(m, func(t *testing.T) {
			req := httptest.NewRequest(m, "/health", nil)
			rec := httptest.NewRecorder()
			healthHandler(rec, req)
			if rec.Code != http.StatusOK {
				t.Fatalf("status = %d, want %d", rec.Code, http.StatusOK)
			}
		})
	}
}

func TestHealthHandler_BodyLength(t *testing.T) {
	rec := httptest.NewRecorder()
	healthHandler(rec, httptest.NewRequest(http.MethodGet, "/health", nil))
	if n := rec.Body.Len(); n != 2 {
		t.Fatalf("body length = %d, want 2", n)
	}
}

// ---------------------------------------------------------------------------
// run() tests (config / store init failures)
// ---------------------------------------------------------------------------

func TestRun_FailsWithoutConfig(t *testing.T) {
	t.Setenv("DIALTONE_LISTEN_ADDR", "")
	t.Setenv("DIALTONE_DB_URL", "")
	t.Setenv("DIALTONE_USERNAME_PEPPER", "")
	t.Setenv("DIALTONE_ADMIN_TOKEN", "")
	t.Setenv("DIALTONE_TLS_CERT", "")
	t.Setenv("DIALTONE_TLS_KEY", "")

	err := run()
	if err == nil {
		t.Fatal("expected error for missing config")
	}
	if !strings.Contains(err.Error(), "config invalid") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestRun_FailsWithPartialTLS(t *testing.T) {
	t.Setenv("DIALTONE_LISTEN_ADDR", ":0")
	t.Setenv("DIALTONE_DB_URL", "postgres://localhost/test")
	t.Setenv("DIALTONE_USERNAME_PEPPER", "pepper")
	t.Setenv("DIALTONE_ADMIN_TOKEN", "admin-token")
	t.Setenv("DIALTONE_TLS_CERT", "/tmp/cert.pem")
	t.Setenv("DIALTONE_TLS_KEY", "")

	err := run()
	if err == nil {
		t.Fatal("expected error for partial TLS")
	}
}

func TestRun_FailsWithBadDBURL(t *testing.T) {
	t.Setenv("DIALTONE_LISTEN_ADDR", ":0")
	t.Setenv("DIALTONE_DB_URL", "not-a-real-url")
	t.Setenv("DIALTONE_USERNAME_PEPPER", "pepper")
	t.Setenv("DIALTONE_ADMIN_TOKEN", "admin-token")
	t.Setenv("DIALTONE_TLS_CERT", "")
	t.Setenv("DIALTONE_TLS_KEY", "")

	err := run()
	if err == nil {
		t.Fatal("expected error for bad DB URL")
	}
	if !strings.Contains(err.Error(), "init store") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestServerMainExitsOnRunError(t *testing.T) {
	if os.Getenv("DIALTONE_TEST_SERVER_MAIN_HELPER") == "1" {
		_ = os.Unsetenv("DIALTONE_LISTEN_ADDR")
		_ = os.Unsetenv("DIALTONE_DB_URL")
		_ = os.Unsetenv("DIALTONE_USERNAME_PEPPER")
		_ = os.Unsetenv("DIALTONE_ADMIN_TOKEN")
		_ = os.Unsetenv("DIALTONE_TLS_CERT")
		_ = os.Unsetenv("DIALTONE_TLS_KEY")
		main()
		os.Exit(0)
	}

	cmd := exec.Command(os.Args[0], "-test.run=TestServerMainExitsOnRunError")
	cmd.Env = append(os.Environ(), "DIALTONE_TEST_SERVER_MAIN_HELPER=1")
	var stderr bytes.Buffer
	cmd.Stderr = &stderr

	err := cmd.Run()
	var exitErr *exec.ExitError
	if !errors.As(err, &exitErr) {
		t.Fatalf("expected subprocess exit error, got %v", err)
	}
	if exitErr.ExitCode() != 1 {
		t.Fatalf("expected exit code 1, got %d", exitErr.ExitCode())
	}
	if !strings.Contains(stderr.String(), "fatal: config invalid") {
		t.Fatalf("expected fatal config error in stderr, got %q", stderr.String())
	}
}

// ---------------------------------------------------------------------------
// serve() tests – exercise everything after config/store init
// ---------------------------------------------------------------------------

func TestServe_MigrationFailure(t *testing.T) {
	store := newStubStore()
	store.migrateErr = errors.New("migration boom")

	cfg := validCfg(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	err := serve(ctx, cfg, store)
	if err == nil {
		t.Fatal("expected migration error")
	}
	if !strings.Contains(err.Error(), "run migrations") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestServe_GracefulShutdown(t *testing.T) {
	store := newStubStore()
	cfg := validCfg(t)
	ctx, cancel := context.WithCancel(context.Background())

	errCh := make(chan error, 1)
	go func() { errCh <- serve(ctx, cfg, store) }()

	// Wait until the server is accepting connections.
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		conn, err := net.DialTimeout("tcp", cfg.ListenAddr, 100*time.Millisecond)
		if err == nil {
			conn.Close()
			break
		}
		time.Sleep(20 * time.Millisecond)
	}

	cancel() // trigger graceful shutdown

	select {
	case err := <-errCh:
		if err != nil {
			t.Fatalf("serve returned error: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("serve did not return within timeout")
	}

	if !store.closed {
		t.Fatal("store was not closed")
	}
}

func TestServe_HealthEndpointAccessible(t *testing.T) {
	store := newStubStore()
	cfg := validCfg(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	errCh := make(chan error, 1)
	go func() { errCh <- serve(ctx, cfg, store) }()

	// Wait for server to be ready.
	var lastErr error
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		conn, err := net.DialTimeout("tcp", cfg.ListenAddr, 100*time.Millisecond)
		if err == nil {
			conn.Close()
			lastErr = nil
			break
		}
		lastErr = err
		time.Sleep(20 * time.Millisecond)
	}
	if lastErr != nil {
		t.Fatalf("server not ready: %v", lastErr)
	}

	resp, err := http.Get(fmt.Sprintf("http://%s/health", cfg.ListenAddr))
	if err != nil {
		t.Fatalf("GET /health: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET /health status = %d, want %d", resp.StatusCode, http.StatusOK)
	}

	cancel()
	<-errCh
}

func TestServe_RegisteredRoutesReturn4xx(t *testing.T) {
	store := newStubStore()
	cfg := validCfg(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	errCh := make(chan error, 1)
	go func() { errCh <- serve(ctx, cfg, store) }()

	waitForServer(t, cfg.ListenAddr)

	// All API routes should be registered. Without auth they should return
	// 4xx (typically 401 or 405), not 404 which would mean unregistered.
	paths := []string{
		"/users",
		"/devices",
		"/auth/register",
		"/auth/login",
		"/channels",
		"/presence",
		"/server/invites",
	}
	base := fmt.Sprintf("http://%s", cfg.ListenAddr)
	for _, p := range paths {
		t.Run(p, func(t *testing.T) {
			resp, err := http.Get(base + p)
			if err != nil {
				t.Fatalf("GET %s: %v", p, err)
			}
			resp.Body.Close()
			// We don't know the exact code (depends on method/auth),
			// just ensure the route is registered (not 404).
			if resp.StatusCode == http.StatusNotFound {
				t.Fatalf("GET %s returned 404 — route not registered", p)
			}
		})
	}

	cancel()
	<-errCh
}

func TestServe_StoreClosedAfterMigrationFailure(t *testing.T) {
	store := newStubStore()
	store.migrateErr = errors.New("boom")

	cfg := validCfg(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	_ = serve(ctx, cfg, store)

	if !store.closed {
		t.Fatal("store should be closed even when migration fails")
	}
}

func TestServe_TLSWithBadCertsFailsFast(t *testing.T) {
	store := newStubStore()
	cfg := validCfg(t)
	cfg.TLSCertPath = "/nonexistent/cert.pem"
	cfg.TLSKeyPath = "/nonexistent/key.pem"

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	errCh := make(chan error, 1)
	go func() { errCh <- serve(ctx, cfg, store) }()

	select {
	case err := <-errCh:
		if err == nil {
			t.Fatal("expected TLS error for bad cert paths")
		}
		if !strings.Contains(err.Error(), "server failed") {
			t.Fatalf("unexpected error: %v", err)
		}
	case <-time.After(5 * time.Second):
		cancel()
		t.Fatal("serve did not return within timeout for bad TLS certs")
	}
}

func TestServe_TLSWithValidCerts(t *testing.T) {
	certPath, keyPath := generateSelfSignedCert(t)

	store := newStubStore()
	cfg := validCfg(t)
	cfg.TLSCertPath = certPath
	cfg.TLSKeyPath = keyPath

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	errCh := make(chan error, 1)
	go func() { errCh <- serve(ctx, cfg, store) }()

	waitForTLSServer(t, cfg.ListenAddr)

	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
	}
	resp, err := client.Get(fmt.Sprintf("https://%s/health", cfg.ListenAddr))
	if err != nil {
		t.Fatalf("GET /health over TLS: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want %d", resp.StatusCode, http.StatusOK)
	}

	cancel()
	<-errCh
}

func TestServe_ConcurrentRequests(t *testing.T) {
	store := newStubStore()
	cfg := validCfg(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	errCh := make(chan error, 1)
	go func() { errCh <- serve(ctx, cfg, store) }()

	waitForServer(t, cfg.ListenAddr)

	const n = 20
	results := make(chan int, n)
	for i := 0; i < n; i++ {
		go func() {
			resp, err := http.Get(fmt.Sprintf("http://%s/health", cfg.ListenAddr))
			if err != nil {
				results <- 0
				return
			}
			resp.Body.Close()
			results <- resp.StatusCode
		}()
	}

	for i := 0; i < n; i++ {
		code := <-results
		if code != http.StatusOK {
			t.Errorf("request %d: status = %d, want %d", i, code, http.StatusOK)
		}
	}

	cancel()
	<-errCh
}

func TestServe_PortAlreadyInUse(t *testing.T) {
	// Grab a port and hold it.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()

	store := newStubStore()
	cfg := validCfg(t)
	cfg.ListenAddr = ln.Addr().String() // already occupied

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	serveErr := make(chan error, 1)
	go func() { serveErr <- serve(ctx, cfg, store) }()

	select {
	case err := <-serveErr:
		if err == nil {
			t.Fatal("expected error for port already in use")
		}
		if !strings.Contains(err.Error(), "server failed") {
			t.Fatalf("unexpected error: %v", err)
		}
	case <-time.After(5 * time.Second):
		cancel()
		t.Fatal("serve did not return for port conflict")
	}
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

func waitForServer(t *testing.T, addr string) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		conn, err := net.DialTimeout("tcp", addr, 100*time.Millisecond)
		if err == nil {
			conn.Close()
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("server at %s not ready in time", addr)
}

func waitForTLSServer(t *testing.T, addr string) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		conn, err := tls.DialWithDialer(
			&net.Dialer{Timeout: 100 * time.Millisecond},
			"tcp", addr,
			&tls.Config{InsecureSkipVerify: true},
		)
		if err == nil {
			conn.Close()
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("TLS server at %s not ready in time", addr)
}

func generateSelfSignedCert(t *testing.T) (certPath, keyPath string) {
	t.Helper()
	dir := t.TempDir()
	certPath = filepath.Join(dir, "cert.pem")
	keyPath = filepath.Join(dir, "key.pem")

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}

	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "localhost"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		IPAddresses:  []net.IP{net.IPv4(127, 0, 0, 1)},
		DNSNames:     []string{"localhost"},
	}

	certDER, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create cert: %v", err)
	}

	certOut, err := os.Create(certPath)
	if err != nil {
		t.Fatalf("create cert file: %v", err)
	}
	if err := pem.Encode(certOut, &pem.Block{Type: "CERTIFICATE", Bytes: certDER}); err != nil {
		t.Fatalf("encode cert: %v", err)
	}
	certOut.Close()

	keyBytes, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatalf("marshal key: %v", err)
	}
	keyOut, err := os.Create(keyPath)
	if err != nil {
		t.Fatalf("create key file: %v", err)
	}
	if err := pem.Encode(keyOut, &pem.Block{Type: "EC PRIVATE KEY", Bytes: keyBytes}); err != nil {
		t.Fatalf("encode key: %v", err)
	}
	keyOut.Close()

	return certPath, keyPath
}
