package proxy

import (
	"bufio"
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/kovaron/tessera/internal/audit"
	"github.com/kovaron/tessera/internal/authn"
	"github.com/kovaron/tessera/internal/authz"
	"github.com/kovaron/tessera/internal/crypto"
	"github.com/kovaron/tessera/internal/pki"
	"github.com/kovaron/tessera/internal/secrets"
	"github.com/kovaron/tessera/internal/store"
	"github.com/kovaron/tessera/internal/upstreams"
)

const permitAllPolicy = `package proxy.authz
default allow := true
`

// testHarness is a self-contained in-process Tessera forward proxy stack.
type testHarness struct {
	CA         *pki.CA
	Leaves     *pki.LeafFactory
	Store      store.Store
	DEK        []byte
	DataPlane  *DataPlane
	Forward    *ForwardServer
	Listener   net.Listener
	AuditLog   *audit.Logger
}

func newTestHarness(t *testing.T) *testHarness {
	t.Helper()

	ctx := context.Background()

	s, err := store.OpenSQLite(t.TempDir() + "/fwd.db")
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })

	dek := make([]byte, 32)
	for i := range dek {
		dek[i] = byte(i + 1)
	}

	ca, err := pki.Generate("Tessera Test CA")
	if err != nil {
		t.Fatal(err)
	}
	leaves := pki.NewLeafFactory(ca)

	reg := upstreams.NewRegistry()

	al := audit.New(io.Discard)

	secReg := secrets.NewRegistry()
	secReg.Register(secrets.NewEnvProvider())
	secCache := secrets.NewCache(secReg, time.Second) // short TTL so t.Setenv takes effect

	dp := &DataPlane{
		Store:       s,
		Engine:      authz.NewOPA(),
		PolicyCache: authz.NewCache(),
		Upstreams:   reg,
		Secrets:     secrets.ByteResolver{Cache: secCache},
		Audit:       al,
		IsUnlocked:  func() bool { return true },
		DEK:         func() []byte { return dek },
	}

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })

	fwd := &ForwardServer{
		DataPlane: dp,
		Leaves:    func() *pki.LeafFactory { return leaves },
		Audit:     al,
	}
	go fwd.Serve(ln)

	return &testHarness{
		CA:        ca,
		Leaves:    leaves,
		Store:     s,
		DEK:       dek,
		DataPlane: dp,
		Forward:   fwd,
		Listener:  ln,
		AuditLog:  al,
	}
}

// addUpstream registers an upstream in the harness registry and store.
func (h *testHarness) addUpstream(t *testing.T, id, baseURL string, hostnames []string, injectRef string) {
	t.Helper()
	ctx := context.Background()

	injectJSON := []byte(`{"type":"bearer","secret_ref":"` + injectRef + `"}`)
	if err := h.Store.UpsertUpstream(ctx, store.Upstream{
		ID:         id,
		BaseURL:    baseURL,
		InjectJSON: injectJSON,
		Hostnames:  hostnames,
		CreatedAt:  time.Now().UnixMilli(),
	}); err != nil {
		t.Fatal(err)
	}
	h.DataPlane.Upstreams.Set(upstreams.Upstream{
		ID:        id,
		BaseURL:   baseURL,
		Inject:    upstreams.InjectRule{Type: "bearer", SecretRef: injectRef},
		Hostnames: hostnames,
	})
}

// addPolicy stores a policy encrypted with the harness DEK, returns the policy ID.
func (h *testHarness) addPolicy(t *testing.T, id, src string) {
	t.Helper()
	ctx := context.Background()

	ct, nonce, err := crypto.AEADSeal(h.DEK, []byte(src), []byte("policy"))
	if err != nil {
		t.Fatal(err)
	}
	if err := h.Store.InsertPolicy(ctx, store.PolicyRow{
		ID:          id,
		Name:        id,
		Engine:      "opa",
		SourceCT:    ct,
		SourceNonce: nonce,
		CreatedAt:   time.Now().UnixMilli(),
	}); err != nil {
		t.Fatal(err)
	}
}

// mintToken creates a plaintext token bound to the given upstream and policy.
func (h *testHarness) mintToken(t *testing.T, upstreamID, policyID string) string {
	t.Helper()
	ctx := context.Background()

	plain, hash, err := authn.Generate()
	if err != nil {
		t.Fatal(err)
	}
	if err := h.Store.InsertToken(ctx, store.Token{
		ID:         plain[:8],
		Hash:       hash,
		Label:      "test",
		PolicyID:   policyID,
		UpstreamID: upstreamID,
		CreatedAt:  time.Now().Unix(),
	}); err != nil {
		t.Fatal(err)
	}
	return plain
}

// caRootPool returns an x509 pool containing the harness CA cert.
func (h *testHarness) caRootPool() *x509.CertPool {
	pool := x509.NewCertPool()
	pool.AddCert(h.CA.Cert)
	return pool
}

// dialAndCONNECT dials the forward proxy, sends CONNECT host:443, and returns
// a TLS conn over the established tunnel.
func (h *testHarness) dialAndCONNECT(t *testing.T, target string) *tls.Conn {
	t.Helper()

	proxyAddr := h.Listener.Addr().String()
	raw, err := net.Dial("tcp", proxyAddr)
	if err != nil {
		t.Fatalf("dial proxy: %v", err)
	}
	t.Cleanup(func() { raw.Close() })

	// Send CONNECT.
	connectLine := "CONNECT " + target + ":443 HTTP/1.1\r\nHost: " + target + ":443\r\n\r\n"
	if _, err := raw.Write([]byte(connectLine)); err != nil {
		t.Fatalf("write CONNECT: %v", err)
	}

	// Read response line (with a short deadline for the CONNECT reply only).
	raw.SetReadDeadline(time.Now().Add(5 * time.Second))
	buf := make([]byte, 256)
	n, err := raw.Read(buf)
	if err != nil {
		t.Fatalf("read CONNECT response: %v", err)
	}
	resp := string(buf[:n])
	if len(resp) < 12 || resp[9:12] != "200" {
		t.Fatalf("CONNECT response: %q", resp)
	}
	// Clear deadline so TLS conn lifetime is not limited.
	raw.SetDeadline(time.Time{})

	// TLS handshake using Tessera CA as trust root.
	tlsConn := tls.Client(raw, &tls.Config{
		ServerName: target,
		RootCAs:    h.caRootPool(),
	})
	if err := tlsConn.Handshake(); err != nil {
		t.Fatalf("TLS handshake: %v", err)
	}
	return tlsConn
}

// TestForwardProxy_UnknownHost: CONNECT to an unregistered host → 502.
func TestForwardProxy_UnknownHost(t *testing.T) {
	h := newTestHarness(t)

	proxyAddr := h.Listener.Addr().String()
	raw, err := net.Dial("tcp", proxyAddr)
	if err != nil {
		t.Fatal(err)
	}
	defer raw.Close()

	raw.Write([]byte("CONNECT unknown.test:443 HTTP/1.1\r\nHost: unknown.test:443\r\n\r\n"))
	raw.SetReadDeadline(time.Now().Add(3 * time.Second))

	buf := make([]byte, 256)
	n, err := raw.Read(buf)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	got := string(buf[:n])
	if len(got) < 12 || got[9:12] != "502" {
		t.Fatalf("expected 502, got: %q", got)
	}
}

// sendRequestOverConn writes a raw HTTP/1.1 request over an already-established
// (TLS or plain) conn and reads back the response. This avoids the Go HTTP client
// trying to negotiate TLS again on top of the already-TLS'd tunnel conn.
func sendRequestOverConn(t *testing.T, conn net.Conn, method, targetURL, bearerToken string) *http.Response {
	t.Helper()

	// Write minimal HTTP/1.1 request.
	u, err := parseTestURL(targetURL)
	if err != nil {
		t.Fatalf("parse url: %v", err)
	}
	reqLine := fmt.Sprintf("%s %s HTTP/1.1\r\nHost: %s\r\nAuthorization: Bearer %s\r\nConnection: close\r\n\r\n",
		method, u.path, u.host, bearerToken)
	if _, err := conn.Write([]byte(reqLine)); err != nil {
		t.Fatalf("write request: %v", err)
	}

	br := bufio.NewReader(conn)
	resp, err := http.ReadResponse(br, nil)
	if err != nil {
		t.Fatalf("read response: %v", err)
	}
	return resp
}

type parsedURL struct{ host, path string }

func parseTestURL(rawURL string) (parsedURL, error) {
	// Simple parser for test URLs like "https://host/path".
	if len(rawURL) < 8 {
		return parsedURL{}, fmt.Errorf("short url")
	}
	// Strip scheme.
	rest := rawURL
	if idx := indexStr(rest, "://"); idx >= 0 {
		rest = rest[idx+3:]
	}
	slash := indexStr(rest, "/")
	if slash < 0 {
		return parsedURL{host: rest, path: "/"}, nil
	}
	return parsedURL{host: rest[:slash], path: rest[slash:]}, nil
}

func indexStr(s, sub string) int {
	for i := 0; i <= len(s)-len(sub); i++ {
		if s[i:i+len(sub)] == sub {
			return i
		}
	}
	return -1
}

// TestForwardProxy_UpstreamMismatch: token bound to "alpha" but request goes to
// "beta.test" which resolves to upstream "beta" → 403.
func TestForwardProxy_UpstreamMismatch(t *testing.T) {
	h := newTestHarness(t)

	h.addUpstream(t, "alpha", "http://127.0.0.1:1", []string{"alpha.test"}, "env://ALPHA_KEY")
	h.addUpstream(t, "beta", "http://127.0.0.1:2", []string{"beta.test"}, "env://BETA_KEY")

	h.addPolicy(t, "permit", permitAllPolicy)
	// Token is scoped to alpha, but we'll request beta.test.
	tok := h.mintToken(t, "alpha", "permit")

	tlsConn := h.dialAndCONNECT(t, "beta.test")

	resp := sendRequestOverConn(t, tlsConn, "GET", "https://beta.test/", tok)
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("expected 403, got %d", resp.StatusCode)
	}
}

// TestForwardProxy_MalformedInner: after CONNECT+TLS, write garbage then close;
// verify the proxy goroutine unblocks promptly and the proxy can serve a second
// connection.
func TestForwardProxy_MalformedInner(t *testing.T) {
	h := newTestHarness(t)
	h.addUpstream(t, "maltest", "http://127.0.0.1:1", []string{"maltest.test"}, "env://NOKEY")

	tlsConn := h.dialAndCONNECT(t, "maltest.test")

	// Write garbage — not a valid HTTP request.
	tlsConn.Write([]byte("NOTHTTP garbage\r\n\r\n")) //nolint:errcheck
	tlsConn.Close()

	// Proxy goroutine should unblock; a subsequent CONNECT to a different host
	// should still succeed (502 expected because "second.test" is unknown).
	proxyAddr := h.Listener.Addr().String()
	raw2, err := net.Dial("tcp", proxyAddr)
	if err != nil {
		t.Fatalf("dial proxy after malformed: %v", err)
	}
	defer raw2.Close()
	raw2.Write([]byte("CONNECT second.test:443 HTTP/1.1\r\nHost: second.test:443\r\n\r\n")) //nolint:errcheck
	raw2.SetReadDeadline(time.Now().Add(3 * time.Second))
	buf := make([]byte, 256)
	n, err := raw2.Read(buf)
	if err != nil {
		t.Fatalf("read after malformed: %v", err)
	}
	got := string(buf[:n])
	if len(got) < 12 || got[9:12] != "502" {
		t.Fatalf("expected 502 from second conn, got: %q", got)
	}
}

// TestBufferedConn_DrainsBufioBuffer: unit test for the bufferedConn shim.
// Verifies that bytes already consumed into a bufio.Reader buffer are re-exposed
// through Read so that a tls.Server handed the bufferedConn sees them correctly
// (regression for pipeline-after-CONNECT bug where pipelined bytes were lost).
func TestBufferedConn_DrainsBufioBuffer(t *testing.T) {
	payload := []byte("CONNECT host:443 HTTP/1.1\r\nHost: host:443\r\n\r\nHELLO_PIPELINED")

	// Write payload to one end of a net.Pipe; read via bufio on the other.
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()

	go client.Write(payload) //nolint:errcheck

	br := bufio.NewReader(server)
	// Consume just the HTTP request (up to \r\n\r\n), leaving "HELLO_PIPELINED"
	// buffered inside br.
	req, err := http.ReadRequest(br)
	if err != nil {
		t.Fatalf("ReadRequest: %v", err)
	}
	if req.Method != "CONNECT" {
		t.Fatalf("expected CONNECT, got %s", req.Method)
	}

	// newBufferedConn should expose the buffered remainder.
	bc := newBufferedConn(server, br)

	got := make([]byte, 16)
	n, err := bc.Read(got)
	if err != nil {
		t.Fatalf("Read from bufferedConn: %v", err)
	}
	if string(got[:n]) != "HELLO_PIPELINED" {
		t.Fatalf("expected %q, got %q", "HELLO_PIPELINED", got[:n])
	}
}

// TestForwardProxy_HappyPath: full MITM flow — authn, authz, inject, forward.
func TestForwardProxy_HappyPath(t *testing.T) {
	t.Setenv("FAKE_KEY", "real-upstream-token")

	// Fake upstream (plain HTTP).
	var gotAuth string
	fakeUpstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		w.WriteHeader(200)
		io.WriteString(w, "ok")
	}))
	defer fakeUpstream.Close()

	h := newTestHarness(t)
	h.addUpstream(t, "fake", fakeUpstream.URL, []string{"fake.test"}, "env://FAKE_KEY")
	h.addPolicy(t, "permit", permitAllPolicy)
	tok := h.mintToken(t, "fake", "permit")

	tlsConn := h.dialAndCONNECT(t, "fake.test")

	resp := sendRequestOverConn(t, tlsConn, "GET", "https://fake.test/", tok)
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("expected 200, got %d: %s", resp.StatusCode, body)
	}
	if gotAuth != "Bearer real-upstream-token" {
		t.Fatalf("upstream saw auth=%q", gotAuth)
	}
}
