package proxy

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"strings"
	"sync"

	"github.com/kovaron/tessera/internal/audit"
	"github.com/kovaron/tessera/internal/pki"
)

// ForwardServer is an HTTP/1.1 forward proxy listener that accepts CONNECT
// tunnels, performs TLS interception using a per-hostname leaf certificate,
// then dispatches the inner request through the existing middleware chain.
type ForwardServer struct {
	DataPlane *DataPlane
	Leaves    *pki.LeafFactory
	// Audit is used for pre-chain events (unknown_host, leaf_mint_failed).
	Audit *audit.Logger
}

// Serve accepts connections on ln until it is closed.
func (fs *ForwardServer) Serve(ln net.Listener) {
	for {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		go fs.handleConn(c)
	}
}

func (fs *ForwardServer) handleConn(c net.Conn) {
	br := bufio.NewReader(c)
	req, err := http.ReadRequest(br)
	if err != nil {
		c.Close()
		return
	}

	host := hostOnly(req.Host)

	if req.Method == http.MethodConnect {
		// handleCONNECT owns the conn lifecycle via http.Server.
		fs.handleCONNECT(c, host, req)
	} else {
		// Plain HTTP (rare for HTTPS-only upstreams).
		defer c.Close()
		fs.dispatchOneRequest(c, host, "http", req)
	}
}

func (fs *ForwardServer) handleCONNECT(c net.Conn, host string, connectReq *http.Request) {
	// Ensure the raw conn is always closed on exit (idempotent with tlsConn.Close).
	defer c.Close()

	// Resolve upstream before replying 200, so unknown hosts get a proper error.
	up, ok := fs.DataPlane.Upstreams.ByHostname(host)
	if !ok {
		fs.Audit.Emit(audit.Event{
			Method:     connectReq.Method,
			Path:       connectReq.URL.RequestURI(),
			Decision:   "deny",
			DenyReason: "unknown_host",
			Status:     http.StatusBadGateway,
			RemoteAddr: c.RemoteAddr().String(),
		})
		writeHTTPError(c, http.StatusBadGateway, "unknown host")
		return
	}

	// Mint leaf cert for this hostname.
	cert, err := fs.Leaves.LeafFor(host)
	if err != nil {
		fs.Audit.Emit(audit.Event{
			Method:     connectReq.Method,
			Path:       connectReq.URL.RequestURI(),
			Decision:   "deny",
			DenyReason: "leaf_mint_failed",
			Status:     http.StatusBadGateway,
			RemoteAddr: c.RemoteAddr().String(),
		})
		writeHTTPError(c, http.StatusBadGateway, "leaf cert error")
		return
	}

	// Acknowledge the tunnel.
	if _, err := fmt.Fprintf(c, "HTTP/1.1 200 Connection established\r\n\r\n"); err != nil {
		return
	}

	// Wrap with TLS using the minted leaf.
	tlsCfg := &tls.Config{
		Certificates: []tls.Certificate{*cert},
		GetCertificate: func(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
			return fs.Leaves.LeafFor(hello.ServerName)
		},
	}
	tlsConn := tls.Server(c, tlsCfg)
	if err := tlsConn.Handshake(); err != nil {
		// Client refused our cert — pre-MITM, no audit.
		return
	}

	// Serve inner HTTP/1.1 requests through the host-mode chain.
	// trackedConn closes a channel on Close() so we can block until http.Server
	// tears down the connection — safe for both malformed HTTP and keep-alive.
	handler := fs.DataPlane.HandlerForHostMode(up.ID)
	tc := &trackedConn{Conn: tlsConn, closed: make(chan struct{})}
	innerSrv := &http.Server{
		Handler:  schemeHostMiddleware(host, "https", handler),
		ErrorLog: log.New(io.Discard, "", 0),
	}
	scl := newSingleConnListener(tc)
	go innerSrv.Serve(scl) //nolint:errcheck
	<-tc.closed
}

// trackedConn wraps a net.Conn and signals closed when Close is called.
// This lets handleCONNECT block until http.Server tears down the connection
// regardless of whether the handler was ever invoked (e.g. malformed HTTP).
type trackedConn struct {
	net.Conn
	once   sync.Once
	closed chan struct{}
}

func (tc *trackedConn) Close() error {
	tc.once.Do(func() { close(tc.closed) })
	return tc.Conn.Close()
}

// dispatchOneRequest handles a single already-parsed plain HTTP request by
// writing the response directly over the conn using a connResponseWriter.
func (fs *ForwardServer) dispatchOneRequest(c net.Conn, host, scheme string, req *http.Request) {
	up, ok := fs.DataPlane.Upstreams.ByHostname(host)
	if !ok {
		fs.Audit.Emit(audit.Event{
			Method:     req.Method,
			Path:       req.URL.RequestURI(),
			Decision:   "deny",
			DenyReason: "unknown_host",
			Status:     http.StatusBadGateway,
			RemoteAddr: c.RemoteAddr().String(),
		})
		writeHTTPError(c, http.StatusBadGateway, "unknown host")
		return
	}
	req.URL.Scheme = scheme
	if req.URL.Host == "" {
		req.URL.Host = host
	}
	handler := fs.DataPlane.HandlerForHostMode(up.ID)
	rw := newConnResponseWriter(c)
	handler.ServeHTTP(rw, req)
	rw.flush()
}

// schemeHostMiddleware ensures inner requests have URL.Scheme and URL.Host set.
func schemeHostMiddleware(host, scheme string, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r.URL.Scheme = scheme
		if r.URL.Host == "" {
			r.URL.Host = host
		}
		next.ServeHTTP(w, r)
	})
}

// hostOnly strips port from "host:port".
func hostOnly(hostport string) string {
	h, _, err := net.SplitHostPort(hostport)
	if err != nil {
		return strings.TrimSuffix(hostport, ":")
	}
	return h
}

func writeHTTPError(c net.Conn, code int, msg string) {
	resp := fmt.Sprintf("HTTP/1.1 %d %s\r\nContent-Length: %d\r\nContent-Type: text/plain\r\nConnection: close\r\n\r\n%s",
		code, http.StatusText(code), len(msg), msg)
	c.Write([]byte(resp)) //nolint:errcheck
}

// connResponseWriter is a minimal http.ResponseWriter that writes a response
// back over a raw net.Conn. Used for the plain-HTTP (non-CONNECT) path only.
type connResponseWriter struct {
	conn    net.Conn
	headers http.Header
	buf     bytes.Buffer
	status  int
	written bool
}

func newConnResponseWriter(c net.Conn) *connResponseWriter {
	return &connResponseWriter{conn: c, headers: make(http.Header), status: 200}
}

func (rw *connResponseWriter) Header() http.Header { return rw.headers }

func (rw *connResponseWriter) WriteHeader(code int) {
	if rw.written {
		return
	}
	rw.status = code
	rw.written = true
	fmt.Fprintf(&rw.buf, "HTTP/1.1 %d %s\r\n", code, http.StatusText(code))
	rw.headers.Write(&rw.buf) //nolint:errcheck
	rw.buf.WriteString("\r\n")
}

func (rw *connResponseWriter) Write(b []byte) (int, error) {
	if !rw.written {
		rw.WriteHeader(200)
	}
	return rw.buf.Write(b)
}

func (rw *connResponseWriter) flush() {
	if !rw.written {
		rw.WriteHeader(200)
	}
	rw.conn.Write(rw.buf.Bytes()) //nolint:errcheck
}

// singleConnListener is a net.Listener that serves exactly one connection then
// returns net.ErrClosed from Accept to signal the server to stop.
type singleConnListener struct {
	conn net.Conn
	once sync.Once
	done chan struct{}
}

func newSingleConnListener(c net.Conn) *singleConnListener {
	return &singleConnListener{conn: c, done: make(chan struct{})}
}

func (l *singleConnListener) Accept() (net.Conn, error) {
	select {
	case <-l.done:
		return nil, net.ErrClosed
	default:
	}
	l.once.Do(func() { close(l.done) })
	return l.conn, nil
}

func (l *singleConnListener) Close() error {
	l.once.Do(func() { close(l.done) })
	return nil
}

func (l *singleConnListener) Addr() net.Addr { return l.conn.LocalAddr() }
