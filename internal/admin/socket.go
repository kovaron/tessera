package admin

import (
	"context"
	"net"
	"net/http"
	"os"
	"path/filepath"
)

type SocketServer struct {
	Path string
	H    http.Handler
	srv  *http.Server
	lis  net.Listener
}

func (s *SocketServer) Start() error {
	if err := os.MkdirAll(filepath.Dir(s.Path), 0o700); err != nil {
		return err
	}
	_ = os.Remove(s.Path)
	lis, err := net.Listen("unix", s.Path)
	if err != nil {
		return err
	}
	if err := os.Chmod(s.Path, 0o600); err != nil {
		return err
	}
	s.lis = lis
	s.srv = &http.Server{Handler: s.H}
	go s.srv.Serve(lis) //nolint:errcheck
	return nil
}

func (s *SocketServer) Stop(ctx context.Context) error {
	if s.srv == nil {
		return nil
	}
	return s.srv.Shutdown(ctx)
}
