package main

import (
	"context"
	"flag"
	"log"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/kovaron/ai-secrets-manager/internal/admin"
	"github.com/kovaron/ai-secrets-manager/internal/audit"
	"github.com/kovaron/ai-secrets-manager/internal/authz"
	"github.com/kovaron/ai-secrets-manager/internal/crypto"
	"github.com/kovaron/ai-secrets-manager/internal/proxy"
	"github.com/kovaron/ai-secrets-manager/internal/secrets"
	"github.com/kovaron/ai-secrets-manager/internal/store"
	"github.com/kovaron/ai-secrets-manager/internal/upstreams"
)

func main() {
	addr := flag.String("addr", "127.0.0.1:8080", "listen addr")
	dbPath := flag.String("db", os.ExpandEnv("$HOME/.proxyd/data.db"), "sqlite path")
	sockPath := flag.String("admin-socket", os.ExpandEnv("$HOME/.proxyd/admin.sock"), "admin socket")
	auditPath := flag.String("audit-log", os.ExpandEnv("$HOME/.proxyd/audit.log"), "audit log file path")
	auditMax := flag.Int64("audit-rotate-bytes", 100*1024*1024, "audit log rotation size")
	auditKeep := flag.Int("audit-keep", 5, "audit log rotations to keep")
	flag.Parse()

	if err := os.MkdirAll(filepath.Dir(*auditPath), 0o700); err != nil {
		log.Fatal(err)
	}
	auditFile, err := audit.NewRotatingWriter(*auditPath, *auditMax, *auditKeep)
	if err != nil {
		log.Fatal(err)
	}
	defer auditFile.Close()
	auditLogger := audit.New(os.Stdout, auditFile)

	s, err := store.OpenSQLite(*dbPath)
	if err != nil {
		log.Fatal(err)
	}
	if err := s.Migrate(context.Background()); err != nil {
		log.Fatal(err)
	}

	kp := &crypto.PassphraseProvider{Params: crypto.DefaultArgon2()}
	st := admin.NewState(s, kp)

	reg := upstreams.NewRegistry()
	if err := reg.HydrateFromStore(context.Background(), s); err != nil {
		log.Fatal(err)
	}

	adminH := admin.NewHandlersWithRegistry(st, reg)
	sock := &admin.SocketServer{Path: *sockPath, H: adminH}
	if err := sock.Start(); err != nil {
		log.Fatal(err)
	}
	defer sock.Stop(context.Background())

	secReg := secrets.NewRegistry()
	secReg.Register(secrets.NewEnvProvider())
	secReg.Register(secrets.NewOnePasswordProvider(nil))
	secReg.Register(secrets.NewDopplerProvider(nil))
	cache := secrets.NewCache(secReg, 5*time.Minute)

	dp := &proxy.DataPlane{
		Store:       s,
		Engine:      authz.NewOPA(),
		PolicyCache: authz.NewCache(),
		Upstreams:   reg,
		Secrets:     secrets.ByteResolver{Cache: cache},
		Audit:       auditLogger,
		IsUnlocked:  st.Unlocked,
		DEK:         st.DEK,
	}

	srv := &http.Server{Addr: *addr, Handler: dp.Handler()}
	go func() {
		log.Printf("proxyd listening on %s", *addr)
		if err := srv.ListenAndServe(); err != http.ErrServerClosed {
			log.Fatal(err)
		}
	}()

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGINT, syscall.SIGTERM)
	<-stop
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	srv.Shutdown(ctx)
}
