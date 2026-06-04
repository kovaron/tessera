package main

import (
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"syscall"

	"github.com/spf13/cobra"
)

// buildExecEnv merges parent env with proxy/CA/token overrides.
// Exported for testability; pure function with no side-effects.
func buildExecEnv(parent []string, proxyAddr, caPath, pxyToken string) []string {
	proxyURL := "http://" + proxyAddr
	overrides := map[string]string{
		"HTTPS_PROXY":         proxyURL,
		"HTTP_PROXY":          proxyURL,
		"NODE_EXTRA_CA_CERTS": caPath,
		"SSL_CERT_FILE":       caPath,
		"REQUESTS_CA_BUNDLE":  caPath,
		"CURL_CA_BUNDLE":      caPath,
		"PXY_TOKEN":           pxyToken,
	}

	result := make([]string, 0, len(parent)+len(overrides))
	for _, kv := range parent {
		keep := true
		for k := range overrides {
			if len(kv) > len(k) && kv[:len(k)] == k && kv[len(k)] == '=' {
				keep = false
				break
			}
		}
		if keep {
			result = append(result, kv)
		}
	}
	for k, v := range overrides {
		result = append(result, k+"="+v)
	}
	return result
}

func cmdExec() *cobra.Command {
	var (
		upstreamID string
		policyID   string
		ttl        int
		label      string
		proxyAddr  string
		caPath     string
	)

	c := &cobra.Command{
		Use:                   "exec [flags] -- <cmd> [args...]",
		Short:                 "Spawn a child process under the forward proxy (mint token, set env, auto-revoke). Use '--' to separate flags from the child command.",
		DisableFlagsInUseLine: true,
		Args:                  cobra.MinimumNArgs(1),
		RunE: func(_ *cobra.Command, args []string) error {
			if label == "" {
				label = fmt.Sprintf("exec:%d", os.Getpid())
			}
			if caPath == "" {
				caPath = os.ExpandEnv("$HOME/.tessera/ca.pem")
			}

			// 1. Mint a child token.
			client := NewClient(socketPath)
			var tokenResp map[string]string
			if err := client.do("POST", "/v1/tokens", map[string]any{
				"label":       label,
				"upstream_id": upstreamID,
				"policy_id":   policyID,
				"ttl_seconds": ttl,
			}, &tokenResp); err != nil {
				return fmt.Errorf("mint token: %w", err)
			}
			tokenID := tokenResp["id"]
			tokenSecret := tokenResp["secret"]

			// Revoke unconditionally after child exits, regardless of exit code.
			defer func() {
				if err := client.do("DELETE", "/v1/tokens/"+tokenID, nil, nil); err != nil {
					fmt.Fprintf(os.Stderr, "tessera-cli exec: revoke token %s: %v\n", tokenID, err)
				}
			}()

			// 2. Build child environment.
			env := buildExecEnv(os.Environ(), proxyAddr, caPath, tokenSecret)

			// 3. Spawn child.
			child := exec.Command(args[0], args[1:]...) //nolint:gosec
			child.Stdin = os.Stdin
			child.Stdout = os.Stdout
			child.Stderr = os.Stderr
			child.Env = env

			if err := child.Start(); err != nil {
				return fmt.Errorf("start child: %w", err)
			}

			// 4. Forward SIGINT / SIGTERM to child while it runs.
			sigCh := make(chan os.Signal, 1)
			stopSig := make(chan struct{})
			signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
			go func() {
				for {
					select {
					case sig := <-sigCh:
						_ = child.Process.Signal(sig)
					case <-stopSig:
						return
					}
				}
			}()

			waitErr := child.Wait()
			signal.Stop(sigCh)
			close(stopSig)

			// 5. Propagate exit code (defer revokes token before we return/exit).
			if waitErr != nil {
				if exitErr, ok := waitErr.(*exec.ExitError); ok {
					code := exitErr.ProcessState.ExitCode()
					if code == -1 {
						// Killed by signal — return 128+signal.
						if status, ok := exitErr.ProcessState.Sys().(syscall.WaitStatus); ok {
							if status.Signaled() {
								// Defer will run before os.Exit in the same goroutine
								// only if we return via RunE. Use a helper to ensure
								// the defer fires by returning a sentinel error that
								// the caller can convert to an exit code.
								return &signalExitError{128 + int(status.Signal())}
							}
						}
						return &exitCodeError{1}
					}
					if code != 0 {
						return &exitCodeError{code}
					}
					return nil
				}
				return waitErr
			}
			return nil
		},
	}

	// Disable interspersed flag parsing so flags after '--' are not parsed by cobra.
	c.Flags().SetInterspersed(false)

	c.Flags().StringVar(&upstreamID, "upstream", "", "(required) upstream ID to bind the token to")
	c.Flags().StringVar(&policyID, "policy", "", "(required) policy ID")
	c.Flags().IntVar(&ttl, "ttl", 3600, "token TTL in seconds")
	c.Flags().StringVar(&label, "label", "", "token label (default: exec:<pid>)")
	c.Flags().StringVar(&proxyAddr, "proxy-addr", "127.0.0.1:8443", "forward proxy address (host:port)")
	c.Flags().StringVar(&caPath, "ca-path", "", "CA certificate path (default: $HOME/.tessera/ca.pem)")

	_ = c.MarkFlagRequired("upstream")
	_ = c.MarkFlagRequired("policy")

	return c
}

// exitCodeError carries a non-zero exit code through cobra's error handling.
// main() detects this type and calls os.Exit with the embedded code.
type exitCodeError struct{ code int }

func (e *exitCodeError) Error() string { return fmt.Sprintf("exit status %d", e.code) }

// signalExitError is like exitCodeError but for signal-terminated children.
type signalExitError struct{ code int }

func (e *signalExitError) Error() string { return fmt.Sprintf("exit status %d", e.code) }
