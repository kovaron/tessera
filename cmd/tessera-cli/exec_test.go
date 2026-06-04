package main

import (
	"strings"
	"testing"
)

func TestBuildExecEnv_ContainsRequiredVars(t *testing.T) {
	parent := []string{"HOME=/home/user", "PATH=/usr/bin:/bin", "EXISTING=value"}
	env := buildExecEnv(parent, "127.0.0.1:8443", "/home/user/.tessera/ca.pem", "tok-secret")

	required := map[string]string{
		"HTTPS_PROXY":         "http://127.0.0.1:8443",
		"HTTP_PROXY":          "http://127.0.0.1:8443",
		"NODE_EXTRA_CA_CERTS": "/home/user/.tessera/ca.pem",
		"SSL_CERT_FILE":       "/home/user/.tessera/ca.pem",
		"REQUESTS_CA_BUNDLE":  "/home/user/.tessera/ca.pem",
		"CURL_CA_BUNDLE":      "/home/user/.tessera/ca.pem",
		"PXY_TOKEN":           "tok-secret",
	}

	for k, wantV := range required {
		found := false
		for _, kv := range env {
			if strings.HasPrefix(kv, k+"=") {
				gotV := kv[len(k)+1:]
				if gotV != wantV {
					t.Errorf("%s = %q, want %q", k, gotV, wantV)
				}
				found = true
				break
			}
		}
		if !found {
			t.Errorf("env missing key %q", k)
		}
	}
}

func TestBuildExecEnv_PreservesParentVars(t *testing.T) {
	parent := []string{"HOME=/home/user", "PATH=/usr/bin:/bin", "MY_VAR=keep-me"}
	env := buildExecEnv(parent, "127.0.0.1:8443", "/ca.pem", "secret")

	for _, kv := range env {
		if kv == "MY_VAR=keep-me" {
			return
		}
	}
	t.Error("parent var MY_VAR=keep-me not preserved in child env")
}

func TestBuildExecEnv_OverridesParentProxyVars(t *testing.T) {
	parent := []string{"HTTPS_PROXY=http://old-proxy:9999", "HTTP_PROXY=http://old-proxy:9999"}
	env := buildExecEnv(parent, "127.0.0.1:8443", "/ca.pem", "secret")

	count := 0
	for _, kv := range env {
		if strings.HasPrefix(kv, "HTTPS_PROXY=") {
			count++
			if kv != "HTTPS_PROXY=http://127.0.0.1:8443" {
				t.Errorf("HTTPS_PROXY not overridden correctly: %q", kv)
			}
		}
	}
	if count != 1 {
		t.Errorf("expected exactly 1 HTTPS_PROXY entry, got %d", count)
	}
}
