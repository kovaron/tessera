package secrets

import (
	"bytes"
	"context"
	"os/exec"
	"strings"
	"time"
)

type dopplerProvider struct {
	cmd []string // e.g. ["doppler", "secrets", "get", "--plain"]
}

func NewDopplerProvider(cmd []string) SecretProvider {
	if len(cmd) == 0 {
		cmd = []string{"doppler", "secrets", "get", "--plain"}
	}
	return &dopplerProvider{cmd: cmd}
}

func (dopplerProvider) Name() string { return "doppler" }

// rest is "<project>/<config>/<NAME>"
func (p *dopplerProvider) Resolve(ctx context.Context, rest string) (Secret, error) {
	parts := strings.SplitN(rest, "/", 3)
	if len(parts) != 3 {
		return Secret{}, errString("doppler: ref must be project/config/NAME")
	}
	args := append([]string{}, p.cmd[1:]...)
	args = append(args, "--project", parts[0], "--config", parts[1], parts[2])
	c := exec.CommandContext(ctx, p.cmd[0], args...)
	var stdout bytes.Buffer
	c.Stdout = &stdout
	if err := c.Run(); err != nil {
		return Secret{}, err
	}
	return Secret{
		Value:     []byte(strings.TrimRight(stdout.String(), "\n")),
		ExpiresAt: time.Now().Add(5 * time.Minute),
	}, nil
}

type errString string

func (e errString) Error() string { return string(e) }
