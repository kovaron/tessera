package secrets

import (
	"bytes"
	"context"
	"os/exec"
	"strings"
	"time"
)

type opProvider struct {
	cmd []string // e.g. ["op", "read"]
}

func NewOnePasswordProvider(cmd []string) SecretProvider {
	if len(cmd) == 0 {
		cmd = []string{"op", "read"}
	}
	return &opProvider{cmd: cmd}
}

func (opProvider) Name() string { return "1password" }

func (p *opProvider) Resolve(ctx context.Context, rest string) (Secret, error) {
	arg := "op://" + rest
	args := append([]string{}, p.cmd[1:]...)
	args = append(args, arg)
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
