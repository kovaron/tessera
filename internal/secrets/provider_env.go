package secrets

import (
	"context"
	"fmt"
	"os"
	"time"
)

type envProvider struct{}

func NewEnvProvider() SecretProvider { return &envProvider{} }

func (envProvider) Name() string { return "env" }

func (envProvider) Resolve(_ context.Context, rest string) (Secret, error) {
	v, ok := os.LookupEnv(rest)
	if !ok {
		return Secret{}, fmt.Errorf("env: %q not set", rest)
	}
	return Secret{Value: []byte(v), ExpiresAt: time.Now().Add(5 * time.Minute)}, nil
}
