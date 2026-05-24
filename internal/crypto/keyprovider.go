package crypto

import "context"

type KeyProvider interface {
	Name() string
	Unlock(ctx context.Context, input any) ([]byte, error) // returns DEK
	Lock()
}
