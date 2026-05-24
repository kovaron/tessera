package secrets

import "context"

type ByteResolver struct{ Cache *Cache }

func (r ByteResolver) Resolve(ctx context.Context, ref string) ([]byte, error) {
	s, err := r.Cache.Get(ctx, ref)
	if err != nil {
		return nil, err
	}
	return s.Value, nil
}
