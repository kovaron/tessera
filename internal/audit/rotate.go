package audit

import (
	"fmt"
	"io"
	"os"
	"sync"
)

// RotatingWriter rotates path when size exceeds maxBytes.
// On rotation: rename path -> path.1 (shifting older), open fresh path.
// Keeps at most keep numbered rotations.
type RotatingWriter struct {
	path     string
	maxBytes int64
	keep     int
	mu       sync.Mutex
	f        *os.File
	size     int64
}

func NewRotatingWriter(path string, maxBytes int64, keep int) (*RotatingWriter, error) {
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return nil, err
	}
	info, err := f.Stat()
	if err != nil {
		f.Close()
		return nil, err
	}
	return &RotatingWriter{
		path:     path,
		maxBytes: maxBytes,
		keep:     keep,
		f:        f,
		size:     info.Size(),
	}, nil
}

func (r *RotatingWriter) Write(p []byte) (int, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.size+int64(len(p)) > r.maxBytes {
		if err := r.rotateLocked(); err != nil {
			return 0, err
		}
	}
	n, err := r.f.Write(p)
	r.size += int64(n)
	return n, err
}

func (r *RotatingWriter) Close() error {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.f.Close()
}

func (r *RotatingWriter) rotateLocked() error {
	if err := r.f.Close(); err != nil {
		return err
	}
	for i := r.keep; i >= 1; i-- {
		src := r.path
		if i > 1 {
			src = fmt.Sprintf("%s.%d", r.path, i-1)
		}
		dst := fmt.Sprintf("%s.%d", r.path, i)
		if _, err := os.Stat(src); err != nil {
			continue
		}
		if i == r.keep {
			_ = os.Remove(dst)
		}
		if err := os.Rename(src, dst); err != nil {
			return err
		}
	}
	f, err := os.OpenFile(r.path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	r.f = f
	r.size = 0
	return nil
}

var _ io.WriteCloser = (*RotatingWriter)(nil)
