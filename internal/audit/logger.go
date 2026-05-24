package audit

import (
	"encoding/json"
	"io"
	"sync"
	"time"
)

type Logger struct {
	mu  sync.Mutex
	w   io.Writer
	enc *json.Encoder
}

func New(w io.Writer) *Logger {
	return &Logger{w: w, enc: json.NewEncoder(w)}
}

func (l *Logger) Emit(e Event) {
	if e.TS == "" {
		e.TS = time.Now().UTC().Format(time.RFC3339Nano)
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	_ = l.enc.Encode(e)
}

func (l *Logger) EmitAdmin(e AdminEvent) {
	if e.TS == "" {
		e.TS = time.Now().UTC().Format(time.RFC3339Nano)
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	_ = l.enc.Encode(e)
}
