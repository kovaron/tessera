package audit

import (
	"bytes"
	"encoding/json"
	"testing"
)

func TestEmitJSON(t *testing.T) {
	var buf bytes.Buffer
	l := New(&buf)
	l.Emit(Event{TokenID: "t", Method: "GET", Path: "/x", Status: 200, Decision: "allow"})
	var m map[string]any
	if err := json.Unmarshal(buf.Bytes(), &m); err != nil {
		t.Fatal(err)
	}
	if m["token_id"] != "t" || m["status"].(float64) != 200 {
		t.Fatalf("bad event: %v", m)
	}
}
