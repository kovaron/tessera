package audit

import (
	"bytes"
	"encoding/json"
	"testing"
)

func TestEmitJSON(t *testing.T) {
	var a, b bytes.Buffer
	l := New(&a, &b)
	l.Emit(Event{TokenID: "t", Method: "GET", Path: "/x", Status: 200, Decision: "allow"})

	for _, buf := range []*bytes.Buffer{&a, &b} {
		var m map[string]any
		if err := json.Unmarshal(buf.Bytes(), &m); err != nil {
			t.Fatal(err)
		}
		if m["token_id"] != "t" || m["status"].(float64) != 200 {
			t.Fatalf("bad event: %v", m)
		}
	}
}
