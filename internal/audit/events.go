package audit

type Event struct {
	TS             string   `json:"ts"`
	ReqID          string   `json:"req_id"`
	TokenID        string   `json:"token_id"`
	TokenLabel     string   `json:"token_label"`
	ParentID       string   `json:"parent_id,omitempty"`
	UpstreamID     string   `json:"upstream_id"`
	Method         string   `json:"method"`
	Path           string   `json:"path"`
	QueryKeys      []string `json:"query_keys,omitempty"`
	Decision       string   `json:"decision"`
	DenyReason     string   `json:"deny_reason,omitempty"`
	UpstreamStatus int      `json:"upstream_status"`
	Status         int      `json:"status"`
	LatencyMS      int64    `json:"latency_ms"`
	BytesIn        int64    `json:"bytes_in"`
	BytesOut       int64    `json:"bytes_out"`
	RemoteAddr     string   `json:"remote_addr"`
}

type AdminEvent struct {
	TS     string         `json:"ts"`
	Actor  string         `json:"actor"`
	Action string         `json:"action"`
	Target string         `json:"target"`
	Fields map[string]any `json:"fields,omitempty"`
}
