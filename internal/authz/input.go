package authz

type TokenView struct {
	ID          string   `json:"id"`
	Label       string   `json:"label"`
	ParentChain []string `json:"parent_chain"`
	CreatedAt   int64    `json:"created_at"`
}

type RequestView struct {
	Method       string              `json:"method"`
	Path         string              `json:"path"`
	PathSegments []string            `json:"path_segments"`
	Query        map[string][]string `json:"query"`
	Headers      map[string]string   `json:"headers"`
	BodyPreview  any                 `json:"body_preview"`
}

type Input struct {
	Token    TokenView   `json:"token"`
	Upstream string      `json:"upstream"`
	Request  RequestView `json:"request"`
}

type Decision struct {
	Allow       bool
	Reason      string
	Obligations map[string]any
}
