package authz

import (
	"context"

	"github.com/open-policy-agent/opa/v1/rego"
)

type opaEngine struct{}

func NewOPA() Engine { return &opaEngine{} }

func (opaEngine) Name() string { return "opa" }

func (opaEngine) Compile(src []byte) (Compiled, error) {
	q, err := rego.New(
		rego.Query("data.proxy.authz.allow"),
		rego.Module("policy.rego", string(src)),
	).PrepareForEval(context.Background())
	if err != nil {
		return nil, err
	}
	return &opaCompiled{q: q}, nil
}

type opaCompiled struct {
	q rego.PreparedEvalQuery
}

func (c *opaCompiled) Eval(ctx context.Context, in Input) (Decision, error) {
	rs, err := c.q.Eval(ctx, rego.EvalInput(in))
	if err != nil {
		return Decision{}, err
	}
	if len(rs) == 0 || len(rs[0].Expressions) == 0 {
		return Decision{Allow: false, Reason: "no result"}, nil
	}
	v, _ := rs[0].Expressions[0].Value.(bool)
	if !v {
		return Decision{Allow: false, Reason: "policy denied"}, nil
	}
	return Decision{Allow: true}, nil
}
