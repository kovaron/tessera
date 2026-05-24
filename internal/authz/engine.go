package authz

import "context"

type Engine interface {
	Name() string
	Compile(src []byte) (Compiled, error)
}

type Compiled interface {
	Eval(ctx context.Context, in Input) (Decision, error)
}
