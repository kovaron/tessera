package authz

import (
	"context"
	"testing"
)

const allowRego = `package proxy.authz
default allow := false
allow if {
    input.request.method == "GET"
    startswith(input.request.path, "/repos/acme/widgets/issues")
}
`

func TestOPAAllow(t *testing.T) {
	e := NewOPA()
	c, err := e.Compile([]byte(allowRego))
	if err != nil {
		t.Fatal(err)
	}
	in := Input{
		Token:    TokenView{ID: "t"},
		Upstream: "github",
		Request:  RequestView{Method: "GET", Path: "/repos/acme/widgets/issues"},
	}
	d, err := c.Eval(context.Background(), in)
	if err != nil {
		t.Fatal(err)
	}
	if !d.Allow {
		t.Fatal("expected allow")
	}
}

func TestOPADeny(t *testing.T) {
	e := NewOPA()
	c, _ := e.Compile([]byte(allowRego))
	in := Input{Request: RequestView{Method: "POST", Path: "/repos/acme/widgets/issues"}}
	d, _ := c.Eval(context.Background(), in)
	if d.Allow {
		t.Fatal("expected deny")
	}
}
