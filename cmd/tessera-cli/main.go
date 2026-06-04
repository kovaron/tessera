package main

import (
	"fmt"
	"os"
)

func main() {
	if err := newRoot().Execute(); err != nil {
		switch e := err.(type) {
		case *exitCodeError:
			os.Exit(e.code)
		case *signalExitError:
			os.Exit(e.code)
		default:
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
	}
}
