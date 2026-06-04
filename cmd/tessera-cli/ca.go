package main

import (
	"os"

	"github.com/spf13/cobra"
)

func cmdCA() *cobra.Command {
	ca := &cobra.Command{Use: "ca", Short: "CA certificate operations"}

	export := &cobra.Command{
		Use:   "export",
		Short: "Write the CA certificate PEM to stdout",
		RunE: func(*cobra.Command, []string) error {
			return NewClient(socketPath).download("/v1/ca", os.Stdout)
		},
	}

	install := &cobra.Command{
		Use:   "install",
		Short: "Install the CA certificate into the macOS system keychain",
		RunE: func(*cobra.Command, []string) error {
			return NewClient(socketPath).do("POST", "/v1/ca/install", nil, nil)
		},
	}

	ca.AddCommand(export, install)
	return ca
}
