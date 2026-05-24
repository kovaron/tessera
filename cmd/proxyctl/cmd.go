package main

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
	"golang.org/x/term"
)

var socketPath string

func newRoot() *cobra.Command {
	root := &cobra.Command{Use: "proxyctl"}
	root.PersistentFlags().StringVar(&socketPath, "socket", os.ExpandEnv("$HOME/.proxyd/admin.sock"), "admin socket path")

	root.AddCommand(cmdUnlock(), cmdLock(), cmdStatus(), cmdUpstream(), cmdPolicy(), cmdToken())
	return root
}

func cmdUnlock() *cobra.Command {
	return &cobra.Command{
		Use: "unlock", Short: "Unlock proxyd",
		RunE: func(_ *cobra.Command, _ []string) error {
			fmt.Print("Passphrase: ")
			pw, err := term.ReadPassword(int(os.Stdin.Fd()))
			fmt.Println()
			if err != nil {
				return err
			}
			c := NewClient(socketPath)
			return c.do("POST", "/v1/unlock", map[string]string{"passphrase": string(pw)}, nil)
		},
	}
}

func cmdLock() *cobra.Command {
	return &cobra.Command{
		Use: "lock", Short: "Lock proxyd",
		RunE: func(*cobra.Command, []string) error {
			return NewClient(socketPath).do("POST", "/v1/lock", nil, nil)
		},
	}
}

func cmdStatus() *cobra.Command {
	return &cobra.Command{
		Use: "status",
		RunE: func(*cobra.Command, []string) error {
			var out map[string]any
			if err := NewClient(socketPath).do("GET", "/v1/status", nil, &out); err != nil {
				return err
			}
			fmt.Printf("%+v\n", out)
			return nil
		},
	}
}

func cmdUpstream() *cobra.Command {
	up := &cobra.Command{Use: "upstream"}
	var id, baseURL, inject string
	add := &cobra.Command{
		Use: "add", Args: cobra.ExactArgs(1),
		RunE: func(_ *cobra.Command, args []string) error {
			id = args[0]
			return NewClient(socketPath).do("POST", "/v1/upstreams", map[string]any{
				"id": id, "base_url": baseURL, "inject": parseInject(inject),
			}, nil)
		},
	}
	add.Flags().StringVar(&baseURL, "base-url", "", "")
	add.Flags().StringVar(&inject, "inject", "", "e.g. bearer:env://TOKEN")
	list := &cobra.Command{
		Use: "list",
		RunE: func(*cobra.Command, []string) error {
			var out []map[string]any
			if err := NewClient(socketPath).do("GET", "/v1/upstreams", nil, &out); err != nil {
				return err
			}
			for _, u := range out {
				fmt.Printf("%s\t%s\n", u["ID"], u["BaseURL"])
			}
			return nil
		},
	}
	up.AddCommand(add, list)
	return up
}

func cmdPolicy() *cobra.Command {
	var engine, file string
	p := &cobra.Command{Use: "policy"}
	add := &cobra.Command{
		Use: "add", Args: cobra.NoArgs,
		RunE: func(*cobra.Command, []string) error {
			b, err := os.ReadFile(file)
			if err != nil {
				return err
			}
			var out map[string]string
			if err := NewClient(socketPath).do("POST", "/v1/policies", map[string]any{
				"engine": engine, "source": string(b),
			}, &out); err != nil {
				return err
			}
			fmt.Println(out["id"])
			return nil
		},
	}
	add.Flags().StringVar(&engine, "engine", "opa", "")
	add.Flags().StringVar(&file, "file", "", "rego file")
	p.AddCommand(add)
	return p
}

func cmdToken() *cobra.Command {
	t := &cobra.Command{Use: "token"}
	var label, upID, polID string
	var ttl int64
	mint := &cobra.Command{
		Use: "mint",
		RunE: func(*cobra.Command, []string) error {
			var out map[string]string
			if err := NewClient(socketPath).do("POST", "/v1/tokens", map[string]any{
				"label": label, "upstream_id": upID, "policy_id": polID, "ttl_seconds": ttl,
			}, &out); err != nil {
				return err
			}
			fmt.Println(out["secret"])
			return nil
		},
	}
	mint.Flags().StringVar(&label, "label", "", "")
	mint.Flags().StringVar(&upID, "upstream", "", "")
	mint.Flags().StringVar(&polID, "policy", "", "")
	mint.Flags().Int64Var(&ttl, "ttl-seconds", 86400, "")
	list := &cobra.Command{
		Use: "list",
		RunE: func(*cobra.Command, []string) error {
			var out []map[string]any
			if err := NewClient(socketPath).do("GET", "/v1/tokens", nil, &out); err != nil {
				return err
			}
			for _, tt := range out {
				fmt.Printf("%s\t%s\n", tt["ID"], tt["Label"])
			}
			return nil
		},
	}
	revoke := &cobra.Command{
		Use: "revoke", Args: cobra.ExactArgs(1),
		RunE: func(_ *cobra.Command, args []string) error {
			return NewClient(socketPath).do("DELETE", "/v1/tokens/"+args[0], nil, nil)
		},
	}
	t.AddCommand(mint, list, revoke)
	return t
}

func parseInject(s string) map[string]string {
	// MVP placeholder: real parser later
	return map[string]string{}
}
