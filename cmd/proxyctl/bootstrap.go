package main

import (
	"context"
	"fmt"
	"os"
	"time"

	"github.com/kovaron/ai-secrets-manager/internal/crypto"
	"github.com/kovaron/ai-secrets-manager/internal/store"
	"github.com/spf13/cobra"
	"golang.org/x/term"
)

func cmdBootstrap() *cobra.Command {
	var dbPath string
	c := &cobra.Command{
		Use: "bootstrap",
		RunE: func(*cobra.Command, []string) error {
			fmt.Print("New passphrase: ")
			pw, _ := term.ReadPassword(int(os.Stdin.Fd()))
			fmt.Println()
			fmt.Print("Confirm: ")
			pw2, _ := term.ReadPassword(int(os.Stdin.Fd()))
			fmt.Println()
			if string(pw) != string(pw2) {
				return fmt.Errorf("passphrase mismatch")
			}

			s, err := store.OpenSQLite(dbPath)
			if err != nil {
				return err
			}
			if err := s.Migrate(context.Background()); err != nil {
				return err
			}
			kp := &crypto.PassphraseProvider{Params: crypto.DefaultArgon2()}
			wrapped, salt, err := kp.WrapNewDEK(context.Background(), pw)
			if err != nil {
				return err
			}
			return s.PutKeystore(context.Background(), store.Keystore{
				DEKWrapped: wrapped, KEKSource: "passphrase", KDFParams: salt, CreatedAt: time.Now().Unix(),
			})
		},
	}
	c.Flags().StringVar(&dbPath, "db", os.ExpandEnv("$HOME/.proxyd/data.db"), "")
	return c
}
