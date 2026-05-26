package main

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/kovaron/ai-secrets-manager/internal/crypto"
	"github.com/kovaron/ai-secrets-manager/internal/store"
	"github.com/spf13/cobra"
	"golang.org/x/term"
)

func cmdBootstrap() *cobra.Command {
	var dbPath string
	var passphraseStdin bool
	c := &cobra.Command{
		Use: "bootstrap",
		RunE: func(*cobra.Command, []string) error {
			var pw []byte
			if passphraseStdin {
				r := bufio.NewReader(os.Stdin)
				line, err := r.ReadString('\n')
				if err != nil {
					return err
				}
				pw = []byte(strings.TrimRight(line, "\r\n"))
			} else {
				fmt.Print("New passphrase: ")
				p, _ := term.ReadPassword(int(os.Stdin.Fd()))
				fmt.Println()
				fmt.Print("Confirm: ")
				p2, _ := term.ReadPassword(int(os.Stdin.Fd()))
				fmt.Println()
				if string(p) != string(p2) {
					return fmt.Errorf("passphrase mismatch")
				}
				pw = p
			}
			if len(pw) == 0 {
				return fmt.Errorf("empty passphrase")
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
	c.Flags().BoolVar(&passphraseStdin, "passphrase-stdin", false, "read passphrase from stdin (one line, no confirm)")
	return c
}
