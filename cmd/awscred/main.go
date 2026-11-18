// SPDX-License-Identifier: BSD-3-Clause

// Command awscred is an AWS credential_process: it prints temporary S3
// credentials for a machine that holds a private key and no password.
//
//	[profile fileshare]
//	credential_process = awscred --issuer https://login.example.org --client winpc-17 --key C:\ProgramData\awscred\winpc-17.pem --sts https://s3.example.org
package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/go-authn/awscred/internal/credproc"
	"github.com/spf13/cobra"
)

var osExit = os.Exit

func main() {
	if err := RootCmd().Execute(); err != nil {
		// Nothing secret reaches stderr: the SDKs and the AWS CLI capture and
		// log it.
		fmt.Fprintln(os.Stderr, "awscred:", err)
		osExit(1)
	}
}

// RootCmd is the command, for main and for the tests.
func RootCmd() *cobra.Command {
	var (
		issuer, client, keyFile, keyID, sts, scope, session, cacheDir string
		duration, refreshBefore                                       time.Duration
		noCache                                                       bool
	)
	cmd := &cobra.Command{
		Use:           "awscred",
		Short:         "AWS credential_process: a private_key_jwt for a token, the token for temporary S3 credentials",
		SilenceUsage:  true,
		SilenceErrors: true,
		Args:          cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			if issuer == "" || client == "" || keyFile == "" || sts == "" {
				return errors.New("give --issuer, --client, --key and --sts")
			}
			key, err := credproc.LoadKey(keyFile)
			if err != nil {
				return err
			}
			if noCache {
				cacheDir = ""
			} else if cacheDir == "" {
				base, err := os.UserConfigDir()
				if err != nil {
					return fmt.Errorf("no place to cache credentials (%v): give --cache-dir, or --no-cache", err)
				}
				cacheDir = filepath.Join(base, "awscred")
			}
			out, err := credproc.Credentials(cmd.Context(), &credproc.Config{
				Issuer: issuer, Client: client, Key: key, KeyID: keyID, STS: sts, Scope: scope,
				SessionName: session, Duration: duration, CacheDir: cacheDir, RefreshBefore: refreshBefore,
			})
			if err != nil {
				return err
			}
			return json.NewEncoder(cmd.OutOrStdout()).Encode(out)
		},
	}
	f := cmd.Flags()
	f.StringVar(&issuer, "issuer", "", "the bridge, exactly as its tokens spell iss (https://login.example.org)")
	f.StringVar(&client, "client", "", "this machine's client ID at the bridge")
	f.StringVar(&keyFile, "key", "", "the machine's private key: PEM, PKCS#8, PKCS#1 RSA or SEC1 EC (RS256, ES256 P-256, EdDSA)")
	f.StringVar(&keyID, "key-id", "", "the kid of the registered key, when the bridge's set holds several")
	f.StringVar(&sts, "sts", "", "the S3 endpoint that answers AssumeRoleWithWebIdentity (https://s3.example.org)")
	f.StringVar(&scope, "scope", "machine", "the scope asked of the token endpoint")
	f.StringVar(&session, "session-name", "", "RoleSessionName (default: the client ID)")
	f.DurationVar(&duration, "duration", 0, "how long the credentials should last (default: the server's)")
	f.StringVar(&cacheDir, "cache-dir", "", "where credentials are kept between runs (default: the user's configuration directory)")
	f.DurationVar(&refreshBefore, "refresh-before", 5*time.Minute, "ask again when less than this is left")
	f.BoolVar(&noCache, "no-cache", false, "keep nothing between runs")
	return cmd
}
