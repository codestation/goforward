/*
 *
 * Copyright 2019 codestation.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 */

package main

import (
	"fmt"
	"os"

	log "github.com/sirupsen/logrus"
	"github.com/urfave/cli"
	"megpoid.xyz/go/goforward/forward"
)

func run(c *cli.Context) error {
	if c.Bool("request") {
		return forward.RequestToken(forward.GmailConfig{
			CredentialsPath: c.String("credentials"),
			TokenPath:       c.String("token"),
		})
	}

	cfg := smtpConfig{
		listen:      c.String("listen"),
		host:        c.String("allowed-host"),
		aliases:     c.String("aliases"),
		credentials: c.String("credentials"),
		token:       c.String("token"),
		debug:       c.Bool("debug"),
		tls:         c.Bool("tls"),
		privateKey:  c.String("private-key"),
		publicKey:   c.String("public-key"),
	}

	return runSMTPServer(cfg)
}

func initialize(c *cli.Context) error {
	if c.Bool("debug") {
		log.SetLevel(log.DebugLevel)
	}

	log.SetOutput(os.Stdout)

	log.WithFields(log.Fields{
		"version":     Version,
		"commit":      Commit,
		"built":       BuildTime,
		"compilation": BuildNumber,
	}).Info("GoForward")

	return nil
}

func printVersion(c *cli.Context) {
	_, _ = fmt.Fprintf(c.App.Writer, `GoForward
Version:      %s
Git commit:   %s
Built:        %s
Compilation:  %s
`, Version, Commit, BuildTime, BuildNumber)
}

func main() {
	app := cli.NewApp()
	app.Usage = "forwards email to a Gmail account"
	app.Version = Version
	cli.VersionPrinter = printVersion

	app.Flags = []cli.Flag{
		cli.StringFlag{
			Name:   "listen, l",
			Usage:  "listen interface",
			Value:  ":2525",
			EnvVar: "LISTEN",
		},
		cli.StringFlag{
			Name:   "allowed-host, H",
			Usage:  "allowed host",
			EnvVar: "ALLOWED_HOST",
		},
		cli.StringFlag{
			Name:   "aliases, a",
			Usage:  "user:user=email:email aliases",
			EnvVar: "ALIASES",
		},
		cli.StringFlag{
			Name:   "credentials, C",
			Usage:  "credentials.json path",
			Value:  "credentials.json",
			EnvVar: "CREDENTIALS_FILE",
		},
		cli.StringFlag{
			Name:   "token, T",
			Usage:  "token.json path",
			Value:  "token.json",
			EnvVar: "TOKEN_FILE",
		},
		cli.BoolFlag{
			Name:   "request, r",
			Usage:  "request oeauth token",
			EnvVar: "REQUEST_TOKEN",
		},
		cli.BoolFlag{
			Name:   "tls, t",
			Usage:  "enable STARTTLS support",
			EnvVar: "TLS",
		},
		cli.StringFlag{
			Name:   "private-key, k",
			Usage:  "private key path",
			EnvVar: "PRIVATE_KEY_FILE",
		},
		cli.StringFlag{
			Name:   "public-key, K",
			Usage:  "public key path",
			EnvVar: "PUBLIC_KEY_FILE",
		},
		cli.BoolFlag{
			Name:   "debug, d",
			Usage:  "enable debug logging",
			EnvVar: "DEBUG",
		},
	}

	app.Before = initialize
	app.Action = run

	err := app.Run(os.Args)
	if err != nil {
		log.Fatalf("Unrecoverable error: %s", err.Error())
	}
}
