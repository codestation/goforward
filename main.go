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
	"os"

	log "github.com/sirupsen/logrus"
	"github.com/urfave/cli"
	"megpoid.xyz/go/goforward/forward"
)

var (
	// BuildTime indicates the date when the binary was built (set by -ldflags)
	BuildTime string
	// BuildCommit indicates the git commit of the build
	BuildCommit string
	// AppVersion indicates the application version
	AppVersion = "0.1"
	// BuildNumber indicates the compilation number
	BuildNumber = "0"
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
		host:        c.String("host"),
		aliases:     c.String("aliases"),
		credentials: c.String("credentials"),
		token:       c.String("token"),
		debug:       c.Bool("debug"),
	}

	return runSMTPServer(cfg)
}

func initialize(c *cli.Context) error {
	if c.Bool("debug") {
		log.SetLevel(log.DebugLevel)
	}

	log.SetOutput(os.Stdout)

	log.Infof("Starting goforward %s.%s", AppVersion, BuildNumber)

	if len(BuildTime) > 0 {
		log.Infof("Build Time: %s", BuildTime)
	}

	if len(BuildCommit) > 0 {
		log.Infof("Build Commit: %s", BuildCommit)
	}

	return nil
}

func main() {
	app := cli.NewApp()
	app.Usage = "forwards email to a Gmail account"
	app.Version = AppVersion + "." + BuildNumber

	app.Flags = []cli.Flag{
		cli.StringFlag{
			Name:   "listen, l",
			Usage:  "listen interface",
			Value:  ":2525",
			EnvVar: "LISTEN",
		},
		cli.StringFlag{
			Name:   "host, H",
			Usage:  "primary mail host",
			EnvVar: "HOST",
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
