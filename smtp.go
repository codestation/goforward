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
	"os/signal"
	"syscall"

	"github.com/flashmob/go-guerrilla"
	"github.com/flashmob/go-guerrilla/backends"
	slog "github.com/flashmob/go-guerrilla/log"
	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
	"megpoid.xyz/go/goforward/forward"
)

type smtpConfig struct {
	listen      string
	host        string
	aliases     string
	credentials string
	token       string
	debug       bool
}

func runSMTPServer(smtpConfig smtpConfig) error {
	cfg := &guerrilla.AppConfig{
		LogFile:      slog.OutputStdout.String(),
		AllowedHosts: []string{smtpConfig.host},
	}

	sc := guerrilla.ServerConfig{
		ListenInterface: smtpConfig.listen,
		IsEnabled:       true,
		Hostname:        smtpConfig.host,
	}

	cfg.Servers = append(cfg.Servers, sc)

	bcfg := backends.BackendConfig{
		"save_workers_size":     3,
		"save_process":          "HeadersParser|Hasher|Header|Debugger|Forwarder",
		"validate_processors":   "Forwarder",
		"log_received_mails":    true,
		"primary_mail_host":     smtpConfig.host,
		"forwarder_aliases_map": smtpConfig.aliases,
		"forwarder_credentials": smtpConfig.credentials,
		"forwarder_token":       smtpConfig.token,
	}

	if smtpConfig.debug {
		cfg.LogLevel = slog.DebugLevel.String()
	} else {
		cfg.LogLevel = slog.InfoLevel.String()
	}

	cfg.BackendConfig = bcfg
	d := guerrilla.Daemon{Config: cfg}
	d.AddProcessor("Forwarder", forward.Processor)

	if err := d.Start(); err == nil {
		log.Printf("SMTP server started on %s", smtpConfig.listen)
	} else {
		return errors.Wrap(err, "failed to start smtp server")
	}

	interrupt := make(chan os.Signal, 1)
	signal.Notify(interrupt, os.Interrupt)
	signal.Notify(interrupt, syscall.SIGTERM)

	<-interrupt
	log.Println("Waiting for the SMTP server to shutdown...")
	d.Shutdown()

	return nil
}
