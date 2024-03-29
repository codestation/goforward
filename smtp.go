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
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/flashmob/go-guerrilla"
	"github.com/flashmob/go-guerrilla/backends"
	slog "github.com/flashmob/go-guerrilla/log"
	"github.com/flashmob/go-guerrilla/tests/testcert"
	log "github.com/sirupsen/logrus"
	"megpoid.dev/go/goforward/forward"
)

type smtpConfig struct {
	listen      string
	host        string
	aliases     string
	credentials string
	token       string
	debug       bool
	tls         bool
	privateKey  string
	publicKey   string
}

func runSMTPServer(smtpConfig smtpConfig) error {
	cfg := &guerrilla.AppConfig{
		AllowedHosts: []string{smtpConfig.host},
		LogFile:      slog.OutputStdout.String(),
	}

	sc := guerrilla.ServerConfig{
		IsEnabled:       true,
		Hostname:        smtpConfig.host,
		MaxSize:         25 * 1024 * 1024,
		ListenInterface: smtpConfig.listen,
	}

	if smtpConfig.tls {
		if smtpConfig.privateKey == "" || smtpConfig.publicKey == "" {
			log.Infof("TLS is set but the private and public keys were not specified, generating self-signed cert...")
			certPath := os.TempDir() + string(os.PathSeparator)
			err := testcert.GenerateCert(smtpConfig.host, "", time.Hour*24*365*10, false, 0, "P256", certPath)

			if err != nil {
				log.Infof("Failed to generate self signed keypair, disabling TLS")
			} else {
				smtpConfig.publicKey = filepath.Join(certPath, smtpConfig.host+".cert.pem")
				smtpConfig.privateKey = filepath.Join(certPath, smtpConfig.host+".key.pem")
				defer os.Remove(smtpConfig.privateKey)
				defer os.Remove(smtpConfig.publicKey)
			}
		}

		if smtpConfig.privateKey != "" && smtpConfig.publicKey != "" {
			sc.TLS = guerrilla.ServerTLSConfig{
				StartTLSOn:               true,
				AlwaysOn:                 false,
				PrivateKeyFile:           smtpConfig.privateKey,
				PublicKeyFile:            smtpConfig.publicKey,
				ClientAuthType:           "NoClientCert",
				PreferServerCipherSuites: true,
				Curves:                   []string{"P256", "P384", "P521", "X25519"},
				Ciphers: []string{
					"TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
					"TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
					"TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305",
					"TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305",
					"TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
					"TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
					"TLS_FALLBACK_SCSV",
				},
				Protocols: []string{"tls1.2"}, //TODO: add tls1.3
			}
		}
	}

	cfg.Servers = append(cfg.Servers, sc)

	var processors string

	if smtpConfig.debug {
		processors = "HeadersParser|Hasher|Header|Debugger|Forwarder"
	} else {
		processors = "HeadersParser|Hasher|Header|Forwarder"
	}

	bcfg := backends.BackendConfig{
		"save_workers_size":     3,
		"save_process":          processors,
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
		return fmt.Errorf("failed to start smtp server: %w", err)
	}

	interrupt := make(chan os.Signal, 1)
	signal.Notify(interrupt, os.Interrupt)
	signal.Notify(interrupt, syscall.SIGTERM)

	<-interrupt
	log.Println("Waiting for the SMTP server to shutdown...")
	d.Shutdown()

	return nil
}
