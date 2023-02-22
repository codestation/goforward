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

package forward

import (
	"fmt"
	"strings"

	"github.com/flashmob/go-guerrilla/backends"
	"github.com/flashmob/go-guerrilla/mail"
	"github.com/flashmob/go-guerrilla/response"
	log "github.com/sirupsen/logrus"
)

type forwardConfig struct {
	AliasesMap  string `json:"forwarder_aliases_map"`
	Credentials string `json:"forwarder_credentials"`
	Token       string `json:"forwarder_token"`
}

type forwarder struct {
	aliases map[string][]string
	config  *forwardConfig
}

func (m *forwarder) validateRcpt(addr mail.Address) backends.RcptError {
	u := strings.ToLower(addr.User)
	_, ok := m.aliases[u]
	if !ok {
		return backends.NoSuchUser
	}

	return nil
}

func newForwarder(config *forwardConfig) (*forwarder, error) {
	var err error
	m := &forwarder{}
	m.config = config
	m.aliases, err = aliasesmap(m.config.AliasesMap)
	if err != nil {
		return nil, fmt.Errorf("failed to build aliases map :%w", err)
	}

	return m, nil
}

func aliasesmap(aliasesmap string) (map[string][]string, error) {
	ret := make(map[string][]string, 0)
	aliases := strings.Split(aliasesmap, ",")

	for i := range aliases {
		u := strings.Split(aliases[i], "=")
		if len(u) != 2 {
			return nil, fmt.Errorf("entry %s ifn't on the key=value format", aliases[i])
		}

		names := strings.Split(u[0], ":")

		for j := range names {
			addresses := strings.Split(u[1], ":")
			name := strings.ToLower(names[j])

			ret[name] = append(ret[name], addresses...)
		}
	}
	return ret, nil
}

// Processor defines a gmail forwarder to be used on go-guerrilla
var Processor = func() backends.Decorator {
	var forwarder *forwarder
	// our initFunc will load the config.
	initFunc := backends.InitializeWith(func(backendConfig backends.BackendConfig) error {
		configType := backends.BaseConfig(&forwardConfig{})
		bcfg, err := backends.Svc.ExtractConfig(backendConfig, configType)
		if err != nil {
			return err
		}
		config := bcfg.(*forwardConfig)
		forwarder, err = newForwarder(config)
		if err != nil {
			return err
		}
		return nil
	})
	// register our initializer
	backends.Svc.AddInitializer(initFunc)

	return func(p backends.Processor) backends.Processor {
		return backends.ProcessWith(
			func(e *mail.Envelope, task backends.SelectTask) (backends.Result, error) {
				if task == backends.TaskValidateRcpt {
					for i := range e.RcptTo {
						err := forwarder.validateRcpt(e.RcptTo[i])
						if err != nil {
							log.WithFields(log.Fields{
								"email": e.RcptTo[i],
								"error": err.Error(),
							}).Info("Failed to validate recipient")
							return backends.NewResult(response.Canned.SuccessVerifyCmd), err
						}
					}

					return p.Process(e, task)
				} else if task == backends.TaskSaveMail {

					srv, err := newGmailService(GmailConfig{
						CredentialsPath: forwarder.config.Credentials,
						TokenPath:       forwarder.config.Token,
					})
					if err != nil {
						return backends.NewResult(fmt.Sprintf("554 Error: %s", err)), err
					}

					message := makeMessage(e)
					log.Debugf("BASE64 message: %s", message.Raw)

					for i := range e.RcptTo {
						addresses := forwarder.aliases[e.RcptTo[i].User]

						for j := range addresses {
							user := addresses[j]
							_, err = srv.Users.Messages.Import(user, message).Do()
							if err != nil {
								log.Warningf("failed to import the message to '%s': %v", user, err)
							}
						}
					}

					return p.Process(e, task)
				}
				return p.Process(e, task)
			},
		)
	}
}
