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
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"

	"github.com/flashmob/go-guerrilla/mail"
	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
	"github.com/skratchdot/open-golang/open"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
	"google.golang.org/api/gmail/v1"
	"google.golang.org/api/option"
)

// GmailConfig defines the credentials.json and token.json locations
type GmailConfig struct {
	CredentialsPath string
	TokenPath       string
}

// RequestToken requests a token from the web
func RequestToken(config GmailConfig) error {
	credConfig, err := readClientSecret(config.CredentialsPath)
	if err != nil {
		return errors.Wrap(err, "failed to read credentials")
	}

	token := getTokenFromWeb(credConfig)
	return saveToken(config.TokenPath, token)
}

// Request a token from the web, then returns the retrieved token.
func getTokenFromWeb(config *oauth2.Config) *oauth2.Token {
	authURL := config.AuthCodeURL("state-token", oauth2.AccessTypeOffline)
	fmt.Printf("Go to the following link in your browser then type the "+
		"authorization code: \n%v\nAuthorization code: ", authURL)

	err := open.Start(authURL)
	if err != nil {
		log.Debugf("Failed to open the auth URL on the browser: %v", err)
	}

	var authCode string
	if _, err := fmt.Scan(&authCode); err != nil {
		log.Fatalf("Unable to read authorization code: %v", err)
	}

	tok, err := config.Exchange(context.TODO(), authCode)
	if err != nil {
		log.Fatalf("Unable to retrieve token from web: %v", err)
	}
	return tok
}

// Retrieves a token from a local file.
func tokenFromFile(file string) (*oauth2.Token, error) {
	f, err := os.Open(file)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	tok := &oauth2.Token{}
	err = json.NewDecoder(f).Decode(tok)
	return tok, err
}

// Saves a token to a file path.
func saveToken(path string, token *oauth2.Token) error {
	log.Debugf("Saving credential file to: %s\n", path)
	f, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		return errors.Wrapf(err, "unable to cache oauth token")
	}

	defer f.Close()

	err = json.NewEncoder(f).Encode(token)
	if err != nil {
		return errors.Wrap(err, "cannot encode token to json")
	}

	return nil
}

func makeMessage(e *mail.Envelope) *gmail.Message {
	msg := &gmail.Message{
		LabelIds: []string{"UNREAD", "INBOX"},
		Raw:      base64.URLEncoding.EncodeToString([]byte(e.String())),
	}

	return msg
}

func readClientSecret(configFile string) (*oauth2.Config, error) {
	var config *oauth2.Config

	bytes, err := ioutil.ReadFile(configFile)
	if err != nil {
		return nil, errors.Wrap(err, "unable to read client secret file")
	}

	config, err = google.ConfigFromJSON(bytes, gmail.GmailInsertScope)
	if err != nil {
		return nil, errors.Wrap(err, "unable to parse client secret file to config")
	}

	return config, nil
}

func newGmailService(config GmailConfig) (*gmail.Service, error) {
	credConfig, err := readClientSecret(config.CredentialsPath)
	if err != nil {
		return nil, errors.Wrap(err, "cannot read client secret")
	}

	token, err := tokenFromFile(config.TokenPath)
	if err != nil {
		return nil, errors.Wrap(err, "cannot read client token")
	}

	ctx := context.Background()
	tokenSrc := credConfig.TokenSource(ctx, token)
	opt := option.WithTokenSource(tokenSrc)

	return gmail.NewService(ctx, opt)
}
