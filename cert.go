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
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"io/ioutil"
	"math/big"
	"os"
	"time"

	"github.com/pkg/errors"
)

func publicKey(priv interface{}) interface{} {
	switch k := priv.(type) {
	case *rsa.PrivateKey:
		return &k.PublicKey
	case *ecdsa.PrivateKey:
		return &k.PublicKey
	default:
		return nil
	}
}

func pemBlockForKey(priv interface{}) (*pem.Block, error) {
	switch k := priv.(type) {
	case *rsa.PrivateKey:
		return &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(k)}, nil
	case *ecdsa.PrivateKey:
		b, err := x509.MarshalECPrivateKey(k)
		if err != nil {
			return nil, errors.Wrap(err, "unable to marshal ECDSA private key")
		}
		return &pem.Block{Type: "EC PRIVATE KEY", Bytes: b}, nil
	default:
		return nil, nil
	}
}

func generateKeys(hostname, privPath, pubPath string) error {
	priv, err := ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
	if err != nil {
		return errors.Wrap(err, "failed to generate private key")
	}

	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Organization: []string{"GoForward"},
			CommonName:   hostname,
		},
		DNSNames:              []string{hostname},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().AddDate(10, 0, 0),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, publicKey(priv), priv)
	if err != nil {
		return errors.Wrap(err, "failed to create certificate")
	}

	out := &bytes.Buffer{}
	if err = pem.Encode(out, &pem.Block{Type: "CERTIFICATE", Bytes: derBytes}); err != nil {
		return errors.Wrap(err, "failed to encode certificate")
	}

	if err = ioutil.WriteFile(pubPath, out.Bytes(), 0644); err != nil {
		return errors.Wrap(err, "failed to create certificate file")
	}

	blk, err := pemBlockForKey(priv)
	if err != nil {
		return errors.Wrap(err, "failed to generate block for private key")
	}

	if err = pem.Encode(out, blk); err != nil {
		os.Remove(pubPath)
		return errors.Wrap(err, "failed to encode private key")
	}

	if err = ioutil.WriteFile(privPath, out.Bytes(), 0600); err != nil {
		os.Remove(pubPath)
		return errors.Wrap(err, "failed to create private key file")
	}

	return nil
}

func generateKeyPair(config *smtpConfig) error {
	priv, err := ioutil.TempFile("", "privkey")
	if err != nil {
		return errors.Wrap(err, "failed to create privkey temp file")
	}
	priv.Close()

	pub, err := ioutil.TempFile("", "pubkey")
	if err != nil {
		os.Remove(priv.Name())
		return errors.Wrap(err, "failed to create pubkey temp file")
	}
	pub.Close()

	if err = generateKeys(config.host, priv.Name(), pub.Name()); err != nil {
		os.Remove(priv.Name())
		os.Remove(pub.Name())
		return errors.Wrap(err, "cannot generate keys")
	}

	config.privateKey = priv.Name()
	config.publicKey = pub.Name()

	return nil
}
