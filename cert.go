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
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return errors.Wrap(err, "failed to generate private key")
	}

	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		return errors.Wrap(err, "failed to generate serial number")
	}

	template := x509.Certificate{
		SerialNumber: serialNumber,
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

	certOut, err := os.Create(pubPath)
	if err != nil {
		return errors.Wrapf(err, "failed to open %s for writing", pubPath)
	}

	if err = pem.Encode(certOut, &pem.Block{Type: "CERTIFICATE", Bytes: derBytes}); err != nil {
		return errors.Wrapf(err, "failed to write public key data to %s", pubPath)
	}

	if err := certOut.Close(); err != nil {
		return errors.Wrapf(err, "error closing %s", pubPath)
	}

	keyOut, err := os.OpenFile(privPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		return errors.Wrapf(err, "failed to open %s for writing", privPath)
	}

	blk, err := pemBlockForKey(priv)
	if err != nil {
		return errors.Wrap(err, "failed to generate block for private key")
	}

	if err = pem.Encode(keyOut, blk); err != nil {
		os.Remove(pubPath)
		return errors.Wrapf(err, "failed to write private key to %s", privPath)
	}

	if err := keyOut.Close(); err != nil {
		os.Remove(pubPath)
		os.Remove(privPath)
		return errors.Wrapf(err, "error closing %s", privPath)
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
