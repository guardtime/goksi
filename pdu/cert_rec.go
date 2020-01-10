/*
 * Copyright 2020 Guardtime, Inc.
 *
 * This file is part of the Guardtime client SDK.
 *
 * Licensed under the Apache License, Version 2.0 (the "License").
 * You may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *     http://www.apache.org/licenses/LICENSE-2.0
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES, CONDITIONS, OR OTHER LICENSES OF ANY KIND, either
 * express or implied. See the License for the specific language governing
 * permissions and limitations under the License.
 * "Guardtime" and "KSI" are trademarks or registered trademarks of
 * Guardtime, Inc., and no license to trademarks is granted; Guardtime
 * reserves and retains all trademark rights.
 */

package pdu

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"fmt"
	"math/big"
	"time"

	"github.com/guardtime/goksi/errors"
	"github.com/guardtime/goksi/log"
)

// CertID returns certificate ID, or error if not present.
func (c *CertificateRecord) CertID() ([]byte, error) {
	if c == nil || c.certID == nil {
		return nil, errors.New(errors.KsiInvalidArgumentError)
	}
	return *c.certID, nil
}

// Cert returns x509 certificate, or error if not present.
func (c *CertificateRecord) Cert() ([]byte, error) {
	if c == nil || c.cert == nil {
		return nil, errors.New(errors.KsiInvalidArgumentError)
	}
	return *c.cert, nil
}

func (c *CertificateRecord) validityBounds() (nb time.Time, na time.Time, err error) {
	if c == nil || c.cert == nil {
		return nb, na, errors.New(errors.KsiInvalidArgumentError)
	}

	cert, err := x509.ParseCertificate(*c.cert)
	if err != nil {
		return nb, na, errors.New(errors.KsiCryptoFailure).SetExtError(err).
			AppendMessage("Failed to parse certificate.")
	}
	return cert.NotBefore, cert.NotAfter, nil
}

// IsValid verifies that the certificate is valid at the given time.
func (c *CertificateRecord) IsValid(at time.Time) (bool, error) {
	if c == nil || at.IsZero() {
		return false, errors.New(errors.KsiInvalidArgumentError)
	}

	notBefore, notAfter, err := c.validityBounds()
	if err != nil {
		return false, err
	}
	return at.After(notBefore) && at.Before(notAfter), nil
}

// VerifySigType compares the signature type OID string representation to the one included in the x509 certificate.
// As an example, the signature type "1.2.840.113549.1.1.11" (for "SHA-256 with RSA encryption") would
// indicate a signature formed by hashing the published data with the SHA2-256 algorithm and then signing the
// resulting hash value with an RSA private key.
// See also asn1.(ObjectIdentifier).String().
func (c *CertificateRecord) VerifySigType(sigType string) error {
	if c == nil || c.cert == nil {
		return errors.New(errors.KsiInvalidArgumentError)
	}

	cert, err := asn1Data(*c.cert).parseCertificate()
	if err != nil {
		return err
	}

	if cert.SignatureAlgorithm.Algorithm.String() != sigType {
		err = errors.New(errors.KsiInvalidPkiSignature).
			AppendMessage("Signature type OID mismatch.").
			AppendMessage(fmt.Sprintf("Certificate OID=%s, expected signature type=%s", cert.SignatureAlgorithm.Algorithm, sigType))
		log.Debug(err)
		return err
	}
	return nil
}

type asn1Data []byte

func (d asn1Data) parseCertificate() (*certificate, error) {
	var tmp certificate
	_, err := asn1.Unmarshal(d, &tmp)
	if err != nil {
		return nil, errors.New(errors.KsiCryptoFailure).SetExtError(err).
			AppendMessage("Failed to parse ASN.1 structure of X.509 certificate.")
	}
	return &tmp, nil
}

// Structures reflecting the ASN.1 structure of X.509 certificates.
type (
	certificate struct {
		TBSCertificate     tbsCertificate
		SignatureAlgorithm pkix.AlgorithmIdentifier
		SignatureValue     asn1.BitString
	}

	tbsCertificate struct {
		Version            int `asn1:"optional,explicit,default:0,tag:0"`
		SerialNumber       *big.Int
		SignatureAlgorithm pkix.AlgorithmIdentifier
		Issuer             asn1.RawValue
		Validity           validity
		Subject            asn1.RawValue
		PublicKey          publicKeyInfo
		UniqueId           asn1.BitString   `asn1:"optional,tag:1"`
		SubjectUniqueId    asn1.BitString   `asn1:"optional,tag:2"`
		Extensions         []pkix.Extension `asn1:"optional,explicit,tag:3"`
	}

	validity struct {
		NotBefore, NotAfter time.Time
	}

	publicKeyInfo struct {
		Algorithm pkix.AlgorithmIdentifier
		PublicKey asn1.BitString
	}
)
