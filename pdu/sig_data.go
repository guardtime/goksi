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
	"github.com/guardtime/goksi/errors"
)

// SignatureType returns the signature type.
// If not set, an error is returned.
//
// A signing algorithm and signature format identifier, as assigned by IANA, represented as an UTF-8 string containing
// a dotted decimal object identifier (OID).
//
// As an example, the signature type "1.2.840.113549.1.1.11" (for "SHA-256 with RSA encryption") would
// indicate a signature formed by hashing the published data with the SHA2-256 algorithm and then signing the
// resulting hash value with an RSA private key.
func (s *SignatureData) SignatureType() (string, error) {
	if s == nil || s.sigType == nil {
		return "", errors.New(errors.KsiInvalidArgumentError)
	}
	return *s.sigType, nil
}

// SignatureValue returns the signature itself, computed and formatted according to the specified method.
// If not set, an error is returned.
func (s *SignatureData) SignatureValue() ([]byte, error) {
	if s == nil || s.sigValue == nil {
		return nil, errors.New(errors.KsiInvalidArgumentError)
	}
	return *s.sigValue, nil
}

// CertID returns the certificate identifier.
// If not set, an error is returned.
func (s *SignatureData) CertID() ([]byte, error) {
	if s == nil || s.certID == nil {
		return nil, errors.New(errors.KsiInvalidArgumentError)
	}
	return *s.certID, nil
}

// CertRepURI returns the optional certificate repository URI, pointing to a repository (e.g. a publication file) that
// contains the certificate identified by the 'certificate identifier' (see (SignatureData).CertID()).
func (s *SignatureData) CertRepURI() (string, error) {
	if s == nil {
		return "", errors.New(errors.KsiInvalidArgumentError)
	}
	if s.certRepURI == nil {
		return "", nil
	}
	return *s.certRepURI, nil
}
