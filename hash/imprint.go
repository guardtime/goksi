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

package hash

import (
	"crypto"
	"crypto/subtle"
	"encoding/hex"
	"strings"

	"github.com/guardtime/goksi/errors"
)

// Imprint represents a hash value and consists of a one-octet hash function identifier concatenated with
// the hash value itself.
type Imprint []byte

// Implements Stringer interface.
// Returns empty string in case of invalid imprint.
func (i Imprint) String() string {
	if i.IsValid() != true {
		return ""
	}
	var b strings.Builder
	b.WriteString(Algorithm(i[0]).String())
	b.WriteString(":")
	b.WriteString(hex.EncodeToString(i[1:]))
	return b.String()
}

// IsValid validates imprint internal consistency to comply with KSI hash Imprint definition.
func (i Imprint) IsValid() bool {
	return len(i) != 0 &&
		Algorithm(i[0]).Defined() &&
		len(i) == Algorithm(i[0]).Size()+1
}

// Algorithm returns the hash functions used to generate digest.
// Returns SHA_NA in case the imprint is not valid (see (Imprint).IsValid()).
func (i Imprint) Algorithm() Algorithm {
	if i.IsValid() != true {
		return SHA_NA
	}
	return Algorithm(i[0])
}

// Digest returns the binary hash value.
// Returns nil in case the imprint is not valid (see (Imprint).IsValid()).
func (i Imprint) Digest() []byte {
	if i.IsValid() != true {
		return nil
	}
	return i[1:]
}

// Equal returns true if, and only if, the two imprints are equal. The time taken is a function of the length of
// the slices and is independent of the contents.
func Equal(l, r Imprint) bool {
	return subtle.ConstantTimeCompare(l, r) == 1
}

// CryptoHashToImprint wraps the digest into Imprint. In case the digest parameter is nil, a zero imprint is returned.
//
// Note that the status of the hash algorithm is not verified. See (Algorithm).StatusAt().
//
// Possible return errors:
//  - KsiUnknownHashAlgorithm error in case the provided cryptoId is not defined by KSI;
//  - KsiInvalidFormatError error in case the length of the provided digest mismatch.
func CryptoHashToImprint(cryptoId crypto.Hash, digest []byte) (Imprint, error) {
	alg := SHA_NA
	for k, v := range hashInfoMap {
		if v.cryptoId != 0 && v.cryptoId == cryptoId {
			alg = k
		}
	}
	if alg == SHA_NA {
		return nil, errors.New(errors.KsiUnknownHashAlgorithm)
	}
	if digest == nil {
		return alg.ZeroImprint(), nil
	}
	if alg.Size() != len(digest) {
		return nil, errors.New(errors.KsiInvalidFormatError).AppendMessage("Algorithm digest length mismatch.")
	}
	tmp := make([]byte, 1+alg.Size())
	tmp[0] = byte(alg)
	copy(tmp[1:], digest)

	return tmp, nil
}
