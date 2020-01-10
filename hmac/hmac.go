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

// Package hmac implements the Keyed-Hash Message Authentication Code (HMAC) computation functions.
//
// An HMAC is a cryptographic hash that uses a key to sign a message. The receiver verifies the hash by recomputing it
// using the same key.
//
// The computed HMAC is represented as an hash.(Imprint).
package hmac

import (
	"crypto/hmac"
	"fmt"
	"hash"

	"github.com/guardtime/goksi/errors"
	ksihash "github.com/guardtime/goksi/hash"
)

// Hasher is the message authentication computation object.
type Hasher struct {
	algo ksihash.Algorithm
	// Crypro library HMAC hasher.
	hsr hash.Hash
}

// New returns a new HMAC hash using the given hash.Algorithm type and key.
func New(alg ksihash.Algorithm, key []byte) (h *Hasher, e error) {
	if !alg.Registered() {
		return nil, errors.New(errors.KsiInvalidArgumentError).AppendMessage("Hash algorithm is not supported.")
	}

	// Recover method for unforeseen panics.
	defer func() {
		if r := recover(); r != nil {
			if ksiError, ok := r.(*errors.KsiError); ok {
				e = ksiError
				return
			}
			// Unknown crypto error returned.
			e = errors.New(errors.KsiCryptoFailure).
				AppendMessage(fmt.Sprintf("Paniced while HMAC initilization: %s", r))
		}
	}()
	// Initialize HMAC hasher.
	tmp := &Hasher{
		algo: alg,
		hsr: hmac.New(
			func() hash.Hash {
				hFunc, err := alg.HashFunc()
				if err != nil {
					panic(err)
				}
				return hFunc
			},
			key,
		),
	}
	return tmp, nil
}

// Imprint returns KSI imprint for the current computation.
// It does not change the underlying hash state.
func (h *Hasher) Imprint() (ksihash.Imprint, error) {
	if h == nil || h.hsr == nil {
		return nil, errors.New(errors.KsiInvalidArgumentError)
	}
	return h.sum(nil), nil
}

func (h *Hasher) sum(b []byte) ksihash.Imprint {
	imprint := make([]byte, 1+h.hsr.Size())
	imprint[0] = byte(h.algo)
	copy(imprint[1:], h.hsr.Sum(b))
	return imprint
}

// Write (via the embedded io.Writer interface) adds more data to the running hash.
// In case of KsiInvalidArgumentError error (e.g. h is nil) function returns non
// standard -1 as count of bytes written.
func (h *Hasher) Write(p []byte) (int, error) {
	if h == nil || h.hsr == nil {
		return -1, errors.New(errors.KsiInvalidArgumentError)
	}

	n, e := h.hsr.Write(p)
	if e != nil {
		return n, errors.New(errors.KsiCryptoFailure).SetExtError(e)
	}
	return n, nil
}

// Size return the resulting digest length in bytes.
func (h *Hasher) Size() int {
	if h == nil || h.hsr == nil {
		return 0
	}
	return h.hsr.Size()
}

// BlockSize returns the size of the data block the underlying hash algorithm operates upon in bytes.
func (h *Hasher) BlockSize() int {
	if h == nil || h.hsr == nil {
		return 0
	}
	return h.hsr.BlockSize()
}

// Reset resets the hasher to its initial state.
func (h *Hasher) Reset() {
	if h == nil || h.hsr == nil {
		return
	}
	h.hsr.Reset()
}
