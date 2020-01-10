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
	"fmt"
	"hash"

	"github.com/guardtime/goksi/errors"
)

// DataHasher is the data hash computation object.
type DataHasher struct {
	algo Algorithm
	hsr  hash.Hash
}

// New returns new hasher for the given hash algo.
// Returns error if the hash function is not linked into the binary.
func (a Algorithm) New() (*DataHasher, error) {
	hFunc, err := a.HashFunc()
	if err != nil {
		return nil, err
	}
	if hFunc == nil {
		return nil, errors.New(errors.KsiInvalidArgumentError).
			AppendMessage(fmt.Sprintf("%s hash function is not registered.", a.String()))
	}

	return &DataHasher{
		algo: a,
		hsr:  hFunc,
	}, nil
}

// Write (via the embedded io.Writer interface) adds more data to the running hash.
// In case of KsiInvalidArgumentError error (e.g. h is nil), function returns non
// standard -1 as count of bytes written.
func (h *DataHasher) Write(p []byte) (int, error) {
	if h == nil || h.hsr == nil {
		return -1, errors.New(errors.KsiInvalidArgumentError)
	}
	n, err := h.hsr.Write(p)
	if err != nil {
		return n, errors.New(errors.KsiCryptoFailure).SetExtError(err)
	}
	return n, nil
}

// Imprint returns KSI imprint for the current computation. It does not change the underlying hash state.
func (h *DataHasher) Imprint() (Imprint, error) {
	if h == nil || h.hsr == nil {
		return nil, errors.New(errors.KsiInvalidArgumentError)
	}
	return h.sum(nil), nil
}

// Sum appends the current hash to b and returns the resulting slice. It does not change the underlying hash state.
// Returns KSI imprint, where imprint first byte represents KSI hash function ID and remaining bytes contain data hash.
func (h *DataHasher) sum(b []byte) Imprint {
	imprint := make([]byte, 1+h.hsr.Size())
	imprint[0] = byte(h.algo)
	copy(imprint[1:], h.hsr.Sum(b))
	return imprint
}

// Reset resets the hasher to its initial state.
func (h *DataHasher) Reset() {
	if h == nil || h.hsr == nil {
		return
	}
	h.hsr.Reset()
}

// Size returns the resulting digest length in bytes for the given hash function.
// In case of an error, a negative value is returned.
func (h *DataHasher) Size() int {
	if h == nil || h.hsr == nil {
		return -1
	}
	return h.algo.Size()
}

// BlockSize returns the hash's underlying block size. The Write method must be able to accept any amount
// of data, but it may operate more efficiently if all writes are a multiple of the block size.
// In case of an error, a negative value is returned.
func (h *DataHasher) BlockSize() int {
	if h == nil || h.hsr == nil {
		return -1
	}
	return h.algo.BlockSize()
}
