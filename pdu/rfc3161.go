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
	"time"

	"github.com/guardtime/goksi/errors"
	"github.com/guardtime/goksi/hash"
)

// AggregationTime returns aggregation chain aggregation time.
// If time is not present, an error is returned.
func (r *RFC3161) AggregationTime() (time.Time, error) {
	if r == nil {
		return time.Time{}, errors.New(errors.KsiInvalidArgumentError)
	}
	if r.aggrTime == nil {
		return time.Time{}, errors.New(errors.KsiInvalidStateError).
			AppendMessage("Inconsistent RFC3161 record.").
			AppendMessage("Missing aggregation time.")
	}
	return time.Unix(int64(*r.aggrTime), 0), nil
}

// ChainIndex returns aggregation chain index.
// If chain index is not present, an error is returned.
func (r *RFC3161) ChainIndex() ([]uint64, error) {
	if r == nil {
		return nil, errors.New(errors.KsiInvalidArgumentError)
	}
	if r.chainIndex == nil {
		return nil, errors.New(errors.KsiInvalidStateError).
			AppendMessage("Inconsistent RFC3161 record.").
			AppendMessage("Missing chain index.")
	}
	return *r.chainIndex, nil
}

// InputData returns input data.
// If data is not present, nil is returned.
func (r *RFC3161) InputData() ([]byte, error) {
	if r == nil {
		return nil, errors.New(errors.KsiInvalidArgumentError)
	}
	if r.inputData == nil {
		return nil, nil
	}

	return *r.inputData, nil
}

// InputHash returns input hash.
// If hash is not present, an error is returned.
func (r *RFC3161) InputHash() (hash.Imprint, error) {
	if r == nil {
		return nil, errors.New(errors.KsiInvalidArgumentError)
	}
	if r.inputHash == nil {
		return nil, errors.New(errors.KsiInvalidStateError).
			AppendMessage("Inconsistent RFC3161 record.").
			AppendMessage("Missing input hash.")
	}
	return *r.inputHash, nil
}

// TstInfoAlgo returns the hash function used to hash the TSTInfo structure.
// If hash is not present, an error is returned.
func (r *RFC3161) TstInfoAlgo() (hash.Algorithm, error) {
	if r == nil {
		return hash.SHA_NA, errors.New(errors.KsiInvalidArgumentError)
	}
	if r.tstInfoAlgo == nil {
		return hash.SHA_NA, errors.New(errors.KsiInvalidStateError).
			AppendMessage("Inconsistent RFC3161 record.").
			AppendMessage("Missing TST info algorithm.")
	}
	return hash.Algorithm(*r.tstInfoAlgo), nil
}

// SigAttrAlgo returns the hash function used to hash the SignedAttributes structure.
// If hash is not present, an error is returned.
func (r *RFC3161) SigAttrAlgo() (hash.Algorithm, error) {
	if r == nil {
		return hash.SHA_NA, errors.New(errors.KsiInvalidArgumentError)
	}
	if r.sigAttrAlgo == nil {
		return hash.SHA_NA, errors.New(errors.KsiInvalidStateError).
			AppendMessage("Inconsistent RFC3161 record.").
			AppendMessage("Missing signature attribute algorithm.")
	}
	return hash.Algorithm(*r.sigAttrAlgo), nil
}

// OutputHash calculates and returns the output hash of the RFC3161 record.
func (r *RFC3161) OutputHash(algorithm hash.Algorithm) (hash.Imprint, error) {
	if r == nil {
		return nil, errors.New(errors.KsiInvalidArgumentError)
	}
	if r.inputHash == nil ||
		r.tstInfoAlgo == nil || r.tstInfoPrefix == nil || r.tstInfoSuffix == nil ||
		r.sigAttrAlgo == nil || r.sigAttrPrefix == nil || r.sigAttrSuffix == nil {
		return nil, errors.New(errors.KsiInvalidStateError).
			AppendMessage("Inconsistent RFC3161 record.").
			AppendMessage("Missing mandatory elements.")
	}
	tstInfoAlgo := hash.Algorithm(*r.tstInfoAlgo)
	sigAttrAlgo := hash.Algorithm(*r.sigAttrAlgo)
	if !tstInfoAlgo.Defined() || !sigAttrAlgo.Defined() {
		return nil, errors.New(errors.KsiUnknownHashAlgorithm).
			AppendMessage("RFC3161 record contains unknown hash algorithm.")
	}

	tstInfoHsh, err := preSufHasher(*r.tstInfoPrefix, *r.inputHash, *r.tstInfoSuffix, tstInfoAlgo)
	if err != nil {
		return nil, errors.KsiErr(err).AppendMessage("Failed to calculate TSTInfo digest.")
	}
	sigAttrHsh, err := preSufHasher(*r.sigAttrPrefix, tstInfoHsh, *r.sigAttrSuffix, sigAttrAlgo)
	if err != nil {
		return nil, errors.KsiErr(err).AppendMessage("Failed to calculate signed attributes digest.")
	}

	hsr, err := algorithm.New()
	if err != nil {
		return nil, err
	}

	if _, err := hsr.Write(sigAttrHsh); err != nil {
		return nil, err
	}
	return hsr.Imprint()
}

func preSufHasher(prefix []byte, hsh hash.Imprint, suffix []byte, algorithm hash.Algorithm) (hash.Imprint, error) {
	if !hsh.IsValid() || !algorithm.Defined() {
		return nil, errors.New(errors.KsiInvalidArgumentError)
	}

	hsr, err := algorithm.New()
	if err != nil {
		return nil, err
	}

	if len(prefix) != 0 {
		if _, err := hsr.Write(prefix); err != nil {
			return nil, err
		}
	}
	if _, err := hsr.Write(hsh.Digest()); err != nil {
		return nil, err
	}
	if len(suffix) != 0 {
		if _, err := hsr.Write(suffix); err != nil {
			return nil, err
		}
	}
	return hsr.Imprint()
}
