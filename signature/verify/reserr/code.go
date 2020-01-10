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

package reserr

// Code is the verification result error code.
type Code byte

const (
	// ErrNA represents an unknown error code (invalid state).
	ErrNA Code = iota
	// Gen01 (GEN-01) Wrong document.
	Gen01
	// Gen02 (GEN-02) Verification inconclusive.
	Gen02
	// Gen03 (GEN-03) Input hash level too large.
	Gen03
	// Gen04 (GEN-04) Wrong input hash algorithm.
	Gen04
	// Int01 (INT-01) Inconsistent aggregation hash chains.
	Int01
	// Int02 (INT-02) Inconsistent aggregation hash chain aggregation times.
	Int02
	// Int03 (INT-03) Calendar hash chain input hash mismatch.
	Int03
	// Int04 (INT-04) Calendar hash chain aggregation time mismatch.
	Int04
	// Int05 (INT-05) Calendar hash chain shape inconsistent with aggregation time.
	Int05
	// Int06 (INT-06) Calendar hash chain time inconsistent with calendar authentication record time.
	Int06
	// Int07 (INT-07) Calendar hash chain time inconsistent with publication time.
	Int07
	// Int08 (INT-08) Calendar hash chain root hash is inconsistent with calendar authentication record input hash.
	Int08
	// Int09 (INT-09) Calendar hash chain root hash is inconsistent with published hash value.
	Int09
	// Int10 (INT-10) Aggregation hash chain chain index mismatch.
	Int10
	// Int11 (INT-11) The metadata record in the aggregation hash chain may not be trusted.
	Int11
	// Int12 (INT-12) Inconsistent chain indexes.
	Int12
	// Int13 (INT-13) Document hash algorithm deprecated at the time of signing.
	Int13
	// Int14 (INT-14) RFC3161 compatibility record composed of hash algorithms that where deprecated at the time of signing.
	Int14
	// Int15 (INT-15) Aggregation hash chain uses hash algorithm that was deprecated at the time of signing.
	Int15
	// Int16 (INT-16) Calendar hash chain hash algorithm was obsolete at publication time.
	Int16
	// Int17 (INT-17) The RFC3161 compatibility record output hash algorithm was deprecated at the time of signing.
	Int17
	// Pub01 (PUB-01) Extender response calendar root hash mismatch.
	Pub01
	// Pub02 (PUB-02) Extender response inconsistent.
	Pub02
	// Pub03 (PUB-03) Extender response input hash mismatch.
	Pub03
	// Pub04 (PUB-04) Publication record hash and user provided publication hash mismatch.
	Pub04
	// Pub05 (PUB-05) Publication record hash and publications file publication hash mismatch.
	Pub05
	// Key02 (KEY-02) PKI signature not verified with certificate.
	Key02
	// Key03 (KEY-03) Signing certificate not valid at aggregation time.
	Key03
	// Cal01 (CAL-01) Calendar root hash mismatch between signature and calendar database chain.
	Cal01
	// Cal02 (CAL-02) Aggregation hash chain root hash and calendar database hash chain input hash mismatch.
	Cal02
	// Cal03 (CAL-03) Aggregation time mismatch.
	Cal03
	// Cal04 (CAL-04) Calendar hash chain right links are inconsistent.
	Cal04
)

type codeInfo struct {
	code    string
	message string
}

var infoMap = map[Code]codeInfo{
	ErrNA: {"None", "Unknown"},

	Gen01: {"GEN-01", "Wrong document"},
	Gen02: {"GEN-02", "Verification inconclusive"},
	Gen03: {"GEN-03", "Input hash level too large"},
	Gen04: {"GEN-04", "Wrong input hash algorithm"},

	Int01: {"INT-01", "Inconsistent aggregation hash chains"},
	Int02: {"INT-02", "Inconsistent aggregation hash chain aggregation times"},
	Int03: {"INT-03", "Calendar hash chain input hash mismatch"},
	Int04: {"INT-04", "Calendar hash chain aggregation time mismatch"},
	Int05: {"INT-05", "Calendar hash chain shape inconsistent with aggregation time"},
	Int06: {"INT-06", "Calendar hash chain time inconsistent with calendar authentication record time"},
	Int07: {"INT-07", "Calendar hash chain time inconsistent with publication time"},
	Int08: {"INT-08", "Calendar hash chain root hash is inconsistent with calendar authentication record input hash"},
	Int09: {"INT-09", "Calendar hash chain root hash is inconsistent with published hash value"},
	Int10: {"INT-10", "Aggregation hash chain chain index mismatch"},
	Int11: {"INT-11", "The metadata record in the aggregation hash chain may not be trusted"},
	Int12: {"INT-12", "Inconsistent chain indexes"},
	Int13: {"INT-13", "Document hash algorithm deprecated at the time of signing"},
	Int14: {"INT-14", "RFC3161 compatibility record composed of hash algorithms that where deprecated at the time of signing"},
	Int15: {"INT-15", "Aggregation hash chain uses hash algorithm that was deprecated at the time of signing"},
	Int16: {"INT-16", "Calendar hash chain hash algorithm was obsolete at publication time"},
	Int17: {"INT-17", "The RFC3161 compatibility record output hash algorithm was deprecated at the time of signing"},

	Pub01: {"PUB-01", "Extender response calendar root hash mismatch"},
	Pub02: {"PUB-02", "Extender response inconsistent"},
	Pub03: {"PUB-03", "Extender response input hash mismatch"},
	Pub04: {"PUB-04", "Publication record hash and user provided publication hash mismatch"},
	Pub05: {"PUB-05", "Publication record hash and publications file publication hash mismatch"},

	Key02: {"KEY-02", "PKI signature not verified with certificate"},
	Key03: {"KEY-03", "Signing certificate not valid at aggregation time"},

	Cal01: {"CAL-01", "Calendar root hash mismatch between signature and calendar database chain"},
	Cal02: {"CAL-02", "Aggregation hash chain root hash and calendar database hash chain input hash mismatch"},
	Cal03: {"CAL-03", "Aggregation time mismatch"},
	Cal04: {"CAL-04", "Calendar hash chain right links are inconsistent"},
}

// String returns the string representation of the error code.
func (c Code) String() string {
	return infoMap[c].code
}

// Message returns the descriptive message for the given error code.
func (c Code) Message() string {
	return infoMap[c].message
}

// CodeByName returns an error code representation of the provided name.
// Returns ErrNA in case of an invalid code name.
func CodeByName(name string) Code {
	for code, inf := range infoMap {
		if inf.code == name {
			return code
		}
	}
	return ErrNA
}
