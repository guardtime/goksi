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

package result

// Code is the verification result code.
type Code byte

const (
	// OK states that verification succeeded, meaning there's a way to prove the correctness of the signature.
	OK Code = iota
	// NA states that verification not possible, meaning there is not enough data to prove or disprove the
	// correctness of the signature.
	NA
	// FAIL states that verification failed, meaning the signature is definitely invalid or the document does not
	// match with the signature.
	FAIL
)

// String implements fmt.(Stringer) interface.
func (c Code) String() string {
	switch c {
	case OK:
		return "OK"
	case NA:
		return "NA"
	case FAIL:
		return "FAIL"
	}
	// Should not happen
	return "Unknown"
}
