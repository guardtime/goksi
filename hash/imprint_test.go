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
	"crypto/subtle"
	"testing"
)

var (
	testImprintData = []struct {
		title    string
		expected bool
		imprint  Imprint
	}{
		{
			"Valid SHA2-256 imprint.",
			true,
			Imprint{0x01,
				0xc4, 0xbb, 0xcb, 0x1f, 0xbe, 0xc9, 0x9d, 0x65, 0xbf, 0x59, 0xd8, 0x5c, 0x8c, 0xb6, 0x2e, 0xe2,
				0xdb, 0x96, 0x3f, 0x0f, 0xe1, 0x06, 0xf4, 0x83, 0xd9, 0xaf, 0xa7, 0x3b, 0xd4, 0xe3, 0x9a, 0x8a},
		},
		{
			"Undefined hash algorithm.",
			true,
			Imprint{0xff,
				0xc4, 0xbb, 0xcb, 0x1f, 0xbe, 0xc9, 0x9d, 0x65, 0xbf, 0x59, 0xd8, 0x5c, 0x8c, 0xb6, 0x2e, 0xe2,
				0xdb, 0x96, 0x3f, 0x0f, 0xe1, 0x06, 0xf4, 0x83, 0xd9, 0xaf, 0xa7, 0x3b, 0xd4, 0xe3, 0x9a, 0x8a},
		},
		{
			"Invalid SHA2-256 digest length (longer).",
			true,
			Imprint{0x01,
				0xc4, 0xbb, 0xcb, 0x1f, 0xbe, 0xc9, 0x9d, 0x65, 0xbf, 0x59, 0xd8, 0x5c, 0x8c, 0xb6, 0x2e, 0xe2,
				0xdb, 0x96, 0x3f, 0x0f, 0xe1, 0x06, 0xf4, 0x83, 0xd9, 0xaf, 0xa7, 0x3b, 0xd4, 0xe3, 0x9a, 0x8a,
				0x00},
		},
		{
			"Invalid SHA2-256 digest length (shorter).",
			true,
			Imprint{0x01,
				0xc4, 0xbb, 0xcb, 0x1f, 0xbe, 0xc9, 0x9d, 0x65, 0xbf, 0x59, 0xd8, 0x5c, 0x8c, 0xb6, 0x2e, 0xe2,
				0xdb, 0x96, 0x3f, 0x0f, 0xe1, 0x06, 0xf4, 0x83, 0xd9, 0xaf, 0xa7, 0x3b, 0xd4, 0xe3, 0x9a},
		},
		{
			"Invalid imprint length.",
			true,
			Imprint{},
		},
	}
)

func TestUnitImprint_IsValid(t *testing.T) {
	for i, td := range testImprintData {
		if td.imprint.IsValid() {
			if !td.expected {
				t.Errorf("Must fail: (%d) %s", i, td.title)
			}
		} else {
			if !td.expected {
				t.Errorf("Must not fail: (%d) %s", i, td.title)
			}
		}
	}
}

func TestUnitImprint_Algorithm(t *testing.T) {
	for i, td := range testImprintData {
		algo := td.imprint.Algorithm()

		if algo != SHA_NA {
			if algo != Algorithm([]byte(td.imprint)[0]) {
				t.Errorf("Hash algorthm mismatch: (%d) %s", i, td.title)
			}

			if !td.expected {
				t.Errorf("Must fail: (%d) %s", i, td.title)
			}
		} else {
			if !td.expected {
				t.Errorf("Must not fail: (%d) %s", i, td.title)
			}
		}
	}
}

func TestUnitImprint_Digest(t *testing.T) {
	for i, td := range testImprintData {
		digest := td.imprint.Digest()

		if digest != nil {
			if subtle.ConstantTimeCompare(digest, []byte(td.imprint)[1:]) != 1 {
				t.Errorf("Digest mismatch: (%d) %s", i, td.title)
			}

			if !td.expected {
				t.Errorf("Must fail: (%d) %s", i, td.title)
			}
		} else {
			if !td.expected {
				t.Errorf("Must not fail: (%d) %s", i, td.title)
			}
		}
	}
}

func TestUnitImprint_String(t *testing.T) {
	var (
		testImprint = Imprint{0x01,
			0xc4, 0xbb, 0xcb, 0x1f, 0xbe, 0xc9, 0x9d, 0x65, 0xbf, 0x59, 0xd8, 0x5c, 0x8c, 0xb6, 0x2e, 0xe2,
			0xdb, 0x96, 0x3f, 0x0f, 0xe1, 0x06, 0xf4, 0x83, 0xd9, 0xaf, 0xa7, 0x3b, 0xd4, 0xe3, 0x9a, 0x8a}
		testResult = "SHA-256:c4bbcb1fbec99d65bf59d85c8cb62ee2db963f0fe106f483d9afa73bd4e39a8a"

		testInvalidImprint = Imprint{0xff, 0, 2, 3, 4, 5, 6, 7, 8, 9}
	)

	if testImprint.String() != testResult {
		t.Error("Imprint string mismatch.")
	}

	if testInvalidImprint.String() != "" {
		t.Error("Invalid imprint must return empty string.")
	}
}
