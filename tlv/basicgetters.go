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

package tlv

import (
	"fmt"

	"github.com/guardtime/goksi/errors"
	"github.com/guardtime/goksi/hash"
)

// Uint64E is getter for uint64. If TLV is empty, 0 is returned. If TLV value is larger than 8 bits, error is returned.
func (t *Tlv) Uint64E() (uint64, error) {
	if t == nil {
		return 0, errors.New(errors.KsiInvalidArgumentError)
	}

	var tmp uint64
	valueLen := len(t.value)

	if valueLen > 8 {
		return 0, errors.New(errors.KsiInvalidFormatError).
			AppendMessage(fmt.Sprintf("TLV value for 64bit integer is too large (%v).", t.value))
	}

	for _, b := range t.value {
		tmp = tmp << 8
		tmp = tmp + uint64(b)
	}

	if valueLen == 0 {
		return 0, nil
	}
	return tmp, nil
}

// Uint64 is getter for uint64. If TLV is empty or TLV value is larger than 8 bits, error is returned.
func (t *Tlv) Uint64() (uint64, error) {
	if t == nil {
		return 0, errors.New(errors.KsiInvalidArgumentError)
	}

	var (
		value    uint64
		valueLen = len(t.value)
	)
	if valueLen == 0 {
		return 0, errors.New(errors.KsiInvalidFormatError).AppendMessage("TLV value for 64bit integer is empty.")
	} else if valueLen > 8 {
		return 0, errors.New(errors.KsiInvalidFormatError).
			AppendMessage(fmt.Sprintf("TLV value for 64bit integer is too large (%v).", t.value))
	}

	for _, b := range t.value {
		value <<= 8
		value += uint64(b)
	}
	return value, nil
}

// Uint8E is getter for uint8. If TLV is empty, 0 is returned. If TLV value is larger than 1 bit, error is returned.
func (t *Tlv) Uint8E() (uint64, error) {
	if t == nil {
		return 0, errors.New(errors.KsiInvalidArgumentError)
	}

	valueLen := len(t.value)
	if valueLen > 1 {
		return 0, errors.New(errors.KsiInvalidFormatError).
			AppendMessage(fmt.Sprintf("TLV value for 8bit integer is too large (%v).", t.value))
	}
	if valueLen == 0 {
		return 0, nil
	}
	return uint64(t.value[0]), nil
}

// Uint8 is getter for uint8. If TLV is empty or TLV value is larger than 1 bit, error is returned.
func (t *Tlv) Uint8() (uint64, error) {
	if t == nil {
		return 0, errors.New(errors.KsiInvalidArgumentError)
	}

	valueLen := len(t.value)
	if valueLen == 0 {
		return 0, errors.New(errors.KsiInvalidFormatError).AppendMessage("TLV value for 8bit integer is empty.")
	} else if valueLen > 1 {
		return 0, errors.New(errors.KsiInvalidFormatError).
			AppendMessage(fmt.Sprintf("TLV value for 8bit integer is too large (%v).", t.value))
	}
	return uint64(t.value[0]), nil
}

// Utf8E is getter for string. TLV value must end with 0 octet that is left out from returned string.
// If TLV is empty, empty string is returned.
func (t *Tlv) Utf8E() (string, error) {
	if t == nil {
		return "", errors.New(errors.KsiInvalidArgumentError)
	}
	n := len(t.value)
	if n > 0 && t.value[n-1] != 0 {
		return "", errors.New(errors.KsiInvalidFormatError).AppendMessage("String must end with 0 octet.")
	}

	if n == 0 {
		return "", nil
	}
	return string(t.value[:n-1]), nil
}

// Utf8 is getter for string. TLV value must end with 0 octet that is left out from returned string.
// If TLV is empty, error is returned.
func (t *Tlv) Utf8() (string, error) {
	if t == nil {
		return "", errors.New(errors.KsiInvalidArgumentError)
	}
	n := len(t.value)
	if n == 0 {
		return "", errors.New(errors.KsiInvalidFormatError).AppendMessage("TLV value for string is empty.")
	}
	if n > 0 && t.value[n-1] != 0 {
		return "", errors.New(errors.KsiInvalidFormatError).AppendMessage("String must end with 0 octet.")
	}

	return string(t.value[:n-1]), nil
}

// Binary is getter for TLV value.
func (t *Tlv) Binary() ([]byte, error) {
	if t == nil {
		return nil, errors.New(errors.KsiInvalidArgumentError)
	}
	return t.value, nil
}

// Imprint is getter for hash imprint value. If imprint format is invalid, error is returned.
func (t *Tlv) Imprint() ([]byte, error) {
	if t == nil {
		return nil, errors.New(errors.KsiInvalidArgumentError)
	}
	imprint := hash.Imprint(t.value)
	if !imprint.IsValid() {
		return nil, errors.New(errors.KsiInvalidFormatError).
			AppendMessage(fmt.Sprintf("TLV value does not contain a valid imprint (%v).", t.value))
	}
	return t.value, nil
}
