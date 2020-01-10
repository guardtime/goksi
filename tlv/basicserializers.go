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
)

// Encoder keeps the TLV serialization state.
//
// Serialization of TLV structures is performed from the most inner structure up to the root TLV.
type Encoder struct {
	buffer   []byte
	position uint64
}

// NewEncoder creates memory buffer ready to store serialized TLV.
func NewEncoder() (*Encoder, error) {
	return &Encoder{
		buffer:   make([]byte, MaxBufferSize),
		position: uint64(MaxBufferSize - 1),
	}, nil
}

// Bytes returns current serialized state of the encoder.
func (e *Encoder) Bytes() []byte {
	if e == nil {
		return nil
	}
	return e.buffer[e.position+1:]
}

// PrependUint64 function serializes uint64 as big-endian beginning from position towards smaller
// indexes.
func (e *Encoder) PrependUint64(value uint64) (uint64, error) {
	if e == nil {
		return 0, errors.New(errors.KsiInvalidArgumentError)
	}

	bufLen := uint64(len(e.buffer))
	// Verify buffer capacity.
	if (e.position == 0 && value > 0xff) || bufLen <= e.position {
		return 0, errors.New(errors.KsiBufferOverflow).AppendMessage("Buffer to serialize uint64 is too small.")
	}

	e.buffer[e.position] = byte(value)
	value >>= 8
	c := uint64(1)

	for value > 0 {
		if (e.position + 1 - c) == 0 {
			return 0, errors.New(errors.KsiBufferOverflow).AppendMessage("Buffer to serialize uint64 is too small.")
		}

		e.buffer[e.position-c] = byte(value)
		c++

		value >>= 8
	}
	e.position -= c

	return c, nil
}

// PrependUint64E function serializes uint64 as big-endian beginning from position towards smaller
// indexes. When value is 0, TLV is built without a value.
func (e *Encoder) PrependUint64E(value uint64) (uint64, error) {
	if value == 0 {
		return 0, nil
	}
	return e.PrependUint64(value)
}

// PrependUint8 function serializes uint64 as big-endian beginning from position towards smaller
// indexes. Note that input is still uint64 but its size is limited with 1 byte.
func (e *Encoder) PrependUint8(value uint64) (uint64, error) {
	if e == nil {
		return 0, errors.New(errors.KsiInvalidArgumentError)
	}

	bufLen := uint64(len(e.buffer))
	// Verify buffer capacity.
	if bufLen <= e.position {
		return 0, errors.New(errors.KsiBufferOverflow).AppendMessage("Buffer to serialize uint8 is too small.")
	}
	if value > 0xff {
		return 0, errors.New(errors.KsiInvalidFormatError).AppendMessage(
			fmt.Sprintf("Value for 8bit integer out of boundaries (%v).", value))
	}

	e.buffer[e.position] = byte(value)
	e.position -= 1

	return 1, nil
}

// PrependUint8E function serializes uint64 as big-endian beginning from position towards smaller
// indexes. Note that input is still uint64 but its size is limited with 1 byte. When value is 0, TLV is built
// without a value.
func (e *Encoder) PrependUint8E(value uint64) (uint64, error) {
	if value == 0 {
		return 0, nil
	}
	return e.PrependUint8(value)
}

// PrependUtf8 function serializes utf8 NUL terminated string as big-endian beginning from position
// towards smaller indexes.
func (e *Encoder) PrependUtf8(str string) (uint64, error) {
	if e == nil {
		return 0, errors.New(errors.KsiInvalidArgumentError)
	}

	var (
		strLen = uint64(len(str))
		bufLen = uint64(len(e.buffer))
	)
	// Verify buffer capacity.
	if (e.position+uint64(1) < (strLen + 1)) || bufLen <= e.position {
		return 0, errors.New(errors.KsiBufferOverflow).AppendMessage("Buffer to serialize string is too small.")
	}

	e.buffer[e.position] = 0
	c := uint64(copy(e.buffer[e.position-strLen:], str))
	e.position -= c + 1

	return c + 1, nil
}

// PrependBinary function serializes binary slice as big-endian beginning from position towards smaller
// indexes.
func (e *Encoder) PrependBinary(bin []byte) (uint64, error) {
	if e == nil {
		return 0, errors.New(errors.KsiInvalidArgumentError)
	}

	var (
		binLen = uint64(len(bin))
		bufLen = uint64(len(e.buffer))
	)
	// Verify buffer capacity.
	if (e.position+uint64(1) < binLen) || bufLen <= e.position {
		return 0, errors.New(errors.KsiBufferOverflow).AppendMessage("Buffer to serialize binary is too small.")
	}

	c := uint64(copy(e.buffer[e.position+1-binLen:], bin))
	e.position -= c

	return c, nil
}

// PrependHeader function serializes TLV header with given parameters as big-endian beginning from
// position towards smaller indexes.
func (e *Encoder) PrependHeader(tag uint16, isNonCritical, isForwardUnknown bool, valueLen uint64) (uint64, error) {
	if e == nil {
		return 0, errors.New(errors.KsiInvalidArgumentError)
	}

	var (
		bufLen = uint64(len(e.buffer))
		hdrLen = uint64(2)
	)
	// Update header length.
	if valueLen > 0xff || tag > uint16(HeaderTypeMask) {
		hdrLen = 4
	}
	// Verify buffer capacity.
	if (e.position+uint64(1) < hdrLen) || bufLen <= e.position {
		return 0, errors.New(errors.KsiBufferOverflow).AppendMessage("Buffer to serialize TLV header is too small.")
	}

	if hdrLen == 4 {
		if tag > MaxTagValue {
			return 0, errors.New(errors.KsiInvalidFormatError).AppendMessage("TLV tag exceeds maximum range.")
		}
		e.buffer[e.position-3] = byte(tag>>8&uint16(HeaderTypeMask)) | byte(HeaderFlag16)
		e.buffer[e.position-2] = byte(tag)

		e.buffer[e.position-1] = byte(valueLen >> 8)
		e.buffer[e.position] = byte(valueLen)
	} else {
		e.buffer[e.position-1] = byte(tag & uint16(HeaderTypeMask))
		e.buffer[e.position] = byte(valueLen)
	}
	e.position -= hdrLen

	if isNonCritical {
		e.buffer[e.position+1] |= byte(HeaderFlagN)
	}
	if isForwardUnknown {
		e.buffer[e.position+1] |= byte(HeaderFlagF)
	}

	return hdrLen, nil
}
