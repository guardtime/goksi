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

// Package tlv provides functionality to map Go structures to TLV encoded data and vice versa.
//
// The mapping is done based on TLV templates. A 'Template' object is bound explicitly to a Go
// struct type (not the object value of that type). For a Template to be constructed, struct type
// fields must be annotated with tags, which provide mapping instructions (see (Template).Parse()
// for available annotations).
//
// A Template is an immutable object and thus may be constructed once and be used thought out the
// program's lifetime (see 'templates' package for template registry).
package tlv

import (
	"fmt"
	"io"
	"reflect"
	"strings"
	"unsafe"

	"github.com/guardtime/goksi/errors"
)

// Marshal returns the binary TLV encoding of v.
//
// Marshal traverses the value v recursively. If an encountered value implements the TlvObj interface and is not a
// nil pointer, Marshal calls its ToTlv method to produce TLV.
//
// Marshal uses default type-dependent encodings as described in (Template).Parse.
func Marshal(v interface{}) ([]byte, error) {
	if v == nil {
		return nil, errors.New(errors.KsiInvalidArgumentError)
	}

	// Create a wrapper parent template.
	objTemplate, err := NewTemplate(0x01)
	if err != nil {
		return nil, err
	}
	if err := objTemplate.Parse(reflect.TypeOf(v)); err != nil {
		return nil, err
	}

	// Serialize the value.
	objTlv, err := NewTlv(ConstructFromObject(v, objTemplate))
	if err != nil {
		return nil, err
	}
	return objTlv.Value(), nil
}

// Unmarshal parses the TLV-encoded data and stores the result in the value pointed to by v.
//
// Unmarshal uses the inverse of the encodings that Marshal uses (meaning only the value part).
func Unmarshal(data []byte, v interface{}) error {
	if data == nil || v == nil {
		return errors.New(errors.KsiInvalidArgumentError)
	}

	// Create a wrapper parent template.
	objTemplate, err := NewTemplate(0x01)
	if err != nil {
		return err
	}
	if err = objTemplate.Parse(reflect.TypeOf(v)); err != nil {
		return err
	}

	// Create a wrapper parent TLV object.
	objTlv, err := NewTlv(ConstructEmpty(0x01, false, false))
	if err != nil {
		return err
	}
	if err = objTlv.SetValue(data); err != nil {
		return err
	}
	if err = objTlv.ParseNested(objTemplate); err != nil {
		return err
	}
	return objTlv.ToObject(v, objTemplate, nil)
}

// HeaderMask holds mask values for different bits in TLV header.
type HeaderMask byte

const (
	// HeaderFlag16 is mask for 16bit flag.
	HeaderFlag16 = HeaderMask(0x80)
	// HeaderFlagN is mask for Non-Critical flag.
	HeaderFlagN = HeaderMask(0x40)
	// HeaderFlagF is mask for Forward Unknown flag.
	HeaderFlagF = HeaderMask(0x20)
	// HeaderTypeMask is mask for type in the first header byte.
	HeaderTypeMask = HeaderMask(0x1f)
)

const (
	// MaxValueLength is the maximum size of the TLV value.
	MaxValueLength = 0xffff
	// MaxHeaderSize is the maximum size of the TLV header.
	MaxHeaderSize = 4
	// MaxBufferSize is the maximum size of the buffer needed to store any TLV.
	MaxBufferSize = MaxHeaderSize + MaxValueLength
	// MaxTagValue is the maximum size of the TLV tag value.
	MaxTagValue = 0x1fff
)

// TLV holds Type-Length-Value encoded data. Entire object is held in single byte array that can be accessed via TLV structure.
type Tlv struct {
	NonCritical    bool   // If set, this TLV is non-critical.
	ForwardUnknown bool   // If set together with NonCritical, this TLV may be skipped by receiver.
	Is16           bool   // If set, this TLV is 16bit.
	Tag            uint16 // TLV type.
	Nested         []*Tlv // List of nested elements.
	Raw            []byte // Raw slice holds entire TLV structure.
	value          []byte // Value slice only holds TLV value part.
}

// NewTlv is a constructor for a TLV object.
func NewTlv(constructor Constructor) (*Tlv, error) {
	if constructor == nil {
		return nil, errors.New(errors.KsiInvalidArgumentError)
	}

	t := tlv{}
	if err := constructor(&t); err != nil {
		return nil, err
	}

	return &t.obj, nil
}

// Constructor is constructor for TLV.
// See ConstructEmpty, ConstructFromObject, ConstructFromReader and ConstructFromSlice.
type Constructor func(*tlv) error
type tlv struct {
	obj Tlv
}

// ConstructEmpty is an option for constructing an empty TLV with initialized header values.
// For setting a value see (Tlv).SetValue().
func ConstructEmpty(tag uint16, nc bool, fu bool) Constructor {
	return func(t *tlv) error {
		if t == nil {
			return errors.New(errors.KsiInvalidArgumentError).AppendMessage("Missing TLV base object.")
		}

		t.obj.Tag = tag
		t.obj.NonCritical = nc
		t.obj.ForwardUnknown = fu
		return nil
	}
}

// ConstructFromReader is an option for constructing TLV object from TLV binary stream.
func ConstructFromReader(r io.Reader) Constructor {
	return func(t *tlv) error {
		if r == nil {
			return errors.New(errors.KsiInvalidArgumentError)
		}
		if t == nil {
			return errors.New(errors.KsiInvalidArgumentError).AppendMessage("Missing TLV base object.")
		}

		b1 := make([]byte, 1)
		// Read first byte.
		n, err := io.ReadFull(r, b1)
		if err != nil || n != 1 {
			return errors.New(errors.KsiIoError).AppendMessage("Unable to read TLV header.")
		}

		var (
			is16      = b1[0]&byte(HeaderFlag16) > 0
			isN       = b1[0]&byte(HeaderFlagN) > 0
			isF       = b1[0]&byte(HeaderFlagF) > 0
			tlvType   = uint16(b1[0] & byte(HeaderTypeMask))
			firstByte = b1[0]

			valueLen  uint16
			headerLen uint16
			b3        = make([]byte, 3)
		)
		// Parse header, depending on the TLV header flags.
		if is16 {
			n, err = io.ReadFull(r, b3)
			if err != nil || n != 3 {
				return errors.New(errors.KsiIoError).AppendMessage("Unable to read TLV16 header.")
			}

			tlvType = (tlvType << 8) | uint16(b3[0])
			valueLen = (uint16(b3[1]) << 8) | uint16(b3[2])
			headerLen = 4
		} else {
			n, err = io.ReadFull(r, b1)
			if err != nil || n != 1 {
				return errors.New(errors.KsiIoError).AppendMessage("Unable to read TLV8 header.")
			}

			valueLen = uint16(b1[0])
			headerLen = 2
		}

		raw := make([]byte, headerLen+valueLen)
		value := raw[headerLen:]

		raw[0] = firstByte
		if is16 {
			raw[1] = b3[0]
			raw[2] = b3[1]
			raw[3] = b3[2]

		} else {
			raw[1] = b1[0]
		}

		// If TLV supposed to have no value don't read it.
		if valueLen != 0 {
			n, err = io.ReadFull(r, value)
			if err != nil || n != int(valueLen) {
				return errors.New(errors.KsiIoError).AppendMessage("Unable to read TLV data.")
			}
		}

		t.obj.Tag = tlvType
		t.obj.NonCritical = isN
		t.obj.ForwardUnknown = isF
		t.obj.Is16 = is16
		t.obj.value = value
		t.obj.Raw = raw
		return nil
	}
}

// ConstructFromSlice is an option for constructing TLV object from TLV binary slice.
func ConstructFromSlice(b []byte) Constructor {
	return func(t *tlv) error {
		if len(b) == 0 {
			return errors.New(errors.KsiInvalidFormatError).AppendMessage("The stream is empty.")
		}
		if t == nil {
			return errors.New(errors.KsiInvalidArgumentError).AppendMessage("Missing TLV base object.")
		}

		var (
			is16    = b[0]&byte(HeaderFlag16) > 0
			isN     = b[0]&byte(HeaderFlagN) > 0
			isF     = b[0]&byte(HeaderFlagF) > 0
			tlvType = uint16(b[0] & byte(HeaderTypeMask))

			valueLen  uint16
			value     []byte
			headerLen uint16
		)

		// Parse header, depending on the TLV header flags.
		if is16 {
			if len(b) < 4 {
				return errors.New(errors.KsiInvalidFormatError).AppendMessage("Not enough bytes for TLV16 header.")
			}
			tlvType = (tlvType << 8) | uint16(b[1])
			valueLen = (uint16(b[2]) << 8) | uint16(b[3])
			headerLen = 4
		} else {
			if len(b) < 2 {
				return errors.New(errors.KsiInvalidFormatError).AppendMessage("Not enough bytes for TLV header.")
			}
			valueLen = uint16(b[1])
			headerLen = 2
		}

		if int(headerLen+valueLen) > len(b) {
			return errors.New(errors.KsiInvalidFormatError).AppendMessage(
				fmt.Sprintf("Not enough bytes for TLV value. Expecting %v but have only %v.",
					valueLen, len(value)-int(headerLen)))
		}

		t.obj.Tag = tlvType
		t.obj.NonCritical = isN
		t.obj.ForwardUnknown = isF
		t.obj.Is16 = is16
		t.obj.Raw = b[:headerLen+valueLen]
		t.obj.value = t.obj.Raw[headerLen:]
		return nil
	}
}

// ConstructFromObject is an option for constructing TLV structure by traversing the value v recursively.
//
// Note that the value v must point to an existing object that is bound to provided template, otherwise the output is
// undefined.
func ConstructFromObject(v interface{}, templateInput *Template) Constructor {
	return func(t *tlv) error {
		if v == nil || templateInput == nil {
			return errors.New(errors.KsiInvalidArgumentError)
		}
		if t == nil {
			return errors.New(errors.KsiInvalidArgumentError).AppendMessage("Missing TLV base object.")
		}
		value := reflect.ValueOf(v)
		if value.Type().Kind() != reflect.Ptr || value.Type().Elem().Kind() != reflect.Struct {
			return errors.New(errors.KsiInvalidFormatError).
				AppendMessage(fmt.Sprintf("Unsupported input type: %T.", v)).
				AppendMessage("Only pointer to struct is supported as input.")
		}

		t.obj.Tag = uint16(templateInput.tag[0])
		if templateInput.options != nil {
			t.obj.ForwardUnknown = templateInput.options.FastForward
			t.obj.NonCritical = templateInput.options.NonCritical
		}

		state := &parserState{
			path: []uint16{uint16(templateInput.tag[0])},
		}
		decoder, err := NewEncoder()
		if err != nil {
			return err
		}
		valLen, err := internalTlvFromTemplate(unsafe.Pointer(value.Pointer()), &t.obj, templateInput, decoder, state)
		if err != nil {
			return err
		}
		hdrLen, err := decoder.PrependHeader(templateInput.headerData(valLen))
		if err != nil {
			return errors.KsiErr(err).AppendMessage(fmt.Sprintf("Unable to serialize %s.", templateInput.path))
		}

		if hdrLen > 2 {
			t.obj.Is16 = true
		}

		raw := decoder.Bytes()
		t.obj.Raw = raw
		t.obj.value = t.obj.Raw[hdrLen:]
		return nil
	}
}

// Value returns the value of the TLV. If the receiver is nil, a nil slice is returned.
func (t *Tlv) Value() []byte {
	if t == nil {
		return nil
	}
	return t.value
}

// SetValue sets the TLV value.
// Note that it will also affect the TLV header according the value length.
//
// See (Tlv).NewTlv option ConstructEmpty for initializing a parent TLV object.
//
// See Marshal for serializing object state into binary TLV value.
func (t *Tlv) SetValue(value []byte) error {
	if t == nil || len(value) == 0 {
		return errors.New(errors.KsiInvalidArgumentError)
	}
	if len(t.value) != 0 {
		return errors.New(errors.KsiInvalidStateError).AppendMessage("Value already set.")
	}

	var (
		valueLen = uint16(len(value))
		raw      = make([]byte, 0, valueLen+4)
	)
	if t.Tag > 0x1F || valueLen > 0xff {
		t.Is16 = true

		// Concatenate 16bit flag with the tag value.
		raw = append(raw, byte(HeaderFlag16)|byte(t.Tag>>8))
		raw = append(raw, byte(t.Tag))
		// Set value length.
		raw = append(raw, byte(valueLen>>8))
		raw = append(raw, byte(valueLen))
	} else {
		// Set the tag value.
		raw = append(raw, byte(t.Tag))
		// Set value length.
		raw = append(raw, byte(valueLen))
	}

	if t.NonCritical {
		raw[0] |= byte(HeaderFlagN)
	}
	if t.ForwardUnknown {
		raw[0] |= byte(HeaderFlagF)
	}

	t.Raw = append(raw, value...)
	t.value = append(t.value, value...)
	return nil
}

// Length returns the size of the TLV in bytes (header size + value length).
// The value length can be obtained via the slice (Tlv).value.
func (t *Tlv) Length() int {
	if t == nil {
		return 0
	}
	if t.Is16 {
		return 4 + len(t.value)
	}
	return 2 + len(t.value)
}

// String implements Stringer interface.
func (t *Tlv) String() string {
	return t.string("  ", 0)
}

// string is used recursively.
func (t *Tlv) string(prefix string, prefLen int) string {
	if t == nil {
		return ""
	}

	var (
		b      strings.Builder
		FF     string
		FN     string
		comma  string
		comma2 string
	)

	if t.NonCritical {
		FN = "N"
		comma2 = ","
	}
	if t.ForwardUnknown {
		FF = "F"
		comma2 = ","
	}
	if t.NonCritical && t.ForwardUnknown {
		comma = ","
	}

	b.WriteString(fmt.Sprintf("%sTLV[0x%x%s%s%s%s]: ", strings.Repeat(prefix, prefLen), t.Tag, comma2, FN, comma, FF))
	if len(t.Nested) > 0 {
		b.WriteString("\n")
		for _, t := range t.Nested {
			b.WriteString(fmt.Sprintf("%s%s", prefix, t.string(prefix, prefLen+1)))
		}
	} else {
		b.WriteString(fmt.Sprintf("%x\n", t.value))
	}
	return b.String()
}

// Extract returns TLV by path.
func (t *Tlv) Extract(path ...uint16) (*Tlv, error) {
	if t == nil {
		return nil, errors.New(errors.KsiInvalidArgumentError)
	}
	if len(path) == 0 {
		return nil, errors.New(errors.KsiInvalidArgumentError).AppendMessage("TLV path must be specified.")
	}

	// Walk through the path.
	tmp := t
	for i, tag := range path {
		notFound := true

		// If it's not the last element, it must be nested TLV.
		if tmp.Nested == nil {
			return nil, errors.New(errors.KsiInvalidStateError).AppendMessage(
				fmt.Sprintf("TLV %s does not contain nested elements.", tlvPathToString(path[:i+1])))
		}

		// Check if it does contain expected TLV.
		for _, tlvBuf := range tmp.Nested {
			if tlvBuf.Tag == tag {
				tmp = tlvBuf
				notFound = false
				break
			}
		}

		if notFound {
			return nil, errors.New(errors.KsiInvalidFormatError).AppendMessage(
				fmt.Sprintf("TLV %s not found.", tlvPathToString(path[:i+1])))
		}
	}

	return tmp, nil
}

// getArrayByPath returns array of TLVs by path.
func (t *Tlv) getArrayByPath(path ...uint16) ([]*Tlv, error) {
	if t == nil {
		return nil, errors.New(errors.KsiInvalidArgumentError)
	}
	pathLen := len(path)
	if path == nil || pathLen == 0 {
		return nil, errors.New(errors.KsiInvalidArgumentError).AppendMessage("TLV path must be specified.")
	}

	arrayOwner := t
	if pathLen > 1 {
		x, err := t.Extract(path[:pathLen-1]...)
		if err != nil {
			return nil, err
		}
		arrayOwner = x
	}

	if arrayOwner.Nested == nil {
		return nil, errors.New(errors.KsiInvalidStateError).AppendMessage(
			fmt.Sprintf("TLV %s does not contain nested elements.", tlvPathToString(path[:pathLen-1])))
	}

	tmp := make([]*Tlv, 0)
	expectedTag := path[pathLen-1]
	for _, nested := range arrayOwner.Nested {
		if nested.Tag == expectedTag {
			tmp = append(tmp, nested)
		}
	}

	return tmp, nil
}

// IsConsistent verifies whether the input stream contains a complete TLV structure.
func IsConsistent(b []byte) bool {
	if len(b) == 0 {
		return false
	}

	var (
		valueLen  uint16
		headerLen uint16
	)
	if b[0]&byte(HeaderFlag16) > 0 {
		if len(b) < 4 {
			// Not enough bytes for TLV header.
			return false
		}
		valueLen = (uint16(b[2]) << 8) | uint16(b[3])
		headerLen = 4
	} else {
		if len(b) < 2 {
			// Not enough bytes for TLV header.
			return false
		}
		valueLen = uint16(b[1])
		headerLen = 2
	}

	if int(headerLen+valueLen) > len(b) {
		// Not enough bytes for TLV value.
		return false
	}
	return true
}
