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
	"bytes"
	"reflect"
	"testing"
)

func assertSerialize(t *testing.T, input interface{}, expected []byte, expectedLen uint64) {
	var (
		enc, _ = NewEncoder()
		length uint64
		err    error
	)
	switch value := input.(type) {
	case uint64:
		length, err = enc.PrependUint64(value)
	case string:
		length, err = enc.PrependUtf8(value)
	case []byte:
		length, err = enc.PrependBinary(value)
	default:
		t.Fatalf("Value to be serialize has unknown type: '%v'.", reflect.TypeOf(input))
	}
	if err != nil {
		t.Fatalf("Unable to serialize input '%v'. %s", input, err)
	}
	if length != expectedLen {
		t.Fatalf("Serializer should have returned: %v bytes, but returned %v.", expectedLen, length)
	}

	if raw := enc.Bytes(); bytes.Compare(expected, raw) != 0 {
		t.Fatalf("Value expected:\n%v\nGot:\n%v", expected, raw)
	}
}

func TestUnitSerializeUint64(t *testing.T) {
	// Test maximums.
	assertSerialize(t, uint64(0xff), []byte{0xff}, 1)
	assertSerialize(t, uint64(0xffff), []byte{0xff, 0xff}, 2)
	assertSerialize(t, uint64(0xffffff), []byte{0xff, 0xff, 0xff}, 3)

	assertSerialize(t, uint64(0xffffffff), []byte{0xff, 0xff, 0xff, 0xff}, 4)
	assertSerialize(t, uint64(0xffffffffff), []byte{0xff, 0xff, 0xff, 0xff, 0xff}, 5)
	assertSerialize(t, uint64(0xffffffffffff), []byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff}, 6)
	assertSerialize(t, uint64(0xffffffffffffff), []byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff}, 7)
	assertSerialize(t, uint64(0xffffffffffffffff), []byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff}, 8)

	// Test borders.
	assertSerialize(t, uint64(0), []byte{0}, 1)
	assertSerialize(t, uint64(0x100), []byte{1, 0}, 2)
	assertSerialize(t, uint64(0x10000), []byte{1, 0, 0}, 3)
	assertSerialize(t, uint64(0x1000000), []byte{1, 0, 0, 0}, 4)
	assertSerialize(t, uint64(0x100000000), []byte{1, 0, 0, 0, 0}, 5)
	assertSerialize(t, uint64(0x10000000000), []byte{1, 0, 0, 0, 0, 0}, 6)
	assertSerialize(t, uint64(0x1000000000000), []byte{1, 0, 0, 0, 0, 0, 0}, 7)
	assertSerialize(t, uint64(0x100000000000000), []byte{1, 0, 0, 0, 0, 0, 0, 0}, 8)
}

func TestUnitSerializeUtf8(t *testing.T) {
	// Test maximums.
	assertSerialize(t, "", []byte{0}, 1)

	assertSerialize(t, "a", []byte{'a', 0}, 2)
	assertSerialize(t, "test", []byte{'t', 'e', 's', 't', 0}, 5)
}

func TestUnitSerializeBinary(t *testing.T) {
	assertSerialize(t, []byte{'a'}, []byte{'a'}, 1)
	assertSerialize(t, []byte{'a', 'b', 'c'}, []byte{'a', 'b', 'c'}, 3)
}

func TestUnitEncoderFunctionsWithNilReceiver(t *testing.T) {
	var encoder *Encoder
	byteVal := encoder.Bytes()
	if byteVal != nil {
		t.Fatal("Should not be possible to get bytes from nil encoder.")
	}

	if _, err := encoder.PrependUint64(uint64(1234)); err == nil {
		t.Fatal("Should not be possible to prepend uint64 with nil encoder.")
	}

	if _, err := encoder.PrependUint64E(uint64(1234)); err == nil {
		t.Fatal("Should not be possible to prepend uint64E with encoder.")
	}

	if _, err := encoder.PrependUint8(uint64(1234)); err == nil {
		t.Fatal("Should not be possible to prepend uint8 with encoder.")
	}

	if _, err := encoder.PrependUint8E(uint64(1234)); err == nil {
		t.Fatal("Should not be possible to prepend uint8E with encoder.")
	}

	if _, err := encoder.PrependUtf8("value"); err == nil {
		t.Fatal("Should not be possible to prepend utf8 with encoder.")
	}

	if _, err := encoder.PrependBinary([]byte{0x1}); err == nil {
		t.Fatal("Should not be possible to to prepend binary with encoder.")
	}

	if _, err := encoder.PrependHeader(0x12, true, true, uint64(1234)); err == nil {
		t.Fatal("Should not be possible to prepend header with encoder.")
	}
}

func TestUnitPrependWithZero(t *testing.T) {
	var (
		enc Encoder
	)

	if _, err := enc.PrependUint64E(uint64(0)); err != nil {
		t.Fatal("Failed to PrependUint64E with zero: ", err)
	}

	if _, err := enc.PrependUint8E(uint64(0)); err != nil {
		t.Fatal("Failed to PrependUint64E with zero: ", err)
	}
}
