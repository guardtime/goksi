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
	"testing"

	"github.com/guardtime/goksi/errors"
)

func createAndTestIntTlv(t *testing.T, value uint64, payload []byte) {
	tlv, _ := NewTlv(ConstructEmpty(0x10, false, false))
	tlv.value = payload

	tmp, err := tlv.Uint64()
	if err != nil {
		t.Fatalf("Unable to get uint64. %s.", err)
	}
	if tmp != value {
		t.Fatalf("Value extracted from TLV is expected %v, but is %v.", value, tmp)
	}
}

func createAndTestIntTlvFailure(t *testing.T, payload []byte, message string) {
	tlv, _ := NewTlv(ConstructEmpty(0x10, false, false))
	tlv.value = payload

	_, err := tlv.Uint64()
	if err == nil {
		t.Fatalf("This call should have been failed!")
	}
	if msg := errors.KsiErr(err).Message()[0]; msg != message {
		t.Fatalf("\nExpecting error: '%s'\nBut got error:   '%s'\n", message, msg)
	}
}

func createAndTestInt8Tlv(t *testing.T, value uint64, payload []byte) {
	tlv, _ := NewTlv(ConstructEmpty(0x10, false, false))
	tlv.value = payload

	tmp, err := tlv.Uint8()
	if err != nil {
		t.Fatalf("Unable to get uint64 (acting as 8bit). %s.", err)
	}
	if tmp != value {
		t.Fatalf("Value extracted from TLV is expected %v, but is %v.", value, tmp)
	}
}

func createAndTestInt8TlvFailure(t *testing.T, payload []byte, message string) {
	tlv, _ := NewTlv(ConstructEmpty(0x10, false, false))
	tlv.value = payload

	_, err := tlv.Uint8()
	if err == nil {
		t.Fatalf("This call should have been failed!")
	}
	if msg := errors.KsiErr(err).Message()[0]; msg != message {
		t.Fatalf("\nExpecting error: '%s'\nBut got error:   '%s'\n", message, msg)
	}
}

func createAndTestUtf8(t *testing.T, value string, payload []byte) {
	tlv, _ := NewTlv(ConstructEmpty(0x10, false, false))
	tlv.value = payload

	tmp, err := tlv.Utf8()
	if err != nil {
		t.Fatalf("Unable to get utf8 string. %s.", err)
	}
	if tmp != value {
		t.Fatalf("Value extracted from TLV is expected '%v', but is '%v'.", value, tmp)
	}
}

func createAndTestUtf8TlvFailure(t *testing.T, payload []byte, message string) {
	tlv, _ := NewTlv(ConstructEmpty(0x10, false, false))
	tlv.value = payload

	_, err := tlv.Utf8()
	if err == nil {
		t.Fatalf("This call should have been failed!")
	}
	if msg := errors.KsiErr(err).Message()[0]; msg != message {
		t.Fatalf("\nExpecting error: '%s'\nBut got error:   '%s'\n", message, msg)
	}
}

func createAndTestBinary(t *testing.T, value []byte, payload []byte) {
	tlv, _ := NewTlv(ConstructEmpty(0x10, false, false))
	tlv.value = []byte(payload)

	tmp, err := tlv.Binary()
	if err != nil {
		t.Fatalf("Unable to get utf8 string. %s.", err)
	}
	if bytes.Compare(tmp, value) != 0 {
		t.Fatalf("Value extracted:\n%v\nGot:\n%v", value, tmp)
	}
}

func TestUnitTlvGetUint64(t *testing.T) {
	createAndTestIntTlv(t, 0, []byte{0x00})
	createAndTestIntTlv(t, 1, []byte{0x01})
	createAndTestIntTlv(t, 127, []byte{127})
	createAndTestIntTlv(t, 128, []byte{128})
	createAndTestIntTlv(t, 0xff, []byte{0xff})
	createAndTestIntTlv(t, 0x0100, []byte{0x01, 0x00})
	createAndTestIntTlv(t, 0x010000, []byte{0x01, 0x00, 0x00})
	createAndTestIntTlv(t, 0x01000000, []byte{0x01, 0x00, 0x00, 0x00})
	createAndTestIntTlv(t, 0x0100000000, []byte{0x01, 0x00, 0x00, 0x00, 0x00})
	createAndTestIntTlv(t, 0x010000000000, []byte{0x01, 0x00, 0x00, 0x00, 0x00, 0x00})
	createAndTestIntTlv(t, 0x01000000000000, []byte{0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00})
	createAndTestIntTlv(t, 0x0100000000000000, []byte{0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00})
	createAndTestIntTlv(t, 0xffffffffffffffff, []byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff})
}

func TestUnitTlvGetUint64Failure(t *testing.T) {
	createAndTestIntTlvFailure(t, []byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff}, "TLV value for 64bit integer is too large ([255 255 255 255 255 255 255 255 255]).")
}

func TestUnitTlvGetUint8(t *testing.T) {
	createAndTestInt8Tlv(t, 0, []byte{0x00})
	createAndTestInt8Tlv(t, 1, []byte{0x01})
	createAndTestInt8Tlv(t, 127, []byte{127})
	createAndTestInt8Tlv(t, 128, []byte{128})
	createAndTestInt8Tlv(t, 0xff, []byte{0xff})
}

func TestUnitTlvGetUint8Failure(t *testing.T) {
	createAndTestInt8TlvFailure(t, []byte{0xff, 0xff}, "TLV value for 8bit integer is too large ([255 255]).")
}

func TestUnitTlvGetUtf8(t *testing.T) {
	// createAndTestUtf8(t, "", []byte{})
	createAndTestUtf8(t, "", []byte{0})
	createAndTestUtf8(t, "0", []byte{'0', 0})
	createAndTestUtf8(t, "Test", []byte{'T', 'e', 's', 't', 0})
}

func TestUnitTlvGetUtf8Failure(t *testing.T) {
	createAndTestUtf8TlvFailure(t, []byte{0xff}, "String must end with 0 octet.")
}

func TestUnitTlvGeBinary(t *testing.T) {
	createAndTestBinary(t, []byte{}, []byte{})
	createAndTestBinary(t, []byte{1}, []byte{1})
	createAndTestBinary(t, []byte{0xff}, []byte{0xff})
	createAndTestBinary(t, []byte{0xff, 0x01}, []byte{0xff, 0x01})
}

func TestUnitGetFromNilTlv(t *testing.T) {
	var (
		tlv *Tlv
	)

	if _, err := tlv.Uint64(); err == nil {
		t.Fatal("Should not be possible to get from nil TLV.")
	}

	if _, err := tlv.Uint64E(); err == nil {
		t.Fatal("Should not be possible to get from nil TLV.")
	}

	if _, err := tlv.Uint8(); err == nil {
		t.Fatal("Should not be possible to get from nil TLV.")
	}

	if _, err := tlv.Uint8E(); err == nil {
		t.Fatal("Should not be possible to get from nil TLV.")
	}

	if _, err := tlv.Utf8(); err == nil {
		t.Fatal("Should not be possible to get from nil TLV.")
	}

	if _, err := tlv.Utf8E(); err == nil {
		t.Fatal("Should not be possible to get from nil TLV.")
	}

	if _, err := tlv.Binary(); err == nil {
		t.Fatal("Should not be possible to get from nil TLV.")
	}

	if _, err := tlv.Imprint(); err == nil {
		t.Fatal("Should not be possible to get from nil TLV.")
	}
}
