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

	"github.com/guardtime/goksi/errors"
	"github.com/guardtime/goksi/test/utils"
)

func isExpectedTlv(t *testing.T, tlv *Tlv, tag uint16, value []byte, raw []byte, n, f bool, is16 bool) {
	if tlv == nil {
		t.Fatalf("TLV compared is nil.")
	}

	if tlv.Tag != tag {
		t.Fatalf("Expected TLV tag 0x%x, but is 0x%x.", tag, tlv.Tag)
	}

	if tlv.NonCritical != n || tlv.ForwardUnknown != f {
		t.Fatalf("TLV flags mismatch!\nExpecting:  F:%v N:%v\nBut is:     F:%v N:%v", f, n, tlv.ForwardUnknown, tlv.NonCritical)
	}

	if tlv.value == nil && value != nil {
		t.Fatalf("TLV value is nil, but comparison value is not!")
	}

	if !bytes.Equal(value, tlv.value) {
		t.Fatalf("TLV value mismatch:\nExpecting:  %v\nBut is:     %v!", value, tlv.value)
	}

	if !bytes.Equal(raw, tlv.Raw) {
		t.Fatalf("TLV raw  mismatch:\nExpecting:  %v\nBut is:     %v!", raw, tlv.Raw)
	}

	if is16 && tlv.Is16 == false {
		t.Fatalf("TLV expected must be 16bit but is 8bit.")
	} else if !is16 && tlv.Is16 == true {
		t.Fatalf("TLV expected must be 8bit but is 16bit.")
	}

}

func parseAndTestTlv(t *testing.T, raw []byte, tag uint16, value []byte, n, f bool, is16 bool) {
	tlvR, err := NewTlv(ConstructFromReader(bytes.NewReader(raw)))

	if err != nil {
		t.Fatalf("Error while creating TLV from reader (%v).", err.Error())
	}

	isExpectedTlv(t, tlvR, tag, value, raw, n, f, is16)

	tlvS, err := NewTlv(ConstructFromSlice(raw))

	if err != nil {
		t.Fatalf("Error while creating TLV from slice (%v).", err.Error())
	}

	isExpectedTlv(t, tlvS, tag, value, raw, n, f, is16)
}

func TestUnitTlv8FromReader(t *testing.T) {
	raw := []byte{0x0a, 0x00}
	parseAndTestTlv(t, raw, 0x0a, nil, false, false, false)

	raw = []byte{0x0a, 0x01, 0x01}
	parseAndTestTlv(t, raw, 0x0a, raw[2:], false, false, false)

	raw = []byte{0x0a, 0x02, 0x01, 0x02}
	parseAndTestTlv(t, raw, 0x0a, raw[2:], false, false, false)

	raw = []byte{0x0a | byte(HeaderFlagN), 0x00}
	parseAndTestTlv(t, raw, 0x0a, nil, true, false, false)

	raw = []byte{0x0a | byte(HeaderFlagF), 0x00}
	parseAndTestTlv(t, raw, 0x0a, nil, false, true, false)

	raw = []byte{0x0a | byte(HeaderFlagN) | byte(HeaderFlagF), 0x00}
	parseAndTestTlv(t, raw, 0x0a, nil, true, true, false)
}

func TestUnitTlv16FromReader(t *testing.T) {
	raw := []byte{0x8a, 0xbc, 0x00, 0x00}
	parseAndTestTlv(t, raw, 0xabc, nil, false, false, true)

	raw = []byte{0x8a, 0xbc, 0x00, 0x01, 0x0d}
	parseAndTestTlv(t, raw, 0xabc, raw[4:], false, false, true)

	raw = []byte{0x8a, 0xbc, 0x00, 0x02, 0x01, 0x02}
	parseAndTestTlv(t, raw, 0xabc, raw[4:], false, false, true)

	raw = []byte{0x8a | byte(HeaderFlagN), 0xbc, 0x00, 0x00}
	parseAndTestTlv(t, raw, 0xabc, nil, true, false, true)

	raw = []byte{0x8a | byte(HeaderFlagF), 0xbc, 0x00, 0x00}
	parseAndTestTlv(t, raw, 0xabc, nil, false, true, true)

	raw = []byte{0x8a | byte(HeaderFlagN) | byte(HeaderFlagF), 0xbc, 0x00, 0x00}
	parseAndTestTlv(t, raw, 0xabc, nil, true, true, true)
}

func isFailure(t *testing.T, raw []byte) {
	tlvR, err := NewTlv(ConstructFromReader(bytes.NewReader(raw)))
	if tlvR != nil {
		t.Fatalf("No TLV should have been created from Reader.")

	}
	if err == nil {
		t.Fatalf("There should have been failure with Reader.")
	}

	tlvS, err := NewTlv(ConstructFromSlice(raw))
	if tlvS != nil {
		t.Fatalf("No TLV should have been created from Slice.")
	}
	if err == nil {
		t.Fatalf("There should have been failure with Slice.")
	}
}

func TestUnitInvalidTlv8FromReader(t *testing.T) {
	raw := []byte{0x0a, 0x02, 0x01, 0x02}
	isFailure(t, []byte{})
	for i := 1; i < len(raw); i++ {
		isFailure(t, raw[:i])
	}
}

func TestUnitInvalidTlv16FromReader(t *testing.T) {
	raw := []byte{0x8a, 0xbc, 0x00, 0x02, 0x01, 0x02}
	isFailure(t, []byte{})
	for i := 1; i < len(raw); i++ {
		isFailure(t, raw[:i])
	}
}

//    TLV[0x10]:
//    	TLV[0x1]:
//    	TLV[0x3]:
//    		TLV[0xa]:
//    		TLV[0xb]:
//    	TLV[0x2]:
func getTestTlv() *Tlv {
	var (
		tlv_10, _     = NewTlv(ConstructEmpty(0x10, false, false)) // Nested
		tlv_10_1, _   = NewTlv(ConstructEmpty(0x1, false, false))
		tlv_10_2, _   = NewTlv(ConstructEmpty(0x2, false, false))
		tlv_10_3, _   = NewTlv(ConstructEmpty(0x3, false, false)) // Nested
		tlv_10_3_a, _ = NewTlv(ConstructEmpty(0xa, false, false))
		tlv_10_3_b, _ = NewTlv(ConstructEmpty(0xb, false, false))
	)
	tlv_10.Nested = []*Tlv{tlv_10_1, tlv_10_3, tlv_10_2}
	tlv_10_3.Nested = []*Tlv{tlv_10_3_a, tlv_10_3_b}
	return tlv_10
}

func assertTlvRequestFailure(t *testing.T, tlv *Tlv, path []uint16, msg string) {
	tlv, err := tlv.Extract(path...)
	if tlv != nil {
		t.Fatalf("In case of a failure, TLV returned must be nil.")
	}
	if err == nil {
		t.Fatalf("In case of a failure, error must be returned.")
	}

	if errors.KsiErr(err).Message()[0] != msg {
		t.Fatalf("\nExpecting error message '%s'\nBut got                 '%s'.", msg, errors.KsiErr(err).Message()[0])
	}
}

func assertTlvRequest(t *testing.T, tlv *Tlv, path []uint16) {
	tlvRet, err := tlv.Extract(path...)
	if err != nil {
		t.Fatalf("It should be possible to retrieve TLV.")
	}
	if tlvRet == nil {
		t.Fatalf("No error but TLV returned is nil.")
	}
	if tlvRet.Tag != path[len(path)-1] {
		t.Fatalf("TLV extracted by path %s has unexpected tag %x!", tlvPathToString(path), tlvRet.Tag)
	}
}

func TestUnitGetTlvByPath(t *testing.T) {
	tlv := getTestTlv()
	assertTlvRequestFailure(t, tlv, []uint16{0x20}, "TLV 20 not found.")
	assertTlvRequestFailure(t, tlv, []uint16{0x2, 0x1}, "TLV 2.1 does not contain nested elements.")
	assertTlvRequestFailure(t, tlv, []uint16{0x3, 0x1}, "TLV 3.1 not found.")
	assertTlvRequestFailure(t, tlv, []uint16{}, "TLV path must be specified.")
	assertTlvRequestFailure(t, tlv, nil, "TLV path must be specified.")

	assertTlvRequest(t, tlv, []uint16{1})
	assertTlvRequest(t, tlv, []uint16{2})
	assertTlvRequest(t, tlv, []uint16{3})
	assertTlvRequest(t, tlv, []uint16{3, 0xa})
	assertTlvRequest(t, tlv, []uint16{3, 0xb})
}

func TestUnitTlvLength(t *testing.T) {

	// Check the size of nil TLV.
	var tlv1 *Tlv
	l := tlv1.Length()
	if l != 0 {
		t.Fatalf("The size of nil TLV must be 0, but is %v!", l)
	}

	// Check the size of empty TLV8.
	tlv8, _ := NewTlv(ConstructEmpty(0x01, false, false))
	l = tlv8.Length()
	if l != 2 {
		t.Fatalf("The size of empty TLV8 must be 2, but is %v!", l)
	}

	// Check the size of empty TLV16.
	tlv16, _ := NewTlv(ConstructEmpty(0x01, false, false))
	tlv16.Is16 = true
	l = tlv16.Length()
	if l != 4 {
		t.Fatalf("The size of empty TLV16 must be 4, but is %v!", l)
	}

	value := make([]byte, 2, 2)

	// Check the size of not empty TLV8.
	tlv8V, _ := NewTlv(ConstructEmpty(0x01, false, false))
	tlv8V.value = value
	l = tlv8V.Length()
	if l != 4 {
		t.Fatalf("The size of not empty TLV8 must be 4, but is %v!", l)
	}

	// Check the size of not empty TLV16.
	tlv16V, _ := NewTlv(ConstructEmpty(0x01, false, false))
	tlv16V.Is16 = true
	tlv16V.value = value
	l = tlv16V.Length()
	if l != 6 {
		t.Fatalf("The size of not empty TLV16 must be 6, but is %v!", l)
	}
}

func TestUnitCreateFromInvalidInput(t *testing.T) {
	type testStruct struct {
		_ string `something:"something"`
	}
	var (
		tl           tlv
		testTemplate = &Template{}
		obj2         = new(testStruct)
	)
	testData := []struct {
		constructor Constructor
		errMsg      string
	}{
		{ConstructFromReader(nil), "Should not be possible to create TLV from nil reader."},
		{ConstructFromSlice(nil), "Should not be possible to create TLV from nil slice."},
		{ConstructFromObject(nil, testTemplate), "Should not be possible create from object if provided interface is nil."},
		{ConstructFromObject(obj2, nil), "Should not be possible create from object if template is nil."},
	}

	for _, data := range testData {
		if err := data.constructor(&tl); err == nil {
			t.Fatal(data.errMsg)

		}
	}
}

func TestUnitTlvMultipleSetValue(t *testing.T) {
	value := make([]byte, 2, 2)

	tlv8, _ := NewTlv(ConstructEmpty(0x02, false, false))
	if err := tlv8.SetValue(value); err != nil {
		t.Fatal("Failed to set TLV value: ", err)
	}
	if err := tlv8.SetValue(value); err == nil {
		t.Fatal("Must fail on setting value multiple times.")
	}
}

func TestUnitTlvSetValueLen8(t *testing.T) {
	value := make([]byte, 2, 2)

	tlv8, _ := NewTlv(ConstructEmpty(0x02, false, false))
	if err := tlv8.SetValue(value); err != nil {
		t.Fatal("Failed to set TLV value: ", err)
	}
	if tlv8.Length() != 1+1+len(value) {
		t.Fatal("TLV length mismatch.")
	}
}

func TestUnitTlvSetValueLen16(t *testing.T) {
	valLen8 := make([]byte, 0xff)
	valLen16 := make([]byte, 0x100)

	tlvTag8, _ := NewTlv(ConstructEmpty(0x02, false, false))
	if err := tlvTag8.SetValue(valLen16); err != nil {
		t.Fatal("Failed to set TLV value: ", err)
	}
	if tlvTag8.Length() != 2+2+len(valLen16) {
		t.Fatal("TLV length mismatch.")
	}

	tlvTag16, _ := NewTlv(ConstructEmpty(0x20, false, false))
	if err := tlvTag16.SetValue(valLen8); err != nil {
		t.Fatal("Failed to set TLV value: ", err)
	}
	if tlvTag16.Length() != 2+2+len(valLen8) {
		t.Fatal("TLV length mismatch.")
	}

	tlvTag16, _ = NewTlv(ConstructEmpty(0x20, false, false))
	if err := tlvTag16.SetValue(valLen16); err != nil {
		t.Fatal("Failed to set TLV value: ", err)
	}
	if tlvTag16.Length() != 2+2+len(valLen16) {
		t.Fatal("TLV length mismatch.")
	}
}

func TestUnitMarshal(t *testing.T) {
	type (
		marshalNstdStruct struct{}
		marshalStruct     struct {
			byt *uint64            `tlv:"1,int"`
			str *string            `tlv:"2,utf8"`
			bin *[]byte            `tlv:"3,bin"`
			obj *marshalNstdStruct `tlv:"4,nstd"`
		}
	)

	var (
		testExpectedVal = utils.StringToBin("0101b50205616e6f6e000302deed0400")

		marshalObj = marshalStruct{
			byt: newInt(0xB5),
			str: newStr("anon"),
			bin: newBin([]byte{0xDE, 0xED}),
			obj: &marshalNstdStruct{},
		}
		unmarshalObj marshalStruct
	)

	value, err := Marshal(&marshalObj)
	if err != nil {
		t.Fatal("Failed to marshal the test object: ", err)
	}
	if !bytes.Equal(value, testExpectedVal) {
		t.Fatal("Marshalled value mismatch.")
	}

	if err := Unmarshal(value, &unmarshalObj); err != nil {
		t.Fatal("Failed to un-marshal the test object: ", err)
	}

	// Verify that the un-marshalled object is a clone of the original.
	if !reflect.DeepEqual(marshalObj, unmarshalObj) {
		t.Fatal("Un-marshalled object values mismatch.")
	}
}
