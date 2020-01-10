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

package templates

import (
	"reflect"
	"strings"
	"testing"

	"github.com/guardtime/goksi/errors"
	"github.com/guardtime/goksi/tlv"
)

func TestEmptyRegistry(t *testing.T) {
	if len(GetAll()) != 0 {
		t.Fatal("TLV registry must be empty.")
	}
}

func TestRegistryWithTemplates(t *testing.T) {
	type registryStruct struct{}
	testObject := &registryStruct{}

	if err := Register(testObject, "", 0x01); err != nil {
		t.Fatal("Failed to initialize templates:\n", err)
	}
	if len(GetAll()) != 1 {
		t.Fatal("TLV registry must contain one template.")
	}

	if err := Register(testObject, "Dummy", 0x01); err != nil {
		t.Fatal("Failed to initialize templates:\n", err)
	}
	if len(GetAll()) != 2 {
		t.Fatal("TLV registry must contain two templates.")
	}

	type registryStruct2 struct{}
	if err := Register(&registryStruct2{}, "", 0x01); err != nil {
		t.Fatal("Failed to initialize templates:\n", err)
	}
	if len(GetAll()) != 3 {
		t.Fatal("TLV registry must contain three templates.")
	}
}

func TestRegisterDuplicates(t *testing.T) {
	type (
		duplicateStruct  struct{}
		duplicateStruct2 struct{}
	)
	var (
		testObject  = &duplicateStruct{}
		testObject1 = &duplicateStruct{}

		assertDuplicate = func(err error) bool {
			ksiErr := errors.KsiErr(err)
			return ksiErr.Code() == errors.KsiInvalidStateError &&
				strings.HasPrefix(ksiErr.Message()[0], "TLV Template already exists")
		}
	)

	if err := Register(testObject, "", 0x01); err != nil {
		t.Fatal("Failed to initialize templates:\n", err)
	}

	if !assertDuplicate(Register(testObject, "", 0x01)) {
		t.Fatal("Must return error for duplicate name (same object already used).")
	}
	if !assertDuplicate(Register(&duplicateStruct2{}, "duplicateStruct", 0x01)) {
		t.Fatal("Must return error for duplicate name (name is already registered).")
	}
	if !assertDuplicate(Register(testObject1, "", 0x01)) {
		t.Fatal("Must return error for duplicate name (obj type is already registered).")
	}
}

func TestEmptyStruct(t *testing.T) {
	type emptyStruct struct{}
	testObject := &emptyStruct{}

	if err := Register(testObject, "", 0x01); err != nil {
		t.Fatal("Failed to initialize templates:\n", err)
	}
	tmpl := assertGetTemplate(t, reflect.Indirect(reflect.ValueOf(testObject)).Type().Name())

	rawTlv, err := tlv.NewTlv(tlv.ConstructFromObject(testObject, tmpl))
	if err != nil {
		t.Fatal("Failed to encode object:", err)
	}
	if len(rawTlv.Value()) != 0 {
		t.Fatal("TLV value must be empty.")
	}
}

func TestNestedNoTag(t *testing.T) {
	type nestedStructNoTag struct{ nested *nestedStructNoTag }
	testObject := &nestedStructNoTag{}

	if err := Register(testObject, "", 0x11); err != nil {
		t.Fatal("Failed to initialize templates:\n", err)
	}
	tmpl := assertGetTemplate(t, reflect.Indirect(reflect.ValueOf(testObject)).Type().Name())

	rawTlv, err := tlv.NewTlv(tlv.ConstructFromObject(testObject, tmpl))
	if err != nil {
		t.Fatal("Failed to encode object:", err)
	}
	if len(rawTlv.Value()) != 0 {
		t.Fatal("TLV value must be empty.")
	}
}

func TestNestedUnknownTag(t *testing.T) {
	type nestedWithUnknownTag struct {
		value byte `bla:"1,int8"`
	}
	testObject := &nestedWithUnknownTag{}

	if err := Register(&nestedWithUnknownTag{}, "", 0x02); err != nil {
		t.Fatal("Failed to initialize templates:\n", err)
	}
	tmpl := assertGetTemplate(t, reflect.Indirect(reflect.ValueOf(testObject)).Type().Name())

	rawTlv, err := tlv.NewTlv(tlv.ConstructFromObject(testObject, tmpl))
	if err != nil {
		t.Fatal("Failed to encode object:", err)
	}
	if len(rawTlv.Value()) != 0 {
		t.Fatal("TLV value must be empty.")
	}
}

func TestNestedTlvTag(t *testing.T) {

	type nestedWithTlvTag struct {
		byteVal *uint64 `tlv:"1,int8,E"`
		strVal  *string `tlv:"2,utf8"`
	}
	testObject := &nestedWithTlvTag{
		byteVal: func(v uint64) *uint64 { return &v }(0xde),
		strVal:  func(v string) *string { return &v }("dummy"),
	}
	testNofNested := 2

	if err := Register(testObject, "", 0x21); err != nil {
		t.Fatal("Failed to initialize templates:", err)
	}
	tmpl := assertGetTemplate(t, reflect.Indirect(reflect.ValueOf(testObject)).Type().Name())

	rawTlv, err := tlv.NewTlv(tlv.ConstructFromObject(testObject, tmpl))
	if err != nil {
		t.Fatal("Failed to encode object:", err)
	}

	if testNofNested != len(rawTlv.Nested) {
		t.Fatal("Nof nested elements mismatch.")
	}

	tlvByteVal, err := rawTlv.Nested[0].Uint8()
	if err != nil {
		t.Fatal("Failed to extract byte value from TLV:", err)
	}
	if tlvByteVal != *testObject.byteVal {
		t.Fatal("Byte value mismatch.")
	}

	tlvStringVal, err := rawTlv.Nested[1].Utf8()
	if err != nil {
		t.Fatal("Failed to extract string value from TLV:", err)
	}
	if tlvStringVal != *testObject.strVal {
		t.Fatal("String value mismatch.")
	}
}

func TestNestedTlvAndCustomTag(t *testing.T) {

	type nestedWithTlvAndCustomTag struct {
		byteVal *uint64 `tlv:"1,int8,E" bla:"some,opt"`
		strVal  *string `bla:"some,opt" tlv:"2,utf8"`
	}
	testObject := &nestedWithTlvAndCustomTag{
		byteVal: func(v uint64) *uint64 { return &v }(0xde),
		strVal:  func(v string) *string { return &v }("dummy"),
	}
	testNofNested := 2

	if err := Register(testObject, "", 0x22); err != nil {
		t.Fatal("Failed to initialize templates:", err)
	}
	tmpl := assertGetTemplate(t, reflect.Indirect(reflect.ValueOf(testObject)).Type().Name())

	rawTlv, err := tlv.NewTlv(tlv.ConstructFromObject(testObject, tmpl))
	if err != nil {
		t.Fatal("Failed to encode object:", err)
	}

	if testNofNested != len(rawTlv.Nested) {
		t.Fatal("Nof nested elements mismatch.")
	}

	tlvByteVal, err := rawTlv.Nested[0].Uint8()
	if err != nil {
		t.Fatal("Failed to extract byte value from TLV:", err)
	}
	if tlvByteVal != *testObject.byteVal {
		t.Fatal("Byte value mismatch.")
	}

	tlvStringVal, err := rawTlv.Nested[1].Utf8()
	if err != nil {
		t.Fatal("Failed to extract string value from TLV:", err)
	}
	if tlvStringVal != *testObject.strVal {
		t.Fatal("String value mismatch.")
	}
}

func TestGetInvalidName(t *testing.T) {
	type dummyEmptyStruct struct{}

	if err := Register(&dummyEmptyStruct{}, "", 0x04); err != nil {
		t.Fatal("Failed to initialize templates.")
	}
	assertGetTemplateInvalid(t, "dummyEmptyStruct ", "TLV Template does not exist for: 'dummyEmptyStruct '.")
	assertGetTemplateInvalid(t, " dummyEmptyStruct", "TLV Template does not exist for: ' dummyEmptyStruct'.")
	assertGetTemplate(t, "dummyEmptyStruct")

	assertGetTemplateInvalid(t, "a", "TLV Template does not exist for: 'a'.")
	assertGetTemplateInvalid(t, "", "TLV Template does not exist for: ''.")
}

func assertGetTemplate(t *testing.T, name string) *tlv.Template {
	tmpl, err := Get(name)
	if err != nil {
		t.Fatal("Failed to extract templates:", err)
	}
	if tmpl == nil {
		t.Fatal("Template must be returned.")
	}
	return tmpl
}

func assertGetTemplateInvalid(t *testing.T, name string, message string) {
	tmpl, err := Get(name)
	if err == nil {
		t.Fatalf("Getting Template '%s' by name should have been failed!", name)
	}
	if tmpl != nil {
		t.Fatal("Template should not be returned.")
	}
	if msg := errors.KsiErr(err).Message()[0]; msg != message {
		t.Fatalf("\nExpecting error: '%s'\nBut got error:   '%s'\n", message, msg)
	}
}
