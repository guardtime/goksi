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
	"unsafe"

	"github.com/guardtime/goksi/errors"
	"github.com/guardtime/goksi/hash"
)

func createTemplateParseTlv(t *testing.T, tlvSlice []byte, structType reflect.Type) (*Template, *Tlv) {
	template, err := NewTemplate(0x10)
	if err != nil {
		t.Fatalf("Unable to create TLV template %s.", err)
	}

	if err = template.Parse(structType); err != nil {
		t.Fatalf("Unable to resolve TLV template %s.", err)
	}

	tlv, err := NewTlv(ConstructFromSlice(tlvSlice))
	if err != nil {
		t.Fatalf("Unable read TLV from slice %s.", err)
	}
	if err = tlv.ParseNested(template); err != nil {
		t.Fatalf("Unable parse TLV %s.", err)
	}

	if !bytes.Equal(tlv.Raw, tlvSlice) {
		t.Fatalf("TLV value mismatch:\nExpecting:  %v\nBut is:     %v!", tlv.Raw, tlvSlice)
	}

	return template, tlv
}

func createTemplateParseTlvParseObjectCatchError(t *testing.T, tlvSlice []byte, structType reflect.Type, message string) (*Template, *Tlv) {
	template, err := NewTemplate(0x10)
	if err != nil {
		t.Fatalf("Unable to create TLV template %s.", err)
	}
	if err = template.Parse(structType); err != nil {
		t.Fatalf("Unable to resolve TLV template %s.", err)
	}

	tlv, err := NewTlv(ConstructFromSlice(tlvSlice))
	if err != nil {
		t.Fatalf("Unable read TLV from slice %s.", err)
	}

	if err = tlv.ParseNested(template); err != nil {
		t.Fatalf("Unable parse TLV %s.", err)
	}

	if !bytes.Equal(tlv.Raw, tlvSlice) {
		t.Fatalf("TLV value mismatch:\nExpecting:  %v\nBut is:     %v!", tlv.Raw, tlvSlice)
	}

	newBlob := createConstructorForObject(getDataTypeFromStructure(structType))

	err = tlv.ToObject(newBlob(), template, nil)
	if err == nil {
		t.Fatalf("This call should have been failed!")
	}

	msg := errors.KsiErr(err).Message()[0]
	if msg != message {
		t.Fatalf("\nExpecting error: '%s'\nBut got error:   '%s'\n", message, msg)
	}

	return template, tlv
}

type simpleInternalTestTlv struct {
	i   *string `tlv:"1,utf8"`
	raw *Tlv    `tlv:"basetlv"`
}

type simpleInternalTestTlv2 struct {
	i   *string `tlv:"4,utf8"`
	raw *Tlv
}

type customStruct struct {
	i   int
	tlv *Tlv
}

func (obj *customStruct) FromTlv(tlv *Tlv) error {
	obj.i = int(tlv.Tag)
	obj.tlv = tlv
	return nil
}

func (obj *customStruct) ToTlv(enc *Encoder) (*Tlv, error) {
	if obj == nil {
		return nil, nil
	}

	helperTemplate, err := newTemplate(VTTlvObj, uint16(obj.i))
	if err != nil {
		return nil, err
	}

	if _, err := enc.PrependHeader(helperTemplate.headerData(0)); err != nil {
		return nil, err
	}

	newTlv, err := NewTlv(ConstructEmpty(
		func() (tag uint16, nc bool, fu bool) {
			tag, nc, fu, _ = helperTemplate.headerData(0)
			return
		}()))
	if err != nil {
		return nil, err
	}

	return newTlv, nil
}

func (obj *simpleInternalTestTlv2) FromTlv(tlv *Tlv) error {
	obj.raw = tlv
	return nil
}

func (obj *simpleInternalTestTlv2) ToTlv(enc *Encoder) (*Tlv, error) {
	if obj == nil {
		return nil, nil
	}

	helperTemplate, err := newTemplate(VTTlvObj, uint16(0x14))
	if err != nil {
		return nil, err
	}
	if _, err := enc.PrependHeader(helperTemplate.headerData(0)); err != nil {
		return nil, err
	}

	newTlv, err := NewTlv(ConstructEmpty(
		func() (tag uint16, nc bool, fu bool) {
			tag, nc, fu, _ = helperTemplate.headerData(0)
			return
		}()))
	if err != nil {
		return nil, err
	}

	return newTlv, nil
}

func TestUnitTemplate2(t *testing.T) {
	type simpleTestTlv struct {
		binaryLst *[][]byte                 `tlv:"e,bin,C0_N"`
		custom    *customStruct             `tlv:"12,tlvobj"`
		customLst *[]*customStruct          `tlv:"13,tlvobj,C0_N"`
		special   *simpleInternalTestTlv2   `tlv:"14,nstd+tlvobj"`
		a         *[]*simpleInternalTestTlv `tlv:"8,nstd,C0_N"`
		b         *simpleInternalTestTlv2   `tlv:"9,nstd"`
		c         *[]uint64                 `tlv:"10,int,C0_N"`

		d                     *[]string `tlv:"11,utf8,C0_N"`
		binary                *[]byte   `tlv:"0f,bin"`
		f                     *uint64   `tlv:"5,int"`
		g                     *uint64   `tlv:"6,int"`
		h                     *uint64   `tlv:"7,int"`
		thisIsNotPartFromTlv1 int       `plah:"dummy"`
		thisIsNotPartFromTlv2 int       ``
		multiTag              *[]uint64 `tlv:"17|18,int,C0_N"`
		raw                   *Tlv      `tlv:"basetlv"`
	}

	var (
		obj = &simpleTestTlv{
			thisIsNotPartFromTlv1: 88,
			thisIsNotPartFromTlv2: 77,
		}

		multipleStrings = []byte{0x11, 0x03, 'S', '1', 0, 0x11, 0x03, 'S', '2', 0}
		multipleBinarys = []byte{0x0e, 0x02, 0xff, 0xaa, 0x0e, 0x02, 0xee, 0xbb}
		customTlv       = []byte{0x12, 0x00}
		customTlv2      = []byte{0x13, 0x00}

		subTlvf                = []byte{0x05, 0x02, 0x01, 0x00}
		subTlvg                = []byte{0x06, 0x01, 0x0f}
		subTlvh                = []byte{0x07, 0x03, 0x01, 0x00, 0x00}
		subTlva                = []byte{0x08, 0x07, 0x01, 0x05, 'T', 'E', 'S', 'T', 0}
		subTlvaa               = []byte{0x08, 0x07, 0x01, 0x05, 'B', 'E', 'S', 'T', 0}
		subTlvaaa              = []byte{0x08, 0x07, 0x01, 0x05, 'R', 'E', 'S', 'T', 0}
		subTlvb                = []byte{0x09, 0x07, 0x04, 0x05, 't', 'e', 's', 't', 0}
		subTlvc0               = []byte{0x10, 0x01, 0x0a}
		subTlvc1               = []byte{0x10, 0x01, 0x0b}
		subTlvc2               = []byte{0x10, 0x01, 0x0c}
		subTlvc3               = []byte{0x10, 0x01, 0x0d}
		binaryTlv3             = []byte{0x0f, 0x03, 0x09, 0x08, 0x07}
		multitag17             = []byte{0x17, 0x01, 0x17}
		multitag18             = []byte{0x18, 0x01, 0x18}
		specialParsebaleStruct = []byte{0x14, 0x09, 0x04, 0x07, 'C', 'U', 'S', 'T', 'O', 'M', 0}
	)

	parentTlvValue := append(subTlvf, subTlvg...)
	parentTlvValue = append(parentTlvValue, multipleBinarys...)
	parentTlvValue = append(parentTlvValue, subTlvh...)
	parentTlvValue = append(parentTlvValue, subTlva...)
	parentTlvValue = append(parentTlvValue, subTlvaa...)
	parentTlvValue = append(parentTlvValue, subTlvaaa...)
	parentTlvValue = append(parentTlvValue, subTlvb...)
	parentTlvValue = append(parentTlvValue, subTlvc0...)
	parentTlvValue = append(parentTlvValue, subTlvc1...)
	parentTlvValue = append(parentTlvValue, subTlvc2...)
	parentTlvValue = append(parentTlvValue, subTlvc3...)
	parentTlvValue = append(parentTlvValue, multipleStrings...)
	parentTlvValue = append(parentTlvValue, binaryTlv3...)
	parentTlvValue = append(parentTlvValue, multitag17...)
	parentTlvValue = append(parentTlvValue, multitag18...)
	parentTlvValue = append(parentTlvValue, customTlv...)
	parentTlvValue = append(parentTlvValue, customTlv2...)
	parentTlvValue = append(parentTlvValue, customTlv2...)
	parentTlvValue = append(parentTlvValue, specialParsebaleStruct...)
	parentTlv := append([]byte{0x10, byte(len(parentTlvValue))}, parentTlvValue...)

	template, tlv := createTemplateParseTlv(t, parentTlv, reflect.TypeOf(obj))

	if err := tlv.ToObject(obj, template, nil); err != nil {
		t.Fatalf("Unable to fill obj %s.", err)
	}

	if *obj.f != 0x100 || *obj.g != 0x0f || *obj.h != 0x10000 {
		t.Fatalf("Invalid integer values extracted.")
	}
	if obj.b == nil || *obj.b.i != "test" {
		t.Fatalf("Sub object not parsed.")
	}
	if len(*obj.a) != 3 || *(*obj.a)[0].i != "TEST" || *(*obj.a)[1].i != "BEST" || *(*obj.a)[2].i != "REST" {
		t.Fatalf("List of objects parsed incorrectly.")
	}
	if len(*obj.c) != 4 || (*obj.c)[0] != 10 || (*obj.c)[1] != 11 || (*obj.c)[2] != 12 || (*obj.c)[3] != 13 {
		t.Fatalf("List of integers parsed incorrectly.")
	}
	if len(*obj.d) != 2 || (*obj.d)[0] != "S1" || (*obj.d)[1] != "S2" {
		t.Fatalf("List of strings parsed incorrectly.")
	}
	if obj.thisIsNotPartFromTlv1 != 88 {
		t.Fatalf("Value not included into TLV template is changed!.")
	}
	if obj.thisIsNotPartFromTlv2 != 77 {
		t.Fatalf("Value not included into TLV template is changed!.")
	}
	if len(*obj.binary) != 3 || (*obj.binary)[0] != 9 || (*obj.binary)[1] != 8 || (*obj.binary)[2] != 7 {
		t.Fatalf("Octet string extracted incorrectly.")
	}
	if len(*obj.binaryLst) != 2 || (*obj.binaryLst)[0][0] != 0xff || (*obj.binaryLst)[0][1] != 0xaa || (*obj.binaryLst)[1][0] != 0xee || (*obj.binaryLst)[1][1] != 0xbb {
		t.Fatalf("Octet string extracted incorrectly.")
	}
	if len(*obj.multiTag) != 2 || (*obj.multiTag)[0] != 0x17 || (*obj.multiTag)[1] != 0x18 {
		t.Fatalf("Value with multiple tags parsed incorrectly.")
	}
	if obj.custom.i != 0x12 || obj.custom.tlv == nil || int(obj.custom.tlv.Tag) != obj.custom.i {
		t.Fatalf("Custom TLV parsed incorrectly.")
	}
	if len(*obj.customLst) != 2 || (*obj.customLst)[0].i != 0x13 || (*obj.customLst)[0].tlv == nil || int((*obj.customLst)[0].tlv.Tag) != (*obj.customLst)[0].i || len(*obj.customLst) != 2 || (*obj.customLst)[1].i != 0x13 || (*obj.customLst)[1].tlv == nil || int((*obj.customLst)[1].tlv.Tag) != (*obj.customLst)[1].i {
		t.Fatalf("Custom TLV list parsed incorrectly.")
	}
	if obj.raw == nil || len(obj.raw.value) != len(tlv.value) {
		t.Fatalf("Base TLV parsed incorrectly.")
	}
	if (*obj.a)[0].raw == nil || len((*obj.a)[0].raw.value) != 7 || (*obj.a)[1].raw == nil || len((*obj.a)[1].raw.value) != 7 {
		t.Fatalf("Base TLV parsed incorrectly.")
	}
}

func TestUnitGetImprint(t *testing.T) {
	type simpleImprints struct {
		imprint     *hash.Imprint   `tlv:"1,imp"`
		imprintList *[]hash.Imprint `tlv:"2,imp,C0_N"`
	}
	var (
		obj = &simpleImprints{}

		imprintTlv      = []byte{0x01, 33, 0x01, 0x10, 0x01, 0xf0, 0x47, 0x6a, 0xe7, 0x60, 0x3d, 0xe7, 0x9a, 0x0a, 0x12, 0x97, 0x38, 0xfb, 0x31, 0xa9, 0x82, 0x63, 0xf8, 0xe5, 0x70, 0xde, 0xba, 0xa1, 0xef, 0xcb, 0x1e, 0x6b, 0x4c, 0xa, 0xf0}
		imprintListTlv0 = []byte{0x02, 33, 0x01, 0x11, 0x01, 0xf0, 0x47, 0x6a, 0xe7, 0x60, 0x3d, 0xe7, 0x9a, 0x0a, 0x12, 0x97, 0x38, 0xfb, 0x31, 0xa9, 0x82, 0x63, 0xf8, 0xe5, 0x70, 0xde, 0xba, 0xa1, 0xef, 0xcb, 0x1e, 0x6b, 0x4c, 0xa, 0xf0}
		imprintListTlv1 = []byte{0x02, 33, 0x01, 0x12, 0x01, 0xf0, 0x47, 0x6a, 0xe7, 0x60, 0x3d, 0xe7, 0x9a, 0x0a, 0x12, 0x97, 0x38, 0xfb, 0x31, 0xa9, 0x82, 0x63, 0xf8, 0xe5, 0x70, 0xde, 0xba, 0xa1, 0xef, 0xcb, 0x1e, 0x6b, 0x4c, 0xa, 0xf0}
		imprintListTlv2 = []byte{0x02, 33, 0x01, 0x13, 0x01, 0xf0, 0x47, 0x6a, 0xe7, 0x60, 0x3d, 0xe7, 0x9a, 0x0a, 0x12, 0x97, 0x38, 0xfb, 0x31, 0xa9, 0x82, 0x63, 0xf8, 0xe5, 0x70, 0xde, 0xba, 0xa1, 0xef, 0xcb, 0x1e, 0x6b, 0x4c, 0xa, 0xf0}
	)
	parentTlvValue := imprintTlv
	parentTlvValue = append(parentTlvValue, imprintListTlv0...)
	parentTlvValue = append(parentTlvValue, imprintListTlv1...)
	parentTlvValue = append(parentTlvValue, imprintListTlv2...)
	parentTlv := append([]byte{0x10, byte(len(parentTlvValue))}, parentTlvValue...)

	template, tlv := createTemplateParseTlv(t, parentTlv, reflect.TypeOf(obj))

	if err := tlv.ToObject(obj, template, nil); err != nil {
		t.Fatalf("Unable to fill obj %s.", err)
	}

	if !bytes.Equal(*(*[]byte)(obj.imprint), imprintTlv[2:]) {
		t.Fatalf("Imprint mismatch:\nExpecting:  %v\nBut is:     %v", hash.Imprint(imprintTlv[2:]), obj.imprint)
	}
	if !bytes.Equal(([]byte)((*obj.imprintList)[0]), imprintListTlv0[2:]) {
		t.Fatalf("Imprint mismatch:\nExpecting:  %v\nBut is:     %v", hash.Imprint(imprintListTlv0[2:]), (*obj.imprintList)[0])
	}
	if !bytes.Equal(([]byte)((*obj.imprintList)[1]), imprintListTlv1[2:]) {
		t.Fatalf("Imprint mismatch:\nExpecting:  %v\nBut is:     %v", hash.Imprint(imprintListTlv1[2:]), (*obj.imprintList)[1])
	}
	if !bytes.Equal(([]byte)((*obj.imprintList)[2]), imprintListTlv2[2:]) {
		t.Fatalf("Imprint mismatch:\nExpecting:  %v\nBut is:     %v", hash.Imprint(imprintListTlv2[2:]), (*obj.imprintList)[2])
	}
}

func TestUnitGetIntegers(t *testing.T) {
	type simpleIntegers struct {
		I64  *uint64   `tlv:"1,int"`
		I64L *[]uint64 `tlv:"2,int,C0_N"`
		I8   *uint64   `tlv:"3,int8"`
		I8L  *[]uint64 `tlv:"4,int8,C0_N"`
	}
	var (
		obj = &simpleIntegers{}

		int_i64    = []byte{0x01, 2, 0x01, 0x00}
		int_i64L_0 = []byte{0x02, 2, 0x02, 0x00}
		int_i64L_1 = []byte{0x02, 2, 0x03, 0x00}
		int_i8     = []byte{0x03, 1, 0xff}
		int_i8L_0  = []byte{0x04, 1, 0x0}
		int_i8L_1  = []byte{0x04, 1, 0xff}
	)
	parentTlvValue := int_i64
	parentTlvValue = append(parentTlvValue, int_i64L_0...)
	parentTlvValue = append(parentTlvValue, int_i64L_1...)
	parentTlvValue = append(parentTlvValue, int_i8...)
	parentTlvValue = append(parentTlvValue, int_i8L_0...)
	parentTlvValue = append(parentTlvValue, int_i8L_1...)
	parentTlv := append([]byte{0x10, byte(len(parentTlvValue))}, parentTlvValue...)

	template, tlv := createTemplateParseTlv(t, parentTlv, reflect.TypeOf(obj))

	if err := tlv.ToObject(obj, template, nil); err != nil {
		t.Fatalf("Unable to fill obj %s.", err)
	}

	if *obj.I64 != 0x100 || *obj.I8 != 0xff {
		t.Fatalf("Simple integer parsed incorrectly.")
	}
	i64L := *obj.I64L
	if len(i64L) != 2 && i64L[0] != 0x200 && i64L[1] != 0x300 {
		t.Fatalf("List of uint64 parsed incorrectly.")
	}
	i8L := *obj.I8L
	if len(i8L) != 2 && i8L[0] != 0x00 && i8L[1] != 0xff {
		t.Fatalf("List of uint64 (acting as 8bit values) parsed incorrectly.")
	}
}

func TestUnitGetEmptyStruct(t *testing.T) {
	type emptyStruct struct{}
	obj := new(emptyStruct)

	parentTlv := []byte{0x10, 0}
	template, tlv := createTemplateParseTlv(t, parentTlv, reflect.TypeOf(obj))

	if err := tlv.ToObject(obj, template, nil); err != nil {
		t.Fatalf("Unable to fill obj %s.", err)
	}
}

func TestUnitGetIntegerEmptyValue(t *testing.T) {
	type integerStruct struct {
		I64E *uint64 `tlv:"1,int,E"`
		I64  *uint64 `tlv:"2,int"`
		I8E  *uint64 `tlv:"3,int8,E"`
		I8   *uint64 `tlv:"4,int8"`
	}
	var (
		obj = &integerStruct{
			I64:  newInt(0xff),
			I64E: newInt(0xff),
			I8:   newInt(0xff),
			I8E:  newInt(0xff),
		}
		parentTlv = []byte{0x10, 0x0a, 0x01, 0x00, 0x02, 0x01, 0xa, 0x03, 0x00, 0x04, 0x01, 0x0b}
	)
	template, tlv := createTemplateParseTlv(t, parentTlv, reflect.TypeOf(obj))

	if err := tlv.ToObject(obj, template, nil); err != nil {
		t.Fatalf("Unable to fill obj %s.", err)
	}
	if *obj.I64E != 0 || *obj.I64 != 0x0a || *obj.I8E != 0 || *obj.I8 != 0x0b {
		t.Fatalf("Object parsed incorrectly")
	}
}

func TestUnitGetIntegerEmptyValueFailure(t *testing.T) {
	type integerStruct struct {
		I64E *uint64 `tlv:"1,int,E"`
		I64  *uint64 `tlv:"2,int"`
		I8E  *uint64 `tlv:"3,int8,E"`
		I8   *uint64 `tlv:"4,int8"`
	}
	parentTlv := []byte{0x10, 0x0a, 0x02, 0x00, 0x01, 0x01, 0xa, 0x03, 0x00, 0x04, 0x01, 0x0b}
	createTemplateParseTlvParseObjectCatchError(t, parentTlv, reflect.TypeOf(new(integerStruct)), "TLV value for 64bit integer is empty.")
	parentTlv = []byte{0x10, 0x0a, 0x01, 0x00, 0x02, 0x01, 0xa, 0x04, 0x00, 0x03, 0x01, 0x0b}
	createTemplateParseTlvParseObjectCatchError(t, parentTlv, reflect.TypeOf(new(integerStruct)), "TLV value for 8bit integer is empty.")
}

func TestUnitGetStringEmptyValue(t *testing.T) {
	type stringStruct struct {
		SE *string `tlv:"1,utf8,E"`
		S  *string `tlv:"2,utf8"`
	}
	var (
		obj       = new(stringStruct)
		parentTlv = []byte{0x10, 0x09, 0x01, 0x00, 0x02, 0x05, 'T', 'E', 'S', 'T', 0x00}
	)
	template, tlv := createTemplateParseTlv(t, parentTlv, reflect.TypeOf(obj))

	if err := tlv.ToObject(obj, template, nil); err != nil {
		t.Fatalf("Unable to fill obj %s.", err)
	}
	if *obj.SE != "" || *obj.S != "TEST" {
		t.Fatalf("Object parsed incorrectly")
	}
}

func TestUnitGetStringEmptyValueFailure(t *testing.T) {
	type stringStruct struct {
		SE *string `tlv:"1,utf8,E"`
		S  *string `tlv:"2,utf8"`
	}
	parentTlv := []byte{0x10, 0x09, 0x02, 0x00, 0x01, 0x05, 'T', 'E', 'S', 'T', 0x00}
	createTemplateParseTlvParseObjectCatchError(t, parentTlv, reflect.TypeOf(new(stringStruct)), "TLV value for string is empty.")
}

func TestUnitInitializeWithStringContext(t *testing.T) {
	type structWithContext struct {
		dummy     *uint64 `tlv:"1,int"`
		myContext *string `tlv:"context,string"`
	}
	var (
		obj       = &structWithContext{}
		parentTlv = []byte{0x10, 0x03, 0x01, 0x01, 0xaa}
	)
	template, tlv := createTemplateParseTlv(t, parentTlv, reflect.TypeOf(obj))

	s := newStr("This is Context!")
	if err := tlv.ToObject(obj, template, unsafe.Pointer(s)); err != nil {
		t.Fatalf("Unable to fill obj %s.", err)
	}
	if *obj.dummy != 0xaa || *obj.myContext != *s {
		t.Fatalf("Object parsed incorrectly")
	}
}

func TestUnitInitializeWithStringContextNil(t *testing.T) {
	type structWithContext struct {
		dummy     *uint64 `tlv:"1,int"`
		myContext *string `tlv:"context,string"`
	}
	var (
		obj       = &structWithContext{}
		parentTlv = []byte{0x10, 0x03, 0x01, 0x01, 0xaa}
	)
	template, tlv := createTemplateParseTlv(t, parentTlv, reflect.TypeOf(obj))

	if err := tlv.ToObject(obj, template, nil); err != nil {
		t.Fatalf("Unable to fill obj %s.", err)
	}
	if *obj.dummy != 0xaa || obj.myContext != nil {
		t.Fatalf("Object parsed incorrectly")
	}
}

func TestUnitInitializeWithStringContextNested(t *testing.T) {
	type (
		internalStruct struct {
			dummy     *uint64 `tlv:"1,int"`
			myContext *string `tlv:"context,string"`
		}
		structWithContext struct {
			dummy  *uint64         `tlv:"1,int"`
			myself *internalStruct `tlv:"2,nstd"`

			myContext *string `tlv:"context,string"`
		}
	)
	var (
		obj       = &structWithContext{}
		parentTlv = []byte{0x10, 0x08, 0x01, 0x01, 0xaa, 0x02, 0x03, 0x01, 0x01, 0xbb}
	)
	template, tlv := createTemplateParseTlv(t, parentTlv, reflect.TypeOf(obj))

	s := newStr("This is Context!")
	if err := tlv.ToObject(obj, template, unsafe.Pointer(s)); err != nil {
		t.Fatalf("Unable to fill obj %s.", err)
	}
	if *obj.dummy != 0xaa || obj.myContext != s || obj.myself == nil || *(*obj.myself).dummy != 0xbb {
		t.Fatalf("Object parsed incorrectly")
	}
}

func TestUnitInitializeWithStructContext(t *testing.T) {
	type (
		context struct {
			someContext string
		}
		structWithContext struct {
			dummy *uint64  `tlv:"1,int"`
			ctx   *context `tlv:"context,context"`
		}
	)
	var (
		obj = new(structWithContext)
		ctx = &context{
			someContext: "This is custom struct inserted into object as some random context.",
		}
		parentTlv = []byte{0x10, 0x03, 0x01, 0x01, 0xaa}
	)
	template, tlv := createTemplateParseTlv(t, parentTlv, reflect.TypeOf(obj))

	if err := tlv.ToObject(obj, template, unsafe.Pointer(ctx)); err != nil {
		t.Fatalf("Unable to fill obj %s.", err)
	}
	if *obj.dummy != 0xaa || obj.ctx != ctx {
		t.Fatalf("Object parsed incorrectly")
	}
}

func TestUnitInitializeWithStructContextNested(t *testing.T) {
	type (
		context struct {
			someContext string
		}
		internalStruct struct {
			dummy *uint64  `tlv:"1,int"`
			ctx   *context `tlv:"context,context"`
		}
		structWithContext struct {
			dummy    *uint64         `tlv:"1,int"`
			internal *internalStruct `tlv:"2,nstd"`
			ctx      *context        `tlv:"context,context"`
		}
	)
	var (
		obj = &structWithContext{}
		ctx = &context{
			someContext: "This is custom struct inserted into object as some random context.",
		}
		parentTlv = []byte{0x10, 0x08, 0x01, 0x01, 0xaa, 0x02, 0x03, 0x01, 0x01, 0xbb}
	)
	template, tlv := createTemplateParseTlv(t, parentTlv, reflect.TypeOf(obj))

	if err := tlv.ToObject(obj, template, unsafe.Pointer(ctx)); err != nil {
		t.Fatalf("Unable to fill obj %s.", err)
	}
	if *obj.dummy != 0xaa || obj.ctx != ctx || obj.internal == nil || obj.internal.ctx != ctx || *obj.internal.dummy != 0xbb {
		t.Fatalf("Object parsed incorrectly")
	}
}

func TestUnitGetUnknownNonCritical(t *testing.T) {
	type integerStruct struct {
		dummy *uint64 `tlv:"1,int"`
	}
	var (
		obj       = &integerStruct{}
		parentTlv = []byte{0x10, 0x06, 0x01, 0x01, 0x05, 0x02 | byte(HeaderFlagN), 0x1, 0x8}
	)
	template, tlv := createTemplateParseTlv(t, parentTlv, reflect.TypeOf(obj))

	if err := tlv.ToObject(obj, template, nil); err != nil {
		t.Fatalf("Unable to fill obj %s.", err)
	}

	var (
		tlvAfterParse = tlv.String()
		expectedTlv   = `TLV[0x10]: 
    TLV[0x1]: 05
    TLV[0x2,N]: 08
`
	)
	if tlvAfterParse != expectedTlv {
		t.Fatalf("Expecting tlv:\n'%s'\nBut got:\n'%s'", expectedTlv, tlvAfterParse)
	}
	if *obj.dummy != 5 {
		t.Fatalf("Object parsed incorrectly")
	}
}

func TestUnitGetUnknownNonCriticalFastForward(t *testing.T) {
	type integerStruct struct {
		dummy *uint64 `tlv:"1,int"`
	}
	var (
		obj       = &integerStruct{}
		parentTlv = []byte{0x10, 0x06, 0x01, 0x01, 0x05, 0x02 | byte(HeaderFlagN) | byte(HeaderFlagF), 0x1, 0x8}
	)
	template, tlv := createTemplateParseTlv(t, parentTlv, reflect.TypeOf(obj))

	if err := tlv.ToObject(obj, template, nil); err != nil {
		t.Fatalf("Unable to fill obj %s.", err)
	}

	var (
		tlvAfterParse = tlv.String()
		expectedTlv   = `TLV[0x10]: 
    TLV[0x1]: 05
`
	)
	if tlvAfterParse != expectedTlv {
		t.Fatalf("Expecting TLV:\n'%s'\nBut got:\n'%s'", expectedTlv, tlvAfterParse)
	}
	if *obj.dummy != 5 {
		t.Fatalf("Object parsed incorrectly")
	}
}

func TestUnitGetUnknownCritical(t *testing.T) {
	type integerStruct struct {
		dummy *uint64 `tlv:"1,int"`
	}

	parentTlv := []byte{0x10, 0x06, 0x01, 0x01, 0x05, 0x02, 0x1, 0x8}
	template, err := NewTemplate(0x10)
	if err != nil {
		t.Fatalf("Unable to create TLV template %s.", err)
	}
	err = template.Parse(reflect.TypeOf(new(integerStruct)))
	if err != nil {
		t.Fatalf("Unable to resolve TLV template %s.", err)
	}

	tlv, err := NewTlv(ConstructFromSlice(parentTlv))
	if err != nil {
		t.Fatalf("Unable read TLV from slice %s.", err)
	}

	if err := tlv.ParseNested(template); err == nil {
		t.Fatalf("Parsing of critical unknown TLV should have been failed. %s.", err)
	} else {
		message := "TLV (10.2) template not found for a mandatory TLV."
		msg := errors.KsiErr(err).Message()[0]
		if msg != message {
			t.Fatalf("\nExpecting error: '%s'\nBut got error:   '%s'\n", message, msg)
		}
	}
}

func TestUnitTemplateDoesNotMatchWithTlvTag(t *testing.T) {
	type integerStruct struct {
		dummy *uint64 `tlv:"1,int"`
	}

	parentTlv := []byte{0x10, 0x06, 0x01, 0x01, 0x05, 0x02, 0x1, 0x8}
	template, err := NewTemplate(0x11)
	if err != nil {
		t.Fatalf("Unable to create TLV template %s.", err)
	}
	err = template.Parse(reflect.TypeOf(new(integerStruct)))
	if err != nil {
		t.Fatalf("Unable to resolve TLV template %s.", err)
	}

	tlv, err := NewTlv(ConstructFromSlice(parentTlv))
	if err != nil {
		t.Fatalf("Unable read TLV from slice %s.", err)
	}

	if err := tlv.ParseNested(template); err == nil {
		t.Fatalf("Parsing with not matching template should have been failed. %s.", err)
	} else {
		message := "TLV (10) does not match with template tags [11]."
		msg := errors.KsiErr(err).Message()[0]
		if msg != message {
			t.Fatalf("\nExpecting error: '%s'\nBut got error:   '%s'\n", message, msg)
		}
	}
}
