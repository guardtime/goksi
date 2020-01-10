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
	"reflect"
	"testing"

	"github.com/guardtime/goksi/errors"
	"github.com/guardtime/goksi/hash"
)

func isDefaultOptionsOk(opt *templateOptions) bool {
	return !(opt.groupID != GroupNone ||
		opt.expectedIndex != IWhatever ||
		opt.expectedCount != Count0_1 ||
		opt.conflictingGroup != nil ||
		opt.dependencyGroup != nil ||
		opt.FastForward ||
		opt.NonCritical)
}

func TestUnitNewTemplateOptions(t *testing.T) {
	if !isDefaultOptionsOk(newTemplateOptions()) {
		t.Fatalf("Unexpected default values for newTemplateOptions.")
	}
}

func TestUnitParsingTlvOptions(t *testing.T) {
	var (
		tests = []struct {
			opts   []string
			assert func(*templateOptions) bool
		}{
			{
				[]string{"C0_N", "IF", "G1", "F"},
				func(o *templateOptions) bool {
					return o.groupID == templateGroup(1) && o.expectedIndex == IFirst && o.expectedCount == Count0_N && o.FastForward && !o.emptyTlvPermitted
				},
			},
			{
				[]string{"C1_N", "IL", "!G3", "N", "E"},
				func(o *templateOptions) bool {
					return o.groupID == GroupNone && o.expectedIndex == ILast && o.expectedCount == Count1_N && o.conflictingGroup[0] == templateGroup(3) && o.dependencyGroup == nil && o.NonCritical && o.emptyTlvPermitted
				},
			},
			{
				[]string{"C10", "I1", "&G4", "N", "F"},
				func(o *templateOptions) bool {
					return o.groupID == GroupNone && o.expectedIndex == templateIndex(1) && o.expectedCount == templateCount(10) && o.conflictingGroup == nil && o.dependencyGroup[0] == templateGroup(4) && o.FastForward && o.NonCritical
				},
			},
		}
	)

	for _, tc := range tests {
		op := newTemplateOptions()

		for _, o := range tc.opts {
			if op.parseTemplateOptions(o) != nil {
				t.Fatalf("Unable to parse TLV option.")
			}
		}
		if !tc.assert(op) {
			t.Fatalf("Unexpected values for TemplateOptions %s.", op.String())
		}
	}
}

func TestUnitParsingInvalidTlvOptions(t *testing.T) {
	var (
		op     = newTemplateOptions()
		values = []string{"random",
			"G", "G 1", "G-2", "GN", "G2x",
			"C", "C 1", "C-2", "CN", "C2X",
			"I", "I 1", "I-2", "IN", "I2X",
			"!", "!G", "!GX", "!G-1", "!G2X",
			"&", "&G", "&GX", "&G-1", "&G2X",
			"FF", "NN", "FN",
		}
	)

	for _, v := range values {
		if err := op.parseTemplateOptions(v); err == nil || errors.KsiErr(err).Code() != errors.KsiInvalidFormatError {
			t.Fatalf("Invalid string parsed as template options must fail.")
		}
	}
}

func isDefaultTlvTemplateOk(template *Template, tag uint16, tt templateType) bool {
	return !(template.childTemplate != nil ||
		!isDefaultOptionsOk(template.options) ||
		!template.IsMatchingTag(tag) ||
		template.templateType != tt)
}

func TestUnitNewTlvTemplate(t *testing.T) {
	template, err := NewTemplate(0x01)
	if err != nil || template == nil {
		t.Fatalf("Unable to create NewTemplate struct.")
	}

	if !isDefaultTlvTemplateOk(template, 0x01, VTNested) {
		t.Fatalf("Unable to create NewTemplate struct.")
	}

	// Create a TLV Template with unknown type.
	template, err = NewTemplate(0xffff)
	if err == nil {
		t.Fatalf("This call should have been failed!")
	}
	if template != nil {
		t.Fatalf("In case of failure returned Template should have been nil!")
	}

	message := "TLV tag out of range is 0xffff, but 0x1fff is maximum."
	msg := errors.KsiErr(err).Message()[0]
	if msg != message {
		t.Fatalf("\nExpecting error: '%s'\nBut got error:   '%s'\n", message, msg)
	}

}

func belongsToGroup(groups []templateGroup, g templateGroup) bool {
	for _, v := range groups {
		if v == g {
			return true
		}
	}

	return false
}

func equalGroups(A, B []templateGroup) bool {
	if A == nil && B == nil {
		return true
	}

	if (len(A) != len(B)) || (A == nil && B != nil) || (A != nil && B == nil) {
		return false
	}

	for _, v := range A {
		if !belongsToGroup(B, v) {
			return false
		}
	}

	return true
}

func parseTlvTemplateAssert(t *testing.T, tag string, tlvtype uint16, templatetype templateType, c templateCount, i templateIndex, g templateGroup, cg, dg []templateGroup) {
	template, err := parseTlvTemplate(tag)
	if err != nil || template == nil {
		t.Fatalf("Unable to parse TLV template from '%s'.", tag)
	}

	if !template.IsMatchingTag(tlvtype) {
		t.Fatalf("Expected TLV tag  mismatch. Expected '%x' but is '%x'.", tlvtype, int(template.tag[0]))
	}

	if templatetype != template.templateType {
		t.Fatalf("Expected Template type  mismatch. Expected '%s' but is '%s'.", templatetype.String(), template.templateType.String())
	}

	if template.options.expectedCount != c {
		t.Fatalf("Expected template count mismatch. Expected '%s' but is '%s'.", c.String(), template.options.expectedCount.String())
	}

	if template.options.expectedIndex != i {
		t.Fatalf("Expected template index mismatch. Expected '%s' but is '%s'.", i.String(), template.options.expectedIndex.String())
	}

	if template.options.groupID != g {
		t.Fatalf("Expected template group mismatch. Expected '%s' but is '%s'.", g.String(), template.options.groupID.String())
	}

	if !equalGroups(cg, template.options.conflictingGroup) {
		t.Fatalf("Conflicting groups mismatch. Expected '%v' but is '%v'.", cg, template.options.conflictingGroup)
	}

	if !equalGroups(dg, template.options.dependencyGroup) {
		t.Fatalf("Dependency groups mismatch. Expected '%v' but is '%v'.", dg, template.options.dependencyGroup)
	}

}

func TestUnitTlvTemplateParsingFromStructTag(t *testing.T) {
	testData := []struct {
		tag          string
		tlvtype      uint16
		templatetype templateType
		c            templateCount
		i            templateIndex
		g            templateGroup
		cg           []templateGroup
		dg           []templateGroup
	}{
		{"0200,int", 0x200, VTInt, Count0_1, IWhatever, GroupNone, nil, nil},
		{"00200,int", 0x200, VTInt, Count0_1, IWhatever, GroupNone, nil, nil},
		{"0x200,int", 0x200, VTInt, Count0_1, IWhatever, GroupNone, nil, nil},
		{"200,int", 0x200, VTInt, Count0_1, IWhatever, GroupNone, nil, nil},
		{"200,int8", 0x200, VTInt8, Count0_1, IWhatever, GroupNone, nil, nil},
		{"200,imp", 0x200, VTImprint, Count0_1, IWhatever, GroupNone, nil, nil},
		{"200,bin", 0x200, VTbin, Count0_1, IWhatever, GroupNone, nil, nil},
		{"200,utf8", 0x200, VTUtf8, Count0_1, IWhatever, GroupNone, nil, nil},
		{"200,nstd", 0x200, VTNested, Count0_1, IWhatever, GroupNone, nil, nil},
		{"a,bin,C0_1", 0xa, VTbin, Count0_1, IWhatever, GroupNone, nil, nil},
		{"b,bin,C0_N", 0xb, VTbin, Count0_N, IWhatever, GroupNone, nil, nil},
		{"c,bin,C1_N", 0xc, VTbin, Count1_N, IWhatever, GroupNone, nil, nil},
		{"d,bin,C5", 0xd, VTbin, templateCount(5), IWhatever, GroupNone, nil, nil},
		{"a,bin,IF", 0xa, VTbin, Count0_1, IFirst, GroupNone, nil, nil},
		{"b,bin,IL", 0xb, VTbin, Count0_1, ILast, GroupNone, nil, nil},
		{"c,bin,IW", 0xc, VTbin, Count0_1, IWhatever, GroupNone, nil, nil},
		{"d,bin,I5", 0xd, VTbin, Count0_1, templateIndex(5), GroupNone, nil, nil},
		{"100,nstd,IL,C0_1,G1", 0x100, VTNested, Count0_1, ILast, templateGroup(1), nil, nil},
		{"200,int,G1,!G2,&G0,&G3", 0x200, VTInt, Count0_1, IWhatever, templateGroup(1), []templateGroup{templateGroup(2)}, []templateGroup{templateGroup(0), templateGroup(3)}},
	}

	for _, tc := range testData {
		parseTlvTemplateAssert(t, tc.tag, tc.tlvtype, tc.templatetype, tc.c, tc.i, tc.g, tc.cg, tc.dg)
	}
}

func TestUnitTlvTemplateParsingFromInvalidStructTag(t *testing.T) {
	testData := []struct {
		tag   string
		ecode errors.ErrorCode
	}{
		{"200", errors.KsiInvalidFormatError},
		{",", errors.KsiInvalidFormatError},
		{"200,plah", errors.KsiInvalidFormatError},
		{"200,bin,plah", errors.KsiInvalidFormatError},
	}

	for _, tc := range testData {
		template, err := parseTlvTemplate(tc.tag)
		if err == nil {
			t.Fatalf("Parsing of TLV struct tag should have been failed!")
		}
		if template != nil {
			t.Fatalf("Parsing of TLV struct tag should have been failed!")
		}
		if errors.KsiErr(err).Code() != tc.ecode {
			t.Fatalf("Expecting '%s' but is '%s' (%s).", tc.ecode.String(), errors.KsiErr(err).Code().String(), errors.KsiErr(err).Message())
		}
	}
}

func TestUnitParseFromStruct(t *testing.T) {
	type (
		subTlv struct {
			f *uint64 `tlv:"5,int,F"`
			g *uint64 `tlv:"6,int8,N"`
			h *uint64 `tlv:"7,int,E"`
			s *string `tlv:"8,utf8,F,N"`
			b *[]byte `tlv:"9,bin,F,N,E"`
		}

		parentTlv struct {
			a  *uint64         `tlv:"1,int,IF"`
			b  *subTlv         `tlv:"2,nstd,I1"`
			c  *[]uint64       `tlv:"3,int,C0_N"`
			i  *hash.Imprint   `tlv:"4,imp"`
			j  *[]hash.Imprint `tlv:"5,imp,C0_N"`
			g1 *string         `tlv:"6,utf8,G1,!G2"`
			g2 *string         `tlv:"7,utf8,G2,!G1,&G3"`
			g3 *string         `tlv:"8,utf8,G3,IL"`
		}
	)

	expected := `[a],nested,(GNone,C0_1,IW,!G[],&G[]) {
  [1],uint64,(GNone,C0_1,IF,!G[],&G[]) struct.a
  [2],nested,(GNone,C0_1,I1,!G[],&G[]) struct.b{
    [5],uint64,(GNone,C0_1,IW,!G[],&G[],F) struct.f
    [6],uint64(8bit limit),(GNone,C0_1,IW,!G[],&G[],N) struct.g
    [7],uint64,(GNone,C0_1,IW,!G[],&G[],E) struct.h
    [8],utf8,(GNone,C0_1,IW,!G[],&G[],NF) struct.s
    [9],binary,(GNone,C0_1,IW,!G[],&G[],NFE) struct.b
  }
  [3],[]uint64,(GNone,C0_N,IW,!G[],&G[]) struct.c
  [4],imprint,(GNone,C0_1,IW,!G[],&G[]) struct.i
  [5],[]imprint,(GNone,C0_N,IW,!G[],&G[]) struct.j
  [6],utf8,(G1,C0_1,IW,!G[2],&G[]) struct.g1
  [7],utf8,(G2,C0_1,IW,!G[1],&G[3]) struct.g2
  [8],utf8,(G3,C0_1,IL,!G[],&G[]) struct.g3
}`

	tmpl, err := NewTemplate(0xa)
	if err != nil {
		t.Fatalf("Unable to create NewTemplate struct.")
	}
	if err := tmpl.Parse(reflect.TypeOf(new(parentTlv))); err != nil {
		t.Fatalf("Unable to create TLV template from struct. %v", err)
	}
	result := tmpl.String()
	if result != expected {
		t.Fatalf("Unexpected TLV template created:\nExpected:\n'%s'\nBut is:\n'%s'\n", expected, result)
	}
}

func TestUnitParseInvalidStructs(t *testing.T) {
	type (
		nokNonSliceTooBig1 struct {
			val *uint64 `tlv:"1,int,C0_N"`
		}
		nokNonSliceTooBig2 struct {
			val *uint64 `tlv:"4,int,C1_N"`
		}
		nokNonSliceTooBig3 struct {
			val *uint64 `tlv:"8,int,C2"`
		}
		nokSliceTooSmall1 struct {
			val *[]uint64 `tlv:"16|17,int,C0_1"`
		}
		nokSliceTooSmall2 struct {
			val *[]uint64 `tlv:"16,int,C1"`
		}
		nokInvalidBaseType1 struct {
			val *string `tlv:"8,int"`
		}
		nokInvalidBaseType2 struct {
			val *uint64 `tlv:"8,utf8"`
		}
		nokInvalidSliceType1 struct {
			val *[]uint64 `tlv:"8,utf8,C0_N"`
		}
		nokInvalidSliceType2 struct {
			val *[]string `tlv:"8,int,C0_N"`
		}
		nokInvalidSliceType3 struct {
			val *[]*uint64 `tlv:"8,int,C0_N"`
		}
		nokInvalidSliceType4 struct {
			val *[][]uint64 `tlv:"8,int,C0_N"`
		}
		okTestStruct struct {
			val *uint64 `tlv:"8,int"`
		}
		okTestStruct3 struct {
			valueUnderNokInvalidBaseType2 *nokInvalidBaseType2 `tlv:"22,nstd"`
		}
		okTestStruct2 struct {
			valueUnderOkTestStruct3 *okTestStruct3 `tlv:"11,nstd"`
		}
		nokInvalidNested1 struct {
			val *okTestStruct `tlv:"8,int"`
		}
		nokInvalidNestedNotPointer struct {
			val okTestStruct `tlv:"8,int"`
		}
		nokByteArrayWithoutExplicitTag1 struct {
			val *[]byte `tlv:"9,int,C0_N"`
		}
		nokByteArrayWithoutExplicitTag2 struct {
			val *[][]byte `tlv:"9,int,C0_N"`
		}
		nokUnimplementedFromTlv1 struct {
			val *okTestStruct `tlv:"e,tlvobj"`
		}
		nokUnimplementedFromTlv2 struct {
			val *[]*okTestStruct `tlv:"e,tlvobj,C0_N"`
		}
		nokIntWithSpecialTag struct {
			val *int `tlv:"e,tlvobj"`
		}
		nokInvalidBaseTlv struct {
			val *int `tlv:"basetlv"`
		}
		nokInvalidBaseTlvStructType struct {
			val *okTestStruct `tlv:"basetlv"`
		}
		nokDoublePointer1 struct {
			val **uint64 `tlv:"9,int"`
		}
		nokDoublePointer2 struct {
			val **okTestStruct `tlv:"8,nstd"`
		}
		nokImprintAsBinary struct {
			val *hash.Imprint `tlv:"9,bin"`
		}
		nokBinaryAsImprint struct {
			val *[]byte `tlv:"9,imp"`
		}
		nokImpListAsBinList struct {
			val *[]hash.Imprint `tlv:"9,bin,C0_N"`
		}
		nokBinListAsImpList struct {
			val *[][]byte `tlv:"9,imp,C0_N"`
		}
		nokUint8AsInt8 struct {
			val *uint8 `tlv:"10,int8"`
		}
		nokStringAsInt8 struct {
			val *string `tlv:"10,int8"`
		}
		nokBinaryAsInt8 struct {
			val *[]byte `tlv:"10,int8"`
		}
		nokInvalidContext1 struct {
			ctx *uint64 `tlv:"context,uint6"`
		}
		nokInvalidContext2 struct {
			ctx uint64 `tlv:"context,uint6"`
		}
		nokInvalidContext3 struct {
			ctx *nokInvalidContext1 `tlv:"context,invalidTestStruct_struct_name"`
		}
		nokIndexConflict1 struct {
			a *uint64 `tlv:"1,int,IF"`
			b *uint64 `tlv:"2,int,IF"`
		}
		nokIndexConflict2 struct {
			a *uint64 `tlv:"1,int,IL"`
			b *uint64 `tlv:"2,int,IL"`
		}
		nokIndexConflict3 struct {
			a *uint64 `tlv:"1,int,IF"`
			b *uint64 `tlv:"2,int,I0"`
		}
		nokIndexConflict4 struct {
			a *uint64 `tlv:"1,int,IL"`
			b *uint64 `tlv:"2,int,I1"`
		}
		nokIndexConflict5 struct {
			a *uint64 `tlv:"1,int,I1"`
			b *uint64 `tlv:"2,int,I1"`
		}
	)

	testData := []struct {
		ty      reflect.Type
		message string
	}{
		{reflect.TypeOf(new(uint64)), "TLV template can only be extracted from struct, but input is uint64!"},
		{reflect.TypeOf(new(string)), "TLV template can only be extracted from struct, but input is string!"},
		{reflect.TypeOf(new(byte)), "TLV template can only be extracted from struct, but input is uint8!"},
		{reflect.TypeOf(new([]byte)), "TLV template can only be extracted from struct, but input is uint8!"},
		{reflect.TypeOf(new(nokNonSliceTooBig1)), "TLV [1] (val) is NOT a slice but its expected value count is C0_N!"},
		{reflect.TypeOf(new(nokNonSliceTooBig2)), "TLV [4] (val) is NOT a slice but its expected value count is C1_N!"},
		{reflect.TypeOf(new(nokNonSliceTooBig3)), "TLV [8] (val) is NOT a slice but its expected value count is C2!"},
		{reflect.TypeOf(new(nokSliceTooSmall1)), "TLV [(16|17)] (val) is a slice but its expected value count is C0_1!"},
		{reflect.TypeOf(new(nokSliceTooSmall2)), "TLV [16] (val) is a slice but its expected value count is C1!"},
		{reflect.TypeOf(new(nokInvalidBaseType1)), "TLV [8] (val) is string, but TLV template describes it as uint64!"},
		{reflect.TypeOf(new(nokInvalidBaseType2)), "TLV [8] (val) is uint64, but TLV template describes it as utf8!"},
		{reflect.TypeOf(new(nokInvalidSliceType1)), "TLV [8] (val) is uint64, but TLV template describes it as utf8!"},
		{reflect.TypeOf(new(nokInvalidSliceType2)), "TLV [8] (val) is string, but TLV template describes it as uint64!"},
		{reflect.TypeOf(new(nokInvalidSliceType3)), "TLV [8] (val) is a slice holding a pointer to uint64! Only pointer to struct is supported!"},
		{reflect.TypeOf(new(nokInvalidSliceType4)), "TLV [8] (val) is a slice holding slice! Only uin64, string and pointer to struct is supported!"},
		{reflect.TypeOf(new(nokInvalidNested1)), "TLV [8] (val) is tlv.okTestStruct, but TLV template describes it as uint64!"},
		{reflect.TypeOf(new(okTestStruct2)), "TLV [11.22.8] (valueUnderOkTestStruct3.valueUnderNokInvalidBaseType2.val) is uint64, but TLV template describes it as utf8!"},
		{reflect.TypeOf(new(nokInvalidNestedNotPointer)), "TLV [8] (val) must be a pointer to something, but is tlv.okTestStruct!"},
		{reflect.TypeOf(new(nokByteArrayWithoutExplicitTag1)), "TLV [9] (val) is []uint8, but TLV template describes it as uint64!"},
		{reflect.TypeOf(new(nokByteArrayWithoutExplicitTag2)), "TLV [9] (val) is []uint8, but TLV template describes it as uint64!"},
		{reflect.TypeOf(new(nokUnimplementedFromTlv1)), "TLV [e] (val) is a struct 'okTestStruct' that does not implement TlvObj interface!"},
		{reflect.TypeOf(new(nokUnimplementedFromTlv2)), "TLV [e] (val) is a list of struct 'okTestStruct' that does not implement TlvObj interface!"},
		{reflect.TypeOf(new(nokIntWithSpecialTag)), "TLV [e] (val) is a tlvobj template that needs to be a struct, but is 'int'!"},
		{reflect.TypeOf(new(nokInvalidBaseTlv)), "TLV [0] (val) is a placeholder for raw TLV and must be pointer to tlv.Tlv but is int!"},
		{reflect.TypeOf(new(nokInvalidBaseTlvStructType)), "TLV [0] (val) is a placeholder for raw TLV and must be tlv.Tlv but is okTestStruct!"},
		{reflect.TypeOf(new(nokDoublePointer1)), "TLV [9] (val) only pointer to string, struct, uint64 and slice is supported, but is **uint64!"},
		{reflect.TypeOf(new(nokDoublePointer2)), "TLV [8] (val) only pointer to string, struct, uint64 and slice is supported, but is **tlv.okTestStruct!"},
		{reflect.TypeOf(new(nokImprintAsBinary)), "TLV [9] (val) is hash.Imprint, but TLV template describes it as binary!"},
		{reflect.TypeOf(new(nokBinaryAsImprint)), "TLV [9] (val) is []uint8, but TLV template describes it as imprint!"},
		{reflect.TypeOf(new(nokImpListAsBinList)), "TLV [9] (val) is hash.Imprint, but TLV template describes it as binary!"},
		{reflect.TypeOf(new(nokBinListAsImpList)), "TLV [9] (val) is []uint8, but TLV template describes it as imprint!"},
		{reflect.TypeOf(new(nokUint8AsInt8)), "TLV setter function has no implementation for value with Kind 'uint8'!"},
		{reflect.TypeOf(new(nokStringAsInt8)), "TLV [10] (val) is string, but TLV template describes it as uint64(8bit limit)!"},
		{reflect.TypeOf(new(nokBinaryAsInt8)), "TLV [10] (val) is []uint8, but TLV template describes it as uint64(8bit limit)!"},
		{reflect.TypeOf(new(nokInvalidContext1)), "TLV [0] (ctx) is a placeholder for Context with Type/Kind 'uint6', but its Kind is 'uint64' and name is 'uint64'.!"},
		{reflect.TypeOf(new(nokInvalidContext2)), "TLV [0] (ctx) must be a pointer to something, but is uint64!"},
		{reflect.TypeOf(new(nokInvalidContext3)), "TLV [0] (ctx) is a placeholder for Context with Type/Kind 'invalidTestStruct_struct_name', but its Kind is 'struct' and name is 'nokInvalidContext1'.!"},
		{reflect.TypeOf(new(nokIndexConflict1)), "There are multiple templates that needs to be at first position!"},
		{reflect.TypeOf(new(nokIndexConflict2)), "There are multiple templates that needs to be at last position!"},
		{reflect.TypeOf(new(nokIndexConflict3)), "There are multiple templates that needs to be at first position!"},
		{reflect.TypeOf(new(nokIndexConflict4)), "TLV Template TLV [2] (b) needs to be at position 1, but this position is owned by template TLV [1] (a)!"},
		{reflect.TypeOf(new(nokIndexConflict5)), "TLV Template TLV [2] (b) needs to be at position 1, but this position is owned by template TLV [1] (a)!"},
	}

	for _, tc := range testData {
		tmpl, err := NewTemplate(0x0)
		if err != nil {
			t.Fatalf("Unable to create NewTemplate struct.")
		}
		err = tmpl.Parse(tc.ty)
		if err == nil {
			t.Fatalf("This call should have been failed!")
		}
		if msg := errors.KsiErr(err).Message()[0]; msg != tc.message {
			t.Fatalf("\nExpecting error: '%s'\nBut got error:   '%s'\n", tc.message, msg)
		}
	}
}

func TestUnitNilTemplateSetPath(t *testing.T) {
	var template *Template
	if err := template.SetPath("SomePath"); err == nil {
		t.Fatal("Should not be possible to set path to nil template.")
	}
}

func TestUnitLockedTemplateSetPath(t *testing.T) {
	var template Template
	template.isLocked = true
	if err := template.SetPath("SomePath"); err == nil {
		t.Fatal("Should not be possible to set path to locked template.")
	}
}

func TestUnitComplexTemplatePath(t *testing.T) {
	var (
		expected = "TLV [a.(2|3).5.f] (st1.st2.f) is NOT a slice but its expected value count is C0_N!"
	)

	type (
		subTlv2 struct {
			f *uint64 `tlv:"f,int,F,C0_N"`
		}

		subTlv1 struct {
			st2 *subTlv2 `tlv:"5,nstd"`
		}

		parentTlv struct {
			st1 *subTlv1 `tlv:"2|3,nstd"`
		}
	)

	tmpl, err := NewTemplate(0xa)
	if err != nil {
		t.Fatalf("Unable to create NewTemplate struct.")
	}

	err = tmpl.Parse(reflect.TypeOf(new(parentTlv)))
	if err == nil {
		t.Fatalf("Parsing of template must fail.")
	}

	if msg := errors.KsiErr(err).Message()[0]; msg != expected {
		t.Fatalf("\nExpecting error: '%s'\nBut got error:   '%s'\n", expected, msg)
	}
}
