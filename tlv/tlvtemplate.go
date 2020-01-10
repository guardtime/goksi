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
	"reflect"
	"sort"
	"strconv"
	"strings"
	"unsafe"

	"github.com/guardtime/goksi/errors"
)

// templateIndex is a wrapper type for TLV object index under parent TLV.
type templateIndex int

// templateCount is a wrapper type for TLV object count under parent TLV.
type templateCount int

// templateGroup is a wrapper type for TLV object group under parent TLV.
type templateGroup int

// templateType specifies the type of the template itself.
type templateType int

// templateTag specifies the tag of the TLV.
type templateTag uint16

// Template is used to convert binary stream into TLV and Go struct. That process can also be reversed where a Go structure is
// converted back into TLV encoded binary stream. TLV Template is generated using reflection and as it is immutable object, TLV Template
// is only generated once and can be reused in multiple goroutines. Note that after generation, Template uses reflection only slightly, thus
// not slowing it down.
//
// To create a new empty TLV Template, see function NewTemplate. In order to bind newly created TLV Template with a struct, see
// function Parse.
type Template struct {
	tag          []templateTag // Tag to match with TLV type. Can have multiple values.
	templateType templateType  // The type of the TLV Template.

	options       *templateOptions // Additional options.
	childTemplate []*Template      // List of child templates (for a nested TLV Template).

	setObj    func(pObj unsafe.Pointer, value interface{}) error // Unique setter function for a struct field represented by THIS TLV Template.
	getObj    func(pObj unsafe.Pointer) (interface{}, error)     // Unique getter function for a struct field represented by THIS TLV Template.
	newObj    func() unsafe.Pointer                              // Unique constructor (e.g malloc) function for a struct field represented by THIS TLV Template.
	fieldName string                                             // Struct field name represented by THIS TLV Template (e.g. 'index'). Used for error handling.
	path      string                                             // The path to THIS TLV Template (e.g. 'TLV [abc.01.02] (root.record.value)'). Used for error handling.
	isLocked  bool

	//newSlice func() unsafe.Pointer
}

// templateOptions is used to add some constraints for TLV elements being parsed. See function Parse.
type templateOptions struct {
	expectedCount    templateCount // Expected count of a TLV element. Default is Count0_1.
	expectedIndex    templateIndex // Expected index (position) of a TLV element in the same level. Default is IWhatever.
	expectedTypeName string        // Expected type name (used with VTContext for error handling only).

	groupID          templateGroup     // TLV element group on the same level. Default is GroupNone.
	conflictingGroup templateGroupList // TLV Groups that can not coexist on the same level. Default is [].
	dependencyGroup  templateGroupList // TLV Groups that must exist on the same level. Default is [].

	FastForward       bool
	NonCritical       bool
	emptyTlvPermitted bool
}

const (
	IUnknown  = templateIndex(-4) // Index unknown.
	IWhatever = templateIndex(-3) // Index can be anything.
	IFirst    = templateIndex(-2) // Must be first element.
	ILast     = templateIndex(-1) // Must be last element.
	IBase     = templateIndex(0)  // Index >= IBase is a concrete element position.
	// For position 1, use templateIndex(1)

	Count0_1  = templateCount(-3) // Zero or one occurrences.
	Count0_N  = templateCount(-2) // Zero to many occurrences.
	Count1_N  = templateCount(-1) // One to many occurrences.
	CountBase = templateCount(0)  // Count >= CountBase is concrete count value.
	// For count 1, use templateCount(1)

	GroupNone = templateGroup(-1)

	VTImprint      = templateType(-1)  // Value (of struct field) must be *hash.Imprint.
	VTInt          = templateType(-2)  // Value (of struct field) must be *uint64.
	VTNested       = templateType(-3)  // Value (of struct field) must be *<struct>.
	VTUtf8         = templateType(-4)  // Value (of struct field) must be *string.
	VTbin          = templateType(-5)  // Value (of struct field) must be *[]byte.
	VTTlvObj       = templateType(-6)  // Value (of struct field) must be *<struct, implements TlvObj>.
	VTNestedTlvObj = templateType(-7)  // Value (of struct field) must be *<struct, implements TlvObj>.
	VTBaseTlv      = templateType(-8)  // Value (of struct field) must be *tlv.Tlc.
	VTUnknown      = templateType(-9)  // Unknown value type.
	VTInt8         = templateType(-10) // Value (of struct field) must be *uint64.
	VTContext      = templateType(-11) // Value (of struct field) must be *<something>.
	// For group 1, use templateGroup(1)
)

// NewTemplate is a function that creates an empty nested TLV Template with TLV tag(s).
func NewTemplate(tags ...uint16) (*Template, error) {
	return newTemplate(VTNested, tags...)
}

// NewTemplate is a function that creates an empty TLV Template with TLV tag(s).
func newTemplate(templateType templateType, tags ...uint16) (*Template, error) {
	if len(tags) == 0 {
		return nil, errors.New(errors.KsiInvalidArgumentError).AppendMessage("At least one TLV tag must be provided.")
	}

	tmplTag := make([]templateTag, 0)

	for _, tag := range tags {
		if tag > MaxTagValue {
			return nil, errors.New(errors.KsiInvalidArgumentError).AppendMessage(
				fmt.Sprintf("TLV tag out of range is 0x%x, but 0x%x is maximum.", tag, MaxTagValue))
		}

		tmplTag = append(tmplTag, templateTag(tag))
	}

	return &Template{
		templateType: templateType,
		tag:          tmplTag,
		options:      newTemplateOptions(),
		isLocked:     false,
	}, nil
}

// Parse is a function that derives a TLV Template for a struct from its reflection.Type. In order to
// parse TLV Template for a struct, an empty TLV Template with value type VTNested must be created. Secondly, the struct
// must contain struct field tags describing how each struct field is related to TLV and what kind of type the fields
// should contain. To improve error handling, the type is not determined by reflection automatically but the real type
// and user given type must match.
//
//
// Possible struct field tags to bind struct field with TLV:
//   tlv:"<TLV type>, bin | int | int8 | imp | nstd | nstd+tlvobj | tlvobj | utf8, [C], [I], [G], [!G].., [&G].., [N], [F], [E]"
//   where:
//     <TLV type>       - TLV type value in hex (e.g 1a).
//     bin              - Field is *[]byte or *[][]byte.
//     int              - Field is *uint64 or *[]uint64.
//     int8             - Field is *uint64 or *[]uint64.
//     imp              - Field is *hash.Imprint or *[]hash.Imprint.
//     nstd             - Field is *<some struct> or *[]*<some struct>. Note that list contains POINTERS!
//     nstd+tlvobj      - Field is *<some struct> or *[]*<some struct>. Note that list contains POINTERS and <some struct>
//                        MUST implement TlvObject interface!
//     tlvobj           - Field is *<some struct> or *[]*<some struct>. Note that list contains POINTERS and <some struct>
//                        MUST implement TlvObject interface!
//     utf8             - Field is utf8 *string or *[]string.
//     C                - Expected count. C0_1 (default), C0_N, C1_N or C<num> (e.g. C5).
//                        Option is Group dependant (see description of option 'G'). Meaning that if a group number is
//                        applied, the count number is relevant only within that Group.
//     I                - Expected position. IW (any position, default), IF (first), IL (last) or I<num> (e.g. I5).
//     G                - Field belongs to a group. GNone (no group, default), G<num> (e.g. G0).
//     !G               - Conflicting groups !G<num> (e.g. !G0 indicates that this field can not coexist with fields belonging
//                        to group G0).
//     &G               - Dependency groups &G<num> (e.g. &G0 indicates that if this field contains a value, the fields
//                        belonging to group G0 must also have a value).
//     N                - Non-Critical TLV.
//     F                - Forward unknown (valid with N).
//     E                - Permit usage of empty values (e.g integer 0 has no value part.)
//
//   tlv:"basetlv"      - Field must be *tlv.Tlv. During TLV to object this field is going to store the base TLV of the
//                        struct itself.
//
//   tlv:"context,name" - Field must be pointer to something and name must verify its type for error handling (for *dummy
//                        name must be 'dummy').
// Usage example:
//  type nestedStruct struct {
//     msg            *string       `tlv:"10,utf8"`
//     unrelatedField uint8
//  }
//
//  type example struct {
//     suffix         *[]bin        `tlv:"1,bin,IF"`
//     id             *uint64       `tlv:"2,int"`
//     value          *nestedStruct `tlv:"2,nstd"`
//     prefix         *[]bin        `tlv:"4,bin,IL"`
//     basetlv        *tlv.Tlv      `tlv:"basetlv"`
//  }
//
//  t := reflect.TypeOf(example)
//  template,_ := NewTemplate(VTNested, 0x2)
//  err := template.Parse(t)
//
func (template *Template) Parse(t reflect.Type) error {
	if template == nil {
		return errors.New(errors.KsiInvalidArgumentError)
	}

	if template.isLocked {
		return errors.New(errors.KsiInvalidStateError).AppendMessage("TLV Template is already parsed.")
	}

	// Create lists for tags and struct field names. Both lists are held to map the
	// path to a concrete TLV template inside of a nested TLV template structure. Values
	// are used for error handling (e.g. TLV [a.(1|2).5] (st1.st2.f)). Note that there
	// may be multiple tags for a single step as Template may have multiple tags.
	tagList := make([][]templateTag, 0)
	fieldList := make([]string, 0)

	if template.path != "" {
		fieldList = append(fieldList, template.path)
	}

	if len(template.tag) == 1 && template.tag[0] != 0 {
		tagList = append(tagList, template.tag)
	}

	err := template.parseNestedFromStructInternal(t, tagList, fieldList)
	if err != nil {
		return err
	}

	template.isLocked = true
	return nil
}

// SetPath is setter for Template path.
func (template *Template) SetPath(path string) error {
	if template == nil {
		return errors.New(errors.KsiInvalidArgumentError)
	}

	if template.isLocked {
		return errors.New(errors.KsiInvalidStateError).AppendMessage("TLV Template is already parsed.")
	}

	template.path = path
	return nil
}

func newTemplateOptions() *templateOptions {
	return &templateOptions{
		expectedCount: Count0_1,
		expectedIndex: IWhatever,
		groupID:       GroupNone,
	}
}

// String implements Stringer interface.
func (tlvopt templateOptions) String() string {
	var b strings.Builder

	b.WriteString(tlvopt.groupID.String())
	b.WriteString(",")
	b.WriteString(tlvopt.expectedCount.String())
	b.WriteString(",")
	b.WriteString(tlvopt.expectedIndex.String())
	b.WriteString(",!")
	b.WriteString(tlvopt.conflictingGroup.String())
	b.WriteString(",&")
	b.WriteString(tlvopt.dependencyGroup.String())

	if tlvopt.NonCritical || tlvopt.FastForward || tlvopt.emptyTlvPermitted {
		b.WriteString(",")

		if tlvopt.NonCritical {
			b.WriteString("N")
		}

		if tlvopt.FastForward {
			b.WriteString("F")
		}

		if tlvopt.emptyTlvPermitted {
			b.WriteString("E")
		}
	}

	return b.String()
}

func (c templateCount) String() string {
	switch c {
	case Count0_1:
		return "C0_1"
	case Count0_N:
		return "C0_N"
	case Count1_N:
		return "C1_N"
	default:
		return fmt.Sprintf("C%v", int(c))
	}
}

func (i templateIndex) String() string {
	switch i {
	case IFirst:
		return "IF"
	case ILast:
		return "IL"
	case IUnknown:
		return "I?"
	case IWhatever:
		return "IW"
	default:
		return fmt.Sprintf("I%v", int(i))
	}
}

// IsMatchingTag checks if TLV tag is matching with the template.
func (template *Template) IsMatchingTag(tag uint16) bool {
	if template == nil {
		return false
	}

	for _, t := range template.tag {
		if uint16(t) == tag {
			return true
		}
	}
	return false
}

func (template *Template) getByTag(tag uint16) (*Template, error) {
	if template == nil {
		return nil, errors.New(errors.KsiInvalidArgumentError).AppendMessage("Template must not be nil.")
	}

	if template.templateType != VTNested && template.templateType != VTNestedTlvObj {
		return nil, errors.New(errors.KsiInvalidStateError).AppendMessage("Template must be a nested TLV template.")
	}

	for _, tmp := range template.childTemplate {
		if tmp.IsMatchingTag(tag) {
			return tmp, nil
		}
	}

	return nil, nil
}

func (g templateGroup) String() string {
	if g == GroupNone {
		return "GNone"
	}
	return "G" + strconv.Itoa(int(g))
}

type templateGroupList []templateGroup

func (l templateGroupList) String() string {
	var b strings.Builder

	b.WriteString("G[")
	for i, v := range l {
		if i != 0 {
			b.WriteString(",")
		}
		b.WriteString(strconv.Itoa(int(v)))
	}
	b.WriteString("]")

	return b.String()
}

func (template *Template) String() string {
	return template.toStringWithIndent(0)
}

func (template *Template) toStringWithIndent(d int) string {
	if template == nil {
		return "nil"
	}

	listSymbol := ""
	structRef := ""
	c := template.options.expectedCount
	if c == Count0_N || c == Count1_N || int(c) > 1 {
		listSymbol = "[]"
	}

	if len(template.fieldName) > 0 {
		structRef = "struct." + template.fieldName
	}

	indent := strings.Repeat("  ", d)
	s := fmt.Sprintf("%s%x,%s%s,(%s) %s",
		indent, template.tag, listSymbol, template.templateType.String(), template.options.String(), structRef)
	if template.templateType == VTNested {
		s = s + "{\n"
		count := len(template.childTemplate)

		for i := count - 1; i >= 0; i-- {
			t := template.childTemplate[i]
			s = s + fmt.Sprintf("%s\n", t.toStringWithIndent(d+1))
		}
		s = s + indent + "}"
	}
	return s
}

func (ttt templateType) String() string {
	switch ttt {
	case VTImprint:
		return "imprint"
	case VTInt:
		return "uint64"
	case VTInt8:
		return "uint64(8bit limit)"
	case VTUtf8:
		return "utf8"
	case VTNested:
		return "nested"
	case VTbin:
		return "binary"
	case VTTlvObj:
		return "tlvobj"
	case VTNestedTlvObj:
		return "nstd+tlvobj"
	case VTBaseTlv:
		return "basetlv"
	case VTContext:
		return "context"
	default:
		return "unknown"
	}
}

func getTlvTemplateTypeFromString(str string) templateType {
	switch str {
	case "nstd":
		return VTNested
	case "imp":
		return VTImprint
	case "int":
		return VTInt
	case "int8":
		return VTInt8
	case "utf8":
		return VTUtf8
	case "bin":
		return VTbin
	case "tlvobj":
		return VTTlvObj
	case "nstd+tlvobj":
		return VTNestedTlvObj
	case "basetlv":
		return VTBaseTlv
	case "context":
		return VTContext
	default:
		return VTUnknown
	}
}

// This function is used to parse additional TLV options from a string. It takes one argument that must
// contain tlv struct field tag string representation.
func (tlvopt *templateOptions) parseTemplateOptions(optionFromTag string) error {
	if tlvopt == nil {
		return errors.New(errors.KsiInvalidArgumentError)
	}

	if optionFromTag == "" {
		return nil
	}

	if optionFromTag == "F" {
		tlvopt.FastForward = true
		return nil
	} else if optionFromTag == "N" {
		tlvopt.NonCritical = true
		return nil
	} else if optionFromTag == "E" {
		tlvopt.emptyTlvPermitted = true
		return nil
	}

	if len(optionFromTag) < 2 {
		return errors.New(errors.KsiInvalidFormatError).AppendMessage(
			fmt.Sprintf("Invalid TLV option struct tag: '%s'.", optionFromTag))
	}

	switch optionFromTag[0] {
	case 'C':
		switch optionFromTag {
		case "C0_1":
			tlvopt.expectedCount = Count0_1
		case "C0_N":
			tlvopt.expectedCount = Count0_N
		case "C1_N":
			tlvopt.expectedCount = Count1_N
		default:
			c, err := strconv.ParseUint(optionFromTag[1:], 10, 8) // Base 10 1Byte
			if err != nil {
				return errors.New(errors.KsiInvalidFormatError).AppendMessage(
					fmt.Sprintf("Invalid TLV option struct tag: '%s'.", optionFromTag))
			}
			tlvopt.expectedCount = templateCount(int(c))
		}
	case 'I':
		switch optionFromTag {
		case "IF":
			tlvopt.expectedIndex = IFirst
		case "IL":
			tlvopt.expectedIndex = ILast
		case "IW":
			tlvopt.expectedIndex = IWhatever
		default:
			i, err := strconv.ParseUint(optionFromTag[1:], 10, 16) // Base 10 2Byte
			if err != nil {
				return errors.New(errors.KsiInvalidFormatError).AppendMessage(
					fmt.Sprintf("Invalid TLV option struct tag: '%s'.", optionFromTag))
			}
			tlvopt.expectedIndex = templateIndex(int(i))
		}
	case 'G':
		switch optionFromTag {
		case "GNone":
			tlvopt.groupID = GroupNone
		default:
			i, err := strconv.ParseUint(optionFromTag[1:], 10, 16) // Base 10 2Byte
			if err != nil {
				return errors.New(errors.KsiInvalidFormatError).AppendMessage(
					fmt.Sprintf("Invalid TLV option struct tag: '%s'.", optionFromTag))
			}
			tlvopt.groupID = templateGroup(int(i))
		}
	default:
		switch optionFromTag[:2] {
		case "!G":
			cg, err := strconv.ParseUint(optionFromTag[2:], 10, 16)
			if err != nil {
				return errors.New(errors.KsiInvalidFormatError).AppendMessage(
					fmt.Sprintf("Invalid TLV option struct tag: '%s'.", optionFromTag))
			}
			tlvopt.conflictingGroup = append(tlvopt.conflictingGroup, templateGroup(int(cg)))
		case "&G":
			dg, err := strconv.ParseUint(optionFromTag[2:], 10, 16)
			if err != nil {
				return errors.New(errors.KsiInvalidFormatError).AppendMessage(
					fmt.Sprintf("Invalid TLV option struct tag: '%s'.", optionFromTag))
			}
			tlvopt.dependencyGroup = append(tlvopt.dependencyGroup, templateGroup(int(dg)))
		default:
			return errors.New(errors.KsiInvalidFormatError).AppendMessage(
				fmt.Sprintf("Unknown TLV option struct tag: '%s'.", optionFromTag))
		}
	}

	return nil
}

func parseTlvTemplate(structTag string) (*Template, error) {
	tmp := new(Template)
	tagList := make([]uint16, 0)

	args := strings.Split(structTag, ",")
	if len(args) == 0 {
		return nil, nil
	} else if len(args) == 1 && args[0] == "basetlv" {
		tmp.options = new(templateOptions)
		tmp.options.expectedIndex = IWhatever
		tmp.tag = append(tmp.tag, templateTag(0))
		tmp.templateType = VTBaseTlv
		return tmp, nil
	} else if len(args) == 2 && args[0] == "context" {
		tmp.options = new(templateOptions)
		tmp.options.expectedIndex = IWhatever
		tmp.options.expectedTypeName = args[1]
		tmp.tag = append(tmp.tag, templateTag(0))
		tmp.templateType = VTContext
		return tmp, nil
	} else if len(args) < 2 {
		msg := fmt.Sprintf("Unrecognized TLV Template configuration %v.", args)
		return nil, errors.New(errors.KsiInvalidFormatError).AppendMessage(msg)
	}

	for i, v := range args {
		if i == 0 {
			tags := strings.Split(v, "|")

			for _, tag := range tags {
				t, err := strconv.ParseUint(strings.TrimPrefix(tag, "0x"), 16, 16)
				if err != nil {
					return nil, errors.New(errors.KsiInvalidFormatError).AppendMessage(
						fmt.Sprintf("Unable to parse template: TLV tag value must be hex, but is '%s'.", tag))
				}

				if t > MaxTagValue {
					return nil, errors.New(errors.KsiInvalidFormatError).AppendMessage(
						fmt.Sprintf("Unable to parse template: TLV tag %x exceeds maximum value %x.", t, MaxTagValue))
				}

				tagList = append(tagList, uint16(t))
			}

		} else if i == 1 {
			ttt := getTlvTemplateTypeFromString(v)
			if ttt == VTUnknown {
				return nil, errors.New(errors.KsiInvalidFormatError).AppendMessage(
					fmt.Sprintf("Unable to parse template: Unrecognized TLV Template type '%s'.", v))
			}

			t, err := newTemplate(ttt, tagList...)
			if err != nil {
				return nil, err
			}

			tmp = t
		} else {
			err := tmp.options.parseTemplateOptions(v)
			if err != nil {
				return nil, err
			}
		}
	}

	return tmp, nil
}

func isLegalBaseType(t reflect.Type) bool {
	switch {
	case t.Kind() == reflect.Uint64:
		return true
	case t.Kind() == reflect.String:
		return true
	case t.Name() == "Imprint":
		return true
	case t.Kind() == reflect.Struct:
		return true
	case t.Kind() == reflect.Slice && t.Elem().Kind() == reflect.Uint8:
		return true
	default:
		return false
	}
}

func realTypePointsTotemplateType(t reflect.Type) templateType {
	switch {
	case t.Kind() == reflect.Uint64:
		return VTInt
	case t.Kind() == reflect.String:
		return VTUtf8
	case t.Name() == "Imprint":
		return VTImprint
	case t.Kind() == reflect.Ptr && t.Elem().Kind() == reflect.Struct:
		return VTNested
	case t.Kind() == reflect.Struct:
		return VTNested
	case t.Kind() == reflect.Slice && t.Elem().Kind() == reflect.Uint8:
		return VTbin
	default:
		return VTUnknown
	}
}

func isLegalSliceType(t reflect.Type) bool {
	if t.Kind() != reflect.Slice {
		return false
	}
	if t.Elem().Kind() == reflect.Ptr && t.Elem().Elem().Kind() == reflect.Struct {
		return true
	}
	return isLegalBaseType(t.Elem())
}

func (template *Template) checkFieldTypeErrors(t reflect.Type, errorLocation string) error {
	if template == nil {
		return errors.New(errors.KsiInvalidArgumentError)
	}
	if t.Kind() != reflect.Ptr {
		return errors.New(errors.KsiInvalidStateError).AppendMessage(
			fmt.Sprintf("%s must be a pointer to something, but is %s!", errorLocation, t))
	}

	var (
		tType = t.Elem()

		isOkBaseType  = isLegalBaseType(tType)
		isOkSliceType = isLegalSliceType(tType)

		isPointer     = tType.Kind() == reflect.Ptr
		isSlice       = tType.Kind() == reflect.Slice
		isStruct      = tType.Kind() == reflect.Struct
		isStructSlice = isSlice && tType.Elem().Kind() == reflect.Ptr && tType.Elem().Elem().Kind() == reflect.Struct

		isTlvObjTemplate   = template.templateType == VTTlvObj || template.templateType == VTNestedTlvObj
		isBaseTlvHolder    = template.templateType == VTBaseTlv
		isContextTlvHolder = template.templateType == VTContext
		isImprint          = template.templateType == VTImprint
		expectedName       = template.options.expectedTypeName
	)

	if !isBaseTlvHolder && !isContextTlvHolder && (isOkBaseType || isOkSliceType) {
		baseType := tType
		if isOkSliceType {
			baseType = baseType.Elem()
		}

		realType := realTypePointsTotemplateType(baseType)
		typeExpected := template.templateType

		isStructType := typeExpected == VTNested || typeExpected == VTNestedTlvObj || typeExpected == VTTlvObj

		if (realType != VTNested && !(realType == VTInt && typeExpected == VTInt8) && realType != typeExpected) ||
			(realType == VTNested && !isStructType) {
			return errors.New(errors.KsiInvalidStateError).AppendMessage(
				fmt.Sprintf("%s is %v, but TLV template describes it as %s!", errorLocation, baseType, template.templateType))
		}
	}

	if isPointer {
		return errors.New(errors.KsiInvalidStateError).AppendMessage(
			fmt.Sprintf("%s only pointer to string, struct, uint64 and slice is supported, but is %v!",
				errorLocation, t))
	} else if !isImprint && !isOkSliceType && isSlice && template.templateType != VTbin {
		var msg string
		if tType.Elem().Kind() == reflect.Ptr {
			msg = fmt.Sprintf("%s is a slice holding a pointer to %v! Only pointer to struct is supported!",
				errorLocation, tType.Elem().Elem().Kind())
		} else {
			msg = fmt.Sprintf("%s is a slice holding %v! Only uin64, string and pointer to struct is supported!",
				errorLocation, tType.Elem().Kind())
		}
		return errors.New(errors.KsiInvalidStateError).AppendMessage(msg)
	} else if isTlvObjTemplate && !isStruct && !isStructSlice {
		return errors.New(errors.KsiInvalidStateError).AppendMessage(
			fmt.Sprintf("%s is a tlvobj template that needs to be a struct, but is '%s'!", errorLocation, tType.Kind()))
	} else if isTlvObjTemplate && isStruct && !t.Implements(reflect.TypeOf(new(TlvObj)).Elem()) {
		return errors.New(errors.KsiInvalidStateError).AppendMessage(
			fmt.Sprintf("%s is a struct '%s' that does not implement TlvObj interface!", errorLocation, tType.Name()))
	} else if isTlvObjTemplate && isStructSlice && !tType.Elem().Implements(reflect.TypeOf(new(TlvObj)).Elem()) {
		return errors.New(errors.KsiInvalidStateError).AppendMessage(
			fmt.Sprintf("%s is a list of struct '%s' that does not implement TlvObj interface!",
				errorLocation, tType.Elem().Elem().Name()))
	} else if isBaseTlvHolder && !isStruct {
		return errors.New(errors.KsiInvalidStateError).AppendMessage(
			fmt.Sprintf("%s is a placeholder for raw TLV and must be pointer to tlv.Tlv but is %s!",
				errorLocation, tType.Kind()))
	} else if isBaseTlvHolder && isStruct && tType.Name() != "tlv.Tlv" && tType.Name() != "Tlv" {
		return errors.New(errors.KsiInvalidStateError).AppendMessage(
			fmt.Sprintf("%s is a placeholder for raw TLV and must be tlv.Tlv but is %s!", errorLocation, tType.Name()))
	} else if isContextTlvHolder && (tType.Kind().String() != expectedName && tType.Name() != expectedName) {
		return errors.New(errors.KsiInvalidStateError).AppendMessage(
			fmt.Sprintf("%s is a placeholder for Context with Type/Kind '%s', but its Kind is '%s' and name is '%s'.!",
				errorLocation, expectedName, tType.Kind(), tType.Name()))
	}

	return nil
}

type pointerPlusInterface struct {
	ObjPointer unsafe.Pointer
	Interface  interface{}
}

func createConstructorForObject(t reflect.Type) func() unsafe.Pointer {
	return func() unsafe.Pointer {
		return unsafe.Pointer(reflect.New(t).Pointer())
	}
}

func createConstructorForObjectWithInterface(t reflect.Type) func() unsafe.Pointer {
	return func() unsafe.Pointer {
		newValue := reflect.New(t)
		wrapper := new(pointerPlusInterface)
		wrapper.ObjPointer = unsafe.Pointer(newValue.Pointer())
		wrapper.Interface = newValue.Interface()
		return unsafe.Pointer(wrapper)
	}
}

func getDataTypeFromStructure(t reflect.Type) reflect.Type {
	elementType := t

	for elementType.Kind() == reflect.Ptr || elementType.Kind() == reflect.Slice || elementType.Kind() == reflect.Array {
		elementType = elementType.Elem()
	}
	return elementType
}

type templateOrderedList []*Template

func (s templateOrderedList) Len() int {
	return len(s)
}
func (s templateOrderedList) Swap(i, j int) {
	s[i], s[j] = s[j], s[i]
}
func (s templateOrderedList) Less(i, j int) bool {
	valueI := s[i]
	valueJ := s[j]

	switch {
	case valueI == nil && valueJ != nil:
		return true
	case valueI == nil && valueJ == nil:
		return false
	case valueI != nil && valueJ == nil:
		return false
	case valueI.options != nil && valueI.options.expectedIndex == IFirst:
		return true
	case valueJ.options != nil && valueJ.options.expectedIndex == ILast:
		return true
	case valueI.options != nil && valueI.options.expectedIndex > IBase && valueI.options.expectedIndex > templateIndex(i):
		return true
	default:
		return false
	}
}

func (s templateOrderedList) fixTemplatesWithConcretePosition() error {
	list := ([]*Template)(s)
	listSize := len(list)

	// i is matching the index inside template options.
	for i := 0; i < listSize; {
		// As the template list is in reverse, a reverseExpectedIndex is used to get the value needed.
		// v is value at some position.

		position := listSize - 1 - i
		v := list[position]
		reverseExpectedIndex := templateIndex(listSize-1) - v.options.expectedIndex
		if v.options.expectedIndex >= IBase && v.options.expectedIndex != templateIndex(i) {
			if int(reverseExpectedIndex) == position {
				i++
				continue
			}
			// j is owner of expected index.
			j := int(reverseExpectedIndex)
			jExpectedI := int(list[j].options.expectedIndex)

			// Check if i and j does not need to be at the same position and if not, make the swap
			// without incrementing i.
			if templateIndex(jExpectedI) >= IBase && templateIndex(jExpectedI) != v.options.expectedIndex {
				s.Swap(position, j)
				continue
			} else if list[j].options.expectedIndex == IWhatever {
				s.Swap(position, j)
			} else {
				return errors.New(errors.KsiInvalidStateError).AppendMessage(
					fmt.Sprintf("TLV Template %v needs to be at position %v, but this position is owned by template %v!",
						v.path, int(v.options.expectedIndex), list[j].path))
			}
		}
		i++
	}
	return nil
}

func (template *Template) isInConflictWithAllTemplate(list []*Template) bool {
	if template == nil || len(list) == 0 {
		return false
	}

	for _, v := range list {
		isConflict := false
		// Loop over the conflicting groups and make sure that template from the list is included.
		for _, conflictingGroupID := range template.options.conflictingGroup {
			if v.options.groupID == conflictingGroupID {
				isConflict = true
				break
			}
		}

		if !isConflict {
			return false
		}
	}
	return true
}

func (template *Template) order() error {
	if template == nil {
		return errors.New(errors.KsiInvalidArgumentError)
	}
	if (len(template.childTemplate)) == 0 {
		return nil
	}

	var (
		// List that contains all possible values for the first position that must be in conflict with each other.
		first []*Template
		// List that contains all possible values for the last position that must be in conflict with each other.
		last []*Template
	)
	for _, t := range template.childTemplate {
		switch t.options.expectedIndex {
		case IFirst, IBase:
			if len(first) > 0 && !t.isInConflictWithAllTemplate(first) {
				return errors.New(errors.KsiInvalidStateError).
					AppendMessage("There are multiple templates that needs to be at first position!")
			}
			first = append(first, t)
		case ILast:
			if len(last) > 0 && !t.isInConflictWithAllTemplate(last) {
				return errors.New(errors.KsiInvalidStateError).
					AppendMessage("There are multiple templates that needs to be at last position!")
			}
			last = append(last, t)
		}
	}

	// Reverse the list as the order of equal objects is not moved.
	s := template.childTemplate
	for i, j := 0, len(s)-1; i < j; i, j = i+1, j-1 {
		s[i], s[j] = s[j], s[i]
	}

	list := templateOrderedList(template.childTemplate)
	sort.Sort(sort.Reverse(list))

	if err := list.fixTemplatesWithConcretePosition(); err != nil {
		return errors.KsiErr(err).AppendMessage(fmt.Sprintf("Unable to order sub templates of %v.", template.path))
	}

	return nil
}

func (template *Template) parseNestedFromStructInternal(t reflect.Type, path [][]templateTag, fieldPath []string) error {
	if template == nil {
		return errors.New(errors.KsiInvalidArgumentError)
	}

	elementType := getDataTypeFromStructure(t)

	if elementType.Kind() != reflect.Struct {
		return errors.New(errors.KsiInvalidFormatError).AppendMessage(
			fmt.Sprintf("TLV template can only be extracted from struct, but input is %v!", elementType.Kind()))
	}

	for i := 0; i < elementType.NumField(); i++ {
		field := elementType.Field(i)
		templateStr := field.Tag.Get("tlv")

		if templateStr == "" {
			continue
		}

		// Get struct field tag value and try to parse it.
		tmplt, err := parseTlvTemplate(templateStr)
		if err != nil {
			return errors.KsiErr(err).
				AppendMessage(fmt.Sprintf("Unable to create a new TLV template under TLV %s.", templatePathToString(path))).
				AppendMessage(fmt.Sprintf("Failed to parse struct (%s) field (%s %s) struct tag '%s'.",
					strings.Join(fieldPath, "."), field.Name, field.Type.Kind(), templateStr))
		}

		// Some strings for error handling.
		newPath := append(path, tmplt.tag)
		newFieldPath := append(fieldPath, field.Name)
		errorLocationMsg := fmt.Sprintf("TLV [%s] (%s)", templatePathToString(newPath), strings.Join(newFieldPath, "."))

		if err = tmplt.checkFieldTypeErrors(field.Type, errorLocationMsg); err != nil {
			return err
		}

		// Check for some errors.
		// Note that when slice is marked as octet string, it is not interpreted as regular array!
		// if (field.Type.Kind() == reflect.Slice && !(tmplt.templateType == VTbin && field.Type.Elem().Kind() == reflect.Uint8)) || (field.Type.Kind() == reflect.Ptr && field.Type.Elem().Kind() == reflect.Slice) {
		if isLegalSliceType(field.Type.Elem()) {
			if tmplt.options.expectedCount == Count0_1 || tmplt.options.expectedCount == templateCount(1) {
				return errors.New(errors.KsiInvalidStateError).AppendMessage(
					fmt.Sprintf("%s is a slice but its expected value count is %s!", errorLocationMsg, tmplt.options.expectedCount))

			}
		} else {
			if tmplt.options.expectedCount == Count0_N || tmplt.options.expectedCount == Count1_N || (int(tmplt.options.expectedCount) > 1) {
				return errors.New(errors.KsiInvalidStateError).AppendMessage(
					fmt.Sprintf("%s is NOT a slice but its expected value count is %s!", errorLocationMsg, tmplt.options.expectedCount))
			}
		}

		// If TLV obj is a nested type, make a recursive call to resolve its internals.
		// Create a function that can be used to make new "empty" struct that matches the TLV.
		if tmplt.templateType == VTNested {
			if err = tmplt.parseNestedFromStructInternal(field.Type.Elem(), newPath, newFieldPath); err != nil {
				return err
			}

			tmplt.newObj = createConstructorForObject(getDataTypeFromStructure(field.Type))
		} else if tmplt.templateType == VTTlvObj || tmplt.templateType == VTNestedTlvObj {
			if err = tmplt.parseNestedFromStructInternal(field.Type.Elem(), newPath, newFieldPath); err != nil {
				return err
			}

			tmplt.newObj = createConstructorForObjectWithInterface(getDataTypeFromStructure(field.Type))
		}

		// Get setter function by field type and kind.
		funcSetObj, err := setObj(field.Offset, field.Type.Elem(), tmplt)
		if err != nil {
			return errors.KsiErr(err).AppendMessage(
				fmt.Sprintf("Unable to get object setter function for %s!", errorLocationMsg))
		}

		funcGetObj, err := getObj(field.Offset, field.Type.Elem(), tmplt)
		if err != nil {
			return errors.KsiErr(err).AppendMessage(
				fmt.Sprintf("Unable to get object getter function for %s!", errorLocationMsg))
		}

		if funcGetObj == nil {
			return errors.New(errors.KsiInvalidStateError).
				AppendMessage(fmt.Sprintf("Unable to get object getter function for %s!", errorLocationMsg)).
				AppendMessage("No error was returned but returned function is nil!")
		}

		if funcSetObj == nil {
			return errors.New(errors.KsiInvalidStateError).
				AppendMessage(fmt.Sprintf("Unable to get object setter function for %s!", errorLocationMsg)).
				AppendMessage("No error was returned but returned function is nil!")
		}

		tmplt.fieldName = field.Name
		tmplt.path = errorLocationMsg
		tmplt.setObj = funcSetObj
		tmplt.getObj = funcGetObj
		template.childTemplate = append(template.childTemplate, tmplt)
	}

	// Order templates, so object can be serialized in proper order.
	err := template.order()
	if err != nil {
		errorLocationMsg := fmt.Sprintf("TLV [%s] (%s)", templatePathToString(path), strings.Join(fieldPath, "."))
		return errors.KsiErr(err).AppendMessage(fmt.Sprintf("Unable to order sub TLV templates for %s!", errorLocationMsg))
	}

	return nil
}

func setObj(offset uintptr, objType reflect.Type, template *Template) (func(unsafe.Pointer, interface{}) error, error) {
	if objType == nil || template == nil {
		return nil, errors.New(errors.KsiInvalidArgumentError)
	}

	isSlice := false
	kind := objType.Kind()

	// Handle special case with []byte, where it is not interpreted as a list, but octet string.
	// Note that [][]byte, should be handled as a list of octet strings.

	if isLegalSliceType(objType) {
		isSlice = true
		kind = objType.Elem().Kind()
	}

	// It must be pointer to something. Change the kind to force it use setter function for pointers.
	if template.templateType == VTContext {
		kind = reflect.Ptr
	}

	switch kind {
	case reflect.Uint64:
		return func(pObj unsafe.Pointer, value interface{}) error {
			if pObj == nil {
				return errors.New(errors.KsiInvalidArgumentError)
			}
			v, ok := value.(uint64)
			if !ok {
				return errors.New(errors.KsiInvalidArgumentError).AppendMessage(
					fmt.Sprintf("TLV setter function is expecting '%v' (%v) instead of '%v (%v)'!",
						reflect.TypeOf(v), reflect.TypeOf(v).Kind(), reflect.TypeOf(value), reflect.TypeOf(value).Kind()))
			}

			// If its a slice, append the value.
			if isSlice {
				slice := (**[]uint64)(unsafe.Pointer(uintptr(pObj) + offset))

				if *slice == nil {
					*slice = &[]uint64{v}
				} else {
					dummySlice := *slice
					dummy := *dummySlice
					tmp := append(dummy, v)
					*slice = &tmp
				}

			} else {
				pInt := (**uint64)(unsafe.Pointer(uintptr(pObj) + offset))
				*pInt = &v
			}
			return nil
		}, nil
	case reflect.Ptr, reflect.Struct:
		return func(pObj unsafe.Pointer, value interface{}) error {
			if pObj == nil {
				return errors.New(errors.KsiInvalidArgumentError)
			}
			// Value must contain a pointer (unsafe Pointer) to a value (e.g. *int, *[]int, *MyStruct)
			usfP, ok := value.(unsafe.Pointer)
			if !ok {
				return errors.New(errors.KsiInvalidArgumentError).AppendMessage(
					fmt.Sprintf("TLV setter function is expecting '%v' (%v) instead of '%v (%v)'!",
						reflect.TypeOf(usfP), reflect.TypeOf(usfP).Kind(), reflect.TypeOf(value), reflect.TypeOf(value).Kind()))
			}

			// It is known that pObj + offset points to a memory field that holds a pointer to a value.
			// New unsafe pointer is created that sums pObj and offset. Its value is transformed to
			// A pointer to pointer to uintptr. value usfP is created to a pointer to uintptr and is used
			// to set the real pointer inside a struct!
			if isSlice {
				slice := (**[]*uintptr)(unsafe.Pointer(uintptr(pObj) + offset))

				if *slice == nil {
					*slice = &[]*uintptr{(*uintptr)(usfP)}
				} else {
					tmp := append(**slice, (*uintptr)(usfP))
					*slice = &tmp
				}

			} else {
				pPtr := (**uintptr)(unsafe.Pointer(uintptr(pObj) + offset))
				*pPtr = (*uintptr)(usfP)
			}

			return nil
		}, nil
	case reflect.String:
		return func(pObj unsafe.Pointer, value interface{}) error {
			if pObj == nil {
				return errors.New(errors.KsiInvalidArgumentError)
			}
			v, ok := value.(string)
			if !ok {
				return errors.New(errors.KsiInvalidArgumentError).AppendMessage(
					fmt.Sprintf("TLV setter function is expecting '%v' (%v) instead of '%v (%v)'!",
						reflect.TypeOf(v), reflect.TypeOf(v).Kind(), reflect.TypeOf(value), reflect.TypeOf(value).Kind()))
			}

			if isSlice {
				slice := (**[]string)(unsafe.Pointer(uintptr(pObj) + offset))

				if *slice == nil {
					*slice = &[]string{v}
				} else {
					tmp := append(**slice, v)
					*slice = &tmp
				}

				// *slice = append(*slice, v)
			} else {
				pStr := (**string)(unsafe.Pointer(uintptr(pObj) + offset))
				*pStr = &v
			}

			return nil
		}, nil
	case reflect.Slice:
		// The only case when slice is allowed is binary array!
		if objType.Elem().Kind() == reflect.Uint8 ||
			(objType.Elem().Kind() == reflect.Slice && objType.Elem().Elem().Kind() == reflect.Uint8) {
			return func(pObj unsafe.Pointer, value interface{}) error {
				if pObj == nil {
					return errors.New(errors.KsiInvalidArgumentError)
				}
				v, ok := value.([]byte)
				if !ok {
					return errors.New(errors.KsiInvalidArgumentError).AppendMessage(
						fmt.Sprintf("TLV setter function is expecting '%v' (%v) instead of '%v' (%v)!",
							reflect.TypeOf(v), reflect.TypeOf(v).Kind(), reflect.TypeOf(value), reflect.TypeOf(value).Kind()))
				}

				if isSlice {
					slice := (**[][]byte)(unsafe.Pointer(uintptr(pObj) + offset))

					if *slice == nil {
						*slice = &[][]byte{v}
					} else {
						tmp := append(**slice, v)
						*slice = &tmp
					}
				} else {
					pStr := (**[]byte)(unsafe.Pointer(uintptr(pObj) + offset))
					*pStr = &v
				}

				return nil
			}, nil
		}
		return nil, errors.New(errors.KsiInvalidArgumentError).
			AppendMessage("TLV setter function is not implemented for regular arrays (only for []byte marked as 'bin').")
	}

	return nil, errors.New(errors.KsiNotImplemented).AppendMessage(
		fmt.Sprintf("TLV setter function has no implementation for value with Kind '%v'!", kind))
}

func getObj(offset uintptr, objType reflect.Type, template *Template) (func(pObj unsafe.Pointer) (interface{}, error), error) {
	if objType == nil || template == nil {
		return nil, errors.New(errors.KsiInvalidArgumentError)
	}

	isSlice := false
	kind := objType.Kind()

	// Handle special case with []byte, where it is not interpreted as a list, but octet string.
	// Note that [][]byte, should be handled as a list of octet strings.
	if kind == reflect.Slice && objType.Elem().Kind() != reflect.Uint8 {
		isSlice = true
		kind = objType.Elem().Kind()
	}

	if template.templateType == VTTlvObj || template.templateType == VTNestedTlvObj {
		if isSlice {
			return func(pObj unsafe.Pointer) (interface{}, error) {
				if pObj == nil {
					return nil, errors.New(errors.KsiInvalidArgumentError)
				}
				objTmpType := objType
				pp := (**[]*uintptr)(unsafe.Pointer(uintptr(pObj) + offset))
				sliceOfPointers := *pp
				if sliceOfPointers == nil {
					return nil, nil
				}
				tmpList := make([]TlvObj, 0, len(*sliceOfPointers))

				for _, pElement := range *sliceOfPointers {
					reflectValue := reflect.NewAt(objTmpType.Elem().Elem(), unsafe.Pointer(pElement))
					buf := reflectValue.Interface()

					x, ok := buf.(TlvObj)
					if !ok {
						return nil, errors.New(errors.KsiInvalidStateError).
							AppendMessage("Object converted to TLV does not implement TlvObj interface.")
					}

					tmpList = append(tmpList, x)
				}

				return tmpList, nil
			}, nil
		} else {
			return func(pObj unsafe.Pointer) (interface{}, error) {
				if pObj == nil {
					return nil, errors.New(errors.KsiInvalidArgumentError)
				}
				objTmpType := objType
				p := *(**uintptr)(unsafe.Pointer(uintptr(pObj) + offset))
				if p == nil {
					return nil, nil
				}
				reflectValue := reflect.NewAt(objTmpType, unsafe.Pointer(p))
				buf := reflectValue.Interface()

				x, ok := buf.(TlvObj)
				if !ok {
					return nil, errors.New(errors.KsiInvalidStateError).
						AppendMessage("Object converted to TLV does not implement TlvObj interface.")
				}

				return x, nil
			}, nil
		}

	}

	switch kind {
	case reflect.Uint64:
		return func(pObj unsafe.Pointer) (interface{}, error) {
			if pObj == nil {
				return nil, errors.New(errors.KsiInvalidArgumentError)
			}
			if isSlice {
				slice := *(**[]uint64)(unsafe.Pointer(uintptr(pObj) + offset))
				return slice, nil
			}

			pInt := *(**uint64)(unsafe.Pointer(uintptr(pObj) + offset))
			return pInt, nil
		}, nil
	case reflect.Ptr, reflect.Struct:
		return func(pObj unsafe.Pointer) (interface{}, error) {
			if pObj == nil {
				return nil, errors.New(errors.KsiInvalidArgumentError)
			}
			// It is known that pObj + offset points to a memory field that holds a pointer to a value.
			// New unsafe pointer is created that sums pObj and offset. Its value is transformed to
			// A pointer to pointer to uintptr. value usfP is created to a pointer to uintptr and is used
			// to set the real pointer inside a struct!
			if isSlice {
				sl := *(**[]*uintptr)(unsafe.Pointer(uintptr(pObj) + offset))
				return sl, nil
			}
			pPtr := *(**uintptr)(unsafe.Pointer(uintptr(pObj) + offset))
			return pPtr, nil
		}, nil
	case reflect.String:
		return func(pObj unsafe.Pointer) (interface{}, error) {
			if pObj == nil {
				return nil, errors.New(errors.KsiInvalidArgumentError)
			}
			if isSlice {
				slice := *(**[]string)(unsafe.Pointer(uintptr(pObj) + offset))
				return slice, nil
			}
			pStr := *(**string)(unsafe.Pointer(uintptr(pObj) + offset))
			return pStr, nil
		}, nil
	case reflect.Slice:
		// The only case when slice is allowed is binary array!
		if objType.Elem().Kind() == reflect.Uint8 ||
			(objType.Elem().Kind() == reflect.Slice && objType.Elem().Elem().Kind() == reflect.Uint8) {
			return func(pObj unsafe.Pointer) (interface{}, error) {
				if pObj == nil {
					return nil, errors.New(errors.KsiInvalidArgumentError)
				}
				if isSlice {
					slice := *(**[][]byte)(unsafe.Pointer(uintptr(pObj) + offset))
					return slice, nil
				}
				pStr := *(**[]byte)(unsafe.Pointer(uintptr(pObj) + offset))
				return pStr, nil
			}, nil
		}
		return nil, errors.New(errors.KsiInvalidArgumentError).
			AppendMessage("TLV object getter function is not implemented for regular arrays (only for []byte marked as 'bin').")
	}

	return nil, errors.New(errors.KsiNotImplemented).AppendMessage(
		fmt.Sprintf("TLV object getter function has no implementation for value with Kind '%v'!", kind))
}

func (template *Template) headerData(valLen uint64) (tag uint16, nc bool, fu bool, vl uint64) {
	if template == nil {
		// Just return default values.
		return
	}

	tag = uint16(template.tag[0])
	vl = valLen
	if template.options != nil {
		return tag, template.options.NonCritical, template.options.FastForward, vl
	}
	return
}

func templatePathToString(path [][]templateTag) string {
	sbldr := strings.Builder{}

	for i, v := range path {
		if i > 0 {
			sbldr.WriteString(".")
		}

		switch len(v) {
		case 0:
			sbldr.WriteString("<nil>")
		case 1:
			sbldr.WriteString(fmt.Sprintf("%x", v[0]))
		default:
			sbldr.WriteString("(")

			for j, tag := range v {
				if j > 0 {
					sbldr.WriteString("|")
				}
				sbldr.WriteString(fmt.Sprintf("%x", tag))
			}

			sbldr.WriteString(")")
		}

	}

	return sbldr.String()
}
