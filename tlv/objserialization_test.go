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
)

func newInt(value uint64) *uint64 { return &value }
func newStr(value string) *string { return &value }
func newBin(value []byte) *[]byte { return &value }

func compareSimilarObjects(t *testing.T, aI, bI interface{}, path string) {
	var (
		a = reflect.ValueOf(aI)
		b = reflect.ValueOf(bI)
	)
	if path == "" {
		if a.Kind() == reflect.Ptr && b.Elem().Kind() == reflect.Struct {
			path = a.Type().Elem().Name()
		} else {
			path = a.Type().Kind().String()
		}
	}
	if a.IsNil() && b.IsNil() {
		return
	} else if a.IsNil() && !b.IsNil() || !a.IsNil() && b.IsNil() {
		t.Fatalf("In %s. One of the input objects is nil and another is not! a is %v and b is %v!", path, a, b)
	}
	if a.Kind() != reflect.Ptr || b.Kind() != reflect.Ptr {
		t.Fatalf("In %s. Only values which Kind is pointer to struct can be compared! a is %v and b is %v!", path, a.Kind(), b.Kind())
	}
	if a.Elem().Kind() != reflect.Struct || b.Elem().Kind() != reflect.Struct {
		t.Fatalf("In %s. Only pointer to values which Kind is struct can be compared! a is %v and b is %v!", path, a.Elem().Kind(), b.Elem().Kind())
	}
	if a.Elem().Type().Name() != b.Elem().Type().Name() {
		t.Fatalf("In %s. Only objects with same name can be compared! a is %v and b is %v!", path, a.Elem().Type().Name(), b.Elem().Type().Name())
	}

	for i := 0; i < a.Elem().NumField(); i++ {
		var (
			aValue    = a.Elem().Field(i)
			bValue    = b.Elem().Field(i)
			fieldName = a.Elem().Type().Field(i).Name

			isPointerToStruct      = aValue.Type().Kind() == reflect.Ptr && aValue.Type().Elem().Kind() == reflect.Struct
			isPointerToStructSlice = aValue.Type().Kind() == reflect.Ptr && aValue.Type().Elem().Kind() == reflect.Slice && aValue.Type().Elem().Elem().Kind() == reflect.Ptr && aValue.Type().Elem().Elem().Elem().Kind() == reflect.Struct
		)
		if isPointerToStruct {
			compareSimilarObjects(t, aValue.Interface(), bValue.Interface(), path+"."+fieldName)
			continue
		} else if isPointerToStructSlice {
			var (
				sizeA = aValue.Elem().Len()
				sizeB = bValue.Elem().Len()
			)
			if sizeA != sizeB {
				t.Fatalf("In %s.%s. Length of the arrays do not match! a is '%v' and b is '%v'", path, fieldName, sizeA, sizeB)
			}

			for i := 0; i < sizeA; i++ {
				var (
					aValue = aValue.Elem().Index(i)
					bValue = bValue.Elem().Index(i)
				)
				if aValue.Pointer() == 0 && bValue.Pointer() == 0 {
					continue
				}
				if (aValue.Pointer() == 0 && bValue.Pointer() != 0) || (aValue.Pointer() != 0 && bValue.Pointer() == 0) {
					t.Fatalf("In %s.%s. One of the pointers is nil and another is not! a is '%v' and b is '%v'", path, fieldName, aValue.Elem().Elem().Elem(), bValue.Elem().Elem().Elem())
				}

				compareSimilarObjects(t, aValue.Interface(), bValue.Interface(), path+"."+fieldName)
			}
			continue
		}

		aInterface := aValue.Interface()
		bInterface := bValue.Interface()
		switch aData := aInterface.(type) {
		case uint64:
			bData := bInterface.(uint64)
			if aData != bData {
				t.Fatalf("In %s.%s. Values do not match! a is '%v' and b is '%v'", path, fieldName, aData, bData)
			}
		case uint16:
			bData := bInterface.(uint16)
			if aData != bData {
				t.Fatalf("In %s.%s. Values do not match! a is '%v' and b is '%v'", path, fieldName, aData, bData)
			}
		case *uint64:
			bData := bInterface.(*uint64)
			if (aData == nil && bData == nil) || (aData != nil && bData != nil && *aData == *bData) {
				continue
			}

			if aData != nil && bData != nil {
				t.Fatalf("In %s.%s. Values pointed by pointers do not match! a is '%v' and b is '%v'", path, fieldName, *aData, *bData)
			} else {
				t.Fatalf("In %s.%s. One of the pointers is nil and another is not! a is %v and b is %v!", path, fieldName, aData, bData)
			}
		case *string:
			bData := bInterface.(*string)
			if (aData == nil && bData == nil) || (aData != nil && bData != nil && *aData == *bData) {
				continue
			}

			if aData != nil && bData != nil {
				t.Fatalf("In %s.%s. Values pointed by pointers do not match! a is '%v' and b is '%v'", path, fieldName, *aData, *bData)
			} else {
				t.Fatalf("In %s.%s. One of the pointers is nil and another is not! a is %v and b is %v!", path, fieldName, aData, bData)
			}
		case *[]byte:
			bData := bInterface.(*[]byte)
			if (aData == nil && bData == nil) || (aData != nil && bData != nil && bytes.Equal(*aData, *bData)) {
				continue
			}

			if aData != nil && bData != nil {
				t.Fatalf("In %s.%s. Values pointed by pointers do not match! a is '%v' and b is '%v'", path, fieldName, *aData, *bData)
			} else {
				t.Fatalf("In %s.%s. One of the pointers is nil and another is not! a is %v and b is %v!", path, fieldName, aData, bData)
			}
		case *[]string:
			bData := bInterface.(*[]string)
			if aData == nil && bData == nil {
				continue
			}

			if (aData == nil && bData != nil) || (aData != nil && bData == nil) {
				t.Fatalf("In %s.%s. One of the pointers is nil and another is not! a is '%v' and b is '%v'", path, fieldName, aData, bData)
			}
			if len(*bData) != len(*aData) {
				t.Fatalf("In %s.%s. Length of the arrays do not match! a is '%v' and b is '%v'", path, fieldName, len(*aData), len(*bData))
			}

			for i, as := range *aData {
				bs := (*bData)[i]

				if as != bs {
					t.Fatalf("In %s.%s. Values held in arrays do not match! a[%v] is '%v' and b[%v] is '%v'", path, fieldName, i, as, i, bs)
				}
			}
		case *[]uint64:
			bData := bInterface.(*[]uint64)
			if aData == nil && bData == nil {
				continue
			}

			if (aData == nil && bData != nil) || (aData != nil && bData == nil) {
				t.Fatalf("In %s.%s. One of the pointers is nil and another is not! a is '%v' and b is '%v'", path, fieldName, aData, bData)
			}
			if len(*bData) != len(*aData) {
				t.Fatalf("In %s.%s. Length of the arrays do not match! a is '%v' and b is '%v'", path, fieldName, len(*aData), len(*bData))
			}

			for i, as := range *aData {
				bs := (*bData)[i]

				if as != bs {
					t.Fatalf("In %s.%s. Values held in arrays do not match! a[%v] is '%v' and b[%v] is '%v'", path, fieldName, i, as, i, bs)
				}
			}
		case *[][]byte:
			bData := bInterface.(*[][]byte)
			if aData == nil && bData == nil {
				continue
			}

			if (aData == nil && bData != nil) || (aData != nil && bData == nil) {
				t.Fatalf("In %s.%s. One of the pointers is nil and another is not! a is '%v' and b is '%v'", path, fieldName, aData, bData)
			}
			if len(*bData) != len(*aData) {
				t.Fatalf("In %s.%s. Length of the arrays do not match! a is '%v' and b is '%v'", path, fieldName, len(*aData), len(*bData))
			}

			for i, as := range *aData {
				bs := (*bData)[i]

				if !bytes.Equal(as, bs) {
					t.Fatalf("In %s.%s. Values held in arrays do not match! a[%v] is '%v' and b[%v] is '%v'", path, fieldName, i, as, i, bs)
				}
			}
		default:
			t.Fatalf("In %s.%s. Compare logic is not implemented!", path, fieldName)
		}
	}

}

func assertFromObjectToTlvAndBackAgain(t *testing.T, template *Template, expectedTlv string, obj1, obj2 interface{}) {
	// Get TLV from template.
	tlv, err := NewTlv(ConstructFromObject(obj1, template))
	if err != nil {
		t.Fatalf("Unable to get TLV from object %s.", err)
	}
	if len(tlv.Raw) != tlv.Length() {
		t.Fatalf("TLV real size (%v) does not match with value returned by Length (%v)", len(tlv.Raw), tlv.Length())
	}

	if expectedTlv != "" {
		tlvAfterParse := tlv.String()
		if tlvAfterParse != expectedTlv {
			t.Fatalf("Expecting TLV:\n'%s'\nBut got:\n'%s'", expectedTlv, tlvAfterParse)
		}
	}

	tlv2, err := NewTlv(ConstructFromSlice(tlv.Raw))
	if err != nil {
		t.Fatalf("Unable read TLV from slice %s.", err)
	}

	if err := tlv2.ParseNested(template); err != nil {
		t.Fatalf("Unable parse TLV %s.", err)
	}

	err = tlv2.ToObject(obj2, template, nil)
	if err != nil {
		t.Fatalf("Unable to fill obj %s.", err)
	}
}

func assertFromObjectToTlvError(t *testing.T, template *Template, obj1 interface{}, message string) {
	// Get TLV from template.
	tlv, err := NewTlv(ConstructFromObject(obj1, template))
	if err == nil {
		t.Fatalf("This call should have been failed!")
	}
	if tlv != nil {
		t.Fatalf("In case of failure, TLV returned must be nil!")
	}

	msg := errors.KsiErr(err).Message()[0]
	if msg != message {
		t.Fatalf("\nExpecting error: '%s'\nBut got error:   '%s'\n", message, msg)
	}
}

func TestUnitObjSerializationOrder(t *testing.T) {
	type structWithOrder struct {
		L5     *uint64 `tlv:"5,int,IL,C1"`
		Just2  *uint64 `tlv:"2,int,I2"`
		Just1  *uint64 `tlv:"4,int,I1"`
		Just3  *uint64 `tlv:"3,int"`
		IsNil4 *uint64 `tlv:"6,int"`
		F0     *uint64 `tlv:"1,int,IF"`
	}

	// Get template.
	template, err := NewTemplate(0xa)
	if err != nil {
		t.Fatalf("Unable to create TLV template %s.", err)
	}
	if err = template.Parse(reflect.TypeOf(new(structWithOrder))); err != nil {
		t.Fatalf("Unable to resolve TLV template %s.", err)
	}

	// Create a test object.
	obj1 := &structWithOrder{
		L5:     newInt(3),
		F0:     newInt(1),
		Just2:  newInt(10),
		Just3:  newInt(11),
		Just1:  newInt(12),
		IsNil4: nil,
	}
	obj2 := new(structWithOrder)

	expectedTlv := `TLV[0xa]: 
    TLV[0x1]: 01
    TLV[0x4]: 0c
    TLV[0x2]: 0a
    TLV[0x3]: 0b
    TLV[0x5]: 03
`
	assertFromObjectToTlvAndBackAgain(t, template, expectedTlv, obj1, obj2)
	compareSimilarObjects(t, obj1, obj2, "")
}

func TestUnitObjSerializationSimpleGroups(t *testing.T) {
	// Specify struct.
	type structWithGroups struct {
		F1 *uint64 `tlv:"1,int,G1,!G2"`
		F2 *uint64 `tlv:"2,int,G2,!G1"`
		F3 *uint64 `tlv:"3,int,G3,&G1"`
	}

	// Get template.
	template, err := NewTemplate(0xa)
	if err != nil {
		t.Fatalf("Unable to create TLV template %s.", err)
	}
	if err = template.Parse(reflect.TypeOf(new(structWithGroups))); err != nil {
		t.Fatalf("Unable to resolve TLV template %s.", err)
	}

	// Just value F1 - no conflicts and no dependencies.
	obj1 := &structWithGroups{
		F1: newInt(1),
	}
	obj2 := &structWithGroups{}

	expectedTlv := `TLV[0xa]: 
    TLV[0x1]: 01
`
	assertFromObjectToTlvAndBackAgain(t, template, expectedTlv, obj1, obj2)
	compareSimilarObjects(t, obj1, obj2, "")

	// Conflicting values F1 and F2.
	obj1 = &structWithGroups{
		F1: newInt(1),
		F2: newInt(2),
	}

	assertFromObjectToTlvError(t, template, obj1, "TLV (TLV [a.2] (F2)) is in conflict with group 1.")

	// Value F3 with missing dependency F1.
	obj1 = &structWithGroups{
		F3: newInt(3),
	}

	assertFromObjectToTlvError(t, template, obj1, "TLV (a.[3]) depends on missing group G1.")

	// Value F3 with dependency F1.
	obj1 = &structWithGroups{
		F1: newInt(1),
		F3: newInt(3),
	}
	obj2 = &structWithGroups{}

	expectedTlv = `TLV[0xa]: 
    TLV[0x1]: 01
    TLV[0x3]: 03
`
	assertFromObjectToTlvAndBackAgain(t, template, expectedTlv, obj1, obj2)
	compareSimilarObjects(t, obj1, obj2, "")
}

func TestUnitSerializeTlvMandatoryFields(t *testing.T) {
	// Specify struct.
	type structWithMandatoryField struct {
		F1 *uint64 `tlv:"1,int"`
		M2 *uint64 `tlv:"2,int,C1"`
	}

	// Get template.
	template, err := NewTemplate(0xa)
	if err != nil {
		t.Fatalf("Unable to create TLV template %s.", err)
	}
	if err = template.Parse(reflect.TypeOf(new(structWithMandatoryField))); err != nil {
		t.Fatalf("Unable to resolve TLV template %s.", err)
	}

	// F1 and missing mandatory field M2.
	obj1 := &structWithMandatoryField{
		F1: newInt(1),
	}
	assertFromObjectToTlvError(t, template, obj1, "TLV [a.2] (M2) count should be C1, but is 0.")

	// F1 and existing mandatory field M2.
	obj1 = &structWithMandatoryField{
		F1: newInt(1),
		M2: newInt(2),
	}
	obj2 := &structWithMandatoryField{}

	expectedTlv := `TLV[0xa]: 
    TLV[0x1]: 01
    TLV[0x2]: 02
`
	assertFromObjectToTlvAndBackAgain(t, template, expectedTlv, obj1, obj2)
	compareSimilarObjects(t, obj1, obj2, "")
}

func TestUnitObjSerializationConflictingGroupsWithOrder(t *testing.T) {
	type structWithConflictingGroupsWithOrder struct {
		L1   *uint64 `tlv:"1,int,G1,!G2,IL"`
		L2   *uint64 `tlv:"2,int,G2,!G1,IL"`
		Just *uint64 `tlv:"3,int"`
		F1   *uint64 `tlv:"4,int,G1,!G2,IF,"`
		F2   *uint64 `tlv:"5,int,G2,!G1,IF"`
	}

	// Get template.
	template, err := NewTemplate(0xa)
	if err != nil {
		t.Fatalf("Unable to create TLV template %s.", err)
	}
	if err = template.Parse(reflect.TypeOf(&structWithConflictingGroupsWithOrder{})); err != nil {
		t.Fatalf("Unable to resolve TLV template %s.", err)
	}

	// Create a test object, containing Group 1.
	obj1 := &structWithConflictingGroupsWithOrder{
		F1:   newInt(4),
		Just: newInt(3),
		L1:   newInt(1),
	}
	obj2 := &structWithConflictingGroupsWithOrder{}
	expectedTlv := `TLV[0xa]: 
    TLV[0x4]: 04
    TLV[0x3]: 03
    TLV[0x1]: 01
`
	assertFromObjectToTlvAndBackAgain(t, template, expectedTlv, obj1, obj2)
	compareSimilarObjects(t, obj1, obj2, "")

	// Create a test object, containing Group 2.
	obj1 = &structWithConflictingGroupsWithOrder{
		F2:   newInt(5),
		Just: newInt(3),
		L2:   newInt(2),
	}
	obj2 = new(structWithConflictingGroupsWithOrder)
	expectedTlv = `TLV[0xa]: 
    TLV[0x5]: 05
    TLV[0x3]: 03
    TLV[0x2]: 02
`
	assertFromObjectToTlvAndBackAgain(t, template, expectedTlv, obj1, obj2)
	compareSimilarObjects(t, obj1, obj2, "")

	// Create a test object, containing Group 2 and part of group 1 - must end with failure.
	obj1 = &structWithConflictingGroupsWithOrder{
		F1:   newInt(0),
		F2:   newInt(5),
		Just: newInt(3),
		L2:   newInt(2),
	}
	obj2 = &structWithConflictingGroupsWithOrder{}
	assertFromObjectToTlvError(t, template, obj1, "TLV (TLV [a.2] (L2)) is in conflict with group 1.")

	// Create a test object, containing Group 2 and part of group 1 - must end with failure.
	obj1 = &structWithConflictingGroupsWithOrder{
		F2:   newInt(5),
		Just: newInt(3),
		L2:   newInt(2),
		L1:   newInt(0),
	}
	obj2 = &structWithConflictingGroupsWithOrder{}
	assertFromObjectToTlvError(t, template, obj1, "TLV (TLV [a.1] (L1)) is in conflict with group 2.")
}

func TestUnitObjSerializationGroupsWithCount(t *testing.T) {
	type structWithGroupsWithCount struct {
		M1 *uint64 `tlv:"1,int,C1,G1,!G2"`
		M2 *uint64 `tlv:"3,int,C1,!G1,G2"`
	}

	// Get template.
	template, err := NewTemplate(0xa)
	if err != nil {
		t.Fatalf("Unable to create TLV template %s.", err)
	}
	if err = template.Parse(reflect.TypeOf(new(structWithGroupsWithCount))); err != nil {
		t.Fatalf("Unable to resolve TLV template %s.", err)
	}

	// Create a test object, containing Group 1.
	obj1 := &structWithGroupsWithCount{M1: newInt(4)}
	obj2 := &structWithGroupsWithCount{}
	expectedTlv := `TLV[0xa]: 
    TLV[0x1]: 04
`
	assertFromObjectToTlvAndBackAgain(t, template, expectedTlv, obj1, obj2)
	compareSimilarObjects(t, obj1, obj2, "")

	// Create a test object, containing Group 2.
	obj1 = &structWithGroupsWithCount{M2: newInt(0x14)}
	obj2 = &structWithGroupsWithCount{}
	expectedTlv = `TLV[0xa]: 
    TLV[0x3]: 14
`
	assertFromObjectToTlvAndBackAgain(t, template, expectedTlv, obj1, obj2)
	compareSimilarObjects(t, obj1, obj2, "")

	// Create a test object, containing both Groups - must end with failure.
	obj1 = &structWithGroupsWithCount{
		M1: newInt(4),
		M2: newInt(0x14),
	}
	obj2 = &structWithGroupsWithCount{}
	assertFromObjectToTlvError(t, template, obj1, "TLV (TLV [a.3] (M2)) is in conflict with group 1.")
}

func TestUnitObjSerializationGroupsWithCountAndNoGroupDepElementNoCount(t *testing.T) {
	type structWithGroupsWithCount struct {
		M1 *uint64 `tlv:"1,int,C1,G1,!G2"`
		M2 *uint64 `tlv:"3,int,C1,!G1,G2"`
		M3 *uint64 `tlv:"5,int"`
	}

	// Get template.
	template, err := NewTemplate(0xa)
	if err != nil {
		t.Fatalf("Unable to create TLV template %s.", err)
	}
	if err = template.Parse(reflect.TypeOf(new(structWithGroupsWithCount))); err != nil {
		t.Fatalf("Unable to resolve TLV template %s.", err)
	}

	// Create a test object, containing Group 1.
	obj1 := &structWithGroupsWithCount{M1: newInt(4)}
	obj2 := &structWithGroupsWithCount{}
	expectedTlv := `TLV[0xa]: 
    TLV[0x1]: 04
`
	assertFromObjectToTlvAndBackAgain(t, template, expectedTlv, obj1, obj2)
	compareSimilarObjects(t, obj1, obj2, "")
	// Add no dep element.
	obj1.M3 = newInt(0xde)
	obj2 = &structWithGroupsWithCount{}
	expectedTlv = `TLV[0xa]: 
    TLV[0x1]: 04
    TLV[0x5]: de
`
	assertFromObjectToTlvAndBackAgain(t, template, expectedTlv, obj1, obj2)
	compareSimilarObjects(t, obj1, obj2, "")

	// Create a test object, containing Group 2.
	obj1 = &structWithGroupsWithCount{M2: newInt(0x14)}
	obj2 = &structWithGroupsWithCount{}
	expectedTlv = `TLV[0xa]: 
    TLV[0x3]: 14
`
	assertFromObjectToTlvAndBackAgain(t, template, expectedTlv, obj1, obj2)
	compareSimilarObjects(t, obj1, obj2, "")
	// Add no dep element.
	obj1.M3 = newInt(0xde)
	obj2 = &structWithGroupsWithCount{}
	expectedTlv = `TLV[0xa]: 
    TLV[0x3]: 14
    TLV[0x5]: de
`
	assertFromObjectToTlvAndBackAgain(t, template, expectedTlv, obj1, obj2)
	compareSimilarObjects(t, obj1, obj2, "")

	// Create a test object, containing all elements - must end with failure.
	obj1 = &structWithGroupsWithCount{
		M1: newInt(4),
		M2: newInt(0x14),
		M3: newInt(0xde),
	}
	assertFromObjectToTlvError(t, template, obj1, "TLV (TLV [a.3] (M2)) is in conflict with group 1.")

	// Create a test object, containing no groups.
	obj1 = &structWithGroupsWithCount{M3: newInt(4)}

	assertFromObjectToTlvError(t, template, obj1, "TLV [a.3] (M2) count should be C1, but is 0.")
}

func TestUnitObjSerializationGroupsWithCountAndNoGroupDepElementWithCount(t *testing.T) {
	type structWithGroupsWithCount struct {
		M1 *uint64 `tlv:"1,int,C1,G1,!G2"`
		M2 *uint64 `tlv:"3,int,C1,!G1,G2"`
		M3 *uint64 `tlv:"5,int,C1"`
	}

	// Get template.
	template, err := NewTemplate(0xa)
	if err != nil {
		t.Fatalf("Unable to create TLV template %s.", err)
	}
	if err = template.Parse(reflect.TypeOf(new(structWithGroupsWithCount))); err != nil {
		t.Fatalf("Unable to resolve TLV template %s.", err)
	}

	// Create a test object, containing Group 1 - must end with failure.
	obj1 := &structWithGroupsWithCount{M1: newInt(4)}
	obj2 := &structWithGroupsWithCount{}
	assertFromObjectToTlvError(t, template, obj1, "TLV [a.5] (M3) count should be C1, but is 0.")
	// Add no dep element.
	obj1.M3 = newInt(0xde)
	expectedTlv := `TLV[0xa]: 
    TLV[0x1]: 04
    TLV[0x5]: de
`
	assertFromObjectToTlvAndBackAgain(t, template, expectedTlv, obj1, obj2)
	compareSimilarObjects(t, obj1, obj2, "")

	// Create a test object, containing Group 2.
	obj1 = &structWithGroupsWithCount{M2: newInt(0x14)}
	assertFromObjectToTlvError(t, template, obj1, "TLV [a.5] (M3) count should be C1, but is 0.")
	// Add no dep element.
	obj1.M3 = newInt(0xde)
	obj2 = &structWithGroupsWithCount{}
	expectedTlv = `TLV[0xa]: 
    TLV[0x3]: 14
    TLV[0x5]: de
`
	assertFromObjectToTlvAndBackAgain(t, template, expectedTlv, obj1, obj2)
	compareSimilarObjects(t, obj1, obj2, "")

	// Create a test object, containing all elements - must end with failure.
	obj1 = &structWithGroupsWithCount{
		M1: newInt(4),
		M2: newInt(0x14),
		M3: newInt(0xde),
	}
	assertFromObjectToTlvError(t, template, obj1, "TLV (TLV [a.3] (M2)) is in conflict with group 1.")

	// Create a test object, containing no groups.
	obj1 = &structWithGroupsWithCount{M3: newInt(4)}
	assertFromObjectToTlvError(t, template, obj1, "TLV [a.3] (M2) count should be C1, but is 0.")
}

func TestUnitSerializeIntegers(t *testing.T) {
	// Specify struct.
	type structWithIntegers struct {
		I64 *uint64 `tlv:"1,int"`
		I8  *uint64 `tlv:"2,int8"`
	}

	// Get template.
	template, err := NewTemplate(0xa)
	if err != nil {
		t.Fatalf("Unable to create TLV template %s.", err)
	}

	if err = template.Parse(reflect.TypeOf(new(structWithIntegers))); err != nil {
		t.Fatalf("Unable to resolve TLV template %s.", err)
	}

	// Both integers within boundaries.
	obj1 := &structWithIntegers{
		I64: newInt(0),
		I8:  newInt(0),
	}
	obj2 := new(structWithIntegers)
	expectedTlv := `TLV[0xa]: 
    TLV[0x1]: 00
    TLV[0x2]: 00
`
	assertFromObjectToTlvAndBackAgain(t, template, expectedTlv, obj1, obj2)
	compareSimilarObjects(t, obj1, obj2, "")

	// Both integers within boundaries 2.
	obj1 = &structWithIntegers{
		I64: newInt(255),
		I8:  newInt(255),
	}
	obj2 = &structWithIntegers{}
	expectedTlv = `TLV[0xa]: 
    TLV[0x1]: ff
    TLV[0x2]: ff
`
	assertFromObjectToTlvAndBackAgain(t, template, expectedTlv, obj1, obj2)
	compareSimilarObjects(t, obj1, obj2, "")

	// I8 too large.
	obj1 = &structWithIntegers{
		I64: newInt(256),
		I8:  newInt(256),
	}
	obj2 = &structWithIntegers{}
	assertFromObjectToTlvError(t, template, obj1, "Value for 8bit integer out of boundaries (256).")

	// I8 too large.
	obj1 = &structWithIntegers{
		I64: newInt(0x1000),
		I8:  newInt(0x1000),
	}
	obj2 = &structWithIntegers{}
	assertFromObjectToTlvError(t, template, obj1, "Value for 8bit integer out of boundaries (4096).")
}

func TestUnitSerializeIntegerList(t *testing.T) {
	// Specify struct.
	type structWithInt struct {
		IL *[]uint64 `tlv:"1,int,C0_N"`
		I2 *uint64   `tlv:"2,int"`

		ILempty *[]uint64 `tlv:"3,int,C0_N"`
		ILnil   *[]uint64 `tlv:"4,int,C0_N"`
	}

	// Get template.
	template, err := NewTemplate(0xa)
	if err != nil {
		t.Fatalf("Unable to create TLV template %s.", err)
	}
	if err := template.Parse(reflect.TypeOf(new(structWithInt))); err != nil {
		t.Fatalf("Unable to resolve TLV template %s.", err)
	}

	// Both integers within boundaries.
	var (
		SLempty = make([]uint64, 0)
		SL      = append([]uint64{}, *newInt(10), *newInt(11), *newInt(12))

		obj1 = &structWithInt{
			IL:      &SL,
			I2:      newInt(5),
			ILempty: &SLempty,
			ILnil:   nil,
		}
		obj2 = &structWithInt{}

		expectedTlv = `TLV[0xa]: 
    TLV[0x1]: 0a
    TLV[0x1]: 0b
    TLV[0x1]: 0c
    TLV[0x2]: 05
`
	)
	assertFromObjectToTlvAndBackAgain(t, template, expectedTlv, obj1, obj2)
	obj1.ILempty = nil
	compareSimilarObjects(t, obj1, obj2, "")
}

func TestUnitSerializeEmptyStruct(t *testing.T) {
	// Specify struct.
	type (
		emptyStruct                 struct{}
		parentStructWithEmptyStruct struct {
			Empty    *emptyStruct    `tlv:"1,nstd"`
			EmptyL   *[]*emptyStruct `tlv:"2,nstd,C0_N"`
			NilValue *emptyStruct    `tlv:"3,nstd"`
		}
	)
	var (
		list = append([]*emptyStruct{}, new(emptyStruct), new(emptyStruct), new(emptyStruct))

		obj1 = &parentStructWithEmptyStruct{
			Empty:  &emptyStruct{},
			EmptyL: &list,
		}
		obj2 = &parentStructWithEmptyStruct{}

		expectedTlv = `TLV[0xa]: 
    TLV[0x1]: 
    TLV[0x2]: 
    TLV[0x2]: 
    TLV[0x2]: 
`
	)

	// Get template.
	template, err := NewTemplate(0xa)
	if err != nil {
		t.Fatalf("Unable to create TLV template %s.", err)
	}
	if err := template.Parse(reflect.TypeOf(obj1)); err != nil {
		t.Fatalf("Unable to resolve TLV template %s.", err)
	}

	assertFromObjectToTlvAndBackAgain(t, template, expectedTlv, obj1, obj2)

	if obj2.Empty == nil {
		t.Fatalf("Empty object should have been set to not nil value!.")
	}
	if len(*(obj2.EmptyL)) != 3 || (*obj2.EmptyL)[0] == nil || (*obj2.EmptyL)[1] == nil || (*obj2.EmptyL)[2] == nil {
		t.Fatalf("List of Empty object should have contain 3 not nil values! %s.", err)
	}
	if obj2.NilValue != nil {
		t.Fatalf("Empty object not existing in TLV should be still nil! %s.", err)
	}
}

func TestUnitSerializeNestedStruct(t *testing.T) {
	// Specify struct.
	type (
		internalStruct struct {
			I *uint64 `tlv:"2,int"`
		}
		parseStructWithNestedSTruct struct {
			S1   *internalStruct    `tlv:"1,nstd"`
			SL1  *[]*internalStruct `tlv:"2,nstd,C0_N"`
			Snil *internalStruct    `tlv:"3,nstd"`
		}
	)
	var (
		list = append([]*internalStruct{},
			&internalStruct{I: newInt(10)},
			&internalStruct{I: newInt(11)},
			&internalStruct{I: newInt(12)},
		)

		obj1 = &parseStructWithNestedSTruct{
			S1:   &internalStruct{I: newInt(5)},
			SL1:  &list,
			Snil: nil,
		}
		obj2 = &parseStructWithNestedSTruct{}

		expectedTlv = `TLV[0xa]: 
    TLV[0x1]: 
      TLV[0x2]: 05
    TLV[0x2]: 
      TLV[0x2]: 0a
    TLV[0x2]: 
      TLV[0x2]: 0b
    TLV[0x2]: 
      TLV[0x2]: 0c
`
	)

	// Get template.
	template, err := NewTemplate(0xa)
	if err != nil {
		t.Fatalf("Unable to create TLV template %s.", err)
	}
	if err := template.Parse(reflect.TypeOf(obj1)); err != nil {
		t.Fatalf("Unable to resolve TLV template %s.", err)
	}
	assertFromObjectToTlvAndBackAgain(t, template, expectedTlv, obj1, obj2)
	compareSimilarObjects(t, obj1, obj2, "")
}

func TestUnitSerializeTlvWithBaseTlv(t *testing.T) {
	// Specify struct.
	type structWithBaseTlv struct {
		F1      *uint64 `tlv:"1,int"`
		baseTlv *Tlv    `tlv:"basetlv"`
	}

	// Get template.
	template, err := NewTemplate(0xa)
	if err != nil {
		t.Fatalf("Unable to create TLV template %s.", err)
	}
	if err := template.Parse(reflect.TypeOf(new(structWithBaseTlv))); err != nil {
		t.Fatalf("Unable to resolve TLV template %s.", err)
	}

	raw := []byte{0x0a, 0x03, 0x01, 0x01, 0x01}
	baseTlv, err := NewTlv(ConstructFromSlice(raw))
	if err != nil {
		t.Fatalf("Unable to create TLV %s.", err)
	}

	// F1 and existing mandatory field M2.
	var (
		obj1 = &structWithBaseTlv{
			F1:      newInt(1),
			baseTlv: baseTlv,
		}
		obj2        = &structWithBaseTlv{}
		expectedTlv = `TLV[0xa]: 
    TLV[0x1]: 01
`
	)
	assertFromObjectToTlvAndBackAgain(t, template, expectedTlv, obj1, obj2)
	if obj2.F1 == nil || *obj2.F1 != *obj1.F1 {
		t.Fatalf("Object parsed incorrectly.")
	}
	if !bytes.Equal(obj2.baseTlv.Raw, baseTlv.Raw) {
		t.Fatalf("TLV value mismatch:\nExpecting:  %v\nBut is:     %v!", obj2.baseTlv.Raw, baseTlv.Raw)
	}
}

func TestUnitSerializeTlvWithContext(t *testing.T) {
	// Specify struct.
	type (
		contextStrut struct {
			value int
		}
		structWithBaseTlv struct {
			F1  *uint64       `tlv:"1,int"`
			ctx *contextStrut `tlv:"context,contextStrut"`
		}
	)
	var (
		obj1 = &structWithBaseTlv{
			F1:  newInt(1),
			ctx: &contextStrut{value: 5},
		}
		obj2 = &structWithBaseTlv{}

		expectedTlv = `TLV[0xa]: 
    TLV[0x1]: 01
`
	)

	// Get template.
	template, err := NewTemplate(0xa)
	if err != nil {
		t.Fatalf("Unable to create TLV template %s.", err)
	}
	if err := template.Parse(reflect.TypeOf(obj1)); err != nil {
		t.Fatalf("Unable to resolve TLV template %s.", err)
	}

	assertFromObjectToTlvAndBackAgain(t, template, expectedTlv, obj1, obj2)
	if obj2.F1 == nil || *obj2.F1 != *obj1.F1 {
		t.Fatalf("Object parsed incorrectly.")
	}
}

func TestUnitSerializeString(t *testing.T) {
	// Specify struct.
	type structWithStrings struct {
		S1 *string `tlv:"1,utf8"`
		S2 *string `tlv:"2,utf8"`
	}
	var (
		// Both integers within boundaries.
		obj1 = &structWithStrings{
			S1: newStr("S1"),
			S2: newStr("S2"),
		}
		obj2 = &structWithStrings{}

		expectedTlv = `TLV[0xa]: 
    TLV[0x1]: 533100
    TLV[0x2]: 533200
`
	)

	// Get template.
	template, err := NewTemplate(0xa)
	if err != nil {
		t.Fatalf("Unable to create TLV template %s.", err)
	}
	err = template.Parse(reflect.TypeOf(obj1))
	if err != nil {
		t.Fatalf("Unable to resolve TLV template %s.", err)
	}

	assertFromObjectToTlvAndBackAgain(t, template, expectedTlv, obj1, obj2)
	compareSimilarObjects(t, obj1, obj2, "")
}

func TestUnitSerializeStringList(t *testing.T) {
	// Specify struct.
	type structWithStrings struct {
		SL *[]string `tlv:"1,utf8,C0_N"`
		S2 *string   `tlv:"2,utf8"`

		ILempty *[]string `tlv:"3,utf8,C0_N"`
		ILnil   *[]string `tlv:"4,utf8,C0_N"`
	}
	var (
		SLempty = make([]string, 0)
		SL      = append([]string{}, *newStr("L1"), *newStr("L2"), *newStr("L3"))

		obj1 = &structWithStrings{
			SL:      &SL,
			S2:      newStr("S2"),
			ILempty: &SLempty,
			ILnil:   nil,
		}
		obj2 = &structWithStrings{}

		expectedTlv = `TLV[0xa]: 
    TLV[0x1]: 4c3100
    TLV[0x1]: 4c3200
    TLV[0x1]: 4c3300
    TLV[0x2]: 533200
`
	)

	// Get template.
	template, err := NewTemplate(0xa)
	if err != nil {
		t.Fatalf("Unable to create TLV template %s.", err)
	}
	if err := template.Parse(reflect.TypeOf(obj1)); err != nil {
		t.Fatalf("Unable to resolve TLV template %s.", err)
	}
	assertFromObjectToTlvAndBackAgain(t, template, expectedTlv, obj1, obj2)
	obj1.ILempty = nil
	compareSimilarObjects(t, obj1, obj2, "")
}

func TestUnitSerializeBinaryList(t *testing.T) {
	// Specify struct.
	type structWithBinary struct {
		BL *[][]byte `tlv:"1,bin,C0_N"`
		B2 *[]byte   `tlv:"2,bin"`
	}
	var (
		BL = append([][]byte{}, []byte{1, 2}, []byte{3, 4}, []byte{5, 6})
		B2 = []byte{7, 8}

		obj1 = &structWithBinary{
			BL: &BL,
			B2: &B2,
		}
		obj2 = &structWithBinary{}

		expectedTlv = `TLV[0xa]: 
    TLV[0x1]: 0102
    TLV[0x1]: 0304
    TLV[0x1]: 0506
    TLV[0x2]: 0708
`
	)

	// Get template.
	template, err := NewTemplate(0xa)
	if err != nil {
		t.Fatalf("Unable to create TLV template %s.", err)
	}
	if err := template.Parse(reflect.TypeOf(obj1)); err != nil {
		t.Fatalf("Unable to resolve TLV template %s.", err)
	}
	assertFromObjectToTlvAndBackAgain(t, template, expectedTlv, obj1, obj2)
	compareSimilarObjects(t, obj1, obj2, "")
}

// Specify struct.
type tlvObjectStruct struct {
	Val uint64
	Tag uint16
}

func (s *tlvObjectStruct) ToTlv(enc *Encoder) (*Tlv, error) {
	if s == nil {
		return nil, nil
	}

	helperTemplate, err := newTemplate(VTTlvObj, s.Tag)
	if err != nil {
		return nil, err
	}

	valLen, err := enc.PrependUint64(s.Val)
	if err != nil {
		return nil, err
	}
	_, err = enc.PrependHeader(helperTemplate.headerData(valLen))
	if err != nil {
		return nil, err
	}

	return NewTlv(ConstructFromSlice(enc.Bytes()))
}

func (s *tlvObjectStruct) FromTlv(tlv *Tlv) error {
	tmp, err := tlv.Uint64()
	if err != nil {
		return err
	}

	s.Val = tmp
	s.Tag = tlv.Tag

	return nil
}

func TestUnitSerializeTlvObject(t *testing.T) {
	type parseStructWithNestedSTruct struct {
		T1   *tlvObjectStruct    `tlv:"1,tlvobj"`
		TL   *[]*tlvObjectStruct `tlv:"2,tlvobj,C0_N"`
		Tnil *tlvObjectStruct    `tlv:"3,tlvobj"`
	}
	var (
		TL = append([]*tlvObjectStruct{},
			&tlvObjectStruct{10, 2},
			&tlvObjectStruct{11, 2},
			&tlvObjectStruct{12, 2})
		T1 = tlvObjectStruct{5, 1}

		obj1 = &parseStructWithNestedSTruct{
			TL: &TL,
			T1: &T1,
		}
		obj2 = &parseStructWithNestedSTruct{}

		expectedTlv = `TLV[0xa]: 
    TLV[0x1]: 05
    TLV[0x2]: 0a
    TLV[0x2]: 0b
    TLV[0x2]: 0c
`
	)

	// Get template.
	template, err := NewTemplate(0xa)
	if err != nil {
		t.Fatalf("Unable to create TLV template %s.", err)
	}
	if err := template.Parse(reflect.TypeOf(obj1)); err != nil {
		t.Fatalf("Unable to resolve TLV template %s.", err)
	}
	assertFromObjectToTlvAndBackAgain(t, template, expectedTlv, obj1, obj2)
	compareSimilarObjects(t, obj1, obj2, "")
}

func TestUnitSerializeNonCriticalFastForward(t *testing.T) {
	type structWithIntegers struct {
		I64 *uint64 `tlv:"1,int,N,F"`
		I8  *uint64 `tlv:"2,int8,N"`
	}
	var (
		obj1 = &structWithIntegers{
			I64: newInt(5),
			I8:  newInt(8),
		}
		obj2 = &structWithIntegers{}

		expectedTlv = `TLV[0xa]: 
    TLV[0x1,N,F]: 05
    TLV[0x2,N]: 08
`
	)

	// Get template.
	template, err := NewTemplate(0xa)
	if err != nil {
		t.Fatalf("Unable to create TLV template %s.", err)
	}
	if err := template.Parse(reflect.TypeOf(obj1)); err != nil {
		t.Fatalf("Unable to resolve TLV template %s.", err)
	}
	assertFromObjectToTlvAndBackAgain(t, template, expectedTlv, obj1, obj2)
	compareSimilarObjects(t, obj1, obj2, "")
}

func TestUnitObjSerializeBigTagSmallData(t *testing.T) {
	type testStruct struct {
		A *uint64 `tlv:"5,int,IL,C1"`
	}
	var (
		obj1 = &testStruct{A: newInt(3)}
		obj2 = &testStruct{}

		expectedTlv = `TLV[0x888]: 
    TLV[0x5]: 03
`
	)

	// Get template.
	template, err := NewTemplate(0x888)
	if err != nil {
		t.Fatalf("Unable to create TLV template %s.", err)
	}
	if err := template.Parse(reflect.TypeOf(obj1)); err != nil {
		t.Fatalf("Unable to resolve TLV template %s.", err)
	}
	assertFromObjectToTlvAndBackAgain(t, template, expectedTlv, obj1, obj2)
	compareSimilarObjects(t, obj1, obj2, "")
}
