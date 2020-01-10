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
	"unsafe"

	"github.com/guardtime/goksi/errors"
)

// TlvObj is interface that provides custom functionality to get object from TLV, or to encode object as TLV.
// This interface is used by functions (Tlv).ToObject and by TLV constructor ConstructFromObject.
type TlvObj interface {
	// FromTlv function configures existing object with the data retrieved from input TLV.
	FromTlv(*Tlv) error

	// ToTlv functions encodes existing object as TLV. Function is provided by buffer which must be filled from highest
	// index to the lowest as TLV serialization must start from the deepest TLV. Note that TLV is still encoded in
	// big-endian.
	//
	// Example:
	//
	// ToTlv gets input buffer that is a slice from a larger structure. Input extBuf is from position 0 to x. TLV is
	// serialized from position y to x. Entire structure is located from y to n.
	//
	// index : i=0                                  i=y                  i=x                   i=n
	// extBuf: [        UNUSED EMPTY BUFFER        ][   type:len:value   ][   PREVIOUS TLVs   ]
	ToTlv(*Encoder) (*Tlv, error)
}

// ToObject decodes structured TLV object (see (Tlv).ParseNested()) and stores the result into value v.
//
// Note that the value v must point to an existing object that is bound to provided template, otherwise the output is
// undefined.
func (t *Tlv) ToObject(v interface{}, templateInput *Template, ctx unsafe.Pointer) error {
	if v == nil || templateInput == nil || t == nil {
		return errors.New(errors.KsiInvalidArgumentError)
	}

	if templateInput.templateType == VTNested && len(t.Nested) > 0 {
		upObj := unsafe.Pointer(reflect.ValueOf(v).Pointer())
		// Check if TLV template contains a template for base TLV!
		baseTlvTemplate := getBaseTlvTemplate(templateInput.childTemplate)
		if baseTlvTemplate != nil {
			if err := baseTlvTemplate.setObj(upObj, unsafe.Pointer(t)); err != nil {
				return err
			}
		}

		// Check if TLV template contains a context TLV!
		contextTlvTemplate := getContextTlvTemplate(templateInput.childTemplate)
		if contextTlvTemplate != nil {
			if err := contextTlvTemplate.setObj(upObj, ctx); err != nil {
				return err
			}
		}

		for _, tlv := range t.Nested {
			template, err := tlv.getTemplate(templateInput.childTemplate)
			if err != nil {
				return err
			}

			// Ignore noncritical TLV.
			if template == nil {
				continue
			}

			// Check for value type and use function setObj automatically created during
			// TLV Template generation, to set values inside a struct blob.
			switch template.templateType {
			case VTInt:
				tmp := uint64(0)

				if template.options.emptyTlvPermitted {
					tmp, err = tlv.Uint64E()
				} else {
					tmp, err = tlv.Uint64()
				}
				if err != nil {
					return err
				}

				if err = template.setObj(upObj, tmp); err != nil {
					return err
				}
			case VTInt8:
				tmp := uint64(0)

				if template.options.emptyTlvPermitted {
					tmp, err = tlv.Uint8E()
				} else {
					tmp, err = tlv.Uint8()
				}
				if err != nil {
					return err
				}

				if err = template.setObj(upObj, tmp); err != nil {
					return err
				}
			case VTUtf8:
				tmp := ""

				if template.options.emptyTlvPermitted {
					tmp, err = tlv.Utf8E()
				} else {
					tmp, err = tlv.Utf8()
				}
				if err != nil {
					return err
				}

				if err = template.setObj(upObj, tmp); err != nil {
					return err
				}
			case VTbin:
				tmp, err := tlv.Binary()
				if err != nil {
					return err
				}

				if err = template.setObj(upObj, tmp); err != nil {
					return err
				}
			case VTImprint:
				tmp, err := tlv.Imprint()
				if err != nil {
					return err
				}

				if err = template.setObj(upObj, tmp); err != nil {
					return err
				}
			case VTNested:
				newObjPointer := template.newObj()
				err := tlv.ToObject(newObjPointer, template, ctx)
				if err != nil {
					return err
				}

				if err = template.setObj(upObj, newObjPointer); err != nil {
					return err
				}
			case VTTlvObj, VTNestedTlvObj:
				if template.newObj == nil {
					return errors.New(errors.KsiInvalidFormatError).AppendMessage("newObj function is nil!")
				}

				wrapper := (*pointerPlusInterface)(template.newObj())
				newObjPointer := wrapper.ObjPointer

				// Check if TLV template contains a template for base TLV!
				baseTlvTemplate2 := getBaseTlvTemplate(template.childTemplate)
				if baseTlvTemplate2 != nil {
					if err := baseTlvTemplate2.setObj(wrapper.ObjPointer, unsafe.Pointer(tlv)); err != nil {
						return err
					}
				}

				// Check if TLV template contains a context TLV!
				contextTlvTemplate2 := getContextTlvTemplate(template.childTemplate)
				if contextTlvTemplate2 != nil {
					if err := contextTlvTemplate2.setObj(wrapper.ObjPointer, ctx); err != nil {
						return err
					}
				}

				// Check if value implements TlvObj interface.
				intrf, isTlvObj := wrapper.Interface.(TlvObj)
				if !isTlvObj {
					return errors.New(errors.KsiInvalidFormatError).
						AppendMessage("Object does not implement TlvObj interface!")
				}

				if err := intrf.FromTlv(tlv); err != nil {
					return err
				}

				if err = template.setObj(upObj, newObjPointer); err != nil {
					return err
				}
			}
		}
	} else if templateInput.templateType != VTNested && len(t.Nested) == 0 {
		return errors.New(errors.KsiInvalidArgumentError)
	}

	return nil
}

func (ps *parserState) registerObject(template *Template) error {
	return ps.registerInternal(template, true)
}

func (t *Tlv) getTemplate(templates []*Template) (*Template, error) {
	if t == nil || templates == nil {
		return nil, errors.New(errors.KsiInvalidArgumentError)
	}

	for _, template := range templates {
		if template.IsMatchingTag(t.Tag) {
			return template, nil
		}
	}

	// In case of noncritical TLV, that has no template, just return nil.
	if t.NonCritical {
		return nil, nil
	}

	return nil, errors.New(errors.KsiInvalidFormatError).AppendMessage("TLV template not found.")
}

func getBaseTlvTemplate(templates []*Template) *Template {
	for _, t := range templates {
		if t.templateType == VTBaseTlv {
			return t
		}
	}
	return nil
}

func getContextTlvTemplate(templates []*Template) *Template {
	for _, t := range templates {
		if t.templateType == VTContext {
			return t
		}
	}
	return nil
}

func internalTlvFromTemplate(pObj unsafe.Pointer, thisTlv *Tlv, templateInput *Template, enc *Encoder, state *parserState) (uint64, error) {
	if pObj == nil || thisTlv == nil || templateInput == nil || enc == nil || state == nil {
		return 0, errors.New(errors.KsiInvalidArgumentError)
	}

	count := uint64(0)
	lastCount := count

	for _, subTemplate := range templateInput.childTemplate {
		if subTemplate.templateType == VTBaseTlv || subTemplate.templateType == VTContext {
			continue
		}

		fieldValueInterface, err := subTemplate.getObj(pObj)
		if err != nil {
			return 0, errors.KsiErr(err).AppendMessage("Unable to get object field value.")
		}

		switch fieldValue := fieldValueInterface.(type) {
		case nil:
			continue
		case *uint64, *[]uint64, *string, *[]string, *[]byte, *[][]byte, *uintptr, *[]*uintptr:
			// Serialize and append TLV sub objects.
			c, tlvList, err := serialize(fieldValue, subTemplate, enc, state)
			if err != nil {
				return 0, err
			}

			thisTlv.Nested = append(thisTlv.Nested, tlvList...)

			count += c
			// Handle only TlvObj.
		case interface{}:
			switch x := fieldValue.(type) {
			case TlvObj:
				tlv, err := x.ToTlv(enc)
				if err != nil {
					return 0, err
				}

				if tlv != nil {
					thisTlv.Nested = append(thisTlv.Nested, tlv)
				}

				count += uint64(tlv.Length())

			case []TlvObj:
				for i := len(x) - 1; i >= 0; i-- {
					obj := x[i]
					tlv, err := obj.ToTlv(enc)
					if err != nil {
						return 0, err
					}

					if tlv != nil {
						thisTlv.Nested = append(thisTlv.Nested, tlv)
					}

					count += uint64(tlv.Length())
				}
			}
		default:
			return 0, errors.New(errors.KsiInvalidFormatError).
				AppendMessage(fmt.Sprintf("Value (%v) is not basic type (value or list of uint64, string byte array), nor object.",
					fieldValue))
		}

		// Register TLV in parser state. Run some checks against constraints on the fly.
		if lastCount < count {
			if err = state.registerObject(subTemplate); err != nil {
				return 0, errors.KsiErr(err).
					AppendMessage(fmt.Sprintf("TLV (%s.%x) template could not be registered.",
						tlvPathToString(state.path), subTemplate.tag[0]))
			}
		}
		lastCount = count

	}

	err := state.checkCountFinal(templateInput.childTemplate)
	if err != nil {
		return 0, errors.KsiErr(err).
			AppendMessage(fmt.Sprintf("TLV (%s) internal constraints failed.", tlvPathToString(state.path)))
	}

	err = state.checkGroupsFinal()
	if err != nil {
		return 0, errors.KsiErr(err).
			AppendMessage(fmt.Sprintf("TLV (%s) internal constraints failed.", tlvPathToString(state.path)))
	}

	err = state.checkIndexFinal()
	if err != nil {
		return 0, errors.KsiErr(err).
			AppendMessage(fmt.Sprintf("TLV (%s) internal constraints failed.", tlvPathToString(state.path)))
	}

	// Reverse the list of nested TLV elements as serialization is done in reverse order!
	nestedCount := len(thisTlv.Nested)
	loopSize := nestedCount / 2
	for i := 0; i < loopSize; i++ {
		tmp := thisTlv.Nested[nestedCount-1-i]
		thisTlv.Nested[nestedCount-1-i] = thisTlv.Nested[i]
		thisTlv.Nested[i] = tmp
	}

	return count, nil
}

func serializeValue(value interface{}, template *Template, enc *Encoder, state *parserState) (uint64, *Tlv, error) {
	if template == nil || enc == nil || state == nil {
		return 0, nil, errors.New(errors.KsiInvalidArgumentError)
	}

	tlv, err := NewTlv(ConstructEmpty(
		func() (tag uint16, nc bool, fu bool) {
			tag, nc, fu, _ = template.headerData(0)
			return
		}()))
	if err != nil {
		return 0, nil, errors.KsiErr(err).
			AppendMessage(fmt.Sprintf("Unable to serialize %s value (%s).", value, template.path))
	}

	var (
		valueLen uint64
		hasValue bool
	)
	// Check if type is pointer to value. If it is, try to serialize it.
	switch fieldValue := value.(type) {
	case *uint64:
		if fieldValue != nil {
			if template.templateType == VTInt8 {
				if template.options.emptyTlvPermitted {
					valueLen, err = enc.PrependUint8E(*fieldValue)
				} else {
					valueLen, err = enc.PrependUint8(*fieldValue)
				}
			} else {
				if template.options.emptyTlvPermitted {
					valueLen, err = enc.PrependUint64E(*fieldValue)
				} else {
					valueLen, err = enc.PrependUint64(*fieldValue)
				}
			}
			hasValue = true
		}
	case *string:
		if fieldValue != nil {
			valueLen, err = enc.PrependUtf8(*fieldValue)
			hasValue = true
		}
	case *[]byte:
		if fieldValue != nil {
			valueLen, err = enc.PrependBinary(*fieldValue)
			hasValue = true
		}
	case *uintptr:
		if fieldValue != nil {
			valueLen, err = internalTlvFromTemplate(unsafe.Pointer(fieldValue), tlv, template,
				enc, state.createChildState(tlv.Tag))
			hasValue = true
		}
	default:
		return 0, nil, errors.New(errors.KsiInvalidFormatError).
			AppendMessage(fmt.Sprintf("Unable to serialize %s value (%s).", value, template.path))
	}
	if !hasValue {
		return 0, nil, nil
	}
	if err != nil {
		return 0, nil, errors.KsiErr(err).
			AppendMessage(fmt.Sprintf("Unable to serialize %s value (%s).", value, template.path))
	}

	headerLen, err := enc.PrependHeader(template.headerData(valueLen))
	if err != nil {
		return 0, nil, errors.KsiErr(err).
			AppendMessage(fmt.Sprintf("Unable to serialize %s value (%s).", value, template.path))
	}

	tlv.Raw = enc.Bytes()[:headerLen+valueLen]
	tlv.value = tlv.Raw[headerLen:]

	return uint64(len(tlv.Raw)), tlv, nil
}

func serialize(value interface{}, template *Template, enc *Encoder, state *parserState) (uint64, []*Tlv, error) {
	count := uint64(0)
	tlvList := make([]*Tlv, 0, 16)

	// Check if type is pointer to value. If it is, try to serialize it.
	switch fieldValue := value.(type) {
	case *uint64, *string, *[]byte, *uintptr:
		c, tlv, err := serializeValue(value, template, enc, state)
		if err != nil {
			return 0, nil, err
		}
		count += c
		if tlv != nil {
			tlvList = append(tlvList, tlv)
		}
		return count, tlvList, nil
	case *[]uint64:
		if fieldValue != nil {
			for i := len(*fieldValue) - 1; i >= 0; i-- {
				v := (*fieldValue)[i]

				c, tlv, err := serializeValue(&v, template, enc, state)
				if err != nil {
					return 0, nil, err
				}
				count += c
				if tlv != nil {
					tlvList = append(tlvList, tlv)
				}
			}
		}
	case *[]string:
		if fieldValue != nil {
			for i := len(*fieldValue) - 1; i >= 0; i-- {
				v := (*fieldValue)[i]

				c, tlv, err := serializeValue(&v, template, enc, state)
				if err != nil {
					return 0, nil, err
				}
				count += c
				if tlv != nil {
					tlvList = append(tlvList, tlv)
				}
			}
		}
	case *[][]byte:
		if fieldValue != nil {
			for i := len(*fieldValue) - 1; i >= 0; i-- {
				v := (*fieldValue)[i]

				c, tlv, err := serializeValue(&v, template, enc, state)
				if err != nil {
					return 0, nil, err
				}
				count += c
				if tlv != nil {
					tlvList = append(tlvList, tlv)
				}
			}
		}

	case *[]*uintptr:
		if fieldValue != nil {
			for i := len(*fieldValue) - 1; i >= 0; i-- {
				v := (*fieldValue)[i]

				c, tlv, err := serializeValue(v, template, enc, state)
				if err != nil {
					return 0, nil, err
				}
				count += c
				if tlv != nil {
					tlvList = append(tlvList, tlv)
				}
			}
		}

	default:
		return 0, nil, errors.New(errors.KsiInvalidFormatError).
			AppendMessage("Unknown type given for serialization!").
			AppendMessage("Can only be pointer to slice, value of uint64, utf8 string or binary array.").
			AppendMessage(fmt.Sprintf("Value is: %v.", value))
	}

	return count, tlvList, nil
}
