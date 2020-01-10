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

package pdu

import (
	"reflect"

	"github.com/guardtime/goksi/errors"
	"github.com/guardtime/goksi/hash"
	"github.com/guardtime/goksi/templates"
	"github.com/guardtime/goksi/tlv"
)

func newUint64(v uint64) *uint64 {
	return &v
}

func newImprint(v hash.Imprint) *hash.Imprint {
	return &v
}

func clonePDU(o interface{}) (interface{}, error) {
	if o == nil {
		return nil, errors.New(errors.KsiInvalidArgumentError)
	}

	t := reflect.TypeOf(o)
	if t.Kind() != reflect.Ptr {
		return nil, errors.New(errors.KsiInvalidFormatError).AppendMessage("Provided object is not a pointer.")
	}

	// Get template.
	pduTemplate, err := templates.Get(t.Elem().Name())
	if err != nil {
		return nil, err
	}

	// Get TLV from template.
	pduTlv, err := tlv.NewTlv(tlv.ConstructFromObject(o, pduTemplate))
	if err != nil {
		return nil, err
	}

	clone := reflect.New(t.Elem())
	if err = pduTlv.ToObject(clone.Interface(), pduTemplate, nil); err != nil {
		return nil, err
	}

	return clone.Interface(), nil
}
