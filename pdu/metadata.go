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
	"strconv"
	"strings"

	"github.com/guardtime/goksi/errors"
	"github.com/guardtime/goksi/templates"
	"github.com/guardtime/goksi/tlv"
)

// NewMetaData returns a new metadata instance. Additional value can be applied via optionals.
func NewMetaData(clientID string, optionals ...MetaDataOptional) (*MetaData, error) {
	tmp := metaData{obj: MetaData{
		clientID: &clientID,
	}}

	for _, setter := range optionals {
		if setter == nil {
			return nil, errors.New(errors.KsiInvalidArgumentError).AppendMessage("Provided option is nil.")
		}
		if err := setter(&tmp); err != nil {
			return nil, errors.KsiErr(err).AppendMessage("Unable to initialize metadata.")
		}
	}

	rawTlv, err := tmp.obj.EncodeToTlv()
	if err != nil {
		return nil, err
	}
	tmp.obj.rawTlv = rawTlv

	return &tmp.obj, nil
}

// MetaDataOptional is functional optional value setter.
type (
	MetaDataOptional func(*metaData) error

	metaData struct {
		obj MetaData
	}
)

// MetaDataMachineID is setter for the optional machine ID value.
func MetaDataMachineID(id string) MetaDataOptional {
	return func(m *metaData) error {
		if m == nil {
			return errors.New(errors.KsiInvalidArgumentError).AppendMessage("Missing metadata base object.")
		}
		m.obj.machineID = &id
		return nil
	}
}

// MetaDataSequenceNr is setter for the optional sequence number value.
func MetaDataSequenceNr(n uint64) MetaDataOptional {
	return func(m *metaData) error {
		if m == nil {
			return errors.New(errors.KsiInvalidArgumentError).AppendMessage("Missing metadata base object.")
		}
		m.obj.sequenceNr = &n
		return nil
	}
}

// MetaDataReqTime is setter for the optional request time value.
func MetaDataReqTime(t uint64) MetaDataOptional {
	return func(m *metaData) error {
		if m == nil {
			return errors.New(errors.KsiInvalidArgumentError).AppendMessage("Missing metadata base object.")
		}
		m.obj.reqTime = &t
		return nil
	}
}

// EncodeToTlv returns the metadata in TLV representation.
func (m *MetaData) EncodeToTlv() (*tlv.Tlv, error) {
	if m == nil {
		return nil, errors.New(errors.KsiInvalidArgumentError)
	}

	if m.rawTlv == nil {
		// Get template.
		pduTemplate, err := templates.Get("MetaData")
		if err != nil {
			return nil, err
		}
		// Get TLV from template.
		pduTlv, err := tlv.NewTlv(tlv.ConstructFromObject(m, pduTemplate))
		if err != nil {
			return nil, err
		}

		// Update padding.
		if len(pduTlv.Value())%2 == 0 {
			m.padding = &[]byte{0x01, 0x01}
		} else {
			m.padding = &[]byte{0x01}
		}

		// Construct new tlv with the updated padding element.
		return tlv.NewTlv(tlv.ConstructFromObject(m, pduTemplate))
	}
	return m.rawTlv, nil
}

// Encode returns the metadata in binary TLV representation.
func (m *MetaData) Encode() ([]byte, error) {
	if m == nil {
		return nil, errors.New(errors.KsiInvalidArgumentError)
	}

	mTlv, err := m.EncodeToTlv()
	if err != nil {
		return nil, err
	}

	return mTlv.Raw, nil
}

// ClientID returns a (human-readable) textual representation of client identity, or nil if not present.
func (m *MetaData) ClientID() (string, error) {
	if m == nil || m.clientID == nil {
		return "", errors.New(errors.KsiInvalidArgumentError)
	}
	return *m.clientID, nil
}

// MachineID returns a (human-readable) identifier of the machine that requested the link structure.
// If not present, an empty string is returned.
func (m *MetaData) MachineID() (string, error) {
	if m == nil {
		return "", errors.New(errors.KsiInvalidArgumentError)
	}
	if m.machineID == nil {
		return "", nil
	}
	return *m.machineID, nil
}

// SequenceNr returns a local sequence number of a request assigned by the machine that created the link.
// If not present, 0 is returned.
func (m *MetaData) SequenceNr() (uint64, error) {
	if m == nil {
		return 0, errors.New(errors.KsiInvalidArgumentError)
	}
	if m.sequenceNr == nil {
		return 0, nil
	}
	return *m.sequenceNr, nil
}

// ReqTime returns the time when the server received the request from the client.
// If not present, 0 is returned.
func (m *MetaData) ReqTime() (uint64, error) {
	if m == nil {
		return 0, errors.New(errors.KsiInvalidArgumentError)
	}
	if m.reqTime == nil {
		return 0, nil
	}
	return *m.reqTime, nil
}

// HasPadding returns true in case the metadata structure contains padding bytes, otherwise false.
func (m *MetaData) HasPadding() bool {
	if m == nil {
		return false
	}
	return m.padding != nil
}

// FromTlv implements tlv.(TlvObj) interface.
func (m *MetaData) FromTlv(objTlv *tlv.Tlv) error {
	if m == nil || objTlv == nil {
		return errors.New(errors.KsiInvalidArgumentError)
	}

	metadataTemplate, err := templates.Get("MetaData")
	if err != nil {
		return err
	}

	err = objTlv.ToObject(m, metadataTemplate, nil)
	if err != nil {
		return err
	}

	m.rawTlv = objTlv
	return nil
}

// ToTlv implements tlv.(TlvObj) interface.
func (m *MetaData) ToTlv(enc *tlv.Encoder) (*tlv.Tlv, error) {
	if m == nil {
		return nil, errors.New(errors.KsiInvalidArgumentError)
	}

	if m.rawTlv == nil {
		return nil, errors.New(errors.KsiInvalidStateError).AppendMessage("Missing metadata base TLV element!")
	}

	// Copy entire TLV into the buffer.
	_, err := enc.PrependBinary(m.rawTlv.Raw)
	if err != nil {
		return nil, err
	}

	metadataTemplate, err := templates.Get("MetaData")
	if err != nil {
		return nil, err
	}

	// Create a TLV object on the same slice.
	tlv, err := tlv.NewTlv(tlv.ConstructFromSlice(enc.Bytes()))
	if err != nil {
		return nil, err
	}

	if err := tlv.ParseNested(metadataTemplate); err != nil {
		return nil, err
	}
	return tlv, nil
}

func (m *MetaData) String() string {
	if m == nil {
		return ""
	}

	var b strings.Builder
	b.WriteString("Client ID: ")
	if m.clientID != nil {
		b.WriteString(*m.clientID)
	} else {
		b.WriteString("<INVALID>")
	}
	if m.machineID != nil {
		b.WriteString("; Machine ID: ")
		b.WriteString(*m.machineID)
	}
	if m.sequenceNr != nil {
		b.WriteString("; Sequence nr: ")
		b.WriteString(strconv.FormatUint(*m.sequenceNr, 10))
	}
	if m.reqTime != nil {
		b.WriteString("; Request time: ")
		b.WriteString(strconv.FormatUint(*m.reqTime, 10))
	}
	return b.String()
}
