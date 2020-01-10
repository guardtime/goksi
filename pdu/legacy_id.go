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
	"encoding/hex"

	"github.com/guardtime/goksi/errors"
	"github.com/guardtime/goksi/log"
	"github.com/guardtime/goksi/tlv"
)

// ClientID returns string representation of the legacy ID octet string.
func (l *LegacyID) ClientID() (string, error) {
	if l == nil {
		return "", errors.New(errors.KsiInvalidArgumentError)
	}
	return l.str, nil
}

const (
	legacyIDHeaderHigh byte = iota
	legacyIDHeaderLow
	legacyIDStrLen
	legacyIDStr
)

const (
	legacyIDRawLen  = 29
	legacyIDHdrHigh = 0x03
	legacyIDHdrLow  = 0x00
)

// Bytes returns raw structure.
//  +------+------+---------+------------------+------------------+
//  |    Header   |  StrLen |    UTF8 string   |      Padding     |
//  +------+------+---------+------------------+------------------+
//  | 0x03 | 0x00 |    x    |        ...       |0x00{1..25-StrLen}|
//  +------+------+---------+------------------+------------------+
// For example, the name 'Test' is encoded as the sequence:
//  03 00 04 54=T 65=e 73=s 74=t 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
//  (all octet values in the example are given in hexadecimal).
func (l *LegacyID) Bytes() ([]byte, error) {
	if l == nil {
		return nil, errors.New(errors.KsiInvalidArgumentError)
	}
	if l.rawTlv == nil {
		return nil, errors.New(errors.KsiInvalidStateError).AppendMessage("Missing legacy ID base TLV element.")
	}
	return l.rawTlv.Value(), nil
}

// FromTlv implements tlv.(TlvObj) interface.
func (l *LegacyID) FromTlv(objTlv *tlv.Tlv) error {
	if l == nil || objTlv == nil {
		return errors.New(errors.KsiInvalidArgumentError)
	}

	var (
		value  = objTlv.Value()
		valLen = len(value)
	)
	// Verify length.
	if valLen != legacyIDRawLen {
		log.Debug("Legacy ID data length mismatch: ", hex.EncodeToString(objTlv.Raw))
		return errors.New(errors.KsiInvalidFormatError).AppendMessage("Legacy ID data length mismatch.")
	}
	// Verify header.
	if !(value[legacyIDHeaderHigh] == legacyIDHdrHigh && value[legacyIDHeaderLow] == legacyIDHdrLow) {
		log.Debug("Legacy ID header mismatch: ", hex.EncodeToString(objTlv.Raw))
		return errors.New(errors.KsiInvalidFormatError).AppendMessage("Legacy ID header mismatch.")
	}
	// Verify string length (at most 25 octets).
	if value[legacyIDStrLen] > 25 {
		log.Debug("Legacy ID string length mismatch: ", hex.EncodeToString(objTlv.Raw))
		return errors.New(errors.KsiInvalidFormatError).AppendMessage("Legacy ID string length mismatch.")
	}
	// Verify padding.
	for i := value[legacyIDStrLen] + legacyIDStr; i < byte(valLen); i++ {
		if value[i] != 0 {
			log.Debug("Legacy ID padding mismatch: ", hex.EncodeToString(objTlv.Raw))
			return errors.New(errors.KsiInvalidFormatError).AppendMessage("Legacy ID padding mismatch.")
		}
	}
	l.str = string(value[legacyIDStr:(legacyIDStr + value[legacyIDStrLen])])
	l.rawTlv = objTlv
	return nil
}

// ToTlv implements tlv.(TlvObj) interface.
func (l *LegacyID) ToTlv(enc *tlv.Encoder) (*tlv.Tlv, error) {
	if l == nil {
		return nil, errors.New(errors.KsiInvalidArgumentError)
	}

	if l.rawTlv == nil {
		return nil, errors.New(errors.KsiInvalidStateError).AppendMessage("Missing legacy ID base TLV element.")
	}

	// Copy entire TLV into the buffer.
	_, err := enc.PrependBinary(l.rawTlv.Raw)
	if err != nil {
		return nil, err
	}

	// Create a TLV object on the same slice.
	return tlv.NewTlv(tlv.ConstructFromSlice(enc.Bytes()))
}
