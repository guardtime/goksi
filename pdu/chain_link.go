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
	"github.com/guardtime/goksi/hash"
	"github.com/guardtime/goksi/templates"
	"github.com/guardtime/goksi/tlv"
)

// IsLeft returns the orientation of the chain link.
func (l *ChainLink) IsLeft() (bool, error) {
	if l == nil {
		return false, errors.New(errors.KsiInvalidArgumentError)
	}
	return l.isLeft, nil
}

// SiblingHash returns the sibling link hash value, or nil if not present.
// See also (ChainLink).MetaData
func (l *ChainLink) SiblingHash() (hash.Imprint, error) {
	if l == nil {
		return nil, errors.New(errors.KsiInvalidArgumentError)
	}
	if l.isCalendar {
		if l.siblingHash == nil {
			return nil, errors.New(errors.KsiInvalidStateError).AppendMessage("Inconsistent calendar chain link.")
		}
	} else {
		if l.siblingHash == nil {
			return nil, nil
		}
	}
	return *l.siblingHash, nil
}

// LevelCorrection returns chain link level correction value.
func (l *ChainLink) LevelCorrection() (uint64, error) {
	if l == nil {
		return 0, errors.New(errors.KsiInvalidArgumentError)
	}
	if l.isCalendar {
		return 0, errors.New(errors.KsiInvalidStateError).
			AppendMessage("Calendar chain link does not have level correction value.")
	}

	if l.levelCorr == nil {
		return 0, nil
	}
	return *l.levelCorr, nil
}

// LegacyID returns legacy ID value, or nil if not present.
func (l *ChainLink) LegacyID() (*LegacyID, error) {
	if l == nil {
		return nil, errors.New(errors.KsiInvalidArgumentError)
	}
	if l.isCalendar {
		return nil, errors.New(errors.KsiInvalidStateError).
			AppendMessage("Calendar chain link does not have legacy id value.")
	}
	return l.legacyID, nil
}

// MetaData returns the metadata value, or nil if not present.
// See also (ChainLink).SiblingHash
func (l *ChainLink) MetaData() (*MetaData, error) {
	if l == nil {
		return nil, errors.New(errors.KsiInvalidArgumentError)
	}
	if l.isCalendar {
		return nil, errors.New(errors.KsiInvalidStateError).
			AppendMessage("Calendar chain link does not have legacy id value.")
	}
	return l.metadata, nil
}

// Identity return link identity, or nil if not present.
func (l *ChainLink) Identity() (*HashChainLinkIdentity, error) {
	if l == nil || l.isCalendar {
		return nil, errors.New(errors.KsiInvalidArgumentError)
	}

	var id *HashChainLinkIdentity
	if l.legacyID != nil {
		id = &HashChainLinkIdentity{
			idType: IdentityTypeLegacyID,
		}

		str, err := l.legacyID.ClientID()
		if err != nil {
			return nil, err
		}
		id.clientID = str
	} else if l.metadata != nil {
		id = &HashChainLinkIdentity{
			idType: IdentityTypeMetadata,
		}

		// Client ID is mandatory element.
		if l.metadata.clientID == nil {
			return nil, errors.New(errors.KsiInvalidStateError).AppendMessage("Metadata client id is missing.")
		}
		id.clientID = *l.metadata.clientID
		if l.metadata.machineID != nil {
			id.machineID = *l.metadata.machineID
		}
		if l.metadata.sequenceNr != nil {
			id.sequenceNr = *l.metadata.sequenceNr
		}
		if l.metadata.reqTime != nil {
			id.requestTime = *l.metadata.reqTime
		}
	}
	return id, nil
}

// String implement Stringer interface.
// Returns an empty string in case of an error.
func (l *ChainLink) String() string {
	if l == nil {
		return ""
	}
	var b strings.Builder
	b.WriteString("Link: ")
	if l.isLeft {
		b.WriteString("L, ")
	} else {
		b.WriteString("R, ")
	}
	if l.levelCorr != nil {
		b.WriteString("LevelCorr: ")
		b.WriteString(strconv.FormatUint(*l.levelCorr, 10))
		b.WriteString(", ")
	}
	if l.siblingHash != nil {
		b.WriteString("Algorithm: ")
		b.WriteString(hash.Imprint(*l.siblingHash).String())
	} else {
		if id, err := l.Identity(); err == nil {
			b.WriteString("Identity: ")
			b.WriteString(id.String())
		}
	}
	return b.String()
}

// FromTlv populates the receiver chain link with the data from TLV.
func (l *ChainLink) FromTlv(objTlv *tlv.Tlv) error {
	if l == nil || objTlv == nil {
		return errors.New(errors.KsiInvalidArgumentError)
	}

	l.isCalendar = len(objTlv.Nested) == 0
	l.isLeft = objTlv.Tag == 0x07
	if l.isCalendar {
		hsh, err := objTlv.Imprint()
		if err != nil {
			return err
		}
		l.siblingHash = newImprint(hsh)
	} else {
		pduTemplate, err := templates.Get("ChainLink")
		if err != nil {
			return err
		}

		// There is no need to re-parse the TLV, as nstd+tlvobj type is used.
		if err = objTlv.ToObject(l, pduTemplate, nil); err != nil {
			return err
		}
	}
	return nil
}

// ToTlv returns a TLV object constructed based on the receiver link data.
func (l *ChainLink) ToTlv(enc *tlv.Encoder) (*tlv.Tlv, error) {
	if l == nil {
		return nil, errors.New(errors.KsiInvalidArgumentError)
	}

	var tmp *tlv.Tlv
	if !l.isCalendar {
		// Create new Nested TLV template with specified TLV tag.
		templateName := "ChainLinkR"
		if l.isLeft {
			templateName = "ChainLinkL"
		}

		pduTemplate, err := templates.Get(templateName)
		if err != nil {
			return nil, err
		}

		if tmp, err = tlv.NewTlv(tlv.ConstructFromObject(l, pduTemplate)); err != nil {
			return nil, err
		}

		// Copy entire TLV into the buffer.
		if _, err = enc.PrependBinary(tmp.Raw); err != nil {
			return nil, err
		}
	} else {
		// Resolve the expected TLV tag.
		tag := uint16(0x08)
		if l.isLeft {
			tag = 0x07
		}

		// Serialize imprint.
		c, err := enc.PrependBinary(*l.siblingHash)
		if err != nil {
			return nil, err
		}
		count := c

		// Serialize TLV header.
		if _, err := enc.PrependHeader(tag, false, false, count); err != nil {
			return nil, err
		}

		// Create a TLV object on the same slice.
		if tmp, err = tlv.NewTlv(tlv.ConstructFromSlice(enc.Bytes())); err != nil {
			return nil, err
		}
	}

	return tmp, nil
}

// ChainLinkList is alias for '[]*ChainLink'.
type ChainLinkList []*ChainLink

// String implements Stringer interface.
// Returns an empty string in case of an error.
func (l ChainLinkList) String() string {
	if l == nil {
		return ""
	}
	var b strings.Builder
	b.WriteString("Aggregation hash chain:\n")
	for _, link := range l {
		b.WriteString(link.String())
		b.WriteString("\n")
	}
	return b.String()
}

// aggregateChain aggregates the hash chain and returns the result hash and tree height.
func (l ChainLinkList) aggregateChain(isCalendar bool, algorithm hash.Algorithm,
	inputHash hash.Imprint, startLevel byte) (hash.Imprint, byte, error) {

	// If calculating the calendar chain, initialize the hash algorithm ID using the input hash.
	if isCalendar {
		algorithm = inputHash.Algorithm()
		if algorithm == hash.SHA_NA {
			return nil, 0, errors.New(errors.KsiUnknownHashAlgorithm)
		}
	}

	var hsr *hash.DataHasher
	var hsh hash.Imprint
	var err error
	level := uint64(startLevel)
	for _, link := range l {
		if isCalendar {
			// Update the hash algo ID when encountering a left link.
			if link.isLeft {
				if link.siblingHash == nil {
					return nil, 0, errors.New(errors.KsiInvalidStateError).
						AppendMessage("Calendar hash chain link missing hash.")
				}
				siblingAlg := (*link.siblingHash).Algorithm()
				if algorithm != siblingAlg {
					algorithm = siblingAlg
					hsr = nil
				}
			}
		} else {
			var linkLvlCorr uint64
			if link.levelCorr != nil {
				linkLvlCorr = *link.levelCorr
			}
			if linkLvlCorr > 0xff || linkLvlCorr+level+1 > 0xff {
				return nil, 0, errors.New(errors.KsiInvalidFormatError).
					AppendMessage("Aggregation chain level out of range.")
			}
			level += linkLvlCorr + 1
		}

		if level > 0xff {
			return nil, 0, errors.New(errors.KsiInvalidFormatError).
				AppendMessage("Aggregation chain length exceeds 0xff.")
		}

		if hsr == nil {
			if hsr, err = algorithm.New(); err != nil {
				return nil, 0, err
			}
		} else {
			hsr.Reset()
		}

		if link.isLeft {
			if err := hasherWriteNvlImprint(hsr, hsh, inputHash); err != nil {
				return nil, 0, err
			}
			if err := hasherWriteLinkImprint(hsr, link); err != nil {
				return nil, 0, err
			}
		} else {
			if err := hasherWriteLinkImprint(hsr, link); err != nil {
				return nil, 0, err
			}
			if err := hasherWriteNvlImprint(hsr, hsh, inputHash); err != nil {
				return nil, 0, err
			}
		}

		if _, err := hsr.Write([]byte{byte(level)}); err != nil {
			return nil, 0, err
		}

		if hsh, err = hsr.Imprint(); err != nil {
			return nil, 0, err
		}
	}
	return hsh, byte(level), nil
}

func hasherWriteNvlImprint(hsr *hash.DataHasher, first, second hash.Imprint) error {
	if hsr == nil {
		return errors.New(errors.KsiInvalidArgumentError)
	}

	tmp := first
	if len(tmp) == 0 {
		if len(second) == 0 {
			return errors.New(errors.KsiInvalidStateError).AppendMessage("NVL second value is nil.")
		}
		tmp = second
	}
	_, err := hsr.Write(tmp)
	return err
}

func hasherWriteLinkImprint(hsr *hash.DataHasher, link *ChainLink) error {
	if hsr == nil {
		return errors.New(errors.KsiInvalidArgumentError)
	}

	// Sibling data must consist of one, and only one, of the following fields:
	var elements byte
	if link.siblingHash != nil {
		elements |= 0x01
	}
	if link.legacyID != nil {
		elements |= 0x02
	}
	if link.metadata != nil {
		elements |= 0x04
	}

	var (
		tmp []byte
		err error
	)
	switch elements {
	case 0x01:
		tmp = *link.siblingHash
	case 0x02:
		if tmp, err = link.legacyID.Bytes(); err != nil {
			return err
		}
	case 0x04:
		if link.metadata.rawTlv == nil {
			return errors.New(errors.KsiNotImplemented).AppendMessage("Serialization of metadata is not implemented.")
		}
		tmp = link.metadata.rawTlv.Value()
	default:
		return errors.New(errors.KsiInvalidFormatError).AppendMessage("Sibling data must consist of only one value")
	}
	_, err = hsr.Write(tmp)
	return err
}
