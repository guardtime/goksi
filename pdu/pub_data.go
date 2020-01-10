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
	"bytes"
	"encoding/base32"
	"encoding/hex"
	"fmt"
	"hash/crc32"
	"strconv"
	"strings"
	"time"

	"github.com/guardtime/goksi/errors"
	"github.com/guardtime/goksi/hash"
	"github.com/guardtime/goksi/log"
	"github.com/guardtime/goksi/templates"
	"github.com/guardtime/goksi/tlv"
)

// PublicationDataBuilder is the concrete publication data constructor.
type (
	PublicationDataBuilder func(*publicationData) error
	publicationData        struct {
		obj PublicationData
	}
)

// NewPublicationData returns a new publication data instance. Use the builder parameter for providing an initializer.
func NewPublicationData(builder PublicationDataBuilder) (*PublicationData, error) {
	if builder == nil {
		return nil, errors.New(errors.KsiInvalidArgumentError)
	}

	var tmp publicationData
	if err := builder(&tmp); err != nil {
		return nil, err
	}
	return &tmp.obj, nil
}

// PubDataFromString returns a builder for constructing publication data from publication string.
//
// A publication string represents the fields of the published data structure, formatted in a way suitable for printed
// media and manual entry into a verification tool. The representation is limited to letters and numbers and embeds a
// checksum to detect typing errors. The publication string is constructed as follows:
//  1. The publication data is assembled as a concatenation of
//     - publication time, represented as a 64-bit unsigned integer, with the bits ordered from the most significant to
//       the least significant. Note that the publication string is not a TLV structure and, in contrast with the TLV
//       encoding rules, the leading zeros are preserved in this encoding to ensure consistent length of the publication
//       strings.
//     - publication imprint, consisting of the one-byte identifier of the hash algorithm and the hash value itself.
//  2. The CRC-32 checksum of the publication data is computed and appended to the data.
//  3. The resulting octet sequence is represented in base32 and optionally broken into groups of 6 or 8 characters
//     by dashes.
//
// For example, the encoding of a publication string for 2009-02-15T00:00:00Z:
//
//  Raw data:
//  1.1 8-byte integer 1234656000, the POSIX time value for 2009-02-15 00:00:00
//      00 00 00 00 49 97 5B 00
//  1.2 Imprint of the root hash value, the first 01 identifies the hash algorithm as SHA2-256
//      01 EE 1F BC 8F D3 FD 78 FD 11 B9 E2 67 DF 9A F2 36 11 B1 C5 BE 44 F0 20 AB 8B 14 19 C9 36 72 C4 D6
//  2.  4-byte CRC-32 checksum of the preceding bytes
//      EE 57 DB C6
//  3.  In base32 encoded printable form:
//      AAAAAA-CJS5NQ-AAPOD6-6I7U75-PD6RDO-PCM7PZV4RWCG-Y4LPSE-6AQKXC-YUDHET-M4WE23-XFPW6G
func PubDataFromString(s string) PublicationDataBuilder {
	return func(p *publicationData) error {
		log.Debug("String: ", s)
		if len(s) == 0 {
			return errors.New(errors.KsiInvalidArgumentError)
		}
		if p == nil {
			return errors.New(errors.KsiInvalidArgumentError).AppendMessage("Missing publication data base object.")
		}

		s = strings.Replace(s, "-", "", -1)

		// Decode the base32 string into binary.
		raw, err := base32.StdEncoding.DecodeString(s)
		if err != nil {
			return errors.New(errors.KsiInvalidFormatError).SetExtError(err).
				AppendMessage(fmt.Sprintf("Unable to decode base32 string: '%s'", s))
		}

		if err := p.obj.encode(raw); err != nil {
			return err
		}
		log.Debug("Pub data:", p)
		return nil
	}
}

// PubDataFromImprint returns an initializer for constructing publication data from published data, where h is the
// output hash of the calendar hash chain at time t.
func PubDataFromImprint(t time.Time, h hash.Imprint) PublicationDataBuilder {
	return func(p *publicationData) error {
		if t.IsZero() || !h.IsValid() {
			return errors.New(errors.KsiInvalidArgumentError)
		}
		if p == nil {
			return errors.New(errors.KsiInvalidArgumentError).AppendMessage("Missing publication data base object.")
		}

		p.obj.pubTime = newUint64(uint64(t.Unix()))
		p.obj.pubHash = newImprint(append(hash.Imprint(nil), h...))

		log.Debug(p)
		return nil
	}
}

// encode de-serializes the publication string raw data.
func (p *PublicationData) encode(raw []byte) error {
	if p == nil || len(raw) == 0 {
		return errors.New(errors.KsiInvalidArgumentError)
	}
	if len(raw) < 13 {
		return errors.New(errors.KsiInvalidFormatError).
			AppendMessage(fmt.Sprintf("Publication data inconsistent length: %s", hex.EncodeToString(raw)))
	}
	if uint64(crc32.ChecksumIEEE(raw[:len(raw)-4])) != bytesToUint64(raw[len(raw)-4:]) {
		return errors.New(errors.KsiInvalidFormatError).AppendMessage("CRC mismatch.")
	}
	alg := hash.Algorithm(raw[8])
	if !alg.Defined() {
		return errors.New(errors.KsiUnknownHashAlgorithm).
			AppendMessage(fmt.Sprintf("Publication data contains unknown hash algorithm: %x", alg))
	}
	if len(raw) != 8+1+alg.Size()+4 {
		return errors.New(errors.KsiInvalidFormatError).AppendMessage("Algorithm algorithm length mismatch.")
	}

	p.pubTime = newUint64(bytesToUint64(raw[:8]))
	p.pubHash = newImprint(append(hash.Imprint(nil), raw[8:8+1+alg.Size()]...))

	return nil
}

func bytesToUint64(s []byte) uint64 {
	var t uint64
	for _, b := range s {
		t <<= 8
		t |= uint64(b)
	}
	return t
}

// Base32 returns a publication string representing the fields of the published data structure, formatted in a way
// suitable for printed media and manual entry into a verification tool. The representation is limited to letters
// and numbers and embeds a checksum to detect typing errors.
func (p *PublicationData) Base32() (string, error) {
	if p == nil || p.pubTime == nil || p.pubHash == nil {
		return "", errors.New(errors.KsiInvalidArgumentError)
	}
	raw := make([]byte, 0, 8+1+(*p.pubHash).Algorithm().Size()+4)
	// Copy the publication time.
	for i := 7; i >= 0; i-- {
		raw = append(raw, byte(*p.pubTime>>uint64(8*i)))
	}
	// Copy publication hash.
	raw = append(raw, *p.pubHash...)
	// Calculate and copy CRC32 value.
	crc := crc32.ChecksumIEEE(raw)
	for i := 3; i >= 0; i-- {
		raw = append(raw, byte(crc>>uint32(8*i)))
	}
	return groupBase32(base32.StdEncoding.EncodeToString(raw), groupLimit), nil
}

const groupLimit = 6

func groupBase32(s string, l int) string {
	if l == 0 {
		return s
	}
	buf := []byte(s)
	chunks := make([][]byte, 0, len(buf)/l+1)
	for len(buf) >= l {
		var chunk []byte
		chunk, buf = buf[:l], buf[l:]
		chunks = append(chunks, chunk)
	}
	if len(buf) > 0 {
		chunks = append(chunks, buf[:])
	}
	return string(bytes.Join(chunks, []byte("-")))
}

// Equal reports whether p and u represent the same publication data instance.
func (p *PublicationData) Equal(u *PublicationData) bool {
	return (p != nil && u != nil) &&
		(p == u || (*p.pubTime == *u.pubTime && hash.Equal(*p.pubHash, *u.pubHash)))
}

// PublicationTime returns the publication time.
func (p *PublicationData) PublicationTime() (time.Time, error) {
	if p == nil {
		return time.Time{}, errors.New(errors.KsiInvalidArgumentError)
	}
	if p.pubTime == nil {
		return time.Time{}, errors.New(errors.KsiInvalidStateError).
			AppendMessage("Inconsistent publication data.").
			AppendMessage("Missing publication time.")
	}
	return time.Unix(int64(*p.pubTime), 0), nil
}

// PublishedHash returns published hash.
func (p *PublicationData) PublishedHash() (hash.Imprint, error) {
	if p == nil {
		return nil, errors.New(errors.KsiInvalidArgumentError)
	}
	if p.pubHash == nil {
		return nil, errors.New(errors.KsiInvalidStateError).
			AppendMessage("Inconsistent publication data.").
			AppendMessage("Missing publication hash.")
	}
	return *p.pubHash, nil
}

// Bytes returns the binary TLV structure.
func (p *PublicationData) Bytes() ([]byte, error) {
	if p == nil {
		return nil, errors.New(errors.KsiInvalidArgumentError)
	}

	if p.rawTlv == nil {
		template, err := templates.Get("PublicationData")
		if err != nil {
			return nil, err
		}

		p.rawTlv, err = tlv.NewTlv(tlv.ConstructFromObject(p, template))
		if err != nil {
			return nil, err
		}
	}
	return p.rawTlv.Raw, nil
}

// String implements fmt.(Stringer) interface.
func (p *PublicationData) String() string {
	if p == nil {
		return ""
	}
	var b strings.Builder
	if p.pubTime != nil {
		b.WriteString("Publication time: (")
		b.WriteString(strconv.FormatUint(*p.pubTime, 10))
		b.WriteString(") ")
		b.WriteString(time.Unix(int64(*p.pubTime), 0).String())
		b.WriteString("\n")
	}
	if p.pubHash != nil {
		b.WriteString("Published hash  : ")
		b.WriteString(hash.Imprint(*p.pubHash).String())
		b.WriteString("\n")
	}
	return b.String()
}
