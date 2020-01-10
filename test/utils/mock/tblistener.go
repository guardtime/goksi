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

package mock

import (
	"fmt"
	"strings"

	"github.com/guardtime/goksi/hash"
)

type (
	TreeBuilderListenerMock struct {
		Entries []TBLMEntry
	}
	TBLMEntry struct {
		ValType TBLMEntryType
		Value   []byte
		Level   byte
	}
	TBLMEntryType byte
)

func (e *TBLMEntry) Equals(x *TBLMEntry) bool {
	return !(e == nil || x == nil) &&
		(e == x || e.ValType == x.ValType &&
			hash.Equal(e.Value, x.Value) &&
			e.Level == x.Level)
}

const (
	TBLMDocumentHash TBLMEntryType = iota
	TBLMMetadataRec
	TBLMIntAggrHash
)

func (et TBLMEntryType) String() string {
	switch et {
	case TBLMDocumentHash:
		return "DH"
	case TBLMMetadataRec:
		return "MD"
	case TBLMIntAggrHash:
		return "AH"
	}
	return "??"
}

func (m *TreeBuilderListenerMock) TreeRecordHash(hsh hash.Imprint, lvl byte) error {
	m.Entries = append(m.Entries, TBLMEntry{TBLMDocumentHash, hsh, lvl})
	return nil
}

func (m *TreeBuilderListenerMock) TreeMetadata(tlv []byte) error {
	m.Entries = append(m.Entries, TBLMEntry{TBLMMetadataRec, tlv, 0})
	return nil
}

func (m *TreeBuilderListenerMock) TreeAggregateHash(hsh hash.Imprint, lvl byte) error {
	m.Entries = append(m.Entries, TBLMEntry{TBLMIntAggrHash, hsh, lvl})
	return nil
}

func (m *TreeBuilderListenerMock) String() string {
	var b strings.Builder
	for i, e := range m.Entries {
		b.WriteString(fmt.Sprintf("[%d] t=%s :: %x @ %d\n", i, e.ValType, e.Value, e.Level))
	}
	return b.String()
}
