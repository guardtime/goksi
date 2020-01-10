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

package main

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"

	"github.com/guardtime/goksi/hash"
	"github.com/guardtime/goksi/signature"
)

type (
	BlockSerializer struct {
		Info      BlockInfo   `json:"info"`
		Values    []HashValue `json:"values"`
		Signature string      `json:"signature"`
	}
	BlockInfo struct {
		Algorithm string `json:"algorithm"`
		IV        string `json:"iv"`
		LastHash  string `json:"last"`
	}
	HashValue struct {
		ValType ValueType `json:"type"`
		Value   string    `json:"value"`
		Level   int       `json:"level,omitempty"`
	}
	ValueType string
)

const (
	ValueIsRecordHash    = "RecordHash"
	ValueIsMetadata      = "MetaData"
	ValueIsAggregateHash = "AggregateHash"
)

// TreeRecordHash implements RecordHashListener interface.
func (b *BlockSerializer) TreeRecordHash(hsh hash.Imprint, lvl byte) error {
	if b == nil || !hsh.IsValid() {
		return errors.New("invalid input parameters")
	}

	b.Values = append(b.Values, HashValue{ValueIsRecordHash, hex.EncodeToString(hsh), int(lvl)})
	return nil
}

// TreeMetadata implements MetadataListener interface.
func (b *BlockSerializer) TreeMetadata(tlv []byte) error {
	if b == nil || tlv == nil {
		return errors.New("invalid input parameters")
	}

	b.Values = append(b.Values, HashValue{ValueIsMetadata, hex.EncodeToString(tlv), 0})
	return nil
}

// TreeAggregateHash implements AggregateHashListener interface.
func (b *BlockSerializer) TreeAggregateHash(hsh hash.Imprint, level byte) error {
	if b == nil || !hsh.IsValid() {
		return errors.New("invalid input parameters")
	}

	b.Values = append(b.Values, HashValue{ValueIsAggregateHash, hex.EncodeToString(hsh), 0})
	return nil
}

// SetRootSignature applies the root signature for the block.
func (b *BlockSerializer) SetRootSignature(ksig *signature.Signature) error {
	if b == nil || ksig == nil {
		return errors.New("invalid input parameters")
	}

	raw, err := ksig.Serialize()
	if err != nil {
		return err
	}
	b.Signature = hex.EncodeToString(raw)
	return nil
}

// SetHashAlgorithm updates block info hash algorithm value.
func (b *BlockSerializer) SetHashAlgorithm(alg hash.Algorithm) error {
	if b == nil {
		return errors.New("invalid input parameters")
	}

	b.Info.Algorithm = alg.String()
	return nil
}

// SetIV updates block info initialization vector value.
func (b *BlockSerializer) SetIV(iv []byte) error {
	if b == nil {
		return errors.New("invalid input parameters")
	}

	b.Info.IV = hex.EncodeToString(iv)
	return nil
}

// SetLastHash updates block info previous block last hash value.
func (b *BlockSerializer) SetLastHash(hsh hash.Imprint) error {
	if b == nil || !hsh.IsValid() {
		return errors.New("invalid input parameters")
	}

	b.Info.LastHash = hex.EncodeToString(hsh)
	return nil
}

func (b *BlockSerializer) SaveToFile(path string) error {
	if b == nil || path == "" {
		return errors.New("invalid input parameters")
	}

	jsonStr, err := json.MarshalIndent(b, "", "  ")
	if err != nil {
		return errors.New(fmt.Sprintf("Failed to encode to JSON:\n%s\n", err))
	}

	jsonFile, err := os.Create(path)
	if err != nil {
		return errors.New(fmt.Sprintf("Failed to create signature file:\n%s\n", err))
	}
	defer func() { _ = jsonFile.Close() }()

	if _, err := jsonFile.Write(jsonStr); err != nil {
		return errors.New(fmt.Sprintf("Failed to write JSON to file:\n%s\n", err))
	}
	return nil
}
