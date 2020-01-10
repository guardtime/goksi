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
	"path/filepath"

	"github.com/guardtime/goksi/errors"
	"github.com/guardtime/goksi/hash"
)

var (
	testRoot        = filepath.Join("..", "test")
	testLogDir      = filepath.Join(testRoot, "out")
	testResourceDir = filepath.Join(testRoot, "resource")
	testTlvDir      = filepath.Join(testResourceDir, "tlv")
)

func buildTestAggrChain() (*AggregationChain, error) {
	builder, err := NewAggregationChainBuilder(BuildFromImprint(hash.Default, hash.Default.ZeroImprint()))
	if err != nil {
		return nil, errors.KsiErr(err).AppendMessage("Failed to create aggregation hash chain builder.")
	}

	md, err := NewMetaData("ClientID", MetaDataMachineID("Machine ID"), MetaDataReqTime(123456), MetaDataSequenceNr(123))
	if err != nil {
		return nil, errors.KsiErr(err).AppendMessage("Failed to create metadata.")
	}
	if err = builder.AddChainLink(true, 2, LinkSiblingMetaData(md)); err != nil {
		return nil, errors.KsiErr(err).AppendMessage("Failed while adding the metadata as left link to the aggregation hash chain builder.")
	}

	if err = builder.AddChainLink(false, 2, LinkSiblingHash(hash.Default.ZeroImprint())); err != nil {
		return nil, errors.KsiErr(err).AppendMessage("Failed while adding the right link to the aggregation hash chain builder.")
	}

	chain, err := builder.Build()
	if err != nil {
		return nil, errors.KsiErr(err).AppendMessage("Failed to build the aggregation hash chain builder.")
	}

	return chain, nil
}
