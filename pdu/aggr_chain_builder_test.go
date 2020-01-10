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
	"testing"
	"time"

	"github.com/guardtime/goksi/errors"
	"github.com/guardtime/goksi/hash"
	"github.com/guardtime/goksi/log"
	"github.com/guardtime/goksi/test"
	"github.com/guardtime/goksi/test/utils"
)

func TestUnitAggrChainBuilder(t *testing.T) {

	logger, defFunc, err := test.InitLogger(t, testLogDir, log.DEBUG, t.Name())
	if err != nil {
		t.Fatal("Failed to initialize logger: ", err)
	}
	defer defFunc()
	// Apply logger.
	log.SetLogger(logger)

	test.Suite{
		{Func: testNilAggrChainBuilder},
		{Func: testInvalidAggrChainBuilderState},
		{Func: testCreateBuildWithInvalidInput},
		{Func: testAddLinkWithInvalidInput},
		{Func: testPrependChainIndexInvalidInput},
		{Func: testSetAggregationTimeInvalidInput},
		{Func: testLinkSiblingMetaDataNilInputs},
		{Func: testLinkSiblingHashNilInputs},
		{Func: testBuildHashChainOk},
		{Func: testAdjustLevelCorrectionInvalidInput},
		{Func: testAdjustLevelCorrectionWithZero},
		{Func: testAdjustLevelCorrectionAddSubSameVal},
		{Func: testAdjustLevelCorrectionAddAggrAtLvl},
		{Func: testAdjustLevelCorrectionSubAggrAtLvl},
		{Func: testAdjustLevelCorrectionChainLinksNil},
	}.Runner(t)
}

func testNilAggrChainBuilder(t *testing.T, _ ...interface{}) {
	var chainBuilder *AggregationChainBuilder

	if _, err := chainBuilder.Build(); err == nil {
		t.Fatal("Should not be possible to build with nil hash chain builder.")
	}

	if err := chainBuilder.AddChainLink(false, 0, LinkSiblingHash(hash.Default.ZeroImprint())); err == nil {
		t.Fatal("Should not be possible to add link to nil builder.")
	}
}

func testInvalidAggrChainBuilderState(t *testing.T, _ ...interface{}) {
	chainBuilder, err := NewAggregationChainBuilder(BuildFromImprint(hash.Default, hash.Default.ZeroImprint()))
	if err != nil {
		t.Fatal("Failed to create aggregation hash chain builder.")
	}

	if _, err = chainBuilder.Build(); err == nil {
		t.Fatal("Should not be possible to build with no links.")
	}
}

func testCreateBuildWithInvalidInput(t *testing.T, _ ...interface{}) {
	var (
		testData = []struct {
			alg    hash.Algorithm
			hsh    hash.Imprint
			errMsg string
		}{
			{hash.SHA3_384, hash.Default.ZeroImprint(),
				"Should not be possible to create builder with not implemented hash algorithm."},
			{hash.Default, nil,
				"Should not be possible to create builder with nil input hash.",
			},
			{hash.Default, utils.StringToBin("0109a9fe430803d8984273324cf462e40a875d483de6dd0d86bc6dff4d27c9"),
				"Should not be possible to create builder with invalid input hash.",
			},
			{hash.Default, utils.StringToBin("2209a9fe430803d8984273324cf462e40a875d483de6dd0d86bc6dff4d27c9d853"),
				"Should not be possible to create builder with unknown input hash.",
			},
		}
	)
	for _, data := range testData {
		if _, err := NewAggregationChainBuilder(BuildFromImprint(data.alg, data.hsh)); err == nil {
			t.Fatal(data.errMsg)
		}
	}
}

func testAddLinkWithInvalidInput(t *testing.T, _ ...interface{}) {
	chainBuilder, err := NewAggregationChainBuilder(BuildFromImprint(hash.Default, hash.Default.ZeroImprint()))
	if err != nil {
		t.Fatal("Failed to create aggregation hash chain builder.")
	}

	err = chainBuilder.AddChainLink(false, 0x1, nil)
	if err == nil {
		t.Fatal("Should not be possible to add link with nil sibling data.")
	}

	if err = chainBuilder.AddChainLink(false, 0x1, LinkSiblingHash(nil)); err == nil {
		t.Fatal("Should not be possible to add link with siblingData that returns error.")
	}
}

func testPrependChainIndexInvalidInput(t *testing.T, _ ...interface{}) {
	chainBuilder, err := NewAggregationChainBuilder(BuildFromImprint(hash.Default, hash.Default.ZeroImprint()))
	if err != nil {
		t.Fatal("Failed to create aggregation hash chain builder.")
	}

	if err = chainBuilder.PrependChainIndex(nil); err == nil {
		t.Fatal("Should not be possible to prepend nil index.")
	}
}

func testSetAggregationTimeInvalidInput(t *testing.T, _ ...interface{}) {
	chainBuilder, err := NewAggregationChainBuilder(BuildFromImprint(hash.Default, hash.Default.ZeroImprint()))
	if err != nil {
		t.Fatal("Failed to create aggregation hash chain builder.")
	}

	// January 1, year 1, 00:00:00 UTC.
	t1, err := time.Parse(
		time.RFC3339,
		"0001-01-01T00:00:00+00:00")
	if err != nil {
		t.Fatal("Failed to create time: ", err)
	}

	if err = chainBuilder.SetAggregationTime(t1); err == nil {
		t.Fatal("Should not be possible to set zero time.")
	}
}

func testLinkSiblingMetaDataNilInputs(t *testing.T, _ ...interface{}) {
	var (
		link chainLink
		md   MetaData
	)
	siblingData := LinkSiblingMetaData(nil)
	if err := siblingData(&link); err == nil {
		t.Fatal("Should not be possible to set nil metadata.")
	}

	siblingData = LinkSiblingMetaData(&md)
	if err := siblingData(nil); err == nil {
		t.Fatal("Should not be possible to set metadata to nil link.")
	}
}

func testLinkSiblingHashNilInputs(t *testing.T, _ ...interface{}) {
	var (
		link chainLink
	)
	siblingData := LinkSiblingHash(nil)
	if err := siblingData(&link); err == nil {
		t.Fatal("Should not be possible to set nil sibling hash.")
	}

	siblingData = LinkSiblingHash(hash.Default.ZeroImprint())
	if err := siblingData(nil); err == nil {
		t.Fatal("Should not be possible to set sibling hash to nil link.")
	}
}

func testBuildHashChainOk(t *testing.T, _ ...interface{}) {
	chain, err := buildTestAggrChain()
	if err != nil || chain == nil {
		t.Fatal("Failed to build aggregation hash chain: ", err)
	}
}

func testAdjustLevelCorrectionInvalidInput(t *testing.T, _ ...interface{}) {
	testChain, err := buildTestAggrChain()
	if err != nil {
		t.Fatal("Failed to build test aggregation hash chain: ", err)
	}
	b, err := NewAggregationChainBuilder(BuildFromAggregationChain(testChain))
	if err != nil {
		t.Fatal("Failed to construct aggregation chain builder.")
	}

	if err := b.AdjustLevelCorrection(nil, 0); err == nil {
		t.Fatal("Should not be possible to adjust level with nil level calculator.")
	}
	if err := b.AdjustLevelCorrection(LevelAdd, 0xfe); err == nil {
		t.Fatal("Should not be possible to adjust level to higher value than 0xff")
	}
	if err := b.AdjustLevelCorrection(LevelSubtract, 0xfe); err == nil {
		t.Fatal("Should not be possible to adjust level to value lower than 0.")
	}
}

func testAdjustLevelCorrectionWithZero(t *testing.T, _ ...interface{}) {
	testChain, err := buildTestAggrChain()
	if err != nil {
		t.Fatal("Failed to build test aggregation hash chain: ", err)
	}
	testLevel := *(*testChain.chainLinks)[0].levelCorr

	b, err := NewAggregationChainBuilder(BuildFromAggregationChain(testChain))
	if err != nil {
		t.Fatal("Failed to construct aggregation chain builder.")
	}

	for _, f := range []LevelCalculator{LevelSubtract, LevelAdd} {
		if err := b.AdjustLevelCorrection(f, 0); err != nil {
			t.Fatal("Failure during level adjustments with zero : ", err)
		}

		if testLevel != *(*b.aggrChain.chainLinks)[0].levelCorr {
			t.Fatal("Level correction value mismatch.")
		}
	}
}

func testAdjustLevelCorrectionAddSubSameVal(t *testing.T, _ ...interface{}) {
	testAdjustVal := byte(10)
	testChain, err := buildTestAggrChain()
	if err != nil {
		t.Fatal("Failed to build test aggregation hash chain: ", err)
	}
	testRootHsh, testRootLvl, err := testChain.Aggregate(0)
	if err != nil {
		t.Fatal("Failed to aggregate: ", err)
	}

	b, err := NewAggregationChainBuilder(BuildFromAggregationChain(testChain))
	if err != nil {
		t.Fatal("Failed to construct aggregation chain builder.")
	}

	if err := b.AdjustLevelCorrection(LevelAdd, testAdjustVal); err != nil {
		t.Fatal("Failed to add level correction: ", err)
	}
	if err := b.AdjustLevelCorrection(LevelSubtract, testAdjustVal); err != nil {
		t.Fatal("Failed to subtract level correction : ", err)
	}

	ac, err := b.Build()
	if err != nil {
		t.Fatal("Failed to build aggregation hash chain: ", err)
	}
	acRootHsh, acRootLvl, err := ac.Aggregate(0)
	if err != nil {
		t.Fatal("Failed aggregate: ", err)
	}

	if !hash.Equal(testRootHsh, acRootHsh) {
		t.Fatal("Root hash value mismatch.")
	}
	if testRootLvl != acRootLvl {
		t.Fatal("Level correction value mismatch.")
	}
}

func testAdjustLevelCorrectionAddAggrAtLvl(t *testing.T, _ ...interface{}) {
	testAdjustVal := byte(10)
	testChain, err := buildTestAggrChain()
	if err != nil {
		t.Fatal("Failed to build test aggregation hash chain: ", err)
	}
	testRootHsh, testRootLvl, err := testChain.Aggregate(testAdjustVal)
	if err != nil {
		t.Fatal("Failed to aggregate: ", err)
	}

	b, err := NewAggregationChainBuilder(BuildFromAggregationChain(testChain))
	if err != nil {
		t.Fatal("Failed to construct aggregation chain builder.")
	}

	if err := b.AdjustLevelCorrection(LevelAdd, testAdjustVal); err != nil {
		t.Fatal("Failed to adjust level correction: ", err)
	}

	ac, err := b.Build()
	if err != nil {
		t.Fatal("Failed to build aggregation hash chain: ", err)
	}
	acRootHsh, acRootLvl, err := ac.Aggregate(0)
	if err != nil {
		t.Fatal("Failed to aggregate: ", err)
	}

	if !hash.Equal(testRootHsh, acRootHsh) {
		t.Fatal("Root hash value mismatch.")
	}
	if testRootLvl != acRootLvl {
		t.Fatal("Root level value mismatch.")
	}
}

func testAdjustLevelCorrectionSubAggrAtLvl(t *testing.T, _ ...interface{}) {
	testAdjustVal := byte(2)
	testChain, err := buildTestAggrChain()
	if err != nil {
		t.Fatal("Failed to build test aggregation hash chain: ", err)
	}
	testRootHsh, testRootLvl, err := testChain.Aggregate(0)
	if err != nil {
		t.Fatal("Failed to aggregate: ", err)
	}

	b, err := NewAggregationChainBuilder(BuildFromAggregationChain(testChain))
	if err != nil {
		t.Fatal("Failed to construct aggregation chain builder.")
	}

	if err := b.AdjustLevelCorrection(LevelSubtract, testAdjustVal); err != nil {
		t.Fatal("Failed to adjust level correction: ", err)
	}

	ac, err := b.Build()
	if err != nil {
		t.Fatal("Failed to build aggregation hash chain: ", err)
	}
	acRootHsh, acRootLvl, err := ac.Aggregate(testAdjustVal)
	if err != nil {
		t.Fatal("Failed to aggregate: ", err)
	}

	if !hash.Equal(testRootHsh, acRootHsh) {
		t.Fatal("Root hash value mismatch.")
	}
	if testRootLvl != acRootLvl {
		t.Fatal("Root level value mismatch.")
	}
}

func testAdjustLevelCorrectionChainLinksNil(t *testing.T, _ ...interface{}) {
	messages := "Missing aggregation hash chain links."

	testChain, err := buildTestAggrChain()
	if err != nil {
		t.Fatal("Failed to build test aggregation hash chain: ", err)
	}

	b, err := NewAggregationChainBuilder(BuildFromAggregationChain(testChain))
	if err != nil {
		t.Fatal("Failed to construct aggregation chain builder.")
	}

	b.aggrChain.chainLinks = nil

	for _, f := range []LevelCalculator{LevelSubtract, LevelAdd} {
		if err := b.AdjustLevelCorrection(f, 0); err == nil {
			t.Fatal("Level correction not allowed without chainLinks")
		}

		if err := b.AdjustLevelCorrection(f, 0); errors.KsiErr(err).Code() != errors.KsiInvalidStateError {
			t.Fatalf("Expecting error code:\n%s\nBut got:\n%s", errors.KsiInvalidStateError, errors.KsiErr(err).Code())
		}

		if err := b.AdjustLevelCorrection(f, 0); errors.KsiErr(err).Message()[1] != messages {
			t.Fatalf("Expecting error message:\n%s\nBut got:\n%s", messages, errors.KsiErr(err).Message()[1])
		}
	}
}
