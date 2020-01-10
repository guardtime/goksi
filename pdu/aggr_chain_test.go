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
	"strings"
	"testing"
	"time"

	"github.com/guardtime/goksi/hash"
	"github.com/guardtime/goksi/log"
	"github.com/guardtime/goksi/test"
)

func TestUnitAggrChain(t *testing.T) {

	logger, defFunc, err := test.InitLogger(t, testLogDir, log.DEBUG, t.Name())
	if err != nil {
		t.Fatal("Failed to initialize logger: ", err)
	}
	defer defFunc()
	// Apply logger.
	log.SetLogger(logger)

	test.Suite{
		{Func: testNilAggrChainUsage},
		{Func: testInvalidAggrChainUsage},
		{Func: testNilAggrChainListUsage},
		{Func: testInvalidAggregationHashChainUsage},
		{Func: testGetFromAggregationHashChain},
		{Func: testInputData},
		{Func: testGetInputDataFromNilReceiver},
		{Func: testGetNilInputData},
	}.Runner(t)
}

func testNilAggrChainUsage(t *testing.T, _ ...interface{}) {
	var chain *AggregationChain
	if aggrTime, err := chain.AggregationTime(); err == nil || !aggrTime.Equal(time.Time{}) {
		t.Fatal("Should not be possible to use nil aggregation chain.")
	}

	if index, err := chain.ChainIndex(); err == nil || index != nil {
		t.Fatal("Should not be possible to use nil aggregation chain.")
	}

	if data, err := chain.InputData(); err == nil || data != nil {
		t.Fatal("Should not be possible to use nil aggregation chain.")
	}

	if hsh, err := chain.InputHash(); err == nil || hsh != nil {
		t.Fatal("Should not be possible to use nil aggregation chain.")
	}

	if algo, err := chain.AggregationAlgo(); err == nil || algo != hash.SHA_NA {
		t.Fatal("Should not be possible to use nil aggregation chain.")
	}

	if links, err := chain.ChainLinks(); err == nil || links != nil {
		t.Fatal("Should not be possible to use nil aggregation chain.")
	}

	if size, err := chain.CalculateShape(); err == nil || size != 0 {
		t.Fatal("Should not be possible to use nil aggregation chain.")
	}

	if val := chain.String(); val != "" {
		t.Fatal("Should not be possible to use nil aggregation chain.")
	}

	if hsh, height, err := chain.Aggregate(0); err == nil || hsh != nil || height != 0 {
		t.Fatal("Should not be possible to use nil aggregation chain.")
	}

	if _, err := chain.Identity(); err == nil {
		t.Fatal("Should not be possible to use nil aggregation chain.")
	}
}

func testInvalidAggrChainUsage(t *testing.T, _ ...interface{}) {
	chain := AggregationChain{}

	if _, err := chain.AggregationTime(); err == nil {
		t.Fatal("Should not be possible to use invalid aggregation chain.")
	}

	if _, err := chain.ChainIndex(); err == nil {
		t.Fatal("Should not be possible to use invalid aggregation chain.")
	}

	if _, err := chain.InputHash(); err == nil {
		t.Fatal("Should not be possible to use invalid aggregation chain.")
	}

	if _, err := chain.AggregationAlgo(); err == nil {
		t.Fatal("Should not be possible to use invalid aggregation chain.")
	}

	if _, err := chain.ChainLinks(); err == nil {
		t.Fatal("Should not be possible to use invalid aggregation chain.")
	}

	if _, err := chain.CalculateShape(); err == nil {
		t.Fatal("Should not be possible to use invalid aggregation chain.")
	}

	expectedString := "Aggregation time: () \n" +
		"Input hash      : \n" +
		"Aggr. algorithm : \n"

	val := chain.String()
	if val != expectedString {
		t.Fatalf("Unexpected string returned.\nExpecting:\n%s\nBut got:\n%s\n", expectedString, val)
	}

	if _, _, err := chain.Aggregate(0); err == nil {
		t.Fatal("Should not be possible to use invalid aggregation chain.")
	}

	if _, err := chain.Identity(); err == nil {
		t.Fatal("Should not be possible to use invalid aggregation chain.")
	}
}

func testNilAggrChainListUsage(t *testing.T, _ ...interface{}) {
	var chainList AggregationChainList

	if _, err := chainList.Aggregate(0); err == nil {
		t.Fatal("Should not be possible to use nil aggregation chain list.")
	}

	if _, err := chainList.Identity(); err == nil {
		t.Fatal("Should not be possible to use nil aggregation chain list.")
	}

	if val := chainList.Len(); val != 0 {
		t.Fatal("Should not be possible to use nil aggregation chain list.")
	}

	chainList.Swap(1, 2)

	bool := chainList.Less(1, 2)
	if bool != false {
		t.Fatal("Should not be possible to use nil aggregation chain list.")
	}
}

func testInvalidAggregationHashChainUsage(t *testing.T, _ ...interface{}) {
	emptyChainList := AggregationChainList{}

	if _, err := emptyChainList.Aggregate(0); err == nil {
		t.Fatal("Should not be possible to aggregate empty chain list.")
	}

	if _, err := emptyChainList.Identity(); err == nil {
		t.Fatal("Should not be possible to  get identity from empty chain list.")
	}

	chainListWithInvalidChain := append(AggregationChainList{}, &AggregationChain{})

	if _, err := chainListWithInvalidChain.Aggregate(0); err == nil {
		t.Fatal("Should not be possible to aggregate invalid chain.")
	}

	if _, err := chainListWithInvalidChain.Identity(); err == nil {
		t.Fatal("Should not be possible to get identity from invalid aggregation chain list.")
	}

	chainListWithInvalidChain2 := append(AggregationChainList{}, &AggregationChain{inputHash: &hash.Imprint{}})

	if _, err := chainListWithInvalidChain2.Aggregate(0); err == nil {
		t.Fatal("Should not be possible to aggregate invalid hash chain.")
	}

	chainListWithSameChains := AggregationChainList{}
	chain, err := buildTestAggrChain()
	if err != nil {
		t.Fatal("Failed to build the test aggregation chain: ", err)
	}
	chainListWithSameChains = append(chainListWithSameChains, chain, chain)

	if _, err = chainListWithSameChains.Aggregate(0); err == nil {
		t.Fatal("Should not be possible to aggregate inconsistent aggregation hash chain.")
	}
}

func testGetFromAggregationHashChain(t *testing.T, _ ...interface{}) {
	chain, err := buildTestAggrChain()
	if err != nil {
		t.Fatal("Failed to build test aggregation hash chain: ", err)
	}

	if aggrTime, err := chain.AggregationTime(); err != nil || aggrTime.IsZero() {
		t.Fatal("Failed to get aggregation time: ", err)
	}

	if indexes, err := chain.ChainIndex(); err != nil || indexes == nil {
		t.Fatal("Failed to get chain index: ", err)
	}

	if inputHash, err := chain.InputHash(); err != nil || inputHash == nil {
		t.Fatal("Failed to get input hash: ", err)
	}

	if algo, err := chain.AggregationAlgo(); err != nil || algo == hash.SHA_NA {
		t.Fatal("Failed to get aggregation algorithm: ", err)
	}

	if link, err := chain.ChainLinks(); err != nil || link == nil {
		t.Fatal("Failed to get chain links: ", err)
	}

	if shape, err := chain.CalculateShape(); err != nil || shape == 0 {
		t.Fatal("Failed to calculate the shape of the chain: ", err)
	}

	if chainString := chain.String(); chainString == "" {
		t.Fatal("Failed to get chain string: ", err)
	}

	imprint, level, err := chain.Aggregate(0)
	if err != nil || imprint == nil || level == 0 {
		t.Fatal("Failed to aggregate the chain: ", err)
	}

	if identityList, err := chain.Identity(); err != nil || identityList == nil {
		t.Fatal("Failed to get the chain identity: ", err)
	}
}

func testInputData(t *testing.T, _ ...interface{}) {
	inputDataBytes := []byte{0x69, 0x6e, 0x70, 0x75, 0x74, 0x20, 0x64, 0x61, 0x74, 0x61}
	chain, err := buildTestAggrChain()
	if err != nil {
		t.Fatal("Failed to build test aggregation hash chain: ", err)
	}

	chain.inputData = &inputDataBytes

	inputData, err := chain.InputData()
	if err != nil {
		t.Fatal("Failed to get input data: ", err)
	}

	if !bytes.Equal(inputData, inputDataBytes) {
		t.Fatal("Unexpected input data: ", inputData)
	}

	chainString := chain.String()
	if chainString == "" {
		t.Fatal("Failed to get chain string.")
	}

	if !strings.Contains(chainString, "Input data      : 696e7075742064617461") {
		t.Fatal("Did not find expected string 'Input data      : anon'  from chain string: ", chainString)
	}
}

func testGetInputDataFromNilReceiver(t *testing.T, _ ...interface{}) {
	var (
		chain *AggregationChain
	)

	if inputData, err := chain.InputData(); err == nil || inputData != nil {
		t.Fatal("Should not be possible to get input data from nil receiver.")
	}
}

func testGetNilInputData(t *testing.T, _ ...interface{}) {
	chain, err := buildTestAggrChain()
	if err != nil {
		t.Fatal("Failed to build test aggregation hash chain: ", err)
	}

	if inputData, err := chain.InputData(); err != nil || inputData != nil {
		t.Fatal("Nil error and input data must be returned if input data is nil: ", err)
	}
}
