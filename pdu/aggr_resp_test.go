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
	"io/ioutil"
	"path/filepath"
	"testing"

	"github.com/guardtime/goksi/errors"
	"github.com/guardtime/goksi/hash"
	"github.com/guardtime/goksi/log"
	"github.com/guardtime/goksi/test"
)

func TestUnitAggregatorResp(t *testing.T) {
	logger, defFunc, err := test.InitLogger(t, testLogDir, log.DEBUG, t.Name())
	if err != nil {
		t.Fatal("Failed to initialize logger: ", err)
	}

	defer defFunc()

	// Apply logger.
	log.SetLogger(logger)

	test.Suite{
		{Func: testAggregatorRespFunctionsWithNilReceiver},
		{Func: testAggregatorRespFunctionsWithOkAggregatorResp},
		{Func: testVerifyInvalidAggregatorResp},
		{Func: testAggrRespFunctionsWithNilReceiver},
		{Func: testAggrRespFunctionsWithInvalidReceiver},
		{Func: testAggrRespPayloadFunctionsWithStatusNotNull},
		{Func: testAggrRespFunctionsWithOkAggregationResponse},
		{Func: testAggrRespFunctionsWithNokAggregationResponse},
		{Func: testAggrRespFunctionsWithUnableToParseResponse},
	}.Runner(t)
}

func testAggregatorRespFunctionsWithNilReceiver(t *testing.T, _ ...interface{}) {
	var (
		resp *AggregatorResp
		conf *Config
	)
	if val, err := resp.AggregationResp(); err == nil || val != nil {
		t.Fatal("Should not be possible to get response from nil aggregator response.")
	}

	if err := resp.Verify(hash.SHA2_256, "key"); err == nil {
		t.Fatal("Should not be possible to verify nil aggregator response.")
	}

	if err := resp.Err(); err == nil {
		t.Fatal("Should not be possible to get error from nil aggregator response.")
	}

	if val, err := resp.Encode(); err == nil || val != nil {
		t.Fatal("Should not be possible to encode nil aggregator response.")
	}

	if err := resp.Decode([]byte{0x1}); err == nil {
		t.Fatal("Should not be possible to decode nil aggregator response.")
	}

	if val, err := resp.Config(); err == nil || val != nil {
		t.Fatal("Should not be possible to get config from nil aggregator response.")
	}

	if err := resp.SetConfig(conf); err == nil {
		t.Fatal("Should not be possible to set config to nil aggregator response.")
	}

	if val, err := resp.Clone(); err == nil || val != nil {
		t.Fatal("Should not be possible to clone nil aggregator response.")
	}
}

func testAggregatorRespFunctionsWithOkAggregatorResp(t *testing.T, _ ...interface{}) {
	var (
		testOkRespFile = filepath.Join(testTlvDir, "ok-sig-2014-07-01.1-aggr_response.tlv")
		nilConfig      *Config
	)
	resp, err := createAggregatorRespFromFile(testOkRespFile)
	if err != nil {
		t.Fatal("Failed to create aggregation response: ", err)
	}

	aggrResp, err := resp.AggregationResp()
	if err != nil || aggrResp == nil {
		t.Fatal("Failed to get aggregation response payload: ", err)
	}

	if err = resp.Verify(hash.SHA2_512, "anon"); err == nil {
		t.Fatal("Should not be possible to verify aggregation response with non suitable hash algorithm.")
	}

	if err = resp.Verify(hash.SHA2_256, "key"); err == nil {
		t.Fatal("Should not be possible to verify aggregation response with wrong key.")
	}

	if err = resp.Verify(hash.SHA2_256, "anon"); err != nil {
		t.Fatal("Failed to verify response: ", err)
	}

	if err = resp.Err(); err != nil {
		t.Fatal("Should not be possible to get error from nil aggregator response.")
	}

	respBytes, err := resp.Encode()
	if err != nil || respBytes == nil {
		t.Fatal("Failed to get encoded response: ", err)
	}

	resp.rawTlv = nil
	respBytes, err = resp.Encode()
	if err != nil || respBytes == nil {
		t.Fatal("Failed to get encoded response when base raw tlv is nil: ", err)
	}

	cfg, err := resp.Config()
	if err != nil || cfg != nil {
		t.Fatal("Failed to get config from response: ", err)
	}

	if err = resp.SetConfig(nilConfig); err != nil {
		t.Fatal("Failed to set config to the response.")
	}

	if clone, err := resp.Clone(); err != nil || clone == nil {
		t.Fatal("Failed to clone aggregator response.")
	}
}

func testVerifyInvalidAggregatorResp(t *testing.T, _ ...interface{}) {
	var (
		testOkRespFile           = filepath.Join(testTlvDir, "ok-sig-2014-07-01.1-aggr_response.tlv")
		testErrorRespFile        = filepath.Join(testTlvDir, "ok_aggr_error_response_301.tlv")
		testReducedErrorRespFile = filepath.Join(testTlvDir, "aggr_reduced_error_101.tlv")
	)
	resp, err := createAggregatorRespFromFile(testOkRespFile)
	if err != nil {
		t.Fatal("Failed to create aggregation response: ", err)
	}

	resp.mac = nil
	if err = resp.Verify(hash.SHA2_256, "key"); err == nil {
		t.Fatal("Should not be possible to verify aggregator response that has no hmac.")
	}

	if resp, err = createAggregatorRespFromFile(testOkRespFile); err != nil {
		t.Fatal("Failed to create aggregator response: ", err)
	}
	resp.header = nil
	if err = resp.Verify(hash.SHA2_256, "key"); err == nil {
		t.Fatal("Should not be possible to verify aggregator response that has no header.")
	}

	if resp, err = createAggregatorRespFromFile(testErrorRespFile); err != nil {
		t.Fatal("Failed to create aggregator response: ", err)
	}
	if err = resp.Verify(hash.SHA2_256, "key"); err == nil {
		t.Fatal("Verify should return error if aggregator response contains error code.")
	}

	resp, err = createAggregatorRespFromFile(testOkRespFile)
	if err != nil {
		t.Fatal("Failed to create aggregator response: ", err)
	}
	resp.aggrResp.status = nil
	if err = resp.Verify(hash.SHA2_256, "key"); err == nil {
		t.Fatal("Should not be possible to verify aggregator response that has no status.")
	}

	resp, err = createAggregatorRespFromFile(testReducedErrorRespFile)
	if err != nil {
		t.Fatal("Failed to create aggregator response: ", err)
	}
	if err = resp.Verify(hash.SHA2_256, "key"); err == nil {
		t.Fatal("Should not be possible to verify aggregator response that contains reduced error response.")
	}

	resp, err = createAggregatorRespFromFile(testReducedErrorRespFile)
	if err != nil {
		t.Fatal("Failed to create aggregator response: ", err)
	}
	resp.aggrErr.status = nil
	if err = resp.Verify(hash.SHA2_256, "key"); err == nil {
		t.Fatal("Should not be possible to verify aggregator response that has no status.")
	}
}

func testAggrRespFunctionsWithNilReceiver(t *testing.T, _ ...interface{}) {
	var resp *AggrResp
	if _, err := resp.RequestID(); err == nil {
		t.Fatal("Should not be possible to get request id from nil aggregator response message.")
	}

	if _, err := resp.Status(); err == nil {
		t.Fatal("Should not be possible to get status from nil aggregator response message.")
	}

	if _, err := resp.ErrorMsg(); err == nil {
		t.Fatal("Should not be possible to get error message from nil aggregator response message.")
	}

	if _, err := resp.AggregationChainList(); err == nil {
		t.Fatal("Should not be possible to get aggregation chain list from nil aggregator response message.")
	}

	if _, err := resp.CalendarChain(); err == nil {
		t.Fatal("Should not be possible to get calendar chain from nil aggregator response message.")
	}

	if _, err := resp.CalendarAuthRec(); err == nil {
		t.Fatal("Should not be possible to get calendar authentication record from nil aggregator response message.")
	}

	if _, err := resp.PublicationRec(); err == nil {
		t.Fatal("Should not be possible to get publication record from nil aggregator response message.")
	}

	if _, err := resp.RFC3161(); err == nil {
		t.Fatal("Should not be possible to get rfc3161 record from nil aggregator response message.")
	}
}

func testAggrRespFunctionsWithInvalidReceiver(t *testing.T, _ ...interface{}) {
	var resp AggrResp

	if _, err := resp.RequestID(); err == nil {
		t.Fatal("Should not be possible to get request id from nil aggregator response message.")
	}

	if _, err := resp.Status(); err == nil {
		t.Fatal("Should not be possible to get status from nil aggregator response message.")
	}
	if errMsg, err := resp.ErrorMsg(); err != nil || errMsg != "" {
		t.Fatal("Should not be an issue to get error message as it is not mandatory and returned error message must be empty.")
	}

	resp.status = newUint64(0)

	if _, err := resp.AggregationChainList(); err == nil {
		t.Fatal("Should not be possible to get aggregation chain list from nil aggregator response message.")
	}
	if calChain, err := resp.CalendarChain(); err != nil || calChain != nil {
		t.Fatal("Should return nil calendar chain as it is not mandatory element in response: ", err)
	}
	if authRec, err := resp.CalendarAuthRec(); err != nil || authRec != nil {
		t.Fatal("Should return nil calendar chain authentication record as it is not mandatory element in response: ", err)
	}
	if pubRec, err := resp.PublicationRec(); err != nil || pubRec != nil {
		t.Fatal("Should return nil publication record as it is not mandatory element in response: ", err)
	}
	if rfc3161Rec, err := resp.RFC3161(); err != nil || rfc3161Rec != nil {
		t.Fatal("Should return nil rfc3161 record as it is not mandatory element in response: ", err)
	}
}

func testAggrRespPayloadFunctionsWithStatusNotNull(t *testing.T, _ ...interface{}) {
	var (
		testOkRespFile = filepath.Join(testTlvDir, "ok-sig-2014-07-01.1-aggr_response.tlv")
	)

	aggregationResp, err := createAggregatorRespFromFile(testOkRespFile)
	if err != nil {
		t.Fatal("Failed to create aggregation response pdu: ", err)
	}
	resp, err := aggregationResp.AggregationResp()
	if err != nil {
		t.Fatal("Failed to get aggregation response payload from aggregation response pdu: ", err)
	}
	resp.status = newUint64(0x101)

	if _, err := resp.RFC3161(); err == nil || err.(*errors.KsiError).Code() != errors.KsiServiceInvalidRequest {
		t.Fatal("Unexpected error when getting RFC3161 while status is not 0: ", err)
	}
	if _, err := resp.AggregationChainList(); err == nil || err.(*errors.KsiError).Code() != errors.KsiServiceInvalidRequest {
		t.Fatal("Unexpected error when getting AggregationChainList while status is not 0: ", err)
	}
	if _, err := resp.PublicationRec(); err == nil || err.(*errors.KsiError).Code() != errors.KsiServiceInvalidRequest {
		t.Fatal("Unexpected error when getting PublicationRec while status is not 0: ", err)
	}
	if _, err := resp.CalendarAuthRec(); err == nil || err.(*errors.KsiError).Code() != errors.KsiServiceInvalidRequest {
		t.Fatal("Unexpected error when getting CalendarAuthRec while status is not 0: ", err)
	}
	if _, err := resp.CalendarChain(); err == nil || err.(*errors.KsiError).Code() != errors.KsiServiceInvalidRequest {
		t.Fatal("Unexpected error when getting CalendarChain while status is not 0: ", err)
	}
}

func testAggrRespFunctionsWithOkAggregationResponse(t *testing.T, _ ...interface{}) {
	var (
		testOkRespFile = filepath.Join(testTlvDir, "ok-sig-2014-07-01.1-aggr_response.tlv")
	)

	aggregationResp, err := createAggregatorRespFromFile(testOkRespFile)
	if err != nil {
		t.Fatal("Failed to create aggregation response pdu: ", err)
	}

	resp, err := aggregationResp.AggregationResp()
	if err != nil {
		t.Fatal("Failed to get aggregation response payload from aggregation response pdu: ", err)
	}

	if id, err := resp.RequestID(); err != nil || id == 0 {
		t.Fatal("Failed to get request id from aggregation response: ", err)
	}

	if status, err := resp.Status(); err != nil || status != uint64(0) {
		t.Fatal("Failed to get status from aggregation response: ", err)
	}

	if errorMsg, err := resp.ErrorMsg(); err != nil || errorMsg != "" {
		t.Fatal("Failed to get error message from aggregation response or it was not empty: ", err)
	}

	if aggrChainList, err := resp.AggregationChainList(); err != nil || aggrChainList == nil {
		t.Fatal("Failed to get aggregation chain list from aggregation response: ", err)
	}

	if calendarChain, err := resp.CalendarChain(); err != nil || calendarChain == nil {
		t.Fatal("Failed to get calendar chain from aggregation response: ", err)
	}

	if calAuthRec, err := resp.CalendarAuthRec(); err != nil || calAuthRec == nil {
		t.Fatal("Failed to get calendar authentication record from aggregation response: ", err)
	}

	pubRec, err := resp.PublicationRec()
	if err != nil || pubRec != nil {
		t.Fatal("Failed to get publication record from aggregation response: ", err)
	}

	if rfcRec, err := resp.RFC3161(); err != nil || rfcRec != nil {
		t.Fatal("Failed to get rfc3161 record from aggregation response: ", err)
	}
}

func testAggrRespFunctionsWithNokAggregationResponse(t *testing.T, _ ...interface{}) {
	var (
		testErrorRespFile = filepath.Join(testTlvDir, "ok_aggr_error_response_301.tlv")
	)

	aggregationResp, err := createAggregatorRespFromFile(testErrorRespFile)
	if err != nil {
		t.Fatal("Failed to create aggregation response pdu: ", err)
	}

	resp, err := aggregationResp.AggregationResp()
	if err != nil {
		t.Fatal("Failed to get aggregation response from aggregator response: ", err)
	}

	if status, err := resp.Status(); err != nil || status != uint64(769) {
		t.Fatal("Failed to get status from aggregation response: ", err)
	}

	errorMsg, err := resp.ErrorMsg()
	if err != nil || errorMsg != "No response from upstream servers" {
		t.Fatal("Failed to get error message from aggregation response or it was not empty.")
	}
}

func testAggrRespFunctionsWithUnableToParseResponse(t *testing.T, _ ...interface{}) {
	var (
		testRespFile = filepath.Join(testTlvDir, "aggregator_unable_to_parse_response.tlv")
		expectedErr  = "Unable to parse aggregator response!"
	)

	_, err := createAggregatorRespFromFile(testRespFile)

	messages := errors.KsiErr(err).Message()

	if messages[2] != expectedErr {
		t.Fatalf("Expecting error message:\n%s\nBut got:\n%s", expectedErr, messages[2])
	}
}

func createAggregatorRespFromFile(testRespFile string) (*AggregatorResp, error) {
	raw, err := ioutil.ReadFile(testRespFile)
	if err != nil {
		return nil, errors.KsiErr(err).AppendMessage("Failed to open aggregation response file.")
	}

	resp := AggregatorResp{}
	if err = resp.Decode(raw); err != nil {
		return nil, errors.KsiErr(err).AppendMessage("Failed to decode aggregation response.")
	}

	return &resp, nil
}
