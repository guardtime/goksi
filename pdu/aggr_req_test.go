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

	"github.com/guardtime/goksi/errors"
	"github.com/guardtime/goksi/hash"
	"github.com/guardtime/goksi/log"
	"github.com/guardtime/goksi/test"
)

func TestUnitAggrReq(t *testing.T) {

	logger, defFunc, err := test.InitLogger(t, testLogDir, log.DEBUG, t.Name())
	if err != nil {
		t.Fatal("Failed to initialize logger: ", err)
	}
	defer defFunc()
	// Apply logger.
	log.SetLogger(logger)

	test.Suite{
		{Func: testNewAggregationReqWithNotValidHash},
		{Func: testNewAggregationReqWithOptionThatReturnsError},
		{Func: testAggregatorReqSettingsInvalidInput},
		{Func: testAggregatorReqFunctionsWithNilReceiver},
		{Func: testAggrReqFunctionsWithNilReceiver},
		{Func: testAggrReqFunctionsWithEmptyReq},
		{Func: testAggrReqInvalidStates},
		{Func: testUpdateHmacWithInvalidHashAlgorithmInput},
		{Func: testAggregationReqDefault},
		{Func: testAggregationReqWithOptions},
		{Func: testConfigReq},
		{Func: testAggrRequestClone},
		{Func: testConfigReqClone},
	}.Runner(t)
}

func testAggregationReqDefault(t *testing.T, _ ...interface{}) {
	var (
		testImprint = hash.Imprint{0x01,
			0xc4, 0xbb, 0xcb, 0x1f, 0xbe, 0xc9, 0x9d, 0x65,
			0xbf, 0x59, 0xd8, 0x5c, 0x8c, 0xb6, 0x2e, 0xe2,
			0xdb, 0x96, 0x3f, 0x0f, 0xe1, 0x06, 0xf4, 0x83,
			0xd9, 0xaf, 0xa7, 0x3b, 0xd4, 0xe3, 0x9a, 0x8a,
		}
	)

	req, err := NewAggregationReq(testImprint)
	if err != nil {
		t.Fatal("Failed to create aggregation request: ", err)
	}

	aggrReq, err := req.AggregationReq()
	if err != nil {
		t.Fatal("Failed to extract aggregation request: ", err)
	}

	hsh, err := aggrReq.RequestHash()
	if err != nil {
		t.Fatal("Failed to get request hash: ", err)
	}
	if !hash.Equal(testImprint, hsh) {
		t.Error("Request level mismatch")
	}

	lvl, err := aggrReq.RequestLevel()
	if err != nil {
		t.Fatal("Failed to get request input level: ", err)
	}
	if lvl != 0 {
		t.Error("Request level mismatch")
	}

	id, err := aggrReq.RequestID()
	if err != nil {
		t.Fatal("Failed to get request id: ", err)
	}
	if id != 0 {
		t.Error("Request level mismatch")
	}
}

func testAggregationReqWithOptions(t *testing.T, _ ...interface{}) {

	var (
		testImprint = hash.Imprint{0x01,
			0xc4, 0xbb, 0xcb, 0x1f, 0xbe, 0xc9, 0x9d, 0x65,
			0xbf, 0x59, 0xd8, 0x5c, 0x8c, 0xb6, 0x2e, 0xe2,
			0xdb, 0x96, 0x3f, 0x0f, 0xe1, 0x06, 0xf4, 0x83,
			0xd9, 0xaf, 0xa7, 0x3b, 0xd4, 0xe3, 0x9a, 0x8a,
		}
	)

	req, err := NewAggregationReq(testImprint,
		AggrReqSetRequestLevel(0x01),
		AggrReqSetRequestID(0xff))
	if err != nil {
		t.Fatal("Failed to create aggregation request: ", err)
	}

	aggrReq, err := req.AggregationReq()
	if err != nil {
		t.Fatal("Failed to extract aggregation request: ", err)
	}

	lvl, err := aggrReq.RequestLevel()
	if err != nil {
		t.Fatal("Failed to create aggregation request: ", err)
	}
	if lvl != 0x01 {
		t.Error("Request level mismatch")
	}

	id, err := aggrReq.RequestID()
	if err != nil {
		t.Fatal("Failed to create aggregation request: ", err)
	}
	if id != 0xff {
		t.Error("Request level mismatch")
	}
}

func testConfigReq(t *testing.T, _ ...interface{}) {

	req, err := NewAggregatorConfigReq()
	if err != nil {
		t.Fatal("Failed to create aggregation request: ", err)
	}
	if req.confReq == nil {
		t.Error("ConfReq must not be nil.")
	}
}

func testAggrRequestClone(t *testing.T, _ ...interface{}) {
	var (
		testImprint = hash.Imprint{0x01,
			0xc4, 0xbb, 0xcb, 0x1f, 0xbe, 0xc9, 0x9d, 0x65,
			0xbf, 0x59, 0xd8, 0x5c, 0x8c, 0xb6, 0x2e, 0xe2,
			0xdb, 0x96, 0x3f, 0x0f, 0xe1, 0x06, 0xf4, 0x83,
			0xd9, 0xaf, 0xa7, 0x3b, 0xd4, 0xe3, 0x9a, 0x8a,
		}
	)

	req, err := NewAggregationReq(testImprint,
		AggrReqSetRequestLevel(0x01),
		AggrReqSetRequestID(0xff))
	if err != nil {
		t.Fatal("Failed to create aggregation request: ", err)
	}

	clone, err := req.Clone()
	if err != nil {
		t.Fatal("Failed to clone aggregator request: ", err)
	}

	if req.aggrReq == clone.aggrReq {
		t.Fatal("clone req  must point to a different location.")
	}
	if *req.aggrReq.id != *clone.aggrReq.id {
		t.Fatal("clone req id mismatch.")
	}
	if *req.aggrReq.level != *clone.aggrReq.level {
		t.Fatal("clone req level mismatch.")
	}
	if !hash.Equal(*req.aggrReq.hash, *clone.aggrReq.hash) {
		t.Fatal("clone req hash mismatch.")
	}
}

func testConfigReqClone(t *testing.T, _ ...interface{}) {

	req, err := NewAggregatorConfigReq()
	if err != nil {
		t.Fatal("Failed to create aggregation request: ", err)
	}

	clone, err := req.Clone()
	if err != nil {
		t.Fatal("Failed to clone aggregator request: ", err)
	}

	if req.confReq == clone.confReq {
		t.Fatal("clone req must point to a different location.")
	}
	if clone.confReq == nil {
		t.Error("ConfReq must not be nil.")
	}
}

func testNewAggregationReqWithNotValidHash(t *testing.T, _ ...interface{}) {
	var (
		testImprint = hash.Imprint{0x01,
			0xc4, 0xbb, 0xcb, 0x1f, 0xbe, 0xc9, 0x9d, 0x65,
			0xbf, 0x59, 0xd8, 0x5c, 0x8c, 0xb6, 0x2e, 0xe2,
			0xdb, 0x96, 0x3f, 0x0f, 0xe1, 0x06, 0xf4, 0x83,
		}
	)
	if _, err := NewAggregationReq(testImprint); err == nil {
		t.Fatal("Should not be possible to create aggregation request with invalid hash.")
	}
}

func aggrReqTestSettingReturnError() AggregationReqSetting {
	return func(r *aggregatorReq) error {
		return errors.New(errors.KsiInvalidArgumentError).AppendMessage("Missing aggregator request base object.")
	}
}

func testNewAggregationReqWithOptionThatReturnsError(t *testing.T, _ ...interface{}) {
	_, err := NewAggregationReq(hash.Default.ZeroImprint(), func() AggregationReqSetting {
		return func(r *aggregatorReq) error {
			return errors.New(errors.KsiNotImplemented)
		}
	}())
	if err == nil {
		t.Fatal("Should not be possible to create aggregation request with request options that return error.")
	}
}

func testAggregatorReqSettingsInvalidInput(t *testing.T, _ ...interface{}) {
	aggrRequestSetting := AggrReqSetRequestLevel(0)
	if err := aggrRequestSetting(nil); err == nil {
		t.Fatal("Should not be possible to set input hash level to nil aggregation request.")
	}
	aggrRequestSetting = AggrReqSetRequestID(12)
	if err := aggrRequestSetting(nil); err == nil {
		t.Fatal("Should not be possible to set request id to nil aggregation request.")
	}
}

func testAggregatorReqFunctionsWithNilReceiver(t *testing.T, _ ...interface{}) {
	var nilReq *AggregatorReq

	if _, err := nilReq.AggregationReq(); err == nil {
		t.Fatal("Should not possible to get aggregation request from nil request.")
	}

	if err := nilReq.SetHeader(nil); err == nil {
		t.Fatal("Should not be possible to set header to nil request.")
	}

	if _, err := nilReq.Header(); err == nil {
		t.Fatal("Should not be possible to update header on nil request.")
	}

	if err := nilReq.UpdateHMAC(hash.SHA2_256, "key"); err == nil {
		t.Fatal("Should not be possible to update hmac on nil request.")
	}

	if err := nilReq.UpdateRequestID(123); err == nil {
		t.Fatal("Should not be possible to update request id on nil request.")
	}

	if _, err := nilReq.Encode(); err == nil {
		t.Fatal("Should not be possible to encode nil request.")
	}

	if _, err := nilReq.Clone(); err == nil {
		t.Fatal("Should not be possible to clone nil request.")
	}

	if _, err := nilReq.Config(); err == nil {
		t.Fatal("Should not be possible to get config from nil request.")
	}
}

func testAggrReqFunctionsWithNilReceiver(t *testing.T, _ ...interface{}) {
	var req *AggrReq
	if _, err := req.RequestHash(); err == nil {
		t.Fatal("Should not be possible to get request hash from nil request.")
	}
	if _, err := req.RequestLevel(); err == nil {
		t.Fatal("Should not be possible to get request level from nil request.")
	}
	if _, err := req.RequestID(); err == nil {
		t.Fatal("Should not be possible to get request id from nil request.")
	}
}

func testAggrReqFunctionsWithEmptyReq(t *testing.T, _ ...interface{}) {
	var req AggrReq
	if _, err := req.RequestHash(); err == nil {
		t.Fatal("Should not be possible to get request hash from empty request.")
	}
	val, err := req.RequestLevel()
	if err != nil || val != 0 {
		t.Fatal("Request level from empty request must be 0.")
	}
	if _, err = req.RequestID(); err == nil {
		t.Fatal("Should not be possible to get request id from nil request.")
	}
}

func testAggrReqInvalidStates(t *testing.T, _ ...interface{}) {
	var req AggrReq
	lvl := uint64(1234567890)
	req.level = &lvl
	if _, err := req.RequestLevel(); err == nil {
		t.Fatal("AggrReq has too large level and requesting it should not pass.")
	}

}

func testUpdateHmacWithInvalidHashAlgorithmInput(t *testing.T, _ ...interface{}) {
	var (
		req    AggregatorReq
		header Header
	)

	if err := req.UpdateHMAC(hash.SHA2_256, "key"); err == nil {
		t.Fatal("Should not be possible to update hmac on aggregator req with no header.")
	}

	req.header = &header
	if err := req.UpdateHMAC(0x23, "key"); err == nil {
		t.Fatal("Should not be possible to update hmac with not registered hmac.")
	}

	if err := req.UpdateHMAC(0x0, "key"); err == nil {
		t.Fatal("Should not be possible to update hmac with not trusted hmac.")
	}
}
