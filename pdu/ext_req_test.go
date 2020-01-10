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
)

func TestUnitExtReq(t *testing.T) {
	logger, defFunc, err := test.InitLogger(t, testLogDir, log.DEBUG, t.Name())
	if err != nil {
		t.Fatal("Failed to initialize logger: ", err)
	}
	defer defFunc()
	// Apply logger.
	log.SetLogger(logger)

	test.Suite{
		{Func: testExtReqFunctionsWithNilReceiver},
		{Func: testExtReqFunctionsWithInvalidReceiver},
		{Func: testExtReqFunctionsWithOkReq},
		{Func: testExtenderReqFunctionsWithNilReceiver},
		{Func: testExtenderReqFunctionsWithInvalidInput},
		{Func: testExtenderReqFunctionsWithInvalidReceiver},
		{Func: testExtenderReqFunctionsWithOkConfReq},
		{Func: testExtenderReqFunctionsWithOkReq},
		{Func: testExtenderReqSettingsWithInvalidReceiver},
		{Func: testExtenderReqSettingsWithOkInput},
		{Func: testExtendingReqDefault},
		{Func: testExtendingReqWithOptions},
		{Func: testExtenderConfigReq},
		{Func: testExtendingReqWithTimeGoingBackwards},
	}.Runner(t)
}

func testExtReqFunctionsWithNilReceiver(t *testing.T, _ ...interface{}) {
	var (
		req *ExtReq
	)

	if _, err := req.AggregationTime(); err == nil {
		t.Fatal("Should not be possible to get aggregation time from nil extension request.")
	}

	if _, err := req.PublicationTime(); err == nil {
		t.Fatal("Should not be possible to get publication time from nil extension request.")
	}

	if _, err := req.RequestID(); err == nil {
		t.Fatal("Should not be possible to get request ID from nil extension request.")
	}
}

func testExtReqFunctionsWithInvalidReceiver(t *testing.T, _ ...interface{}) {
	var (
		req ExtReq
	)

	if _, err := req.AggregationTime(); err == nil {
		t.Fatal("Should not be possible to get aggregation time from extension request that has nil time.")
	}
}

func testExtReqFunctionsWithOkReq(t *testing.T, _ ...interface{}) {
	req := &ExtReq{
		id:       newUint64(1234),
		aggrTime: newUint64(uint64(time.Now().Unix())),
		pubTime:  newUint64(uint64(time.Now().Unix())),
	}

	aggrTime, err := req.AggregationTime()
	if err != nil {
		t.Fatal("Failed to get aggregation time from extension request: ", err)
	}
	if aggrTime != time.Unix(int64(*req.aggrTime), 0) {
		t.Fatal("Unexpected aggregation time from extension request: ", aggrTime)
	}

	pubTime, err := req.PublicationTime()
	if err != nil {
		t.Fatal("Failed to get publication time from extension request: ", err)
	}
	if pubTime != time.Unix(int64(*req.pubTime), 0) {
		t.Fatal("Unexpected publication time from extension request: ", pubTime)
	}

	id, err := req.RequestID()
	if err != nil {
		t.Fatal("Failed to get request id from extension request: ", err)
	}
	if id != *req.id {
		t.Fatal("Unexpected request ID from extension request: ", id)
	}

	req.pubTime = nil
	req.id = nil
	pubTime, err = req.PublicationTime()
	if err != nil {
		t.Fatal("Failed to get publication time from extension request: ", err)
	}
	if !pubTime.IsZero() {
		t.Fatal("Publication time did not default to zero: ", pubTime)
	}

	id, err = req.RequestID()
	if err != nil {
		t.Fatal("Failed to get request id from extension request: ", err)
	}
	if id != 0 {
		t.Fatal("Request ID did not default to zero: ", id)
	}
}

func testExtenderReqFunctionsWithNilReceiver(t *testing.T, _ ...interface{}) {
	var (
		req    *ExtenderReq
		header Header
	)
	if err := req.SetHeader(&header); err == nil {
		t.Fatal("Should not be possible to set header to nil extender request.")
	}

	if err := req.UpdateHMAC(hash.SHA2_256, "key"); err == nil {
		t.Fatal("Should not be possible to update HMAC on nil extender request.")
	}

	if err := req.UpdateRequestID(uint64(123)); err == nil {
		t.Fatal("Should not be possible to update request ID on nil extender request.")
	}

	if _, err := req.Encode(); err == nil {
		t.Fatal("Should not be possible to encode nil extender request.")
	}

	if _, err := req.Clone(); err == nil {
		t.Fatal("Should not be possible to clone nil extender request.")
	}

	if _, err := req.Config(); err == nil {
		t.Fatal("Should not be possible to get config from nil extender request.")
	}

	if _, err := req.ExtendingReq(); err == nil {
		t.Fatal("Should not be possible to get extending request from nil extender request.")
	}

	if _, err := req.HMAC(); err == nil {
		t.Fatal("Should not be possible to get HMAC from nil extender request.")
	}

	if _, err := req.Header(); err == nil {
		t.Fatal("Should not be possible to get header from nil extender request.")
	}
}

func testExtenderReqFunctionsWithInvalidInput(t *testing.T, _ ...interface{}) {
	var (
		req = ExtenderReq{
			header: &Header{},
		}
	)

	if err := req.UpdateHMAC(hash.SHA1, "key"); err == nil {
		t.Fatal("Should not be possible to update HMAC with not trusted algorithm.")
	}

	if err := req.UpdateHMAC(hash.SHA3_256, "key"); err == nil {
		t.Fatal("Should not be possible to update HMAC with not implemented algorithm.")
	}

	if err := req.UpdateHMAC(0x34, "key"); err == nil {
		t.Fatal("Should not be possible to update HMAC with unknown algorithm.")
	}
}

func testExtenderReqFunctionsWithInvalidReceiver(t *testing.T, _ ...interface{}) {
	var (
		req ExtenderReq
	)

	req.header = nil
	if err := req.UpdateHMAC(hash.SHA2_256, "key"); err == nil {
		t.Fatal("Should not be possible to update HMAC with missing header.")
	}
}

func testExtenderReqFunctionsWithOkConfReq(t *testing.T, _ ...interface{}) {
	req, err := NewExtenderConfigReq()
	if err != nil {
		t.Fatal("Failed to create extending request: ", err)
	}

	extenderReqFunctionsWithOkReq(t, req)
}

func testExtenderReqFunctionsWithOkReq(t *testing.T, _ ...interface{}) {
	req, err := NewExtendingReq(time.Now())
	if err != nil {
		t.Fatal("Failed to create extending request: ", err)
	}

	extenderReqFunctionsWithOkReq(t, req)
}

func extenderReqFunctionsWithOkReq(t *testing.T, req *ExtenderReq) {
	header, err := NewHeader("loginId", nil)
	if err != nil {
		t.Fatal("Failed to create a header: ", err)
	}

	if err = req.SetHeader(header); err != nil {
		t.Fatal("Failed to set header to request: ", err)
	}

	if err = req.UpdateRequestID(uint64(123)); err != nil {
		t.Fatal("Failed to update request ID: ", err)
	}

	if err = req.UpdateHMAC(hash.SHA2_256, "key"); err != nil {
		t.Fatal("Failed to update HMAC: ", err)
	}

	if _, err = req.Encode(); err != nil {
		t.Fatal("Failed to encode the request: ", err)
	}

	if _, err = req.Clone(); err != nil {
		t.Fatal("Failed to clone the request: ", err)
	}

	if _, err = req.Config(); err != nil {
		t.Fatal("Failed to get config from the request: ", err)
	}

	if _, err = req.ExtendingReq(); err != nil {
		t.Fatal("Failed to get the extending request from extender request: ", err)
	}

	if _, err = req.HMAC(); err != nil {
		t.Fatal("Failed to get the HMAC: ", err)
	}

	if _, err = req.Header(); err != nil {
		t.Fatal("Failed to get the header: ", err)
	}
}

func testExtenderReqSettingsWithInvalidReceiver(t *testing.T, _ ...interface{}) {
	var (
		nilReq *extenderReq
		req    extenderReq
	)
	setting := ExtReqSetPubTime(time.Now())
	if err := setting(nilReq); err == nil {
		t.Fatal("Should not be possible to set publication time on nil request.")
	}

	setting = ExtReqSetRequestID(uint64(1234))
	if err := setting(nilReq); err == nil {
		t.Fatal("Should not be possible to set request id on nil request.")
	}

	setting = ExtReqSetPubTime(time.Now())
	err := setting(&req)
	if err == nil {
		t.Fatal("Should not be possible to set publication time to nil extending request.")
	}

	setting = ExtReqSetRequestID(uint64(1234))
	if err := setting(&req); err == nil {
		t.Fatal("Should not be possible to set request ID to nil extending request.")
	}
}

func testExtenderReqSettingsWithOkInput(t *testing.T, _ ...interface{}) {
	var (
		req = extenderReq{ExtenderReq{extReq: &ExtReq{
			id:       newUint64(0),
			aggrTime: newUint64(uint64(time.Now().Unix())),
		}}}
	)

	setting := ExtReqSetPubTime(time.Now())
	if err := setting(&req); err != nil {
		t.Fatal("Failed to set publication time: ", err)
	}

	setting = ExtReqSetRequestID(uint64(1234))
	if err := setting(&req); err != nil {
		t.Fatal("Failed to set request ID: ", err)
	}
}

func testExtendingReqDefault(t *testing.T, _ ...interface{}) {

	var (
		testAggrTime = time.Unix(int64(1502755200), 0)
	)

	req, err := NewExtendingReq(testAggrTime)
	if err != nil {
		t.Fatal("Failed to create request: ", err)
	}

	extReq, err := req.ExtendingReq()
	if err != nil {
		t.Fatal("Failed to extract extending request: ", err)
	}

	aggrTime, err := extReq.AggregationTime()
	if err != nil {
		t.Fatal("Failed to get request aggregation hash time: ", err)
	}
	if !aggrTime.Equal(testAggrTime) {
		t.Error("Aggregation time mismatch")
	}

	id, err := extReq.RequestID()
	if err != nil {
		t.Fatal("Failed to get request id: ", err)
	}
	if id != 0 {
		t.Error("Request level mismatch")
	}

	pubTime, err := extReq.PublicationTime()
	if err != nil {
		t.Fatal("Failed to get request pub time: ", err)
	}
	if !pubTime.IsZero() {
		t.Error("Publication time mismatch")
	}
}

func testExtendingReqWithOptions(t *testing.T, _ ...interface{}) {

	var (
		testAggrTime = time.Unix(int64(1502755200), 0)
		testPubTime  = testAggrTime.Add(1 * time.Second)
	)

	req, err := NewExtendingReq(testAggrTime,
		ExtReqSetPubTime(testPubTime),
		ExtReqSetRequestID(0xff),
	)
	if err != nil {
		t.Fatal("Failed to create request: ", err)
	}

	extReq, err := req.ExtendingReq()
	if err != nil {
		t.Fatal("Failed to extract extending request: ", err)
	}

	aggrTime, err := extReq.AggregationTime()
	if err != nil {
		t.Fatal("Failed to get request aggregation time: ", err)
	}
	if !aggrTime.Equal(testAggrTime) {
		t.Error("Aggregation time mismatch")
	}

	id, err := extReq.RequestID()
	if err != nil {
		t.Fatal("Failed to create aggregation request: ", err)
	}
	if id != 0xff {
		t.Error("Request level mismatch")
	}

	pubTime, err := extReq.PublicationTime()
	if err != nil {
		t.Fatal("Failed to get request pub time: ", err)
	}
	if pubTime.Equal(testPubTime) == false {
		t.Error("Publication time mismatch")
	}
}

func testExtendingReqWithTimeGoingBackwards(t *testing.T, _ ...interface{}) {
	var (
		testAggrTime = time.Unix(int64(1502755200), 0)
		testPubTime  = testAggrTime.Add(-1 * time.Second)
	)

	_, err := NewExtendingReq(testAggrTime,
		ExtReqSetPubTime(testPubTime),
		ExtReqSetRequestID(0xff),
	)
	if err == nil {
		t.Fatal("This call should have been failed!")
	}

	if errors.KsiErr(err).Code() != errors.KsiServiceExtenderInvalidTimeRange {
		t.Fatalf("This call should have been with %v instead of %v!", errors.KsiServiceExtenderInvalidTimeRange, errors.KsiErr(err).Code())
	}
}

func testExtenderConfigReq(t *testing.T, _ ...interface{}) {
	req, err := NewExtenderConfigReq()
	if err != nil {
		t.Fatal("Failed to create config request: ", err)
	}
	if req.confReq == nil {
		t.Error("ConfReq must not be nil.")
	}
}
