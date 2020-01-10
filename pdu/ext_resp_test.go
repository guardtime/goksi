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
	"strings"
	"testing"

	"github.com/guardtime/goksi/errors"
	"github.com/guardtime/goksi/hash"
	"github.com/guardtime/goksi/log"
	"github.com/guardtime/goksi/test"
	"github.com/guardtime/goksi/test/utils"
)

func TestUnitExtResp(t *testing.T) {
	logger, defFunc, err := test.InitLogger(t, testLogDir, log.DEBUG, t.Name())
	if err != nil {
		t.Fatal("Failed to initialize logger: ", err)
	}

	defer defFunc()

	// Apply logger.
	log.SetLogger(logger)

	test.Suite{
		{Func: testExtRespFunctionsWithNilReceiver},
		{Func: testExtRespFunctionsWithInvalidReceiver},
		{Func: testExtRespPayloadFunctionsWithStatusNotNull},
		{Func: testExtRespFunctionsWithOkReq},
		{Func: testExtenderRespFunctionsWithNilReceiver},
		{Func: testExtenderRespFunctionsWithInvalidReceiver},
		{Func: testExtenderRespFunctionsWithOkReq},
		{Func: testExtenderRespFunctionsWithUnableToParseResponse},
	}.Runner(t)
}

func testExtRespFunctionsWithNilReceiver(t *testing.T, _ ...interface{}) {
	var (
		resp *ExtResp
	)

	if _, err := resp.RequestID(); err == nil {
		t.Fatal("Should not be possible to get request id from nil response.")
	}

	if _, err := resp.Status(); err == nil {
		t.Fatal("Should not be possible to get status from nil response.")
	}

	if _, err := resp.ErrorMsg(); err == nil {
		t.Fatal("Should not be possible to get error message from nil response.")
	}

	if _, err := resp.CalendarLast(); err == nil {
		t.Fatal("Should not be possible to get latest calendar from nil response.")
	}

	if _, err := resp.CalendarChain(); err == nil {
		t.Fatal("Should not be possible to get calendar hash chain from nil response.")
	}
}

func testExtRespFunctionsWithInvalidReceiver(t *testing.T, _ ...interface{}) {
	var (
		resp ExtResp
	)

	if _, err := resp.RequestID(); err == nil {
		t.Fatal("Should not be possible to get request id if it was nil.")
	}

	if _, err := resp.CalendarChain(); err == nil {
		t.Fatal("Should not be possible to get calendar hash chain from response that contains nothing.")
	}
}

func testExtRespPayloadFunctionsWithStatusNotNull(t *testing.T, _ ...interface{}) {
	extResp, err := createExtensionResponse()
	if err == nil {
		t.Fatal("Failed to create response.")
	}
	extResp.status = newUint64(0x101)

	if _, err := extResp.CalendarChain(); err == nil || err.(*errors.KsiError).Code() != errors.KsiServiceInvalidRequest {
		t.Fatal("Unexpected error when getting calendar chain while status is not 0: ", err)
	}
	if _, err := extResp.CalendarLast(); err == nil || err.(*errors.KsiError).Code() != errors.KsiServiceInvalidRequest {
		t.Fatal("Unexpected error when getting calendar last time while status is not 0: ", err)
	}
}

func testExtRespFunctionsWithOkReq(t *testing.T, _ ...interface{}) {
	msg := "Error message"
	resp, calChain := createExtensionResponse()

	id, err := resp.RequestID()
	if err != nil {
		t.Fatal("Failed to get request id from extension response: ", err)
	}
	if id != uint64(1234) {
		t.Fatal("Unexpected request id: ", id)
	}

	resp.status = newUint64(12)
	status, err := resp.Status()
	if err != nil {
		t.Fatal("Failed to get response status from extension response: ", err)
	}
	if status != uint64(12) {
		t.Fatal("Unexpected status code: ", status)
	}

	resp.status = newUint64(0)
	status, err = resp.Status()
	if err != nil {
		t.Fatal("Failed to get response status from extension response: ", err)
	}
	if status != uint64(0) {
		t.Fatal("Unexpected status code: ", status)
	}

	resp.errorMsg = &msg
	errMsg, err := resp.ErrorMsg()
	if err != nil {
		t.Fatal("Failed to get error message from extension response: ", err)
	}
	if !strings.Contains(errMsg, msg) {
		t.Fatal("Unexpected error message: ", errMsg)
	}

	resp.errorMsg = nil
	errMsg, err = resp.ErrorMsg()
	if err != nil {
		t.Fatal("Failed to get error message from extension response: ", err)
	}
	if errMsg != "" {
		t.Fatal("Unexpected error message: ", errMsg)
	}

	last, err := resp.CalendarLast()
	if err != nil {
		t.Fatal("Failed to get last calendar from extension response: ", err)
	}
	if last != uint64(2323) {
		t.Fatal("Unexpected last calendar from extender: ", last)
	}

	resp.calLast = nil
	last, err = resp.CalendarLast()
	if err != nil {
		t.Fatal("Failed to get last calendar from extension response: ", err)
	}
	if last != uint64(0) {
		t.Fatal("Unexpected last calendar from extender: ", last)
	}

	respCalChain, err := resp.CalendarChain()
	if err != nil {
		t.Fatal("Failed to get calendar chain from extension response: ", err)
	}
	if err = respCalChain.VerifyCompatibility(calChain); err != nil {
		t.Fatal("Unexpected calendar chain: ", respCalChain)
	}
}

func testExtenderRespFunctionsWithNilReceiver(t *testing.T, _ ...interface{}) {
	var (
		resp *ExtenderResp
		cfg  Config
	)
	if _, err := resp.ExtendingResp(); err == nil {
		t.Fatal("Should not be possible to get extending response from nil extender response.")
	}

	if err := resp.Verify(hash.SHA2_256, "key"); err == nil {
		t.Fatal("Should not be possible to verify nil extender response.")
	}

	if err := resp.Err(); err == nil {
		t.Fatal("Should not be possible to get error from nil extender response.")
	}

	if _, err := resp.Encode(); err == nil {
		t.Fatal("Should not be possible to encode nil extender response.")
	}

	if err := resp.Decode([]byte{0x12, 0x23, 0x34, 0x45}); err == nil {
		t.Fatal("Should not be possible to decode with nil extender response.")
	}

	if _, err := resp.Config(); err == nil {
		t.Fatal("Should not be possible to get config from nil extender response.")
	}

	if err := resp.SetConfig(&cfg); err == nil {
		t.Fatal("Should not be possible to set config to nil extender response.")
	}

	if _, err := resp.Clone(); err == nil {
		t.Fatal("Should not be possible to clone nil extender response.")
	}
}

func testExtenderRespFunctionsWithInvalidReceiver(t *testing.T, _ ...interface{}) {
	var (
		resp = ExtenderResp{
			mac: newImprint(hash.SHA2_512.ZeroImprint()),
		}
		//header Header
	)

	if err := resp.Verify(hash.SHA2_256, "key"); err == nil || !strings.Contains(err.Error(), "Extender response must have a Header") {
		t.Fatal("Response verification should not be possible with no header.")
	}
	resp.header = &Header{}

	resp.mac = nil
	if err := resp.Verify(hash.SHA2_256, "key"); err == nil || !strings.Contains(err.Error(), "Extender response must have an HMAC") {
		t.Fatal("Response verification should not be possible with no mac.")
	}
	resp.header = nil

	if _, err := resp.Encode(); err == nil {
		t.Fatal("Should not be possible to encode nil extender response.")
	}

	if err := resp.Decode(nil); err == nil {
		t.Fatal("Should not be possible to decode nil bytes.")
	}

	if err := resp.Decode([]byte{0x12, 0x23, 0x34}); err == nil {
		t.Fatal("Should not be possible to decode non extension response.")
	}

	//FIXME: KSIGOAPI-76 Should not be possible to set nil config to the response.
	//err = resp.SetConfig(nil)
	//if err == nil {
	//	t.Fatal("Should not be possible to set nil config.")
	//}

	resp, _ = createExtenderResponse()

	if err := resp.Verify(hash.SHA2_256, "WrongKey"); err.(*errors.KsiError).Code() != errors.KsiHmacMismatch {
		t.Fatal("Unexpected error when hmac do not match: ", err)
	}

	if err := resp.Verify(hash.SHA2_512, "key"); err.(*errors.KsiError).Code() != errors.KsiHmacAlgorithmMismatch {
		t.Fatal("Unexpected error when hmac do not match: ", err)
	}

	resp.extResp.status = nil
	if err := resp.Err(); err.(*errors.KsiError).Code() != errors.KsiInvalidStateError {
		t.Fatal("Unexpected error when status field is missing from extension response: ", err)
	}

	msg := "Error message"
	extErr := &Error{
		status:   nil,
		errorMsg: &msg,
	}

	resp.extResp = nil
	resp.extErr = extErr
	if err := resp.Err(); err.(*errors.KsiError).Code() != errors.KsiInvalidStateError {
		t.Fatal("Unexpected error when status field is missing from extension error response: ", err)
	}
}

func testExtenderRespFunctionsWithOkReq(t *testing.T, _ ...interface{}) {
	resp, cfg := createExtenderResponse()

	response, err := resp.ExtendingResp()
	if err != nil {
		t.Fatal("Failed to get extension response: ", err)
	}
	if response == nil {
		t.Fatal("Response is nil.")
	}

	if err = resp.Verify(hash.SHA2_256, "key"); err != nil {
		t.Fatal("Failed to verify response: ", err)
	}

	if err = resp.Err(); err != nil {
		t.Fatal("Failed to get error from response: ", err)
	}

	encoded, err := resp.Encode()
	if err != nil {
		t.Fatal("Failed to encode response: ", err)
	}
	if encoded == nil {
		t.Fatal("Invalid encoded response: ", encoded)
	}

	config, err := resp.Config()
	if err != nil {
		t.Fatal("Failed to get config: ", err)
	}
	if config == nil || *config != cfg {
		t.Fatal("Invalid config was returned: ", config)
	}

	if err = resp.SetConfig(&cfg); err != nil {
		t.Fatal("Failed to set config: ", err)
	}

	clone, err := resp.Clone()
	if err != nil {
		t.Fatal("Failed to clone response: ", err)
	}
	if clone == nil {
		t.Fatal("Nil clone was returned.")
	}
}

func testExtenderRespFunctionsWithUnableToParseResponse(t *testing.T, _ ...interface{}) {
	var (
		testExtResp = filepath.Join(testTlvDir, "extender_unable_to_parse_response.tlv")
		expectedErr = "Unable to parse extender response!"
	)

	_, err := createExtenderRespFromFile(testExtResp)

	messages := errors.KsiErr(err).Message()

	if messages[2] != expectedErr {
		t.Fatalf("Expecting error message:\n%s\nBut got:\n%s", expectedErr, messages[2])
	}
}

func createExtensionResponse() (*ExtResp, *CalendarChain) {
	imprint := newImprint(hash.SHA2_256.ZeroImprint())

	chainLink := ChainLink{
		levelCorr:   newUint64(0),
		siblingHash: imprint,
		legacyID:    nil,
		metadata:    nil,
		isLeft:      false,
		isCalendar:  true,
	}

	chainLinks := append([]*ChainLink{}, &chainLink)

	calChain := &CalendarChain{
		pubTime:    newUint64(56566767),
		aggrTime:   newUint64(455667),
		inputHash:  imprint,
		chainLinks: &chainLinks,
	}

	resp := &ExtResp{
		id:       newUint64(1234),
		status:   newUint64(0),
		errorMsg: nil,
		calLast:  newUint64(2323),
		calChain: calChain,
	}
	return resp, calChain
}

func createExtenderResponse() (ExtenderResp, Config) {
	var (
		header, _ = NewHeader("LoginID", nil)

		extResp, _ = createExtensionResponse()
		cfg        = Config{
			calLast:  newUint64(8956),
			calFirst: newUint64(5632),
			maxReq:   newUint64(20),
		}

		resp = ExtenderResp{
			header:   header,
			extResp:  extResp,
			confResp: &cfg,
			mac:      newImprint(utils.StringToBin("010604648be68d63c09b269663c989860bcd1965f1aa5a1d71ca8291d9a3100923")),
		}
	)

	return resp, cfg
}

func createExtenderRespFromFile(testRespFile string) (*ExtenderResp, error) {
	raw, err := ioutil.ReadFile(testRespFile)
	if err != nil {
		return nil, errors.KsiErr(err).AppendMessage("Failed to open extender response file.")
	}

	resp := ExtenderResp{}
	if err = resp.Decode(raw); err != nil {
		return nil, errors.KsiErr(err).AppendMessage("Failed to decode extender response.")
	}

	return &resp, nil
}
