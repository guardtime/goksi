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

package service

import (
	"context"
	"fmt"
	"path/filepath"
	"strings"
	"testing"
	"time"
	"unsafe"

	"github.com/guardtime/goksi/errors"
	"github.com/guardtime/goksi/hash"
	"github.com/guardtime/goksi/log"
	"github.com/guardtime/goksi/pdu"
	"github.com/guardtime/goksi/publications"
	"github.com/guardtime/goksi/signature"
	"github.com/guardtime/goksi/test"
	"github.com/guardtime/goksi/test/utils/mock"
)

func TestUnitExtender(t *testing.T) {

	logger, defFunc, err := test.InitLogger(t, testLogDir, log.DEBUG, t.Name())
	if err != nil {
		t.Fatal("Failed to initialize logger: ", err)
	}
	defer defFunc()
	// Apply logger.
	log.SetLogger(logger)

	test.Suite{
		{Func: testCreateExtenderWithEmptyOptions},
		{Func: testCreateExtenderWithNilOptions},
		{Func: testSendWithExtender},
		{Func: testSendWithNonInitializedExtender},
		{Func: testSendNilRequest},
		{Func: testSendEmptyRequest},
		{Func: testExtendWithExtender},
		{Func: testExtendWithNotInitializedExtender},
		{Func: testExtendNilSignature},
		{Func: testExtendEmptySignature},
		{Func: testExtendToWithExtender},
		{Func: testExtendToWithNotInitializedExtender},
		{Func: testExtendToWithNilSignature},
		{Func: testExtendToWithEmptySignature},
		{Func: testExtendWithNilOption},
		{Func: testExtendOptionWithContextNil},
		{Func: testRequestConfigFromExtender},
		{Func: testRequestConfigFromNotInitializedExtender},
		{Func: testRequestCalendarFromExtender},
		{Func: testRequestCalendarNotInitializedExtender},
		{Func: testRequestCalendarWithInvalidTimeOrder},
		{Func: testInvalidExtenderResponses},
		{Func: testExtenderParallel},
		{Func: testExtenderHmacOption},
		{Func: testExtenderHmacAlgNotTrusted},
		{Func: testExtenderHmacAlgNotSupported},
		{Func: testExtenderHmacOptionOverride},
		{Func: testExtenderReqHdrFunc},
		{Func: testExtenderExtendWithConfListener},
		{Func: testExtenderTryToExtendBackwards},
		{Func: testExtenderResponseError},
		{Func: testExtenderReducedError},
		{Func: testExtenderWithAggregatorResponse},
	}.Runner(t)
}

var (
	nilReturnErrorMsgOnError = "Nil should be returned in case of error: "
)

func testCreateExtenderWithEmptyOptions(t *testing.T, _ ...interface{}) {
	var opts []Option

	ext, err := NewExtender(nil, opts...)
	if err == nil {
		t.Fatal("Extender creation should have failed with empty options list")
	}

	if ext != nil {
		t.Fatal(nilReturnErrorMsgOnError, err)
	}
}

func testCreateExtenderWithNilOptions(t *testing.T, _ ...interface{}) {
	ext, err := NewExtender(nil, nil)
	if err == nil {
		t.Fatal("Extender creation should have failed with nil options")
	}

	if ext != nil {
		t.Fatal(nilReturnErrorMsgOnError, err)
	}
}

func testSendWithExtender(t *testing.T, _ ...interface{}) {
	var (
		extender     *Extender
		emptyRequest pdu.ExtenderReq
	)
	resp, err := extender.Send(&emptyRequest)
	if err == nil {
		t.Fatal("It should not be possible to send request with nil extender")
	}

	if resp != nil {
		t.Fatal(nilReturnErrorMsgOnError, err)
	}
}

func testSendWithNonInitializedExtender(t *testing.T, _ ...interface{}) {
	var (
		extender     Extender
		emptyRequest pdu.ExtenderReq
	)
	resp, err := extender.Send(&emptyRequest)
	if err == nil {
		t.Fatal("It should not be possible to send request with not initialized extender")
	}

	if resp != nil {
		t.Fatal(nilReturnErrorMsgOnError, err)
	}
}

func testSendNilRequest(t *testing.T, _ ...interface{}) {
	ext, err := NewExtender(nil, OptNetClient(&mock.RequestCounterClient{}))
	if err != nil {
		t.Fatal("Failed to create extender: ", err)
	}

	resp, err := ext.Send(nil)
	if err == nil {
		t.Fatal("It should not be possible to send nil request")
	}

	if resp != nil {
		t.Fatal(nilReturnErrorMsgOnError, err)
	}
}

func testSendEmptyRequest(t *testing.T, _ ...interface{}) {
	var emptyExtReq pdu.ExtenderReq

	ext, err := NewExtender(nil, OptNetClient(&mock.RequestCounterClient{}))
	if err != nil {
		t.Fatal("Failed to create extender: ", err)
	}

	resp, err := ext.Send(&emptyExtReq)
	if err == nil {
		t.Fatal("It should not be possible to send request with not initialized request")
	}

	if resp != nil {
		t.Fatal(nilReturnErrorMsgOnError, err)
	}
}

func testExtendWithExtender(t *testing.T, _ ...interface{}) {
	var (
		emptySig signature.Signature
		extender *Extender
	)

	sig, err := extender.Extend(&emptySig)
	if err == nil {
		t.Fatal("It should not be possible to extend with nil extender")
	}

	if sig != nil {
		t.Fatal(nilReturnErrorMsgOnError, err)
	}
}

func testExtendWithNotInitializedExtender(t *testing.T, _ ...interface{}) {
	var (
		emptySig signature.Signature
		extender Extender
	)

	sig, err := extender.Extend(&emptySig)
	if err == nil {
		t.Fatal("It should not be possible to extend with not initialized extender")
	}

	if sig != nil {
		t.Fatal(nilReturnErrorMsgOnError, err)
	}
}

func testExtendNilSignature(t *testing.T, _ ...interface{}) {
	ext, err := NewExtender(nil, OptNetClient(&mock.RequestCounterClient{}))
	if err != nil {
		t.Fatal("Failed to create extender: ", err)
	}

	sig, err := ext.Extend(nil)
	if err == nil {
		t.Fatal("It is not possible to extend nil signature.")
	}
	if sig != nil {
		t.Fatal(nilReturnErrorMsgOnError, err)
	}
}

func testExtendEmptySignature(t *testing.T, _ ...interface{}) {
	var sig signature.Signature

	ext, err := NewExtender(nil, OptNetClient(&mock.RequestCounterClient{}))
	if err != nil {
		t.Fatal("Failed to create extender: ", err)
	}

	sigExtended, err := ext.Extend(&sig)
	if err == nil {
		t.Fatal("It is not possible to extend not initialized signature.")
	}
	if sigExtended != nil {
		t.Fatal(nilReturnErrorMsgOnError, err)
	}
}

func testExtendToWithExtender(t *testing.T, _ ...interface{}) {
	var (
		emptySig signature.Signature
		extender *Extender
	)

	sig, err := extender.Extend(&emptySig, ExtendOptionToTime(time.Now()))
	if err == nil {
		t.Fatal("It should not be possible to extend with nil extender")
	}

	if sig != nil {
		t.Fatal(nilReturnErrorMsgOnError, err)
	}
}

func testExtendToWithNotInitializedExtender(t *testing.T, _ ...interface{}) {
	var (
		emptySig signature.Signature
		extender Extender
	)

	sig, err := extender.Extend(&emptySig, ExtendOptionToTime(time.Now()))
	if err == nil {
		t.Fatal("It should not be possible to extend with not initialized extender")
	}

	if sig != nil {
		t.Fatal(nilReturnErrorMsgOnError, err)
	}
}

func testExtendToWithNilSignature(t *testing.T, _ ...interface{}) {
	ext, err := NewExtender(nil, OptNetClient(&mock.RequestCounterClient{}))
	if err != nil {
		t.Fatal("Failed to create extender: ", err)
	}

	sig, err := ext.Extend(nil, ExtendOptionToTime(time.Now()))
	if err == nil {
		t.Fatal("It is not possible to extend nil signature.")
	}
	if sig != nil {
		t.Fatal(nilReturnErrorMsgOnError, err)
	}
}

func testExtendToWithEmptySignature(t *testing.T, _ ...interface{}) {
	var sig signature.Signature

	ext, err := NewExtender(nil, OptNetClient(&mock.RequestCounterClient{}))
	if err != nil {
		t.Fatal("Failed to create extender: ", err)
	}

	extSig, err := ext.Extend(&sig, ExtendOptionToTime(time.Unix(1, 1)))
	if err == nil {
		t.Fatal("It is not possible to extend nil signature.")
	}
	if extSig != nil {
		t.Fatal(nilReturnErrorMsgOnError, err)
	}
}

func testExtendWithNilOption(t *testing.T, _ ...interface{}) {
	var (
		testSigFile  = filepath.Join(testResourceSigDir, "ok-sig-2014-04-30.1.ksig")
		testResponse = filepath.Join(testResourceTlvDir, "ok-sig-2014-04-30.1-extend_response-with-conf.tlv")
		testClient   = mock.NewFileReaderClient(testResponse, "anon", "anon")
		option       ExtendOption
	)

	pfh, err := publications.NewFileHandler()
	if err != nil {
		t.Fatal("Failed to initialize publications file handler: ", err)
	}

	srv, err := NewExtender(pfh,
		OptNetClient(testClient),
	)
	if err != nil {
		t.Fatal("Failed to create extender: ", err)
	}

	sig, err := signature.New(signature.BuildNoVerify(signature.BuildFromFile(testSigFile)))
	if err != nil {
		t.Fatal("Failed to create ksi signature from file: ", err)
	}

	if _, err = srv.Extend(sig, option); err == nil {
		t.Fatal("Must return error.")
	}

	if errors.KsiErr(err).Code() != errors.KsiInvalidArgumentError {
		t.Fatalf("Expecting error code:\n%s\nBut got:\n%s", errors.KsiInvalidArgumentError, errors.KsiErr(err).Code())
	}

	if errors.KsiErr(err).Message()[0] != "Provided option is nil." {
		t.Fatalf("Expecting \"%v\", but got \"%v\"!", "Provided option is nil.", errors.KsiErr(err).Message()[0])
	}
}

func testExtendOptionWithContextNil(t *testing.T, _ ...interface{}) {
	var (
		testSigFile  = filepath.Join(testResourceSigDir, "ok-sig-2014-04-30.1.ksig")
		testResponse = filepath.Join(testResourceTlvDir, "ok-sig-2014-04-30.1-extend_response-with-conf.tlv")
		testClient   = mock.NewFileReaderClient(testResponse, "anon", "anon")
		reqContext   context.Context
	)

	pfh, err := publications.NewFileHandler()
	if err != nil {
		t.Fatal("Failed to initialize publications file handler: ", err)
	}

	srv, err := NewExtender(pfh,
		OptNetClient(testClient),
	)
	if err != nil {
		t.Fatal("Failed to create extender: ", err)
	}

	sig, err := signature.New(signature.BuildNoVerify(signature.BuildFromFile(testSigFile)))
	if err != nil {
		t.Fatal("Failed to create ksi signature from file: ", err)
	}

	if _, err = srv.Extend(sig, ExtendOptionToTime(time.Time{}), ExtendOptionWithContext(reqContext)); err == nil {
		t.Fatal("Must return error.")
	}

	if errors.KsiErr(err).Code() != errors.KsiInvalidArgumentError {
		t.Fatalf("Expecting error code:\n%s\nBut got:\n%s", errors.KsiInvalidArgumentError, errors.KsiErr(err).Code())
	}

	if errors.KsiErr(err).Message()[1] != "Failed to resolve extend option." {
		t.Fatalf("Expecting \"%v\", but got \"%v\"!", "Failed to resolve extend option.", errors.KsiErr(err).Message()[1])
	}
}

func testRequestConfigFromExtender(t *testing.T, _ ...interface{}) {
	var (
		extender *Extender
	)

	cfg, err := extender.Config()
	if err == nil {
		t.Fatal("It should be not possible to request config from nil extender.")
	}
	if cfg != nil {
		t.Fatal(nilReturnErrorMsgOnError, err)
	}
}

func testRequestConfigFromNotInitializedExtender(t *testing.T, _ ...interface{}) {
	var (
		extender Extender
	)

	cfg, err := extender.Config()
	if err == nil {
		t.Fatal("It should be not possible to request config from empty extender.")
	}
	if cfg != nil {
		t.Fatal(nilReturnErrorMsgOnError, err)
	}
}

func testRequestCalendarFromExtender(t *testing.T, _ ...interface{}) {
	var (
		extender *Extender
	)

	cfg, err := extender.ReceiveCalendar(time.Now(), time.Now())
	if err == nil {
		t.Fatal("It should be not possible to request calendar from nil extender.")
	}
	if cfg != nil {
		t.Fatal(nilReturnErrorMsgOnError, err)
	}
}

func testRequestCalendarNotInitializedExtender(t *testing.T, _ ...interface{}) {
	var (
		extender Extender
	)

	cfg, err := extender.ReceiveCalendar(time.Now(), time.Now())
	if err == nil {
		t.Fatal("It should be not possible to request calendar from empty extender.")
	}
	if cfg != nil {
		t.Fatal(nilReturnErrorMsgOnError, err)
	}
}

func testRequestCalendarWithInvalidTimeOrder(t *testing.T, _ ...interface{}) {
	ext, err := NewExtender(nil, OptNetClient(&mock.RequestCounterClient{}))
	if err != nil {
		t.Fatal("Failed to create extender: ", err)
	}

	cal, err := ext.ReceiveCalendar(
		time.Date(2000, time.May, 1, 1, 1, 1, 1, time.Local),
		time.Date(1000, time.May, 1, 1, 1, 1, 1, time.Local))
	if err == nil {
		t.Fatal("It is not possible to request calendar with start time after the end time.")
	}
	if cal != nil {
		t.Fatal(nilReturnErrorMsgOnError, err)
	}
}

func testExtenderParallel(t *testing.T, _ ...interface{}) {
	const (
		testCount = 10
	)
	var (
		testFrom = time.Unix(1467331200, 0)
	)

	pfh, err := publications.NewFileHandler()
	if err != nil {
		t.Fatal("Failed to initialize publications file handler: ", err)
	}

	resultCh := make(chan error, testCount)
	for i := 0; i < testCount; i++ {
		go func(done chan error) {
			srv, err := NewExtender(pfh,
				OptNetClient(&mock.RequestCounterClient{}))
			if err != nil {
				done <- errors.KsiErr(err).AppendMessage("Failed to create extender.")
			}

			for k := 0; k < testCount; k++ {
				req, err := pdu.NewExtendingReq(testFrom)
				if err != nil {
					done <- errors.KsiErr(err).AppendMessage("Failed to create extending request.")
				}

				// Do not bother about the Send() response, it will fail.
				// We need for the request container to be updated prior to the actual message attempt.
				srv.Send(req)

				extReq, err := req.ExtendingReq()
				if err != nil {
					t.Fatal("Failed to extract aggregation request: ", err)
				}

				reqId, err := extReq.RequestID()
				if err != nil {
					done <- errors.KsiErr(err).AppendMessage("Failed to extract request ID.")
				}

				if reqId != uint64(k+1) {
					done <- errors.New(errors.KsiRequestIdMismatch).
						AppendMessage(fmt.Sprintf("request id mismatch: %d, extected: %d.", reqId, k+1))
				}
			}
			done <- nil
		}(resultCh)
	}
	// Wait for the workers to finish.
	count := testCount
	for {
		err := <-resultCh
		if err != nil {
			t.Error("Worker returned error: ", err)
		}
		count--
		if count == 0 {
			break
		}
	}
}

func testExtenderHmacOption(t *testing.T, _ ...interface{}) {
	var (
		testAlgorithm = hash.SHA2_512
	)

	pfh, err := publications.NewFileHandler()
	if err != nil {
		t.Fatal("Failed to initialize publications file handler: ", err)
	}

	srv, err := NewExtender(pfh,
		OptNetClient(&mock.RequestCounterClient{}),
		OptHmacAlgorithm(testAlgorithm),
	)
	if err != nil {
		t.Fatal("Failed to create extender: ", err)
	}

	req, err := pdu.NewExtenderConfigReq()
	if err != nil {
		t.Fatal("Failed to create extender request: ", err)
	}

	// Don't care about the result.
	_, _ = srv.Send(req)

	mac, err := req.HMAC()
	if err != nil {
		t.Fatal("Failed to get the HMAC: ", err)
	}
	if mac.Algorithm() != testAlgorithm {
		t.Fatal("HMAC algorithm mismatch.")
	}
}

func testExtenderHmacAlgNotTrusted(t *testing.T, _ ...interface{}) {
	var (
		testAlgorithm = hash.SHA1
	)

	pfh, err := publications.NewFileHandler()
	if err != nil {
		t.Fatal("Failed to initialize publications file handler: ", err)
	}

	srv, err := NewExtender(pfh,
		OptNetClient(&mock.RequestCounterClient{}),
		OptHmacAlgorithm(testAlgorithm),
	)
	if err == nil || srv != nil {
		t.Fatal("Must fail with untrusted algorithm.")
	}
}

func testExtenderHmacAlgNotSupported(t *testing.T, _ ...interface{}) {
	var (
		testAlgorithm = hash.SM3
	)

	pfh, err := publications.NewFileHandler()
	if err != nil {
		t.Fatal("Failed to initialize publications file handler: ", err)
	}

	srv, err := NewExtender(pfh,
		OptNetClient(&mock.RequestCounterClient{}),
		OptHmacAlgorithm(testAlgorithm),
	)
	if err == nil || srv != nil {
		t.Fatal("Must fail with unsupported algorithm.")
	}
}

func testExtenderHmacOptionOverride(t *testing.T, _ ...interface{}) {
	var (
		testAlgorithm = hash.SHA2_384
	)

	pfh, err := publications.NewFileHandler()
	if err != nil {
		t.Fatal("Failed to initialize publications file handler: ", err)
	}

	srv, err := NewExtender(pfh,
		OptNetClient(&mock.RequestCounterClient{}),
		OptHmacAlgorithm(testAlgorithm),
	)
	if err != nil {
		t.Fatal("Failed to create extender: ", err)
	}

	req, err := pdu.NewExtenderConfigReq()
	if err != nil {
		t.Fatal("Failed to create extender request: ", err)
	}

	// Don't care about the result.
	_, _ = srv.Send(req)

	mac, err := req.HMAC()
	if err != nil {
		t.Fatal("Failed to get the HMAC: ", err)
	}
	if mac.Algorithm() != testAlgorithm {
		t.Fatal("HMAC algorithm mismatch.")
	}
}

func testExtenderReqHdrFunc(t *testing.T, _ ...interface{}) {
	var (
		client = &mock.RequestCounterClient{}
		instID = uint64(uintptr(unsafe.Pointer(t)))
		msgID  uint64
	)

	pfh, err := publications.NewFileHandler()
	if err != nil {
		t.Fatal("Failed to initialize publications file handler: ", err)
	}

	srv, err := NewExtender(pfh,
		OptNetClient(client),
		OptRequestHeaderFunc(func(h *pdu.Header) error {
			if h == nil {
				return errors.New(errors.KsiInvalidArgumentError)
			}
			if err := h.SetInstID(instID); err != nil {
				return err
			}
			if err := h.SetMsgID(msgID); err != nil {
				return err
			}
			return nil
		}),
	)
	if err != nil {
		t.Fatal("Failed to create extender: ", err)
	}

	for ; msgID < 10; msgID++ {
		req, err := pdu.NewExtendingReq(time.Now())
		if err != nil {
			t.Fatal("Failed to create extender request: ", err)
		}

		srv.Send(req)

		header, err := req.Header()
		if err != nil {
			t.Fatal("Failed to extract header: ", err)
		}

		hdrLoginID, err := header.LoginID()
		if err != nil {
			t.Fatal("Failed to extract header login ID: ", err)
		}
		if hdrLoginID != client.LoginID() {
			t.Fatal("Header login id mismatch.")
		}

		hrdInstID, err := header.InstanceID()
		if err != nil {
			t.Fatal("Failed to extract header instance ID: ", err)
		}
		if hrdInstID != instID {
			t.Fatal("Header instance id mismatch.")
		}

		hrdMsgID, err := header.MessageID()
		if err != nil {
			t.Fatal("Failed to extract header message ID: ", err)
		}
		if hrdMsgID != msgID {
			t.Fatal("Header message id mismatch.")
		}
	}
}

func testExtenderExtendWithConfListener(t *testing.T, _ ...interface{}) {
	var (
		testSigFile         = filepath.Join(testResourceSigDir, "ok-sig-2014-04-30.1.ksig")
		testResponse        = filepath.Join(testResourceTlvDir, "ok-sig-2014-04-30.1-extend_response-with-conf.tlv")
		testClient          = mock.NewFileReaderClient(testResponse, "anon", "anon")
		testCallbackInvoked = false
	)

	pfh, err := publications.NewFileHandler()
	if err != nil {
		t.Fatal("Failed to initialize publications file handler: ", err)
	}

	srv, err := NewExtender(pfh,
		OptNetClient(testClient),
		OptConfigListener(func(c *pdu.Config) error {
			if c == nil {
				return errors.New(errors.KsiInvalidArgumentError)
			}
			testCallbackInvoked = true
			return nil
		}),
	)
	if err != nil {
		t.Fatal("Failed to create signer: ", err)
	}

	sig, err := signature.New(signature.BuildNoVerify(signature.BuildFromFile(testSigFile)))
	if err != nil {
		t.Fatal("Failed to create ksi signature from file: ", err)
	}

	resp, err := srv.Extend(sig, ExtendOptionToTime(time.Time{}))
	if err != nil {
		t.Fatal("Failed to sign: ", err)
	}
	if resp == nil {
		t.Fatal("Signature must be returned.")
	}

	if !testCallbackInvoked {
		t.Fatal("Listener callback should have been invoked.")
	}
}

func testInvalidExtenderResponses(t *testing.T, _ ...interface{}) {
	var (
		testExtResponses = [...]struct {
			file    string
			errMsg  string
			errCode errors.ErrorCode
		}{
			{filepath.Join(testResourceTlvDir, "aggr_reduced_error_101.tlv"), "Invalid response", errors.KsiInvalidFormatError},
			{filepath.Join(testResourceTlvDir, "ok-sig-2014-07-01.1-aggr_response.tlv"), "Invalid response", errors.KsiInvalidFormatError},
		}
	)

	pfh, err := publications.NewFileHandler()
	if err != nil {
		t.Fatal("Failed to initialize publications file handler: ", err)
	}

	for _, d := range testExtResponses {
		extender, err := NewExtender(pfh,
			OptNetClient(mock.NewFileReaderClient(d.file, "anon", "anon")),
		)
		if err != nil {
			t.Fatal("Failed to create extender: ", err)
		}

		req, err := pdu.NewExtendingReq(time.Now())
		if err != nil {
			t.Fatal("Failed to create request: ", err)
		}

		_, err = extender.Send(req)
		if err == nil {
			t.Fatal("Must return error.")
		}

		ksierr := errors.KsiErr(err)
		if ksierr.Code() != d.errCode {
			t.Fatal("Unexpected error code, expected vs actual: ", d.errCode, ksierr.Code())
		}
		if ksierr.Message() != nil {
			if strings.Contains(ksierr.Message()[0], d.errMsg) {
				t.Error("Extension error message mismatch.")
			}
		}
	}
}

func testExtenderTryToExtendBackwards(t *testing.T, _ ...interface{}) {
	var (
		testSigFile       = filepath.Join(testResourceSigDir, "ok-sig-2014-04-30.1.ksig")
		dummyTestResponse = filepath.Join(testResourceTlvDir, "ok-sig-2014-04-30.1-extend_response-with-conf.tlv")
		testClient        = mock.NewFileReaderClient(dummyTestResponse, "anon", "anon")
	)

	pfh, err := publications.NewFileHandler()
	if err != nil {
		t.Fatal("Failed to initialize publications file handler: ", err)
	}

	srv, err := NewExtender(pfh,
		OptNetClient(testClient),
	)
	if err != nil {
		t.Fatal("Failed to create signer: ", err)
	}

	sig, err := signature.New(signature.BuildNoVerify(signature.BuildFromFile(testSigFile)))
	if err != nil {
		t.Fatal("Failed to create ksi signature from file: ", err)
	}

	sigtime, err := sig.SigningTime()
	if err != nil {
		t.Fatal("Failed to get signing time: ", err)
	}

	resp, err := srv.Extend(sig, ExtendOptionToTime(sigtime.Add(-1*time.Second)))
	if err == nil {
		t.Fatal("This call should have been failed.")
	}

	if resp != nil {
		t.Fatal("Response must be nil!")
	}

	if errors.KsiErr(err).Code() != errors.KsiServiceExtenderInvalidTimeRange {
		t.Fatalf("This call should have been with %v instead of %v!", errors.KsiServiceExtenderInvalidTimeRange, errors.KsiErr(err).Code())
	}
}

func testExtenderResponseError(t *testing.T, _ ...interface{}) {
	var (
		testExtResponses = [...]struct {
			file   string
			extErr int
		}{
			{filepath.Join(testResourceTlvDir, "ok_extender_error_response_101.tlv"), 0x101},
			{filepath.Join(testResourceTlvDir, "ok_extender_error_response_102.tlv"), 0x102},
			{filepath.Join(testResourceTlvDir, "ok_extender_error_response_103.tlv"), 0x103},
			{filepath.Join(testResourceTlvDir, "ok_extender_error_response_104.tlv"), 0x104},
			{filepath.Join(testResourceTlvDir, "ok_extender_error_response_105.tlv"), 0x105},
			{filepath.Join(testResourceTlvDir, "ok_extender_error_response_106.tlv"), 0x106},
			{filepath.Join(testResourceTlvDir, "ok_extender_error_response_107.tlv"), 0x107},
			{filepath.Join(testResourceTlvDir, "ok_extender_error_response_200.tlv"), 0x200},
			{filepath.Join(testResourceTlvDir, "ok_extender_error_response_201.tlv"), 0x201},
			{filepath.Join(testResourceTlvDir, "ok_extender_error_response_202.tlv"), 0x202},
			{filepath.Join(testResourceTlvDir, "ok_extender_error_response_300.tlv"), 0x300},
			{filepath.Join(testResourceTlvDir, "ok_extender_error_response_301.tlv"), 0x301},
		}
	)

	pfh, err := publications.NewFileHandler()
	if err != nil {
		t.Fatal("Failed to initialize publications file handler: ", err)
	}

	for _, d := range testExtResponses {
		extender, err := NewExtender(pfh,
			OptNetClient(mock.NewFileReaderClient(d.file, "anon", "anon")),
		)
		if err != nil {
			t.Fatal("Failed to create extender: ", err)
		}

		req, err := pdu.NewExtendingReq(time.Now())
		if err != nil {
			t.Fatal("Failed to create request: ", err)
		}

		_, err = extender.Send(req)
		if err == nil {
			t.Fatal("Must return error.")
		}
		if errors.KsiErr(err).ExtCode() != d.extErr {
			t.Error("Ext error code mismatch.")
		}
	}
}

func testExtenderReducedError(t *testing.T, _ ...interface{}) {
	var (
		testExtResponses = []struct {
			file   string
			extErr int
		}{
			{filepath.Join(testResourceTlvDir, "ext_reduced_error_101.tlv"), 0x101},
		}
	)

	pfh, err := publications.NewFileHandler()
	if err != nil {
		t.Fatal("Failed to initialize publications file handler: ", err)
	}

	for _, d := range testExtResponses {
		extender, err := NewExtender(pfh,
			OptNetClient(mock.NewFileReaderClient(d.file, "anon", "anon")),
		)
		if err != nil {
			t.Fatal("Failed to create extender: ", err)
		}

		req, err := pdu.NewExtendingReq(time.Now())
		if err != nil {
			t.Fatal("Failed to create request: ", err)
		}

		_, err = extender.Send(req)
		if err == nil {
			t.Fatal("Must return error.")
		}
		if err.(*errors.KsiError).ExtCode() != d.extErr {
			t.Error("Ext error code mismatch.")
		}
	}
}

func testExtenderWithAggregatorResponse(t *testing.T, _ ...interface{}) {
	var (
		testResponse = filepath.Join(testResourceTlvDir, "aggr_reduced_error_101.tlv")
		testClient   = mock.NewFileReaderClient(testResponse, "anon", "anon")
		expectedErr  = "Unexpected extender response PDU type: 0x221!"
	)

	pfh, err := publications.NewFileHandler()
	if err != nil {
		t.Fatal("Failed to initialize publications file handler: ", err)
	}

	srv, err := NewExtender(pfh,
		OptNetClient(testClient),
	)
	if err != nil {
		t.Fatal("Failed to create extender: ", err)
	}

	req, err := pdu.NewExtenderConfigReq()
	if err != nil {
		t.Fatal("Failed to create extender request: ", err)
	}

	_, err = srv.Send(req)
	if err == nil {
		t.Fatal("Aggregator response instead of extender response must fail!")
	}

	messages := errors.KsiErr(err).Message()

	if messages[0] != expectedErr {
		t.Fatalf("Expecting error message:\n%s\nBut got:\n%s", expectedErr, messages[0])
	}
}
