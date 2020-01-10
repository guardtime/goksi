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
	"fmt"
	"path/filepath"
	"testing"
	"unsafe"

	"github.com/guardtime/goksi/errors"
	"github.com/guardtime/goksi/hash"
	"github.com/guardtime/goksi/log"
	"github.com/guardtime/goksi/pdu"
	"github.com/guardtime/goksi/publications"
	"github.com/guardtime/goksi/signature"
	"github.com/guardtime/goksi/signature/verify/result"
	"github.com/guardtime/goksi/test"
	"github.com/guardtime/goksi/test/utils/mock"
)

func TestUnitSigner(t *testing.T) {

	logger, defFunc, err := test.InitLogger(t, testLogDir, log.DEBUG, t.Name())
	if err != nil {
		t.Fatal("Failed to initialize logger: ", err)
	}
	defer defFunc()
	// Apply logger.
	log.SetLogger(logger)

	test.Suite{
		{Func: testCreateSignerWithEmptyOptions},
		{Func: testCreateSignerWithNilOptions},
		{Func: testSendWithNilReceiver},
		{Func: testSendWithNotInitializedSigner},
		{Func: testSignWithNilReceiver},
		{Func: testSignWithNotInitializedSigner},
		{Func: testSignOptionsWithNilReceiver},
		{Func: testSignOptionsInvalidInput},
		{Func: testSignWithNilOpt},
		{Func: testSignWithOptListContainingNil},
		{Func: testRequestConfigFromNilSigner},
		{Func: testRequestConfigFromNotInitializedSigner},
		{Func: testSignerHmacOption},
		{Func: testSignerHmacAlgNotTrusted},
		{Func: testSignerHmacAlgNotSupported},
		{Func: testSignerHmacOptionOverride},
		{Func: testSignerWithRandomResponse},
		{Func: testParallelSigners},
		{Func: testSignerReqHdrFunc},
		{Func: testSignerSignWithConfListener},
		{Func: testSignerResponseError},
		{Func: testSignerReducedError},
		{Func: testSignerResponseAndReducedError},
		{Func: testSignerSignWithOptionsInternalPolicy},
		{Func: testSignerSignWithOptionsFailPolicy},
		{Func: testSignerSignWithPolicyOptionNil},
		{Func: testSignerSignWithOptionsDefaultPolicyNoExtraOptions},
		{Func: testSignerSignWithOptionsDefaultPolicyAndPubFile},
		{Func: testSignerWithExtenderResponse},
	}.Runner(t)
}

func testCreateSignerWithEmptyOptions(t *testing.T, _ ...interface{}) {
	var opts []Option

	signer, err := NewSigner(opts...)
	if err == nil {
		t.Fatal("Signer creation should have failed with empty options list.")
	}

	if signer != nil {
		t.Fatal(nilReturnErrorMsgOnError, err)
	}
}

func testCreateSignerWithNilOptions(t *testing.T, _ ...interface{}) {
	signer, err := NewSigner(nil)
	if err == nil {
		t.Fatal("Signer creation should have failed with nil.")
	}

	if signer != nil {
		t.Fatal(nilReturnErrorMsgOnError, err)
	}
}

func testSendWithNilReceiver(t *testing.T, _ ...interface{}) {
	var (
		signer       *Signer
		emptyRequest pdu.AggregatorReq
	)

	resp, err := signer.Send(&emptyRequest)
	if err == nil {
		t.Fatal("It should not be possible to send request with nil signer")
	}

	if resp != nil {
		t.Fatal(nilReturnErrorMsgOnError, err)
	}
}

func testSendWithNotInitializedSigner(t *testing.T, _ ...interface{}) {
	var (
		signer       Signer
		emptyRequest pdu.AggregatorReq
	)

	resp, err := signer.Send(&emptyRequest)
	if err == nil {
		t.Fatal("It should not be possible to send request with not initialized signer")
	}

	if resp != nil {
		t.Fatal(nilReturnErrorMsgOnError, err)
	}
}

func testSignWithNilReceiver(t *testing.T, _ ...interface{}) {
	var (
		signer      *Signer
		testImprint = hash.Imprint{0x01,
			0xc4, 0xbb, 0xcb, 0x1f, 0xbe, 0xc9, 0x9d, 0x65,
			0xbf, 0x59, 0xd8, 0x5c, 0x8c, 0xb6, 0x2e, 0xe2,
			0xdb, 0x96, 0x3f, 0x0f, 0xe1, 0x06, 0xf4, 0x83,
			0xd9, 0xaf, 0xa7, 0x3b, 0xd4, 0xe3, 0x9a, 0x8a,
		}
	)

	resp, err := signer.Sign(testImprint)
	if err == nil {
		t.Fatal("It should not be possible to sign with nil signer")
	}

	if resp != nil {
		t.Fatal(nilReturnErrorMsgOnError, err)
	}
}

func testSignWithNotInitializedSigner(t *testing.T, _ ...interface{}) {
	var (
		signer      Signer
		testImprint = hash.Imprint{0x01,
			0xc4, 0xbb, 0xcb, 0x1f, 0xbe, 0xc9, 0x9d, 0x65,
			0xbf, 0x59, 0xd8, 0x5c, 0x8c, 0xb6, 0x2e, 0xe2,
			0xdb, 0x96, 0x3f, 0x0f, 0xe1, 0x06, 0xf4, 0x83,
			0xd9, 0xaf, 0xa7, 0x3b, 0xd4, 0xe3, 0x9a, 0x8a,
		}
	)

	resp, err := signer.Sign(testImprint)
	if err == nil {
		t.Fatal("It should not be possible to sign with not initialized signer")
	}

	if resp != nil {
		t.Fatal(nilReturnErrorMsgOnError, err)
	}
}

func testSignOptionsWithNilReceiver(t *testing.T, _ ...interface{}) {
	var (
		sigOptions *signOptions
	)
	opt := SignOptionLevel(1)
	if err := opt(sigOptions); err == nil {
		t.Fatal("Should not be possible to execute SignOptionLevel with nil sig options base object.")
	}

	opt = SignOptionVerificationPolicy(signature.SuccessPolicy)
	if err := opt(sigOptions); err == nil {
		t.Fatal("Should not be possible to execute SignOptionVerificationPolicy with nil sig options base object.")
	}

	opt = SignOptionVerificationOptions(signature.VerCtxOptInputHashLevel(1))
	if err := opt(sigOptions); err == nil {
		t.Fatal("Should not be possible to execute SignOptionVerificationOptions with nil sig options base object.")
	}
}

func testSignOptionsInvalidInput(t *testing.T, _ ...interface{}) {
	var (
		sigOptions signOptions
		verCtxOpt  []signature.VerCtxOption
	)

	opt := SignOptionVerificationPolicy(nil)
	if err := opt(&sigOptions); err == nil {
		t.Fatal("Should not be possible to execute SignOptionVerificationPolicy with nil policy input.")
	}

	opt = SignOptionVerificationOptions()
	if err := opt(&sigOptions); err == nil {
		t.Fatal("Should not be possible to execute SignOptionVerificationOptions with no verification option input.")
	}

	opt = SignOptionVerificationOptions(nil)
	if err := opt(&sigOptions); err == nil {
		t.Fatal("Should not be possible to execute SignOptionVerificationOptions with nil verification option.")
	}

	opt = SignOptionVerificationOptions(verCtxOpt...)
	if err := opt(&sigOptions); err == nil {
		t.Fatal("Should not be possible to execute SignOptionVerificationOptions with empty verification option.")
	}
}

func testSignWithNilOpt(t *testing.T, _ ...interface{}) {
	var (
		signer      Signer
		testImprint = hash.Imprint{0x01,
			0xc4, 0xbb, 0xcb, 0x1f, 0xbe, 0xc9, 0x9d, 0x65,
			0xbf, 0x59, 0xd8, 0x5c, 0x8c, 0xb6, 0x2e, 0xe2,
			0xdb, 0x96, 0x3f, 0x0f, 0xe1, 0x06, 0xf4, 0x83,
			0xd9, 0xaf, 0xa7, 0x3b, 0xd4, 0xe3, 0x9a, 0x8a,
		}
	)

	resp, err := signer.Sign(testImprint, nil)
	if err == nil {
		t.Fatal("It should not be possible to sign with nil option.")
	}

	if resp != nil {
		t.Fatal(nilReturnErrorMsgOnError, err)
	}
}

func testSignWithOptListContainingNil(t *testing.T, _ ...interface{}) {
	var (
		signer      Signer
		testImprint = hash.Imprint{0x01,
			0xc4, 0xbb, 0xcb, 0x1f, 0xbe, 0xc9, 0x9d, 0x65,
			0xbf, 0x59, 0xd8, 0x5c, 0x8c, 0xb6, 0x2e, 0xe2,
			0xdb, 0x96, 0x3f, 0x0f, 0xe1, 0x06, 0xf4, 0x83,
			0xd9, 0xaf, 0xa7, 0x3b, 0xd4, 0xe3, 0x9a, 0x8a,
		}
		signOpt = []SignOption{nil}
	)

	resp, err := signer.Sign(testImprint, signOpt...)
	if err == nil {
		t.Fatal("It should not be possible to sign with signing option that is nil.")
	}

	if resp != nil {
		t.Fatal(nilReturnErrorMsgOnError, err)
	}
}

func testRequestConfigFromNilSigner(t *testing.T, _ ...interface{}) {
	var (
		signer *Signer
	)

	resp, err := signer.Config()
	if err == nil {
		t.Fatal("It should not be possible to request config with nil signer")
	}

	if resp != nil {
		t.Fatal(nilReturnErrorMsgOnError, err)
	}
}

func testRequestConfigFromNotInitializedSigner(t *testing.T, _ ...interface{}) {
	var (
		signer Signer
	)

	resp, err := signer.Config()
	if err == nil {
		t.Fatal("It should not be possible to request config with not initialized signer")
	}

	if resp != nil {
		t.Fatal(nilReturnErrorMsgOnError, err)
	}
}

func testParallelSigners(t *testing.T, _ ...interface{}) {
	var (
		testImprint = hash.Imprint{0x01,
			0xc4, 0xbb, 0xcb, 0x1f, 0xbe, 0xc9, 0x9d, 0x65, 0xbf, 0x59, 0xd8, 0x5c, 0x8c, 0xb6, 0x2e, 0xe2,
			0xdb, 0x96, 0x3f, 0x0f, 0xe1, 0x06, 0xf4, 0x83, 0xd9, 0xaf, 0xa7, 0x3b, 0xd4, 0xe3, 0x9a, 0x8a,
		}
	)
	const (
		testCount = 10
	)

	resultCh := make(chan error, testCount)
	for i := 0; i < testCount; i++ {
		go func(done chan error) {
			srv, err := NewSigner(OptNetClient(&mock.RequestCounterClient{}))
			if err != nil {
				done <- errors.KsiErr(err).AppendMessage("Failed to create signer.")
			}

			for k := 0; k < testCount; k++ {
				req, err := pdu.NewAggregationReq(testImprint)
				if err != nil {
					done <- errors.KsiErr(err).AppendMessage("Failed to create aggregator request.")
				}

				// Do not bother about the Send() response, it will fail.
				// We need for the request container to be updated prior to the actual message attempt.
				srv.Send(req)

				aggrReq, err := req.AggregationReq()
				if err != nil {
					t.Fatal("Failed to extract aggregation request: ", err)
				}

				id, err := aggrReq.RequestID()
				if err != nil {
					done <- errors.KsiErr(err).AppendMessage("Failed to get request id.")
				}

				if id != uint64(k+1) {
					done <- errors.New(errors.KsiRequestIdMismatch).
						AppendMessage(fmt.Sprintf("Aggregation request id mismatch: %d, expected: %d.", id, k+1))
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

func testSignerHmacOption(t *testing.T, _ ...interface{}) {
	var (
		testAlgorithm = hash.SHA2_512
	)

	srv, err := NewSigner(
		OptNetClient(&mock.RequestCounterClient{}),
		OptHmacAlgorithm(testAlgorithm),
	)
	if err != nil {
		t.Fatal("Failed to create signer: ", err)
	}

	req, err := pdu.NewAggregatorConfigReq()
	if err != nil {
		t.Fatal("Failed to create signer request: ", err)
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

func testSignerReqHdrFunc(t *testing.T, _ ...interface{}) {
	var (
		testImprint = hash.Imprint{0x01,
			0xc4, 0xbb, 0xcb, 0x1f, 0xbe, 0xc9, 0x9d, 0x65, 0xbf, 0x59, 0xd8, 0x5c, 0x8c, 0xb6, 0x2e, 0xe2,
			0xdb, 0x96, 0x3f, 0x0f, 0xe1, 0x06, 0xf4, 0x83, 0xd9, 0xaf, 0xa7, 0x3b, 0xd4, 0xe3, 0x9a, 0x8a,
		}
		client = &mock.RequestCounterClient{}
		instID = uint64(uintptr(unsafe.Pointer(t)))
		msgID  uint64
	)

	srv, err := NewSigner(
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
		t.Fatal("Failed to create signer: ", err)
	}

	for ; msgID < 10; msgID++ {
		req, err := pdu.NewAggregationReq(testImprint)
		if err != nil {
			t.Fatal("Failed to create signer request: ", err)
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

func testSignerSignWithConfListener(t *testing.T, _ ...interface{}) {
	var (
		testImprint = hash.Imprint{0x01,
			0x11, 0xa7, 0x00, 0xb0, 0xc8, 0x06, 0x6c, 0x47, 0xec, 0xba, 0x05, 0xed, 0x37, 0xbc, 0x14, 0xdc,
			0xad, 0xb2, 0x38, 0x55, 0x2d, 0x86, 0xc6, 0x59, 0x34, 0x2d, 0x1d, 0x7e, 0x87, 0xb8, 0x77, 0x2d,
		}
		testResponse        = filepath.Join(testResourceTlvDir, "ok-sig-2014-07-01.1-aggr_response-with-conf-and-ack.tlv")
		testClient          = mock.NewFileReaderClient(testResponse, "anon", "anon")
		testCallbackInvoked = false
	)

	srv, err := NewSigner(
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

	resp, err := srv.Sign(testImprint)
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

func testSignerReducedError(t *testing.T, _ ...interface{}) {
	var (
		testAggrResponses = []struct {
			file   string
			extErr int
		}{
			{filepath.Join(testResourceTlvDir, "aggr_reduced_error_101.tlv"), 0x101},
		}

		testImprint = hash.Imprint{0x01,
			0x11, 0xa7, 0x00, 0xb0, 0xc8, 0x06, 0x6c, 0x47, 0xec, 0xba, 0x05, 0xed, 0x37, 0xbc, 0x14, 0xdc,
			0xad, 0xb2, 0x38, 0x55, 0x2d, 0x86, 0xc6, 0x59, 0x34, 0x2d, 0x1d, 0x7e, 0x87, 0xb8, 0x77, 0x2d,
		}
	)

	for _, d := range testAggrResponses {
		srv, err := NewSigner(
			OptNetClient(mock.NewFileReaderClient(d.file, "anon", "anon")),
		)
		if err != nil {
			t.Fatal("Failed to create aggregator: ", err)
		}

		resp, err := srv.Sign(testImprint)
		if err == nil {
			t.Fatal("Failed to sign: ", err)
		}
		if resp != nil {
			t.Fatal("Signature must not be returned.")
		}
		if err.(*errors.KsiError).ExtCode() != d.extErr {
			t.Error("Aggregator reduced error code mismatch.", err)
		}
	}
}

func testSignerResponseAndReducedError(t *testing.T, _ ...interface{}) {
	var (
		testAggrResponse = filepath.Join(testResourceTlvDir, "nok_aggr_response_and_reduced_error_301.tlv")
		testImprint      = hash.Imprint{0x01,
			0x11, 0xa7, 0x00, 0xb0, 0xc8, 0x06, 0x6c, 0x47, 0xec, 0xba, 0x05, 0xed, 0x37, 0xbc, 0x14, 0xdc,
			0xad, 0xb2, 0x38, 0x55, 0x2d, 0x86, 0xc6, 0x59, 0x34, 0x2d, 0x1d, 0x7e, 0x87, 0xb8, 0x77, 0x2d,
		}
	)

	srv, err := NewSigner(
		OptNetClient(mock.NewFileReaderClient(testAggrResponse, "anon", "anon")),
	)
	if err != nil {
		t.Fatal("Failed to create signer: ", err)
	}

	resp, err := srv.Sign(testImprint)
	if err == nil {
		t.Fatal("Signing must fail.")
	}
	if resp != nil {
		t.Fatal("Signature must not be returned.")
	}
}

func testSignerSignWithOptionsInternalPolicy(t *testing.T, _ ...interface{}) {
	var (
		testAggrResponse = filepath.Join(testResourceTlvDir, "ok-sig-2014-07-01.1-aggr_response.tlv")
		testImprint      = hash.Imprint{0x01,
			0x11, 0xa7, 0x00, 0xb0, 0xc8, 0x06, 0x6c, 0x47, 0xec, 0xba, 0x05, 0xed, 0x37, 0xbc, 0x14, 0xdc,
			0xad, 0xb2, 0x38, 0x55, 0x2d, 0x86, 0xc6, 0x59, 0x34, 0x2d, 0x1d, 0x7e, 0x87, 0xb8, 0x77, 0x2d,
		}
	)

	srv, err := NewSigner(
		OptNetClient(mock.NewFileReaderClient(testAggrResponse, "anon", "anon")),
	)
	if err != nil {
		t.Fatal("Failed to create signer: ", err)
	}

	sig, err := srv.Sign(testImprint,
		SignOptionVerificationPolicy(signature.InternalVerificationPolicy),
	)
	if err != nil {
		t.Fatal("Failed to receive response: ", err)
	}
	if sig == nil {
		t.Fatal("KSI signature must be returned.")
	}
}

func testSignerSignWithOptionsFailPolicy(t *testing.T, _ ...interface{}) {
	var (
		testAggrResponse = filepath.Join(testResourceTlvDir, "ok-sig-2014-07-01.1-aggr_response.tlv")
		testImprint      = hash.Imprint{0x01,
			0x11, 0xa7, 0x00, 0xb0, 0xc8, 0x06, 0x6c, 0x47, 0xec, 0xba, 0x05, 0xed, 0x37, 0xbc, 0x14, 0xdc,
			0xad, 0xb2, 0x38, 0x55, 0x2d, 0x86, 0xc6, 0x59, 0x34, 0x2d, 0x1d, 0x7e, 0x87, 0xb8, 0x77, 0x2d,
		}
	)

	srv, err := NewSigner(
		OptNetClient(mock.NewFileReaderClient(testAggrResponse, "anon", "anon")),
	)
	if err != nil {
		t.Fatal("Failed to create signer: ", err)
	}

	sig, err := srv.Sign(testImprint,
		SignOptionVerificationPolicy(signature.FailPolicy),
	)
	if err == nil {
		t.Fatal("Must fail to receive response: ", err)
	}
	if sig != nil {
		t.Fatal("No KSI signature must be returned.")
	}
}

func testSignerSignWithPolicyOptionNil(t *testing.T, _ ...interface{}) {
	var (
		testAggrResponse = filepath.Join(testResourceTlvDir, "ok-sig-2014-07-01.1-aggr_response.tlv")
		testImprint      = hash.Imprint{0x01,
			0x11, 0xa7, 0x00, 0xb0, 0xc8, 0x06, 0x6c, 0x47, 0xec, 0xba, 0x05, 0xed, 0x37, 0xbc, 0x14, 0xdc,
			0xad, 0xb2, 0x38, 0x55, 0x2d, 0x86, 0xc6, 0x59, 0x34, 0x2d, 0x1d, 0x7e, 0x87, 0xb8, 0x77, 0x2d,
		}
	)

	srv, err := NewSigner(
		OptNetClient(mock.NewFileReaderClient(testAggrResponse, "anon", "anon")),
	)
	if err != nil {
		t.Fatal("Failed to create signer: ", err)
	}
	sig, err := srv.Sign(testImprint, SignOptionVerificationPolicy(nil))
	if err == nil {
		t.Fatal("Must failed with nil policy.")
	}
	if sig != nil {
		t.Fatal("No KSI signature must be returned.")
	}
}

func testSignerHmacAlgNotTrusted(t *testing.T, _ ...interface{}) {
	var (
		testAlgorithm = hash.SHA1
	)

	srv, err := NewSigner(
		OptNetClient(&mock.RequestCounterClient{}),
		OptHmacAlgorithm(testAlgorithm),
	)

	if err == nil || srv != nil {
		t.Fatal("Must fail with untrusted algorithm.")
	}
}

func testSignerHmacAlgNotSupported(t *testing.T, _ ...interface{}) {
	var (
		testAlgorithm = hash.SM3
	)

	srv, err := NewSigner(
		OptNetClient(&mock.RequestCounterClient{}),
		OptHmacAlgorithm(testAlgorithm),
	)

	if err == nil || srv != nil {
		t.Fatal("Must fail with unsupported algorithm.")
	}
}

func testSignerHmacOptionOverride(t *testing.T, _ ...interface{}) {
	var (
		testAlgorithm = hash.SHA2_384
	)
	srv, err := NewSigner(
		OptNetClient(&mock.RequestCounterClient{}),
		OptHmacAlgorithm(testAlgorithm),
	)
	req, err := pdu.NewAggregatorConfigReq()
	if err != nil {
		t.Fatal("Failed to create signer request: ", err)
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

func testSignerResponseError(t *testing.T, _ ...interface{}) {
	var (
		testSignResponses = [...]struct {
			file   string
			extErr int
		}{
			{filepath.Join(testResourceTlvDir, "ok-sig-2014-07-01.1-aggr-err-response-101.tlv"), 0x101},
			{filepath.Join(testResourceTlvDir, "ok-sig-2014-07-01.1-aggr-err-response-102.tlv"), 0x102},
			{filepath.Join(testResourceTlvDir, "ok-sig-2014-07-01.1-aggr-err-response-103.tlv"), 0x103},
			{filepath.Join(testResourceTlvDir, "ok-sig-2014-07-01.1-aggr-err-response-104.tlv"), 0x104},
			{filepath.Join(testResourceTlvDir, "ok-sig-2014-07-01.1-aggr-err-response-105.tlv"), 0x105},
			{filepath.Join(testResourceTlvDir, "ok-sig-2014-07-01.1-aggr-err-response-106.tlv"), 0x106},
			{filepath.Join(testResourceTlvDir, "ok-sig-2014-07-01.1-aggr-err-response-107.tlv"), 0x107},
			{filepath.Join(testResourceTlvDir, "ok-sig-2014-07-01.1-aggr-err-response-200.tlv"), 0x200},
			{filepath.Join(testResourceTlvDir, "ok-sig-2014-07-01.1-aggr-err-response-300.tlv"), 0x300},
			{filepath.Join(testResourceTlvDir, "ok-sig-2014-07-01.1-aggr-err-response-301.tlv"), 0x301},
			{filepath.Join(testResourceTlvDir, "ok-sig-2014-07-01.1-aggr-err-response-559.tlv"), 0x559},
		}
		testImprint = hash.Imprint{0x01,
			0xc4, 0xbb, 0xcb, 0x1f, 0xbe, 0xc9, 0x9d, 0x65,
			0xbf, 0x59, 0xd8, 0x5c, 0x8c, 0xb6, 0x2e, 0xe2,
			0xdb, 0x96, 0x3f, 0x0f, 0xe1, 0x06, 0xf4, 0x83,
			0xd9, 0xaf, 0xa7, 0x3b, 0xd4, 0xe3, 0x9a, 0x8a,
		}
	)

	for _, d := range testSignResponses {
		signer, err := NewSigner(OptNetClient(mock.NewFileReaderClient(d.file, "anon", "anon")))
		if err != nil {
			t.Fatal("Failed to create signer: ", err)
		}

		req, err := pdu.NewAggregationReq(testImprint)
		if err != nil {
			t.Fatal("Failed to create request: ", err)
		}

		_, err = signer.Send(req)
		if err == nil {
			t.Fatal("Must return error.")
		}
		if err.(*errors.KsiError).ExtCode() != d.extErr {
			t.Error("Ext error code mismatch.: ", err.(*errors.KsiError).ExtCode(), d.extErr, err.(*errors.KsiError).Message())
		}
	}
}

func testSignerSignWithOptionsDefaultPolicyNoExtraOptions(t *testing.T, _ ...interface{}) {
	var (
		testAggrResponse = filepath.Join(testResourceTlvDir, "ok-sig-2014-07-01.1-aggr_response.tlv")
		testImprint      = hash.Imprint{0x01,
			0x11, 0xa7, 0x00, 0xb0, 0xc8, 0x06, 0x6c, 0x47, 0xec, 0xba, 0x05, 0xed, 0x37, 0xbc, 0x14, 0xdc,
			0xad, 0xb2, 0x38, 0x55, 0x2d, 0x86, 0xc6, 0x59, 0x34, 0x2d, 0x1d, 0x7e, 0x87, 0xb8, 0x77, 0x2d,
		}
		testPolicy = signature.DefaultVerificationPolicy
	)

	srv, err := NewSigner(OptNetClient(mock.NewFileReaderClient(testAggrResponse, "anon", "anon")))
	if err != nil {
		t.Fatal("Failed to create signer: ", err)
	}

	sig, err := srv.Sign(testImprint, SignOptionVerificationPolicy(testPolicy))
	if err == nil {
		t.Fatal("Must fail due to inconclusive verification resource.")
	}
	if sig != nil {
		t.Fatal("No KSI signature must be returned.")
	}
}

func testSignerSignWithOptionsDefaultPolicyAndPubFile(t *testing.T, _ ...interface{}) {
	var (
		testAggrResponse = filepath.Join(testResourceTlvDir, "ok-sig-2014-07-01.1-aggr_response.tlv")
		testImprint      = hash.Imprint{0x01,
			0x11, 0xa7, 0x00, 0xb0, 0xc8, 0x06, 0x6c, 0x47, 0xec, 0xba, 0x05, 0xed, 0x37, 0xbc, 0x14, 0xdc,
			0xad, 0xb2, 0x38, 0x55, 0x2d, 0x86, 0xc6, 0x59, 0x34, 0x2d, 0x1d, 0x7e, 0x87, 0xb8, 0x77, 0x2d,
		}
		testPubFile = filepath.Join(testResourcePubDir, "publications.bin")
		testCrtFile = filepath.Join(testResourceCrtDir, "mock.crt")
		testPolicy  = signature.DefaultVerificationPolicy
	)

	pubFile, err := publications.NewFile(publications.FileFromFile(testPubFile))
	if err != nil {
		t.Fatal("Failed to initialize publications file: ", err)
	}

	pfh, err := publications.NewFileHandler(
		publications.FileHandlerSetFile(pubFile),
		publications.FileHandlerSetTrustedCertificateFromFilePem(testCrtFile),
		publications.FileHandlerSetFileCertConstraint(publications.OidEmail, "publications@guardtime.com"),
	)
	if err != nil {
		t.Fatal("Failed to initialize publications file handler: ", err)
	}

	srv, err := NewSigner(OptNetClient(mock.NewFileReaderClient(testAggrResponse, "anon", "anon")))
	if err != nil {
		t.Fatal("Failed to create signer: ", err)
	}

	sig, err := srv.Sign(testImprint,
		SignOptionVerificationPolicy(testPolicy),
		SignOptionVerificationOptions(
			signature.VerCtxOptPublicationsFileHandler(pfh),
		),
	)
	if err != nil {
		t.Fatal("Failed to receive response: ", err)
	}
	if sig == nil {
		t.Fatal("KSI signature must be returned.")
	}
	sigVerRes, err := sig.VerificationResult()
	if err != nil {
		t.Fatal("Failed to get signature verification result: ", err)
	}
	if sigVerRes == nil {
		t.Fatal("Must return verification result.")
	}
	res, err := sigVerRes.FinalResult().ResultCode()
	if err != nil {
		t.Fatal("Failed to get verification result code: ", err)
	}
	if res != result.OK {
		t.Fatal("Verification failed with result: ", res)
	}
}

func testSignerWithExtenderResponse(t *testing.T, _ ...interface{}) {
	var (
		testAggrResp = filepath.Join(testResourceTlvDir, "ok_extender_error_response_101.tlv")
		expectedErr  = "Unexpected aggregator response PDU type: 0x321!"
	)

	signer, err := NewSigner(
		OptNetClient(mock.NewFileReaderClient(testAggrResp, "anon", "anon")),
	)
	if err != nil {
		t.Fatal("Failed to create signer: ", err)
	}

	req, err := pdu.NewAggregatorConfigReq()
	if err != nil {
		t.Fatal("Failed to create request: ", err)
	}

	_, err = signer.Send(req)
	if err == nil {
		t.Fatal("Extender response instead of aggregator response must fail!")
	}

	messages := errors.KsiErr(err).Message()

	if messages[0] != expectedErr {
		t.Fatalf("Expecting error message:\n%s\nBut got:\n%s", expectedErr, messages[0])
	}
}

func testSignerWithRandomResponse(t *testing.T, _ ...interface{}) {
	var (
		testAggrResp = filepath.Join(testResourcePubDir, "ksi-publications.bin")
		expectedErr  = "Unexpected aggregator response PDU type: 0xb!"
	)

	signer, err := NewSigner(
		OptNetClient(mock.NewFileReaderClient(testAggrResp, "anon", "anon")),
	)
	if err != nil {
		t.Fatal("Failed to create signer: ", err)
	}

	req, err := pdu.NewAggregatorConfigReq()
	if err != nil {
		t.Fatal("Failed to create request: ", err)
	}

	_, err = signer.Send(req)
	if err == nil {
		t.Fatal("Unknown response instead of aggregator response must fail!")
	}

	messages := errors.KsiErr(err).Message()

	if messages[0] != expectedErr {
		t.Fatalf("Expecting error message:\n%s\nBut got:\n%s", expectedErr, messages[0])
	}
}
