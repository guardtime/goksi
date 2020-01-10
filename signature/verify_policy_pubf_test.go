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

package signature

import (
	"path/filepath"
	"testing"

	"github.com/guardtime/goksi/errors"
	"github.com/guardtime/goksi/log"
	"github.com/guardtime/goksi/publications"
	"github.com/guardtime/goksi/signature/verify/reserr"
	"github.com/guardtime/goksi/signature/verify/result"
	"github.com/guardtime/goksi/test"
	"github.com/guardtime/goksi/test/utils/mock"
)

func TestUnitPublicationsFileBasedVerificationPolicy(t *testing.T) {

	logger, defFunc, err := test.InitLogger(t, testLogDir, log.DEBUG, t.Name())
	if err != nil {
		t.Fatal("Failed to initialize logger: ", err)
	}
	defer defFunc()
	// Apply logger.
	log.SetLogger(logger)

	test.Suite{
		{Func: testPubfPolicyVerifySignature},
		{Func: testPubfPolicyVerifyExtendedSignaturePubNotInPubsFile},
		{Func: testPubfPolicyVerifyExtendedSignature},
		{Func: testPubfVerifyExtenderFailure},
	}.Runner(t)
}

func testPubfPolicyVerifySignature(t *testing.T, _ ...interface{}) {
	var (
		testSigFile  = filepath.Join(testSigDir, "ok-sig-2018-06-15.1.ksig")
		testRespFile = filepath.Join(testTlvDir, "ok-sig-2018-06-15.1-extend_response.tlv")
		testPubFile  = filepath.Join(testPubDir, "ksi-publications.bin")
		testPolicy   = PublicationsFileBasedVerificationPolicy
	)

	sig, err := New(BuildNoVerify(BuildFromFile(testSigFile)))
	if err != nil {
		t.Fatal("Failed to create ksi signature: ", err)
	}

	pubFile, err := publications.NewFile(publications.FileFromFile(testPubFile))
	if err != nil {
		t.Fatal("Failed to initialize publications file: ", err)
	}

	verCtx, err := NewVerificationContext(sig,
		VerCtxOptExtendingPermitted(true),
		VerCtxOptCalendarProvider(&mockCalendarProvider{
			client: mock.NewFileReaderClient(testRespFile, "anon", "anon"),
		}),
		VerCtxOptPublicationsFile(pubFile),
	)
	if err != nil {
		t.Fatal("Failed to create verification context: ", err)
	}

	res, err := testPolicy.Verify(verCtx)
	if err != nil {
		t.Fatal(testPolicy, " returned error: ", err)
	}
	if res != result.OK {
		verRes, _ := verCtx.Result()
		t.Error(testPolicy, "Verify result: ", res)
		t.Error(testPolicy, "Final  result: ", verRes.FinalResult())
	}
}

func testPubfPolicyVerifyExtendedSignaturePubNotInPubsFile(t *testing.T, _ ...interface{}) {
	var (
		testSigFile  = filepath.Join(testSigDir, "ok-sig-2014-04-30.1-extended.ksig")
		testRespFile = filepath.Join(testTlvDir, "ok-sig-2014-04-30.1-extend_response.tlv")
		testPubFile  = filepath.Join(testPubDir, "publications.15042014.bin")
		testPolicy   = PublicationsFileBasedVerificationPolicy
	)

	sig, err := New(BuildNoVerify(BuildFromFile(testSigFile)))
	if err != nil {
		t.Fatal("Failed to create ksi signature: ", err)
	}

	pubFile, err := publications.NewFile(publications.FileFromFile(testPubFile))
	if err != nil {
		t.Fatal("Failed to initialize publications file: ", err)
	}

	verCtx, err := NewVerificationContext(sig,
		VerCtxOptExtendingPermitted(true),
		VerCtxOptCalendarProvider(&mockCalendarProvider{
			client: mock.NewFileReaderClient(testRespFile, "anon", "anon"),
		}),
		VerCtxOptPublicationsFile(pubFile),
	)
	if err != nil {
		t.Fatal("Failed to create verification context: ", err)
	}

	res, err := testPolicy.Verify(verCtx)
	if err != nil {
		t.Fatal(testPolicy, " returned error: ", err)
	}
	if res != result.NA {
		verRes, _ := verCtx.Result()
		t.Error(testPolicy, "Verify result: ", res)
		t.Error(testPolicy, "Final  result: ", verRes.FinalResult())
	}
}

func testPubfPolicyVerifyExtendedSignature(t *testing.T, _ ...interface{}) {
	var (
		testSigFile = filepath.Join(testSigDir, "ok-sig-2014-04-30.1-extended.ksig")
		testPubFile = filepath.Join(testPubDir, "publications.bin")
		testCrtFile = filepath.Join(testCrtDir, "mock.crt")

		testPolicy = PublicationsFileBasedVerificationPolicy
	)

	sig, err := New(BuildNoVerify(BuildFromFile(testSigFile)))
	if err != nil {
		t.Fatal("Failed to create ksi signature: ", err)
	}

	pubFile, err := publications.NewFile(publications.FileFromFile(testPubFile))
	if err != nil {
		t.Fatal("Failed to initialize publications file: ", err)
	}

	pubFileHandler, err := publications.NewFileHandler(
		publications.FileHandlerSetFile(pubFile),
		publications.FileHandlerSetTrustedCertificateFromFilePem(testCrtFile),
		publications.FileHandlerSetFileCertConstraint(publications.OidEmail, "publications@guardtime.com"),
	)
	if err != nil {
		t.Fatal("Failed to initialize publications file handler: ", err)
	}

	verCtx, err := NewVerificationContext(sig,
		VerCtxOptPublicationsFileHandler(pubFileHandler),
	)
	if err != nil {
		t.Fatal("Failed to create verification context: ", err)
	}

	res, err := testPolicy.Verify(verCtx)
	if err != nil {
		t.Fatal(testPolicy, " returned error: ", err)
	}
	if res != result.OK {
		verRes, _ := verCtx.Result()
		t.Error(testPolicy, "Verify result: ", res)
		t.Error(testPolicy, "Final  result: ", verRes.FinalResult())
	}
}

func testPubfVerifyExtenderFailure(t *testing.T, _ ...interface{}) {
	var (
		testSigFiles = [...]struct {
			file string
			rule Rule
		}{
			{filepath.Join(testSigDir, "ok-sig-2014-04-30.1.ksig"), PublicationsFileExtendToPublication{}},
		}
		testRespFiles = [...]struct {
			file       string
			extErrCode int
			staErrCode errors.ErrorCode
		}{
			{filepath.Join(testTlvDir, "ok_extender_error_response_101.tlv"), 0x101, errors.KsiServiceInvalidRequest},
			{filepath.Join(testTlvDir, "ok_extender_error_response_102.tlv"), 0x102, errors.KsiServiceAuthenticationFailure},
			{filepath.Join(testTlvDir, "ok_extender_error_response_103.tlv"), 0x103, errors.KsiServiceInvalidPayload},
			{filepath.Join(testTlvDir, "ok_extender_error_response_104.tlv"), 0x104, errors.KsiServiceExtenderInvalidTimeRange},
			{filepath.Join(testTlvDir, "ok_extender_error_response_105.tlv"), 0x105, errors.KsiServiceExtenderRequestTimeTooOld},
			{filepath.Join(testTlvDir, "ok_extender_error_response_106.tlv"), 0x106, errors.KsiServiceExtenderRequestTimeTooNew},
			{filepath.Join(testTlvDir, "ok_extender_error_response_107.tlv"), 0x107, errors.KsiServiceExtenderRequestTimeInFuture},
			{filepath.Join(testTlvDir, "ok_extender_error_response_200.tlv"), 0x200, errors.KsiServiceInternalError},
			{filepath.Join(testTlvDir, "ok_extender_error_response_201.tlv"), 0x201, errors.KsiServiceExtenderDatabaseMissing},
			{filepath.Join(testTlvDir, "ok_extender_error_response_202.tlv"), 0x202, errors.KsiServiceExtenderDatabaseCorrupt},
			{filepath.Join(testTlvDir, "ok_extender_error_response_300.tlv"), 0x300, errors.KsiServiceUpstreamError},
			{filepath.Join(testTlvDir, "ok_extender_error_response_301.tlv"), 0x301, errors.KsiServiceUpstreamTimeout},
		}
		testPubFile = filepath.Join(testPubDir, "publications.bin")
		testCrtFile = filepath.Join(testCrtDir, "mock.crt")
		testPolicy  = PublicationsFileBasedVerificationPolicy
	)

	for _, s := range testSigFiles {

		sig, err := New(BuildNoVerify(BuildFromFile(s.file)))
		if err != nil {
			t.Fatal("Failed to create ksi signature: ", err)
		}

		pubFile, err := publications.NewFile(publications.FileFromFile(testPubFile))
		if err != nil {
			t.Fatal("Failed to initialize publications file: ", err)
		}

		pubFileHandler, err := publications.NewFileHandler(
			publications.FileHandlerSetFile(pubFile),
			publications.FileHandlerSetTrustedCertificateFromFilePem(testCrtFile),
			publications.FileHandlerSetFileCertConstraint(publications.OidEmail, "publications@guardtime.com"),
		)
		if err != nil {
			t.Fatal("Failed to initialize publications file handler: ", err)
		}

		for _, r := range testRespFiles {
			verCtx, err := NewVerificationContext(sig,
				VerCtxOptPublicationsFileHandler(pubFileHandler),
				VerCtxOptExtendingPermitted(true),
				VerCtxOptCalendarProvider(&mockCalendarProvider{
					mock.NewFileReaderClient(r.file, "anon", "anon")}),
			)
			if err != nil {
				t.Fatal("Failed to create verification context: ", err)
			}

			res, err := testPolicy.Verify(verCtx)
			if err != nil {
				t.Fatal(testPolicy, "Verify must not end with error (returned error must be wrapped into RuleResult). File", r.file, "):", err)
			}
			if res != result.NA {
				t.Fatal(testPolicy, "Verify result must be NA, instead:", res)
			}

			verRes, err := sig.VerificationResult()
			if err != nil {
				t.Fatal("Failed to get verification result: ", err)
			}

			ruleResult := verRes.FinalResult()
			if errCode, err := ruleResult.ErrorCode(); err != nil {
				t.Fatal("Failed to get verification error code: ", err)
			} else if errCode != reserr.Gen02 {
				t.Fatal("Wrong verification error code.")
			}

			if statusErr, err := ruleResult.StatusErr(); err != nil {
				t.Fatal("Failed to get verification status error: ", err)
			} else if statusErr == nil {
				t.Fatal("Verification result must contain status error.")
			} else if statusErr.(*errors.KsiError).Code() != r.staErrCode {
				t.Fatal("Service status error code mismatch.")
			} else if statusErr.(*errors.KsiError).ExtCode() != r.extErrCode {
				t.Fatal("Service status ext error code mismatch.")
			}

			if ruleResult.RuleName() != s.rule.String() {
				t.Fatal("Final verification rule mismatch:", ruleResult.RuleName(), "vs", s.rule.String())
			}
		}
	}
}
