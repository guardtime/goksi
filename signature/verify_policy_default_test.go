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

	"github.com/guardtime/goksi/log"
	"github.com/guardtime/goksi/pdu"
	"github.com/guardtime/goksi/publications"
	"github.com/guardtime/goksi/signature/verify/result"
	"github.com/guardtime/goksi/test"
)

func TestUnitDefaultVerificationPolicy(t *testing.T) {

	logger, defFunc, err := test.InitLogger(t, testLogDir, log.DEBUG, t.Name())
	if err != nil {
		t.Fatal("Failed to initialize logger: ", err)
	}
	defer defFunc()
	// Apply logger.
	log.SetLogger(logger)

	test.Suite{
		{Func: testDefPolicyVerifySignature},
		{Func: testSignatureVerifyDefPolicy},
		{Func: testSignatureVerifyDefPolicyAndUserPubHasNoAffect},
	}.Runner(t)
}

func testDefPolicyVerifySignature(t *testing.T, _ ...interface{}) {
	var (
		testSigFile = filepath.Join(testSigDir, "ok-sig-2014-08-01.1.ksig")
		testPubFile = filepath.Join(testPubDir, "publications.bin")
		testCrtFile = filepath.Join(testCrtDir, "mock.crt")
		testPolicy  = DefaultVerificationPolicy
	)

	sig, err := New(BuildNoVerify(BuildFromFile(testSigFile)))
	if err != nil {
		t.Fatal("Failed to create ksi signature: ", err)
	}

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

	verCtx, err := NewVerificationContext(sig,
		VerCtxOptPublicationsFileHandler(pfh),
	)
	if err != nil {
		t.Fatal("Failed to create verification context: ", err)
	}

	res, err := testPolicy.Verify(verCtx)
	if err != nil {
		t.Fatal(testPolicy, " returned error: ", err)
	}
	if res != result.OK {
		verRes, err := verCtx.Result()
		if err != nil {
			t.Fatal("Unable to extract verification result: ", err)
		}
		t.Error(testPolicy, " result: ", verRes.FinalResult())
	}
}

func testSignatureVerifyDefPolicy(t *testing.T, _ ...interface{}) {
	var (
		testSigFile = filepath.Join(testSigDir, "ok-sig-2014-08-01.1.ksig")
		testPubFile = filepath.Join(testPubDir, "publications.bin")
		testCrtFile = filepath.Join(testCrtDir, "mock.crt")
		testPolicy  = DefaultVerificationPolicy
	)

	sig, err := New(BuildNoVerify(BuildFromFile(testSigFile)))
	if err != nil {
		t.Fatal("Failed to create ksi signature: ", err)
	}

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

	err = sig.Verify(testPolicy,
		VerCtxOptPublicationsFileHandler(pfh),
	)
	if err != nil {
		t.Fatal("Signature must not fail: ", err)
	}

	verRes, err := sig.VerificationResult()
	if err != nil {
		t.Fatal("Unable to extract verification result: ", err)
	}
	if verRes == nil {
		t.Fatal("Inconsistent verification result.")
	}
	finalResult := verRes.FinalResult()
	if finalResult == nil {
		t.Fatal("Inconsistent verification result.")
	}

	resCode, err := finalResult.ResultCode()
	if err != nil {
		t.Fatal("Unable to extract final result code: ", err)
	}
	if resCode != result.OK {
		t.Error(testPolicy, " result: ", finalResult)
	}
}

func testSignatureVerifyDefPolicyAndUserPubHasNoAffect(t *testing.T, _ ...interface{}) {
	var (
		testSigFile = filepath.Join(testSigDir, "signature-extended-to-user-publication-time.ksig")
		testPubFile = filepath.Join(testPubDir, "publications.bin")
		testCrtFile = filepath.Join(testCrtDir, "mock.crt")
		testPolicy  = DefaultVerificationPolicy
	)

	sig, err := New(BuildNoVerify(BuildFromFile(testSigFile)))
	if err != nil {
		t.Fatal("Failed to create ksi signature: ", err)
	}

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

	pubRec, err := sig.Publication()
	if err != nil {
		t.Fatal("Failed to get publication record from signature: ", err)
	}

	pubData, err := pubRec.PublicationData()
	if err != nil {
		t.Fatal("Failed to get publication data from signature's publication record: ", err)
	}

	pubStr, err := pubData.Base32()
	if err != nil {
		t.Fatal("Failed to get publication string in base32 from publication data: ", err)
	}

	usrPub, err := pdu.NewPublicationData(pdu.PubDataFromString(pubStr))
	if err != nil {
		t.Fatal("Failed to parse publication string: ", err)
	}

	err = sig.Verify(testPolicy,
		VerCtxOptPublicationsFileHandler(pfh),
		VerCtxOptExtendingPermitted(false),
		VerCtxOptUserPublication(usrPub),
	)
	if err == nil {
		t.Fatal("Signature verification must not succeed.")
	}

	verRes, err := sig.VerificationResult()
	if err != nil {
		t.Fatal("Unable to extract verification result: ", err)
	}
	if verRes == nil {
		t.Fatal("Inconsistent verification result.")
	}
	finalResult := verRes.FinalResult()
	if finalResult == nil {
		t.Fatal("Inconsistent verification result.")
	}

	resCode, err := finalResult.ResultCode()
	if err != nil {
		t.Fatal("Unable to extract final result code: ", err)
	}
	if resCode != result.NA {
		t.Error(testPolicy, " result: ", finalResult)
	}
}
