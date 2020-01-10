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
	"github.com/guardtime/goksi/signature/verify/reserr"
	"github.com/guardtime/goksi/signature/verify/result"
	"github.com/guardtime/goksi/test"
)

func TestUnitInternalVerificationPolicy(t *testing.T) {

	logger, defFunc, err := test.InitLogger(t, testLogDir, log.DEBUG, t.Name())
	if err != nil {
		t.Fatal("Failed to initialize logger: ", err)
	}
	defer defFunc()
	// Apply logger.
	log.SetLogger(logger)

	test.Suite{
		{Func: testValidSignatureUsingPolicyVerify},
		{Func: testValidSignatureUsingSignatureVerify},
		{Func: testSignatureWithRfc3161},
		{Func: testSignatureAggrWithLegacyID},
		{Func: testSignatureAggrWithMetadata},
		{Func: testSignatureWithSha1},
	}.Runner(t)
}

func testValidSignatureUsingPolicyVerify(t *testing.T, _ ...interface{}) {
	// Test case resources.
	var (
		testSigFile = filepath.Join(testSigDir, "ok-sig-2014-08-01.1.ksig")
	)

	sig, err := New(BuildNoVerify(BuildFromFile(testSigFile)))
	if err != nil {
		t.Fatal("Failed to create ksi signature: ", err)
	}

	verCtx, err := NewVerificationContext(sig)
	if err != nil {
		t.Fatal("Failed to create verification context: ", err)
	}

	policy := InternalVerificationPolicy
	res, err := policy.Verify(verCtx)
	if err != nil {
		t.Fatal(policy, " returned error: ", err)
	}
	if res != result.OK {
		verRes, _ := verCtx.Result()

		t.Error(policy, "Verify result: ", res)
		t.Error(policy, "Final  result: ", verRes.FinalResult())
	}
}

func testValidSignatureUsingSignatureVerify(t *testing.T, _ ...interface{}) {
	// Test case resources.
	var (
		testSigFile = filepath.Join(testSigDir, "ok-sig-2014-08-01.1.ksig")
	)

	sig, err := New(BuildNoVerify(BuildFromFile(testSigFile)))
	if err != nil {
		t.Fatal("Failed to create ksi signature: ", err)
	}

	if err := sig.Verify(InternalVerificationPolicy); err != nil {
		t.Fatal("Signature must succeed.")
	}

	verRes, err := sig.VerificationResult()
	if err != nil {
		t.Fatal("Unable to extract verification result.")
	}

	if verRes.Error() != nil {
		t.Fatal("Verification must succeed.")
	}
}

func testSignatureWithRfc3161(t *testing.T, _ ...interface{}) {
	// Test case resources.
	var (
		testData = []struct {
			sigFile string
			resCode result.Code
			errCode reserr.Code
			rule    Rule
		}{
			{filepath.Join(testSigDir, "rfc3161-sha1-as-input-hash-2016-01.ksig"),
				result.OK, reserr.ErrNA, OkRule{}},
			{filepath.Join(testSigDir, "rfc3161-sha1-as-input-hash-2017.ksig"),
				result.FAIL, reserr.Int13, InputHashAlgorithmVerificationRule{}},
			{filepath.Join(testSigDir, "rfc3161-sha1-in-aggr-input.ksig"),
				result.FAIL, reserr.Int17, Rfc3161RecordOutputHashAlgorithmVerificationRule{}},
			{filepath.Join(testSigDir, "rfc3161-sha1-in-sig-atr-2016-01.ksig"),
				result.OK, reserr.ErrNA, OkRule{}},
			{filepath.Join(testSigDir, "rfc3161-sha1-in-sig-atr-2017.ksig"),
				result.FAIL, reserr.Int14, Rfc3161RecordHashAlgorithmVerificationRule{}},
			{filepath.Join(testSigDir, "rfc3161-sha1-in-tst-algo-2016-01.ksig"),
				result.OK, reserr.ErrNA, OkRule{}},
			{filepath.Join(testSigDir, "rfc3161-sha1-in-tst-algo-2017.ksig"),
				result.FAIL, reserr.Int14, Rfc3161RecordHashAlgorithmVerificationRule{}},
			{filepath.Join(testSigDir, "signature-with-rfc3161-record-ok.ksig"),
				result.OK, reserr.Int08, CalendarAuthenticationRecordAggregationHashVerificationRule{}},
			{filepath.Join(testSigDir, "signature-with-invalid-rfc3161-output-hash.ksig"),
				result.FAIL, reserr.Int01, AggregationHashChainConsistencyVerificationRule{}},
			{filepath.Join(testSigDir, "signature-with-rfc3161-record-ok-changed-aggregation-time.ksig"),
				result.FAIL, reserr.Int02, AggregationHashChainTimeConsistencyVerificationRule{}},
			{filepath.Join(testSigDir, "signature-with-rfc3161-record-ok-changed-chain-index.ksig"),
				result.FAIL, reserr.Int12, AggregationHashChainIndexContinuationVerificationRule{}},
			{filepath.Join(testSigDir, "signature-with-rfc3161-record-ok-changed-chain-index-and-aggr-time.ksig"),
				result.FAIL, reserr.Int12, AggregationHashChainIndexContinuationVerificationRule{}},
		}
	)

	for _, d := range testData {
		sig, err := New(BuildNoVerify(BuildFromFile(d.sigFile)))
		if err != nil {
			t.Fatal("Failed to create ksi signature: ", err)
		}

		if err := sig.Verify(InternalVerificationPolicy); err == nil {
			if d.resCode == result.FAIL {
				t.Fatal("Signature must fail.")
			}
		}

		verRes, err := sig.VerificationResult()
		if err != nil {
			t.Fatal("Unable to extract verification result.")
		}

		verificationResultMatch(t, verRes.FinalResult(), d.resCode, d.errCode, d.rule.String())
	}
}

func testSignatureAggrWithLegacyID(t *testing.T, _ ...interface{}) {
	// Test case resources.
	var (
		testSigFile = filepath.Join(testSigDir, "ok-sig-2014-08-01.1.ksig")
	)

	sig, err := New(BuildFromFile(testSigFile))
	if err != nil {
		t.Fatal("Failed to create ksi signature from file: ", err)
	}

	verRes, err := sig.VerificationResult()
	if err != nil {
		t.Fatal("Unable to extract verification result.")
	}

	if verRes.Error() != nil {
		t.Fatal("Verification must succeed.")
	}
}

func testSignatureAggrWithMetadata(t *testing.T, _ ...interface{}) {
	// Test case resources.
	var (
		testSigFile = filepath.Join(testSigDir, "ok-sig-2018-06-15.1.ksig")
	)

	sig, err := New(BuildFromFile(testSigFile))
	if err != nil {
		t.Fatal("Failed to create ksi signature from file: ", err)
	}

	verRes, err := sig.VerificationResult()
	if err != nil {
		t.Fatal("Unable to extract verification result.")
	}

	if verRes.Error() != nil {
		t.Fatal("Verification must succeed.")
	}
}

func testSignatureWithSha1(t *testing.T, _ ...interface{}) {
	// Test case resources.
	var (
		testData = []struct {
			sigFile string
			resCode result.Code
			errCode reserr.Code
			rule    Rule
		}{
			{filepath.Join(testSigDir, "sha1-as-aggregation-algo-2016-01.ksig"),
				result.OK, reserr.ErrNA, OkRule{}},
			{filepath.Join(testSigDir, "sha1-as-aggregation-algo-2017.ksig"),
				result.FAIL, reserr.Int15, AggregationChainHashAlgorithmVerificationRule{}},
		}
	)

	for _, d := range testData {
		sig, err := New(BuildNoVerify(BuildFromFile(d.sigFile)))
		if err != nil {
			t.Fatal("Failed to create ksi signature: ", err)
		}

		if err := sig.Verify(InternalVerificationPolicy); err == nil {
			if d.resCode == result.FAIL {
				t.Fatal("Signature must fail.")
			}
		}

		verRes, err := sig.VerificationResult()
		if err != nil {
			t.Fatal("Unable to extract verification result.")
		}
		verificationResultMatch(t, verRes.FinalResult(), d.resCode, d.errCode, d.rule.String())
	}
}
