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
	"strings"
	"testing"

	"github.com/guardtime/goksi/errors"
	"github.com/guardtime/goksi/log"
	"github.com/guardtime/goksi/signature/verify/reserr"
	"github.com/guardtime/goksi/signature/verify/result"
	"github.com/guardtime/goksi/test"
)

func TestUnitVerificationPolicy(t *testing.T) {

	logger, defFunc, err := test.InitLogger(t, testLogDir, log.DEBUG, t.Name())
	if err != nil {
		t.Fatal("Failed to initialize logger: ", err)
	}
	defer defFunc()
	// Apply logger.
	log.SetLogger(logger)

	test.Suite{
		{Func: testPolicyImplFunctionsWithNilReceiver},
		{Func: testVerifyPolicyImplCtxNil},
		{Func: testVerifyNilPolicyImpl},
		{Func: testVerifyPolicyRuleNilCtxFail},
		{Func: testVerifyPolicyRuleNilCtxOk},
		{Func: testVerifyPolicyRuleNilCtx},
		{Func: testVerifyNotInitializedPolicyRuleThatDefaultsToUnknownRule},
		{Func: testVerifyPolicyRuleWithRuleReturnsNilResult},
		{Func: testVerifyPolicyImplWithFallbackFailure},
		{Func: testVerifyPolicyImplWithFailingFallback},
		{Func: testVerifyPolicyImplWithFallbackThatReturnsError},
		{Func: testCopyOkPolicy},
		{Func: testSetNilFallbackToPolicy},
		{Func: testWithFallback},
		{Func: testEmptyPolicyReturnOk},
		{Func: testFailPolicyReturnNok},
		{Func: testCopyPolicyWithFallback},
	}.Runner(t)
}

func testPolicyImplFunctionsWithNilReceiver(t *testing.T, _ ...interface{}) {
	var (
		policyImpl *policyImpl
		verCtx     VerificationContext
	)

	if policyImpl.String() != "" {
		t.Fatal("Nil policy to string must be empty string.")
	}

	if pol := policyImpl.Fallback(); pol != nil {
		t.Fatal("Should not get any fallback policy from nil receiver.")
	}

	if pol := policyImpl.WithFallback(SuccessPolicy); pol != nil {
		t.Fatal("Should not be possible to set fallback policy to nil receiver.")
	}

	if res, err := policyImpl.Verify(&verCtx); err == nil || res != result.NA {
		t.Fatal("Should not be possible to verify nil receiver.")
	}

	if pol := policyImpl.Copy(); pol != nil {
		t.Fatal("Should not be possible to copy nil receiver.")
	}

	if rules := policyImpl.Rules(); rules != nil {
		t.Fatal("Should not be possible to get rules from nil receiver.")
	}
}

func testEmptyPolicyReturnOk(t *testing.T, _ ...interface{}) {
	var (
		testPolicy = SuccessPolicy
		testSig    = []string{
			filepath.Join(testSigDir, "ok-sig-2014-06-2.ksig"),
			filepath.Join(testSigDir, "nok-sig-doc-hsh-sha1.ksig"),
		}
	)

	for _, sigFile := range testSig {
		sig, err := New(BuildNoVerify(BuildFromFile(sigFile)))
		if err != nil {
			t.Fatal("Failed to create ksi signature: ", err)
		}

		if err := sig.Verify(testPolicy); err != nil {
			t.Fatal("Signature must succeed.")
		}
	}
}

func testFailPolicyReturnNok(t *testing.T, _ ...interface{}) {
	var (
		testPolicy = FailPolicy
		testSig    = []string{
			filepath.Join(testSigDir, "ok-sig-2014-06-2.ksig"),
			filepath.Join(testSigDir, "nok-sig-doc-hsh-sha1.ksig"),
		}
	)

	for _, sigFile := range testSig {
		sig, err := New(BuildNoVerify(BuildFromFile(sigFile)))
		if err != nil {
			t.Fatal("Failed to create ksi signature: ", err)
		}

		if err := sig.Verify(testPolicy); err == nil {
			t.Fatal("Signature must succeed.")
		}
	}
}

func testVerifyPolicyImplCtxNil(t *testing.T, _ ...interface{}) {
	var (
		testPolicy = SuccessPolicy
	)
	_, err := testPolicy.Verify(nil)
	if err == nil {
		t.Fatal("Should not be possible to verify with nil context.")
	}
}

func testVerifyNilPolicyImpl(t *testing.T, _ ...interface{}) {
	var (
		testPolicy = policyImpl{}
		verCtx     = VerificationContext{}
	)
	_, err := testPolicy.Verify(&verCtx)
	if err == nil {
		t.Fatal("Should not be possible to verify with using nil policy.")
	}
}

func testVerifyPolicyRuleNilCtxFail(t *testing.T, _ ...interface{}) {
	var (
		rule = DocumentHashPresenceRule{}
	)
	_, err := rule.Verify(nil)
	if err == nil {
		t.Fatal("Should not be possible to verify rule with nil context that requires context.")
	}
}

func testVerifyPolicyRuleNilCtxOk(t *testing.T, _ ...interface{}) {
	var (
		rule = OkRule{}
	)
	_, err := rule.Verify(nil)
	if err != nil {
		t.Fatal("Should be possible to verify rule with nil context that does not require context.")
	}
}

func testVerifyPolicyRuleNilCtx(t *testing.T, _ ...interface{}) {
	var (
		rule = PolicyRule{}
	)
	_, err := rule.Verify(nil)
	if err == nil {
		t.Fatal("Should not be possible to verify rule with nil context.")
	}
}

func testVerifyNotInitializedPolicyRuleThatDefaultsToUnknownRule(t *testing.T, _ ...interface{}) {
	var (
		rule   = PolicyRule{}
		verCtx = VerificationContext{result: &VerificationResult{}}
	)
	_, err := rule.Verify(&verCtx)
	if err.(*errors.KsiError).Code() != errors.KsiInvalidFormatError ||
		!strings.Contains(err.(*errors.KsiError).Message()[0], "Unknown Rule type") {
		t.Fatal("Should not be possible to verify using nil rule.")
	}
}

type testRuleReturnsNilRuleResult struct{}

func (r testRuleReturnsNilRuleResult) errCode() reserr.Code { return reserr.ErrNA }
func (r testRuleReturnsNilRuleResult) String() string       { return getName(r) }
func (r testRuleReturnsNilRuleResult) Verify(context *VerificationContext) (*RuleResult, error) {
	return nil, nil
}

func testVerifyPolicyRuleWithRuleReturnsNilResult(t *testing.T, _ ...interface{}) {
	var (
		rule = PolicyRule{
			Rule: testRuleReturnsNilRuleResult{},
		}
		verCtx VerificationContext
	)

	if _, err := rule.Verify(&verCtx); err == nil {
		t.Fatal("Should not be possible to verify successfully with rule that returns nil result.")
	}
}

func testVerifyPolicyImplWithFallbackFailure(t *testing.T, _ ...interface{}) {
	var (
		fallback = &policyImpl{
			name: "Failing fallback policy",
			rules: &PolicyRule{
				Rule: FailRule{},
			},
		}
		policy = (&policyImpl{
			name: "Ok test policy",
			rules: &PolicyRule{
				Rule: OkRule{},
			},
		}).WithFallback(fallback)

		verCtx = VerificationContext{
			signature: &Signature{},
			result:    &VerificationResult{},
		}
	)

	code, err := policy.Verify(&verCtx)
	if err != nil {
		t.Fatal("Policy verification returned error: ", err)
	}
	if code != result.OK {
		t.Fatal("Wrong result code was returned: ", code)
	}
}

func testVerifyPolicyImplWithFailingFallback(t *testing.T, _ ...interface{}) {
	var (
		fallback = &policyImpl{
			name: "Failing fallback policy",
			rules: &PolicyRule{
				Rule: FailRule{},
			},
		}
		policy = (&policyImpl{
			name: "Failing test policy",
			rules: &PolicyRule{
				Rule: FailRule{},
			},
		}).WithFallback(fallback)

		verCtx = VerificationContext{
			signature: &Signature{},
			result:    &VerificationResult{},
		}
	)

	code, err := policy.Verify(&verCtx)
	if err != nil {
		t.Fatal("Policy verification returned error: ", err)
	}
	if code != result.FAIL {
		t.Fatal("Wrong result code was returned: ", code)
	}
}

func testVerifyPolicyImplWithFallbackThatReturnsError(t *testing.T, _ ...interface{}) {
	var (
		fallback = &policyImpl{
			name: "Fallback policy that returns error",
			rules: &PolicyRule{
				Rule: AggregationHashChainTimeConsistencyVerificationRule{},
			},
		}
		policy = (&policyImpl{
			name: "Failing test policy",
			rules: &PolicyRule{
				Rule: FailRule{},
			},
		}).WithFallback(fallback)

		verCtx = VerificationContext{
			signature: &Signature{},
			result:    &VerificationResult{},
		}
	)

	code, err := policy.Verify(&verCtx)
	if err == nil || errors.KsiErr(err).Code() != errors.KsiInvalidStateError {
		t.Fatal("Policy verification failed with wrong error: ", err)
	}
	if code != result.NA {
		t.Fatal("Wrong result code was returned: ", code)
	}
}

func testCopyOkPolicy(t *testing.T, _ ...interface{}) {
	var (
		testPolicy = SuccessPolicy
	)
	newPolicy := testPolicy.Copy()
	if newPolicy.String() != testPolicy.String() {
		t.Fatal("Copy and original policy must be same.")
	}
}

func testCopyPolicyWithFallback(t *testing.T, _ ...interface{}) {
	var (
		testPolicy = SuccessPolicy
	)
	newPolicy := testPolicy.WithFallback(FailPolicy)
	copyPolicy := newPolicy.Copy()
	if copyPolicy.Fallback() != nil {
		t.Fatal("Created policy copy should not copy fallback policies.")
	}
	if newPolicy.Fallback() == nil {
		t.Fatal("Fallback policy(or more) were removed from original policy.")
	}
}

func testSetNilFallbackToPolicy(t *testing.T, _ ...interface{}) {
	var (
		testPolicy = SuccessPolicy
	)
	newPolicy := testPolicy.WithFallback(nil)
	if newPolicy == nil {
		t.Fatal("Failed to reset fallback policy.")
	}
}

func testWithFallback(t *testing.T, _ ...interface{}) {
	var (
		testPolicy = SuccessPolicy
	)
	newPolicy := testPolicy.WithFallback(FailPolicy)
	if newPolicy.Fallback() != FailPolicy {
		t.Fatal("Unexpected fallback policy.")
	}
}
