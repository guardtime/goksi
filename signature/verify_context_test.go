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
	"testing"

	"github.com/guardtime/goksi/errors"
	"github.com/guardtime/goksi/hash"
	"github.com/guardtime/goksi/log"
	"github.com/guardtime/goksi/pdu"
	"github.com/guardtime/goksi/publications"
	"github.com/guardtime/goksi/signature/verify"
	"github.com/guardtime/goksi/signature/verify/reserr"
	"github.com/guardtime/goksi/signature/verify/result"
	"github.com/guardtime/goksi/test"
)

func TestUnitVerifyContext(t *testing.T) {
	logger, defFunc, err := test.InitLogger(t, testLogDir, log.DEBUG, t.Name())
	if err != nil {
		t.Fatal("Failed to initialize logger: ", err)
	}
	defer defFunc()
	// Apply logger.
	log.SetLogger(logger)

	test.Suite{
		{Func: testNewVerificationContextOk},
		{Func: testNewVerificationContextNilOptions},
		{Func: testNewVerificationContextWithFailingOption},
		{Func: testNewVerificationContextWithNilSignature},
		{Func: testVerCtxOptDocumentHashNil},
		{Func: testVerCtxOptDocumentHash},
		{Func: testVerCtxOptInputHashLevelMaxValue},
		{Func: testVerCtxOptExtendingPermittedTrue},
		{Func: testVerCtxOptExtendingPermittedFalse},
		{Func: testVerCtxOptCalendarProviderNil},
		{Func: testVerCtxOptCalendarProviderNotInitialized},
		{Func: testVerCtxOptPublicationsFileHandlerNil},
		{Func: testVerCtxOptUserPublicationNil},
		{Func: testVerCtxOptPublicationsFileNil},
		{Func: testVerCtxOptPublicationsFileNilVerCtxBaseObject},
		{Func: testVerCtxOptUserPublicationNilVerCtxBaseObject},
		{Func: testVerCtxOptPublicationsFileHandlerNilVerCtxBaseObject},
		{Func: testVerCtxOptCalendarProviderNilVerCtxBaseObject},
		{Func: testVerCtxOptExtendingPermittedNilVerCtxBaseObject},
		{Func: testVerCtxOptInputHashLevelNilVerCtxBaseObject},
		{Func: testVerCtxOptDocumentHashNilVerCtxBaseObject},
		{Func: testGetResultsFromNilVerCtx},
		{Func: testGetResultsFromNotInitializedVerCtx},
		{Func: testGetStringFromNilVerResult},
		{Func: testGetStringFromNotInitializedVerResult},
		{Func: testGetErrorFromNilVerResult},
		{Func: testGetErrorFromNotInitializedVerResult},
		{Func: testGetPolicyResultsFromNilVerResult},
		{Func: testGetPolicyResultsFromNotInitializedVerResult},
		{Func: testGetFinalResultFromNilVerResult},
		{Func: testGetFinalResultFromNotInitializedVerResult},
		{Func: testGetPolicyNameFromNilPolicyResult},
		{Func: testGetPolicyNameFromNotInitializedPolicyResult},
		{Func: testGetPolicyNameFromOkPolicyResult},
		{Func: testGetRuleResultsFromNilPolicyResult},
		{Func: testGetRuleResultsFromNotInitializedPolicyResult},
		{Func: testGetStringFromNilRuleResult},
		{Func: testGetResultCodeFromNilRuleResult},
		{Func: testGetResultCodeFromNotInitializedRuleResult},
		{Func: testGetErrorCodeFromNilRuleResult},
		{Func: testGetErrorCodeFromNotInitializedRuleResult},
		{Func: testGetStatusErrFromNilRuleResult},
		{Func: testGetStatusErrFromNotInitializedRuleResult},
		{Func: testGetRuleNameFromNilRuleResult},
		{Func: testGetRuleNameFromNotInitializedRuleResult},
		{Func: testUnitVerificationResultWorkWithNotInitialized},
		{Func: testUnitPolicyResultWorkWithNotInitialized},
		{Func: testUnitRuleResultWorkWithNotInitialized},
	}.Runner(t)
}

func testNewVerificationContextOk(t *testing.T, _ ...interface{}) {
	sig := createSignature(t)
	if val, err := NewVerificationContext(sig); err != nil || val == nil {
		t.Fatal("Failed to create verification context with only signature.")
	}
}

func testNewVerificationContextNilOptions(t *testing.T, _ ...interface{}) {
	sig := createSignature(t)
	if val, err := NewVerificationContext(sig, nil); err == nil || val != nil {
		t.Fatal("Should not be possible to create verification context with context option that is nil pointer.")
	}
}

func testNewVerificationContextWithFailingOption(t *testing.T, _ ...interface{}) {
	sig := createSignature(t)
	if val, err := NewVerificationContext(sig, func(fail bool) VerCtxOption {
		return func(_ *context) error {
			if fail {
				return errors.New(errors.KsiInvalidArgumentError).AppendMessage("Failed verification context option.")
			}
			return nil
		}
	}(true)); err == nil || val != nil {
		t.Fatal("Should not be possible to create verification context with context option fails.")
	}
}

func testNewVerificationContextWithNilSignature(t *testing.T, _ ...interface{}) {
	if _, err := NewVerificationContext(nil, nil); err == nil {
		t.Fatal("It should not be possible to create signature with nil builder.")
	}
}

func testVerCtxOptDocumentHashNil(t *testing.T, _ ...interface{}) {
	var ctx context
	verCtx := VerCtxOptDocumentHash(nil)
	if err := verCtx(&ctx); err == nil {
		t.Fatal("Document hash reset should not be possible.")
	}
}

func testVerCtxOptDocumentHash(t *testing.T, _ ...interface{}) {
	var (
		ctx     context
		docHash hash.Imprint
	)
	verCtx := VerCtxOptDocumentHash(docHash)
	if err := verCtx(&ctx); err == nil {
		t.Fatal("Document hash reset should not be possible.")
	}
}

func testVerCtxOptDocumentHashNilVerCtxBaseObject(t *testing.T, _ ...interface{}) {
	var (
		docHash = hash.Default.ZeroImprint()
	)
	verCtx := VerCtxOptDocumentHash(docHash)
	if err := verCtx(nil); err == nil {
		t.Fatal("Should not be possible to use nil verification context.")
	}
}

func testVerCtxOptInputHashLevelMaxValue(t *testing.T, _ ...interface{}) {
	var ctx context
	verCtx := VerCtxOptInputHashLevel(255)
	if err := verCtx(&ctx); err != nil {
		t.Fatal("Failed to set max document hash level.")
	}
}

func testVerCtxOptInputHashLevelNilVerCtxBaseObject(t *testing.T, _ ...interface{}) {
	verCtx := VerCtxOptInputHashLevel(0)
	if err := verCtx(nil); err == nil {
		t.Fatal("Should not be possible to use nil verification context.")
	}
}

func testVerCtxOptExtendingPermittedTrue(t *testing.T, _ ...interface{}) {
	var ctx context
	verCtx := VerCtxOptExtendingPermitted(true)
	if err := verCtx(&ctx); err != nil {
		t.Fatal("Failed to set extending permitted to true.")
	}
	if ctx.obj.extendingPerm != true {
		t.Fatal("Extending permitted was not set to true.")
	}
}

func testVerCtxOptExtendingPermittedFalse(t *testing.T, _ ...interface{}) {
	var ctx context
	verCtx := VerCtxOptExtendingPermitted(false)
	if err := verCtx(&ctx); err != nil {
		t.Fatal("Failed to set extending permitted to false.")
	}
	if ctx.obj.extendingPerm != false {
		t.Fatal("Extending permitted was not set to false.")
	}
}

func testVerCtxOptExtendingPermittedNilVerCtxBaseObject(t *testing.T, _ ...interface{}) {
	verCtx := VerCtxOptExtendingPermitted(false)
	if err := verCtx(nil); err == nil {
		t.Fatal("Should not be possible to use nil verification context.")
	}
}

func testVerCtxOptCalendarProviderNil(t *testing.T, _ ...interface{}) {
	var ctx context
	verCtx := VerCtxOptCalendarProvider(nil)
	if err := verCtx(&ctx); err == nil {
		t.Fatal("")
	}
}

func testVerCtxOptCalendarProviderNotInitialized(t *testing.T, _ ...interface{}) {
	var (
		ctx context
		cp  verify.CalendarProvider
	)
	verCtx := VerCtxOptCalendarProvider(cp)
	if err := verCtx(&ctx); err == nil {
		t.Fatal("")
	}
}

func testVerCtxOptCalendarProviderNilVerCtxBaseObject(t *testing.T, _ ...interface{}) {
	var (
		cp mockCalendarProvider
	)
	verCtx := VerCtxOptCalendarProvider(&cp)
	if err := verCtx(nil); err == nil {
		t.Fatal("Should not be possible to use nil verification context.")
	}
}

func testVerCtxOptPublicationsFileHandlerNil(t *testing.T, _ ...interface{}) {
	var (
		ctx context
	)
	verCtx := VerCtxOptPublicationsFileHandler(nil)
	if err := verCtx(&ctx); err == nil {
		t.Fatal("Publications file handler reset should not be possible")
	}
}

func testVerCtxOptPublicationsFileHandlerNilVerCtxBaseObject(t *testing.T, _ ...interface{}) {
	var (
		pfh publications.FileHandler
	)
	verCtx := VerCtxOptPublicationsFileHandler(&pfh)
	if err := verCtx(nil); err == nil {
		t.Fatal("Should not be possible to use nil verification context.")
	}
}

func testVerCtxOptUserPublicationNil(t *testing.T, _ ...interface{}) {
	var (
		ctx context
	)
	verCtx := VerCtxOptUserPublication(nil)
	if err := verCtx(&ctx); err == nil {
		t.Fatal("User publication reset should not be possible")
	}
}

func testVerCtxOptUserPublicationNilVerCtxBaseObject(t *testing.T, _ ...interface{}) {
	var (
		userPub pdu.PublicationData
	)
	verCtx := VerCtxOptUserPublication(&userPub)
	if err := verCtx(nil); err == nil {
		t.Fatal("Should not be possible to use nil verification context.")
	}
}

func testVerCtxOptPublicationsFileNil(t *testing.T, _ ...interface{}) {
	var (
		ctx context
	)
	verCtx := VerCtxOptPublicationsFile(nil)
	if err := verCtx(&ctx); err == nil {
		t.Fatal("Publications file reset should not be possible")
	}
}

func testVerCtxOptPublicationsFileNilVerCtxBaseObject(t *testing.T, _ ...interface{}) {
	var (
		pubFile publications.File
	)
	verCtx := VerCtxOptPublicationsFile(&pubFile)
	if err := verCtx(nil); err == nil {
		t.Fatal("Should not be possible to use nil verification context.")
	}
}

func testGetResultsFromNilVerCtx(t *testing.T, _ ...interface{}) {
	var ctx *VerificationContext
	if _, err := ctx.Result(); err == nil {
		t.Fatal("Should not be possible to get results from nil object.")
	}
}

func testGetResultsFromNotInitializedVerCtx(t *testing.T, _ ...interface{}) {
	var ctx VerificationContext
	if result, err := ctx.Result(); err != nil || result != nil {
		t.Fatal("Not initialized context could only have nil result.")
	}
}

func testGetStringFromNilVerResult(t *testing.T, _ ...interface{}) {
	var result *VerificationResult
	if result.String() != "" {
		t.Fatal("Nil verification results should return empty string.")
	}
}

func testGetStringFromNotInitializedVerResult(t *testing.T, _ ...interface{}) {
	var result VerificationResult
	if result.String() == "" {
		t.Fatal("Not initialized verification results should return empty string.")
	}
}
func testGetErrorFromNilVerResult(t *testing.T, _ ...interface{}) {
	var result *VerificationResult
	if err := result.Error(); err == nil {
		t.Fatal("Should not be possible to get Error from nil object.")
	}
}

func testGetErrorFromNotInitializedVerResult(t *testing.T, _ ...interface{}) {
	var result VerificationResult
	if err := result.Error(); err == nil {
		t.Fatal("Not initialized verification should not return nil error as final result is nil.")
	}
}

func testGetPolicyResultsFromNilVerResult(t *testing.T, _ ...interface{}) {
	var result *VerificationResult
	if results := result.PolicyResults(); results != nil {
		t.Fatal("Nil verification results can not have anything but nil results.")
	}
}

func testGetPolicyResultsFromNotInitializedVerResult(t *testing.T, _ ...interface{}) {
	var result VerificationResult
	if results := result.PolicyResults(); results != nil {
		t.Fatal("Not initialized verification results can not have anything but nil results.")
	}
}
func testGetFinalResultFromNilVerResult(t *testing.T, _ ...interface{}) {
	var result *VerificationResult
	if finalResult := result.FinalResult(); finalResult != nil {
		t.Fatal("Nil verification results can not have anything but nil final result.")
	}
}

func testGetFinalResultFromNotInitializedVerResult(t *testing.T, _ ...interface{}) {
	var result VerificationResult
	if finalResult := result.FinalResult(); finalResult != nil {
		t.Fatal("Not initialized verification results can not have anything but nil final result.")
	}
}

func testGetPolicyNameFromNilPolicyResult(t *testing.T, _ ...interface{}) {
	var policyResult *PolicyResult
	if policyResult.PolicyName() != "" {
		t.Fatal("Nil policy result can have nothing but empty string as name.")
	}
}

func testGetPolicyNameFromNotInitializedPolicyResult(t *testing.T, _ ...interface{}) {
	var policyResult PolicyResult
	if policyResult.PolicyName() != "" {
		t.Fatal("Not initialized policy result can have nothing but empty string as name.")
	}
}

func testGetPolicyNameFromOkPolicyResult(t *testing.T, _ ...interface{}) {
	var policyResult = &PolicyResult{policy: SuccessPolicy}
	if policyName := policyResult.PolicyName(); policyName != SuccessPolicy.String() {
		t.Fatal("Unexpected policy name in policy result: ", policyName)
	}
}

func testGetRuleResultsFromNilPolicyResult(t *testing.T, _ ...interface{}) {
	var policyResult *PolicyResult
	if ruleResults := policyResult.RuleResults(); ruleResults != nil {
		t.Fatal("Nil policy result can have nothing but nil rule results.")
	}
}

func testGetRuleResultsFromNotInitializedPolicyResult(t *testing.T, _ ...interface{}) {
	var policyResult PolicyResult
	if ruleResults := policyResult.RuleResults(); ruleResults != nil {
		t.Fatal("Not initialized policy result can have nothing but nil rule results.")
	}
}

func testGetStringFromNilRuleResult(t *testing.T, _ ...interface{}) {
	var ruleResult *RuleResult
	if ruleResult.String() != "" {
		t.Fatal("Nil rule results should return empty string on String() call.")
	}
}

func testGetResultCodeFromNilRuleResult(t *testing.T, _ ...interface{}) {
	var ruleResult *RuleResult
	if _, err := ruleResult.ResultCode(); err == nil {
		t.Fatal("Should not be possible to get result code from nil result")
	}
}

func testGetResultCodeFromNotInitializedRuleResult(t *testing.T, _ ...interface{}) {
	var ruleResult RuleResult
	if code, err := ruleResult.ResultCode(); err != nil && code != result.OK {
		t.Fatal("Not initialized result's result code should be OK.")
	}
}

func testGetErrorCodeFromNilRuleResult(t *testing.T, _ ...interface{}) {
	var ruleResult *RuleResult
	if _, err := ruleResult.ErrorCode(); err == nil {
		t.Fatal("Should not be possible to get error code from nil result")
	}
}

func testGetErrorCodeFromNotInitializedRuleResult(t *testing.T, _ ...interface{}) {
	var ruleResult RuleResult
	if code, err := ruleResult.ErrorCode(); err != nil && code != reserr.ErrNA {
		t.Fatal("Not initialized result's error code should be NA.")
	}
}

func testGetStatusErrFromNilRuleResult(t *testing.T, _ ...interface{}) {
	var ruleResult *RuleResult
	if _, err := ruleResult.StatusErr(); err == nil {
		t.Fatal("Should not be possible to get status error from nil result")
	}
}

func testGetStatusErrFromNotInitializedRuleResult(t *testing.T, _ ...interface{}) {
	var ruleResult RuleResult
	if status, err := ruleResult.StatusErr(); err != nil && status != nil {
		t.Fatal("Not initialized result's status error should be nil.")
	}
}

func testGetRuleNameFromNilRuleResult(t *testing.T, _ ...interface{}) {
	var ruleResult *RuleResult
	if ruleResult.String() != "" {
		t.Fatal("Nil rule result can have nothing but empty string as name.")
	}
}

func testGetRuleNameFromNotInitializedRuleResult(t *testing.T, _ ...interface{}) {
	var ruleResult RuleResult
	if ruleResult.RuleName() != "" {
		t.Fatal("Not initialized rule result can have nothing but empty string as name.")
	}
}

func testUnitVerificationResultWorkWithNotInitialized(t *testing.T, _ ...interface{}) {
	r := &VerificationResult{}

	err := r.Error()
	if err == nil {
		t.Fatal("Previous call should have been failed.")
	}

	if ec := errors.KsiErr(err).Code(); ec != errors.KsiInvalidArgumentError {
		t.Fatalf("Invalid error code: expecting %v, but got %v.", errors.KsiInvalidArgumentError, ec)
	}

	expStr := "Final <no final result>\n"
	if str := r.String(); str != expStr {
		t.Fatalf("String() on not initialized stuct must return '%v' instead of '%v'!", expStr, str)
	}

	if ret := r.PolicyResults(); ret != nil {
		t.Fatal("Getter on not initialized object must return nil!")
	}

	if ret := r.FinalResult(); ret != nil {
		t.Fatal("Getter on not initialized object must return nil!")
	}
}

func testUnitPolicyResultWorkWithNotInitialized(t *testing.T, _ ...interface{}) {
	r := &PolicyResult{}

	if str := r.PolicyName(); str != "" {
		t.Fatalf("PolicyName() on not initialized stuct must return empty string instead of '%v'!", str)
	}

	if ret := r.RuleResults(); ret != nil {
		t.Fatal("Getter on not initialized object must return nil!")
	}
}

func testUnitRuleResultWorkWithNotInitialized(t *testing.T, _ ...interface{}) {
	r := &RuleResult{}

	if str := r.String(); str != "" {
		t.Fatalf("String() on not initialized stuct must return empty string instead of '%v'!", str)
	}

	if str := r.RuleName(); str != "" {
		t.Fatalf("RuleName() on not initialized stuct must return empty string instead of '%v'!", str)
	}
}
