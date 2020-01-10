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
	"fmt"

	"github.com/guardtime/goksi/errors"
	"github.com/guardtime/goksi/log"
	"github.com/guardtime/goksi/signature/verify/result"
)

// PolicyRule describes a state for a certain Rule result.
type PolicyRule struct {
	// Can be of type Rule or *PolicyRule.
	Rule interface{}
	// Next step in case of result.OK.
	OnSuccess *PolicyRule
	// Next step in case of result.NA or result.FAIL.
	OnFail *PolicyRule
}

// Policy is verification policy interface. Verification policies consist of multiple
// PolicyRule rules.
type Policy interface {
	fmt.Stringer
	// Rules returns the PolicyRule set.
	Rules() *PolicyRule
	// Fallback returns the assigned fallback policy.
	Fallback() Policy
	// WithFallback returns a copy of the original policy with updated fallback value.
	WithFallback(Policy) Policy
	// Copy returns a copy of the original policy, excluding any modifications done to it (e.g. fallback policy).
	Copy() Policy
	// Verify performs policy verification.
	Verify(verCtx *VerificationContext) (result.Code, error)
}

// KSI policy implementation of the Policy interface.
type policyImpl struct {
	name     string
	rules    *PolicyRule
	fallback Policy
}

func (p *policyImpl) String() string {
	if p == nil {
		return ""
	}
	return p.name
}
func (p *policyImpl) Rules() *PolicyRule {
	if p == nil {
		return nil
	}
	return p.rules
}

func (p *policyImpl) Fallback() Policy {
	if p == nil {
		return nil
	}
	return p.fallback
}

func (p *policyImpl) WithFallback(fbPolicy Policy) Policy {
	if p == nil {
		return nil
	}
	tmp := p.Copy().(*policyImpl)
	tmp.fallback = fbPolicy
	return tmp
}

func (p *policyImpl) Copy() Policy {
	if p == nil {
		return nil
	}
	tmp := *p
	tmp.fallback = nil
	return &tmp
}

func (p *policyImpl) Verify(verCtx *VerificationContext) (result.Code, error) {
	if p == nil || verCtx == nil || verCtx.result == nil {
		return result.NA, errors.New(errors.KsiInvalidArgumentError)
	}

	log.Debug("Verify policy: ", p)
	verCtx.result.policyResult = append(verCtx.result.policyResult, &PolicyResult{policy: p})
	var resCode = result.FAIL
	var err error
	if resCode, err = p.Rules().Verify(verCtx); err != nil {
		return resCode, err
	}
	if resCode != result.OK {
		if fallback := p.Fallback(); fallback != nil {
			// Clear temporary data.
			verCtx.temp = &verificationTemp{}
			// Invoke the fallback policy.
			if resCode, err = fallback.Verify(verCtx); err != nil {
				return resCode, err
			}
		}
	}
	// Update verification result.
	verCtx.signature.verificationResult = verCtx.result
	return resCode, nil
}

// Verify verifies the PolicyRule set.
func (pr *PolicyRule) Verify(verCtx *VerificationContext) (result.Code, error) {
	if pr == nil || verCtx == nil || verCtx.result == nil {
		return result.NA, errors.New(errors.KsiInvalidArgumentError)
	}

	var (
		ruleRes *RuleResult
		ruleErr error
		resCode result.Code
	)
	switch rule := pr.Rule.(type) {
	case Rule:
		ruleRes, ruleErr = rule.Verify(verCtx)
		if ruleRes == nil {
			return result.NA, errors.New(errors.KsiInvalidStateError).AppendMessage("Missing rule result.")
		}
		resCode = ruleRes.resCode
		if ruleErr != nil {
			log.Debug("Rule error: ", rule, " :: ", ruleErr)
			return resCode, ruleErr
		}
		// Create new Rule result and set it as final (for actual step, as
		// this method is used recursively).
		verCtx.result.finalResult = ruleRes
		// Update policy result if it has been initialized.
		if len(verCtx.result.policyResult) != 0 {
			verCtx.result.policyResult[len(verCtx.result.policyResult)-1].ruleResults =
				append(verCtx.result.policyResult[len(verCtx.result.policyResult)-1].ruleResults,
					verCtx.result.finalResult)
		}
		log.Debug(verCtx.result.finalResult)
	case *PolicyRule:
		if resCode, ruleErr = rule.Verify(verCtx); ruleErr != nil {
			return resCode, ruleErr
		}
	default:
		return result.NA, errors.New(errors.KsiInvalidFormatError).
			AppendMessage(fmt.Sprintf("Unknown Rule type: %T", rule))
	}

	// Check what is next.
	switch resCode {
	case result.OK:
		if pr.OnSuccess != nil {
			return pr.OnSuccess.Verify(verCtx)
		}
	case result.NA, result.FAIL:
		if pr.OnFail != nil {
			return pr.OnFail.Verify(verCtx)
		}
	default:
		return result.NA, errors.New(errors.KsiInvalidStateError).
			AppendMessage("Unknown verification result code.")
	}
	return resCode, nil
}

var (
	// FailPolicy contains only one Rule (FailRule) with no further action.
	FailPolicy = &policyImpl{
		name:     "FailPolicy",
		rules:    &failPolicyRule,
		fallback: nil,
	}

	failPolicyRule = PolicyRule{
		Rule:      FailRule{},
		OnSuccess: nil,
		OnFail:    nil,
	}
)

var (
	// SuccessPolicy contains only one Rule (OkRule) with no further action.
	SuccessPolicy = &policyImpl{
		name:     "SuccessPolicy",
		rules:    &okPolicyRule,
		fallback: nil,
	}

	okPolicyRule = PolicyRule{
		Rule:      OkRule{},
		OnSuccess: nil,
		OnFail:    nil,
	}
)

var (
	// DefaultVerificationPolicy policy uses all the defined policies in the specified order. Verification starts off
	// with internal verification and if successful, continues with publication-based and/or key-based verification,
	// depending on the availability of calendar hash chain, calendar authentication record or publication
	// record in the signature. The default policy tries all available verification policies until a signature
	// correctness is proved or disproved and is thus the recommended policy for verification unless some restriction
	// dictates the use of a specific verification policy.
	//
	// See verification context options to provide needed information:
	//   VerCtxOptPublicationsFile        - Provide a trusted publications file or set publications file handler (optional).
	//   VerCtxOptPublicationsFileHandler
	//   VerCtxOptExtendingPermitted      - Permit extending (optional).
	//   VerCtxOptCalendarProvider        - Provider extending service provider (optional).
	//   VerCtxOptDocumentHash            - Document hash (optional).
	//   VerCtxOptInputHashLevel          - Input hash level (optional).
	DefaultVerificationPolicy = &policyImpl{
		name:     "DefaultPolicy",
		rules:    &defPolicyRule_internal,
		fallback: nil,
	}

	defPolicyRule_internal = PolicyRule{
		Rule:      &internalPolicyRule,
		OnSuccess: &defPolicyRule_pubFileVerificaiton,
		OnFail:    nil,
	}

	defPolicyRule_pubFileVerificaiton = PolicyRule{
		Rule:      &pubFileBasedPolicyRule,
		OnSuccess: nil,
		OnFail:    &defPolicyRule_keyVerificaiton,
	}

	defPolicyRule_keyVerificaiton = PolicyRule{
		Rule:      &keyBasedPolicyRule,
		OnSuccess: nil,
		OnFail:    nil,
	}
)

var (
	// InternalVerificationPolicy verifies the consistency of various internal components of the signature without
	// requiring any additional data from the user. The verified components are the aggregation chain, calendar chain
	// (optional), calendar authentication record (optional) and publication record (optional). Additionally, if a
	// document hash is provided, the signature is verified against it.
	//
	// See verification context options to provide needed information:
	//   VerCtxOptDocumentHash       - Document hash (optional).
	//   VerCtxOptInputHashLevel     - Input hash level (optional).
	InternalVerificationPolicy = &policyImpl{
		name:     "InternalVerificationPolicy",
		rules:    &internalPolicyRule,
		fallback: nil,
	}

	internalPolicyRule = PolicyRule{
		Rule:      DocumentHashPresenceRule{},
		OnSuccess: &internalPolicyRule_DocumentHashAlgorithmVerification,
		OnFail:    &internalPolicyRule_InputHashLevelVerificationRule,
	}

	internalPolicyRule_DocumentHashAlgorithmVerification = PolicyRule{
		Rule:      DocumentHashAlgorithmVerificationRule{},
		OnSuccess: &internalPolicyRule_DocumentHashVerification,
		OnFail:    nil,
	}
	internalPolicyRule_DocumentHashVerification = PolicyRule{
		Rule:      DocumentHashVerificationRule{},
		OnSuccess: &internalPolicyRule_InputHashLevelVerificationRule,
		OnFail:    nil,
	}

	internalPolicyRule_InputHashLevelVerificationRule = PolicyRule{
		Rule:      InputHashLevelVerificationRule{},
		OnSuccess: &internalPolicyRule_InputHashAlgorithmVerification,
		OnFail:    nil,
	}

	internalPolicyRule_InputHashAlgorithmVerification = PolicyRule{
		Rule:      InputHashAlgorithmVerificationRule{},
		OnSuccess: &internalPolicyRule_ContainsRFC3161,
		OnFail:    nil,
	}

	internalPolicyRule_ContainsRFC3161 = PolicyRule{
		Rule:      Rfc3161RecordPresenceRule{},
		OnSuccess: &internalPolicyRule_Rfc3161RecordHashAlgorithmVerification,
		OnFail:    &internalPolicyRule_AggregationHashChainIndexContinuationVerification,
	}

	internalPolicyRule_Rfc3161RecordHashAlgorithmVerification = PolicyRule{
		Rule:      Rfc3161RecordHashAlgorithmVerificationRule{},
		OnSuccess: &internalPolicyRule_Rfc3161RecordOutputHashAlgorithmVerification,
		OnFail:    nil,
	}

	internalPolicyRule_Rfc3161RecordOutputHashAlgorithmVerification = PolicyRule{
		Rule:      Rfc3161RecordOutputHashAlgorithmVerificationRule{},
		OnSuccess: &internalPolicyRule_AggregationHashChainIndexContinuationVerification,
		OnFail:    nil,
	}

	internalPolicyRule_AggregationHashChainIndexContinuationVerification = PolicyRule{
		Rule:      AggregationHashChainIndexContinuationVerificationRule{},
		OnSuccess: &internalPolicyRule_AggregationChainMetaDataVerification,
		OnFail:    nil,
	}

	internalPolicyRule_AggregationChainMetaDataVerification = PolicyRule{
		Rule:      AggregationChainMetaDataVerificationRule{},
		OnSuccess: &internalPolicyRule_AggregationChainHashAlgorithmVerification,
		OnFail:    nil,
	}

	internalPolicyRule_AggregationChainHashAlgorithmVerification = PolicyRule{
		Rule:      AggregationChainHashAlgorithmVerificationRule{},
		OnSuccess: &internalPolicyRule_AggregationHashChainConsistencyVerification,
		OnFail:    nil,
	}

	internalPolicyRule_AggregationHashChainConsistencyVerification = PolicyRule{
		Rule:      AggregationHashChainConsistencyVerificationRule{},
		OnSuccess: &internalPolicyRule_AggregationHashChainTimeConsistencyVerification,
		OnFail:    nil,
	}

	internalPolicyRule_AggregationHashChainTimeConsistencyVerification = PolicyRule{
		Rule:      AggregationHashChainTimeConsistencyVerificationRule{},
		OnSuccess: &internalPolicyRule_AggregationHashChainIndexConsistencyVerification,
		OnFail:    nil,
	}

	internalPolicyRule_AggregationHashChainIndexConsistencyVerification = PolicyRule{
		Rule:      AggregationHashChainIndexConsistencyVerificationRule{},
		OnSuccess: &internalPolicyRule_ContainsCalendarChain,
		OnFail:    nil,
	}

	internalPolicyRule_ContainsCalendarChain = PolicyRule{
		Rule:      CalendarHashChainPresenceRule{},
		OnSuccess: &internalPolicyRule_CalendarHashChainInputHashVerification,
		OnFail:    &okPolicyRule,
	}

	internalPolicyRule_CalendarHashChainInputHashVerification = PolicyRule{
		Rule:      CalendarHashChainInputHashVerificationRule{},
		OnSuccess: &internalPolicyRule_CalendarHashChainAggregationTimeVerification,
		OnFail:    nil,
	}

	internalPolicyRule_CalendarHashChainAggregationTimeVerification = PolicyRule{
		Rule:      CalendarHashChainAggregationTimeVerificationRule{},
		OnSuccess: &internalPolicyRule_CalendarHashChainRegistrationTimeVerification,
		OnFail:    nil,
	}

	internalPolicyRule_CalendarHashChainRegistrationTimeVerification = PolicyRule{
		Rule:      CalendarHashChainRegistrationTimeVerificationRule{},
		OnSuccess: &internalPolicyRule_CalendarChainHashAlgorithmObsoleteAtPubTime,
		OnFail:    nil,
	}

	internalPolicyRule_CalendarChainHashAlgorithmObsoleteAtPubTime = PolicyRule{
		Rule:      CalendarChainHashAlgorithmObsoleteAtPubTimeVerificationRule{},
		OnSuccess: &internalPolicyRule_PublicationRecordPresence,
		OnFail:    nil,
	}

	internalPolicyRule_PublicationRecordPresence = PolicyRule{
		Rule:      PublicationRecordPresenceRule{},
		OnSuccess: &internalPolicyRule_PublicationRecordPublicationTimeVerification,
		OnFail:    &internalPolicyRule_CalendarAuthRecordPresence,
	}

	internalPolicyRule_PublicationRecordPublicationTimeVerification = PolicyRule{
		Rule:      PublicationRecordPublicationTimeVerificationRule{},
		OnSuccess: &internalPolicyRule_PublicationRecordPublicationHashVerification,
		OnFail:    nil,
	}

	internalPolicyRule_PublicationRecordPublicationHashVerification = PolicyRule{
		Rule:      PublicationRecordPublicationHashVerificationRule{},
		OnSuccess: nil,
		OnFail:    nil,
	}

	internalPolicyRule_CalendarAuthRecordPresence = PolicyRule{
		Rule:      CalendarAuthRecordPresenceRule{},
		OnSuccess: &internalPolicyRule_CalendarAuthenticationRecordAggregationTimeVerification,
		OnFail:    &okPolicyRule,
	}

	internalPolicyRule_CalendarAuthenticationRecordAggregationTimeVerification = PolicyRule{
		Rule:      CalendarAuthenticationRecordAggregationTimeVerificationRule{},
		OnSuccess: &internalPolicyRule_CalendarAuthenticationRecordAggregationHashVerification,
		OnFail:    nil,
	}

	internalPolicyRule_CalendarAuthenticationRecordAggregationHashVerification = PolicyRule{
		Rule:      CalendarAuthenticationRecordAggregationHashVerificationRule{},
		OnSuccess: nil,
		OnFail:    nil,
	}
)

var (
	// UserProvidedPublicationBasedVerificationPolicy (Publication-based verification) verifies signature internally
	// using InternalVerificationPolicy followed by publication record verification against user provided publication.
	// If publication record does not exist or publication time differs from the user provided publication and extending
	// is permitted, signature is extended and the received calendar hash chain match is verified against input signature
	// aggregation hash chain and user publication.
	//
	// For conclusive results the signature must either contain a publication record with a suitable publication or
	// signature extending must be permitted and configured. Note that input signature is not changed.
	//
	// See verification context options to provide needed information:
	//   VerCtxOptUserPublication    - Provide user publication (mandatory).
	//   VerCtxOptExtendingPermitted - Permit extending (optional).
	//   VerCtxOptCalendarProvider   - Provider extending service provider (optional).
	//   VerCtxOptDocumentHash       - Document hash (optional).
	//   VerCtxOptInputHashLevel     - Input hash level (optional).
	UserProvidedPublicationBasedVerificationPolicy = &policyImpl{
		name:     "UserProvidedPublicationBasedVerificationPolicy",
		rules:    &userPubBasedPolicyRule_internal,
		fallback: nil,
	}

	userPubBasedPolicyRule_internal = PolicyRule{
		Rule:      &internalPolicyRule,
		OnSuccess: &userPubBasedPolicyRule,
		OnFail:    nil,
	}

	userPubBasedPolicyRule = PolicyRule{
		Rule:      UserProvidedPublicationExistenceRule{},
		OnSuccess: &userPubBasedPolicyRule_PublicationRecordPresence,
		OnFail:    nil,
	}

	userPubBasedPolicyRule_PublicationRecordPresence = PolicyRule{
		Rule:      PublicationRecordPresenceRule{},
		OnSuccess: &userPubBasedPolicyRule_TimeVerification,
		OnFail:    &userPubBasedPolicyRule_CreationTimeVerification,
	}

	userPubBasedPolicyRule_TimeVerification = PolicyRule{
		Rule:      UserProvidedPublicationTimeVerificationRule{},
		OnSuccess: &userPubBasedPolicyRule_HashVerification,
		OnFail:    &userPubBasedPolicyRule_CreationTimeVerification,
	}

	userPubBasedPolicyRule_HashVerification = PolicyRule{
		Rule:      UserProvidedPublicationHashVerificationRule{},
		OnSuccess: &userPubBasedPolicyRule_SignatureCalendarHashAlgorithmDeprecatedAtPubTimeVerification,
		OnFail:    nil,
	}

	userPubBasedPolicyRule_SignatureCalendarHashAlgorithmDeprecatedAtPubTimeVerification = PolicyRule{
		Rule:      SignatureCalendarHashAlgorithmDeprecatedAtPubTimeVerificationRule{},
		OnSuccess: nil,
		OnFail:    nil,
	}

	userPubBasedPolicyRule_CreationTimeVerification = PolicyRule{
		Rule:      UserProvidedPublicationCreationTimeVerificationRule{},
		OnSuccess: &userPubBasedPolicyRule_ExtendingPermitted,
		OnFail:    nil,
	}

	userPubBasedPolicyRule_ExtendingPermitted = PolicyRule{
		Rule:      ExtendingPermittedRule{},
		OnSuccess: &userPubBasedPolicyRule_ExtendToPublication,
		OnFail:    nil,
	}

	userPubBasedPolicyRule_ExtendToPublication = PolicyRule{
		Rule:      UserProvidedPublicationExtendToPublication{},
		OnSuccess: &userPubBasedPolicyRule_ExtendedCalendarHashAlgorithmDeprecatedAtPubTimeVerification,
		OnFail:    nil,
	}

	userPubBasedPolicyRule_ExtendedCalendarHashAlgorithmDeprecatedAtPubTimeVerification = PolicyRule{
		Rule:      UserProvidedPublicationExtendedCalendarHashAlgorithmDeprecatedAtPubTimeVerificationRule{},
		OnSuccess: &userPubBasedPolicyRule_HashMatchesExtendedResponseVerification,
		OnFail:    nil,
	}

	userPubBasedPolicyRule_HashMatchesExtendedResponseVerification = PolicyRule{
		Rule:      UserProvidedPublicationHashMatchesExtendedResponseVerificationRule{},
		OnSuccess: &userPubBasedPolicyRule_TimeMatchesExtendedResponseVerification,
		OnFail:    nil,
	}

	userPubBasedPolicyRule_TimeMatchesExtendedResponseVerification = PolicyRule{
		Rule:      UserProvidedPublicationTimeMatchesExtendedResponseVerificationRule{},
		OnSuccess: &userPubBasedPolicyRule_ExtendedSignatureInputHashVerification,
		OnFail:    nil,
	}

	userPubBasedPolicyRule_ExtendedSignatureInputHashVerification = PolicyRule{
		Rule:      UserProvidedPublicationExtendedSignatureInputHashVerificationRule{},
		OnSuccess: nil,
		OnFail:    nil,
	}
)

var (
	// PublicationsFileBasedVerificationPolicy (Publication-based verification) verifies signature internally
	// using InternalVerificationPolicy followed by publication record verification against provided publications file.
	// If the signature does not contain a publication record or identical publication record can not be found in the
	// publications file, the signature is extended. Successful extending can only be performed if extending is
	// permitted and the publications file contains suitable publication record. Received (extended) calendar hash chain
	// compatibility is verified with the signature and matching suitable publication record.
	//
	// For conclusive results, a trusted publications file that contains suitable publications must be provided.
	// If verification needs extending, signature extending must be permitted and configured. Note that input
	// signature is not changed.
	//
	// See verification context options to provide needed information:
	//   VerCtxOptPublicationsFile        - Provide a trusted publications file or set publications file handler (mandatory).
	//   VerCtxOptPublicationsFileHandler
	//   VerCtxOptCalendarProvider        - Provider extending service provider (optional).
	//   VerCtxOptDocumentHash            - Document hash (optional).
	//   VerCtxOptInputHashLevel          - Input hash level (optional).
	PublicationsFileBasedVerificationPolicy = &policyImpl{
		name:     "PublicationsFileBasedVerificationPolicy",
		rules:    &pubFileBasedPolicyRule_internal,
		fallback: nil,
	}

	pubFileBasedPolicyRule_internal = PolicyRule{
		Rule:      &internalPolicyRule,
		OnSuccess: &pubFileBasedPolicyRule,
		OnFail:    nil,
	}

	pubFileBasedPolicyRule = PolicyRule{
		Rule:      PublicationRecordPresenceRule{},
		OnSuccess: &pubFileBasedPolicyRule_PublicationsFileContainsSignaturePublication,
		OnFail:    &pubFileBasedPolicyRule_PublicationsFileContainsSuitablePublicationVerification,
	}

	pubFileBasedPolicyRule_PublicationsFileContainsSignaturePublication = PolicyRule{
		Rule:      PublicationsFileContainsSignaturePublicationVerificationRule{},
		OnSuccess: &pubFileBasedPolicyRule_PublicationsFileSignaturePublicationVerification,
		OnFail:    &pubFileBasedPolicyRule_PublicationsFileContainsSuitablePublicationVerification,
	}

	pubFileBasedPolicyRule_PublicationsFileSignaturePublicationVerification = PolicyRule{
		Rule:      PublicationsFileSignaturePublicationHashVerificationRule{},
		OnSuccess: &pubFileBasedPolicyRule_SignatureCalendarHashAlgorithmDeprecatedAtPubTimeVerification,
		OnFail:    nil,
	}

	pubFileBasedPolicyRule_SignatureCalendarHashAlgorithmDeprecatedAtPubTimeVerification = PolicyRule{
		Rule:      SignatureCalendarHashAlgorithmDeprecatedAtPubTimeVerificationRule{},
		OnSuccess: nil,
		OnFail:    nil,
	}

	pubFileBasedPolicyRule_PublicationsFileContainsSuitablePublicationVerification = PolicyRule{
		Rule:      PublicationsFileContainsSuitablePublicationVerificationRule{},
		OnSuccess: &pubFileBasedPolicyRule_ExtendingPermitted,
		OnFail:    nil,
	}

	pubFileBasedPolicyRule_ExtendingPermitted = PolicyRule{
		Rule:      ExtendingPermittedRule{},
		OnSuccess: &pubFileBasedPolicyRule_ExtendToPublication,
		OnFail:    nil,
	}

	pubFileBasedPolicyRule_ExtendToPublication = PolicyRule{
		Rule:      PublicationsFileExtendToPublication{},
		OnSuccess: &pubFileBasedPolicyRule_ExtendedCalendarHashAlgorithmDeprecatedAtPubTimeVerification,
		OnFail:    nil,
	}

	pubFileBasedPolicyRule_ExtendedCalendarHashAlgorithmDeprecatedAtPubTimeVerification = PolicyRule{
		Rule:      PubFileExtendedCalendarHashAlgorithmDeprecatedAtPubTimeVerificationRule{},
		OnSuccess: &pubFileBasedPolicyRule_HashMatchesExtendedResponseVerification,
		OnFail:    nil,
	}

	pubFileBasedPolicyRule_HashMatchesExtendedResponseVerification = PolicyRule{
		Rule:      PublicationsFilePublicationHashMatchesExtenderResponseVerificationRule{},
		OnSuccess: &pubFileBasedPolicyRule_TimeMatchesExtendedResponseVerification,
		OnFail:    nil,
	}

	pubFileBasedPolicyRule_TimeMatchesExtendedResponseVerification = PolicyRule{
		Rule:      PublicationsFilePublicationTimeMatchesExtendedResponseVerificationRule{},
		OnSuccess: &pubFileBasedPolicyRule_ExtendedSignatureInputHashVerification,
		OnFail:    nil,
	}

	pubFileBasedPolicyRule_ExtendedSignatureInputHashVerification = PolicyRule{
		Rule:      PublicationsFileExtendedSignatureInputHashVerificationRule{},
		OnSuccess: nil,
		OnFail:    nil,
	}
)

var (
	// KeyBasedVerificationPolicy (Key-based verification) verifies signature internally using
	// InternalVerificationPolicy followed by calendar authentication record verification against PKI signature
	// and certificates provided by trusted publications file.
	//
	// For conclusive results, a calendar authentication record must be present in the signature. A trusted
	// publications file must be provided for performing lookup of a matching certificate.
	//
	// See verification context options to provide needed information:
	//   VerCtxOptPublicationsFile        - Provide trusted publications file or set publications file handler (mandatory).
	//   VerCtxOptPublicationsFileHandler
	//   VerCtxOptDocumentHash            - Document hash (optional).
	//   VerCtxOptInputHashLevel          - Input hash level (optional).
	KeyBasedVerificationPolicy = &policyImpl{
		name:     "KeyBasedVerificationPolicy",
		rules:    &keyBasedPolicyRule_internal,
		fallback: nil,
	}

	keyBasedPolicyRule_internal = PolicyRule{
		Rule:      &internalPolicyRule,
		OnSuccess: &keyBasedPolicyRule,
		OnFail:    nil,
	}

	keyBasedPolicyRule = PolicyRule{
		Rule:      CalendarHashChainExistenceRule{},
		OnSuccess: &keyBasedPolicyRule_CalendarHashChainAlgorithmDeprecated,
		OnFail:    nil,
	}
	keyBasedPolicyRule_CalendarHashChainAlgorithmDeprecated = PolicyRule{
		Rule:      CalendarHashChainAlgorithmDeprecatedRule{},
		OnSuccess: &keyBasedPolicyRule_CalendarAuthenticationRecordExistence,
		OnFail:    nil,
	}
	keyBasedPolicyRule_CalendarAuthenticationRecordExistence = PolicyRule{
		Rule:      CalendarAuthenticationRecordExistenceRule{},
		OnSuccess: &keyBasedPolicyRule_CertificateExistence,
		OnFail:    nil,
	}
	keyBasedPolicyRule_CertificateExistence = PolicyRule{
		Rule:      CertificateExistenceRule{},
		OnSuccess: &keyBasedPolicyRule_CertificateValidity,
		OnFail:    nil,
	}
	keyBasedPolicyRule_CertificateValidity = PolicyRule{
		Rule:      CertificateValidityRule{},
		OnSuccess: &keyBasedPolicyRule_CalendarAuthenticationRecordSignatureVerification,
		OnFail:    nil,
	}
	keyBasedPolicyRule_CalendarAuthenticationRecordSignatureVerification = PolicyRule{
		Rule:      CalendarAuthenticationRecordSignatureVerificationRule{},
		OnSuccess: nil,
		OnFail:    nil,
	}
)

var (
	// CalendarBasedVerificationPolicy (Calendar-based verification) verifies signature internally using
	// InternalVerificationPolicy followed by the signature extending to either the head of the
	// calendar database (in case signature is missing calendar hash chain) or to the same publication
	// time as the signature's calendar chain. Received (extended) calendar chain compatibility is verified
	// with the signature.
	//
	// For conclusive results the Extender must be configured. Note that input signature is not changed.
	//
	// See verification context options to provide needed information:
	//   VerCtxOptCalendarProvider - Provider extending service provider (calendar data base) (mandatory).
	//   VerCtxOptDocumentHash     - Document hash (optional).
	//   VerCtxOptInputHashLevel   - Input hash level (optional).
	CalendarBasedVerificationPolicy = &policyImpl{
		name:     "CalendarBasedVerificationPolicy",
		rules:    &calBasedPolicyRule_internal,
		fallback: nil,
	}

	calBasedPolicyRule_internal = PolicyRule{
		Rule:      &internalPolicyRule,
		OnSuccess: &calBasedPolicyRule,
		OnFail:    nil,
	}

	calBasedPolicyRule = PolicyRule{
		Rule:      CalendarHashChainPresenceRule{},
		OnSuccess: &calBasedPolicyRule_ExtendSignatureCalendarChainInputHashToSamePubTime,
		OnFail:    &calBasedPolicyRule_ExtendSignatureCalendarChainInputHashToHead,
	}

	calBasedPolicyRule_ExtendSignatureCalendarChainInputHashToHead = PolicyRule{
		Rule:      ExtendSignatureCalendarChainInputHashToHead{},
		OnSuccess: &calBasedPolicyRule_ExtendedSignatureCalendarChainInputHash,
		OnFail:    nil,
	}

	calBasedPolicyRule_ExtendedSignatureCalendarChainInputHash = PolicyRule{
		Rule:      ExtendedSignatureCalendarChainInputHashVerificationRule{},
		OnSuccess: &calBasedPolicyRule_ExtendedSignatureCalendarChainAggregationTime,
		OnFail:    nil,
	}
	calBasedPolicyRule_ExtendedSignatureCalendarChainAggregationTime = PolicyRule{
		Rule:      ExtendedSignatureCalendarChainAggregationTimeVerificationRule{},
		OnSuccess: nil,
		OnFail:    nil,
	}

	calBasedPolicyRule_ExtendSignatureCalendarChainInputHashToSamePubTime = PolicyRule{
		Rule:      ExtendSignatureCalendarChainInputHashToSamePubTime{},
		OnSuccess: &calBasedPolicyRule_SignatureContainPublicationRecord,
		OnFail:    nil,
	}

	calBasedPolicyRule_SignatureContainPublicationRecord = PolicyRule{
		Rule:      PublicationRecordPresenceRule{},
		OnSuccess: &calBasedPolicyRule_CalendarChainRootHashMaches,
		OnFail:    &calBasedPolicyRule_CalendarHashChainRightLinksMatches,
	}

	calBasedPolicyRule_CalendarChainRootHashMaches = PolicyRule{
		Rule:      ExtendedSignatureCalendarChainRootHashVerificationRule{},
		OnSuccess: &calBasedPolicyRule_ExtendedSignatureCalendarChainInputHash,
		OnFail:    nil,
	}

	calBasedPolicyRule_CalendarHashChainRightLinksMatches = PolicyRule{
		Rule:      ExtendedSignatureCalendarHashChainRightLinksMatchesVerificationRule{},
		OnSuccess: &calBasedPolicyRule_ExtendedSignatureCalendarChainInputHash,
		OnFail:    nil,
	}
)
