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
	"strings"
	"time"

	"github.com/guardtime/goksi/errors"
	"github.com/guardtime/goksi/hash"
	"github.com/guardtime/goksi/log"
	"github.com/guardtime/goksi/pdu"
	"github.com/guardtime/goksi/publications"
	"github.com/guardtime/goksi/signature/verify"
	"github.com/guardtime/goksi/signature/verify/reserr"
	"github.com/guardtime/goksi/signature/verify/result"
)

type verificationTemp struct {
	aggregationOutputHash hash.Imprint
	// Signature extending response calendar hash chain.
	extendedCalendar *pdu.CalendarChain
	// Publication file to be used.
	publicationsFile *publications.File
}

// VerificationContext is a set of KSI signature verification parameters.
type VerificationContext struct {
	/*
	   User input.
	*/
	// Signature being verified.
	signature *Signature
	// Document hash to be verified.
	documentHash hash.Imprint
	// Initial aggregation level.
	inputHashLvl byte
	// Indicates whether signature extension is allowed.
	extendingPerm bool
	// The set Extender is used also for extending while verification process.
	calProvider verify.CalendarProvider
	// Initialized publications file handler for downloading publications file.
	publicationsFileHandler *publications.FileHandler
	// Publication string to be used.
	userPublication *pdu.PublicationData
	// Publication file to be used.
	userPublicationsFile *publications.File

	/*
		Verification runtime temporary data.
	*/
	temp *verificationTemp

	/*
		Verification result report.
	*/
	result *VerificationResult
}

// NewVerificationContext returns new VerificationContext instance, or error in case any input parameters are not valid.
// Optionally, additional data can be added for using while verification process via parameter opts.
func NewVerificationContext(sig *Signature, opts ...VerCtxOption) (*VerificationContext, error) {
	if sig == nil {
		return nil, errors.New(errors.KsiInvalidArgumentError)
	}

	tmp := context{obj: VerificationContext{
		signature: sig,
		result:    &VerificationResult{},
		temp:      &verificationTemp{},
	}}
	for _, optSetter := range opts {
		if optSetter == nil {
			return nil, errors.New(errors.KsiInvalidArgumentError).AppendMessage("Provided option is nil.")
		}
		if err := optSetter(&tmp); err != nil {
			return nil, errors.KsiErr(err).AppendMessage("Unable to setup verification context.")
		}
	}
	return &tmp.obj, nil
}

// VerCtxOption is verification context option to be used when initializing VerificationContext.
type VerCtxOption func(*context) error
type context struct {
	obj VerificationContext
}

// VerCtxOptDocumentHash is for setting document hash for verification process.
func VerCtxOptDocumentHash(imprint hash.Imprint) VerCtxOption {
	return func(c *context) error {
		if !imprint.IsValid() {
			return errors.New(errors.KsiInvalidArgumentError)
		}
		if c == nil {
			return errors.New(errors.KsiInvalidArgumentError).AppendMessage("Missing verification context base object.")
		}
		c.obj.documentHash = imprint
		return nil
	}
}

// VerCtxOptInputHashLevel is for setting data hash input level.
// See also VerCtxOptDocumentHash() for setting document hash.
func VerCtxOptInputHashLevel(level byte) VerCtxOption {
	return func(c *context) error {
		if c == nil {
			return errors.New(errors.KsiInvalidArgumentError).AppendMessage("Missing verification context base object.")
		}
		c.obj.inputHashLvl = level
		return nil
	}
}

// VerCtxOptExtendingPermitted option provides the ability to enable verification procedure based on signature extending.
func VerCtxOptExtendingPermitted(b bool) VerCtxOption {
	return func(c *context) error {
		if c == nil {
			return errors.New(errors.KsiInvalidArgumentError).AppendMessage("Missing verification context base object.")
		}
		c.obj.extendingPerm = b
		return nil
	}
}

// VerCtxOptCalendarProvider option specifies the calendar provider to be used in verification process
// See VerCtxOptExtendingPermitted() for enabling the use of Extender service.
func VerCtxOptCalendarProvider(cp verify.CalendarProvider) VerCtxOption {
	return func(c *context) error {
		if cp == nil {
			return errors.New(errors.KsiInvalidArgumentError)
		}
		if c == nil {
			return errors.New(errors.KsiInvalidArgumentError).AppendMessage("Missing verification context base object.")
		}
		c.obj.calProvider = cp
		return nil
	}
}

// VerCtxOptPublicationsFileHandler option specifies the publications file handler.
func VerCtxOptPublicationsFileHandler(h *publications.FileHandler) VerCtxOption {
	return func(c *context) error {
		if h == nil {
			return errors.New(errors.KsiInvalidArgumentError)
		}
		if c == nil {
			return errors.New(errors.KsiInvalidArgumentError).AppendMessage("Missing verification context base object.")
		}
		c.obj.publicationsFileHandler = h
		return nil
	}
}

// VerCtxOptUserPublication options enables verification process to be performed base on the provided publication.
func VerCtxOptUserPublication(pub *pdu.PublicationData) VerCtxOption {
	return func(c *context) error {
		if pub == nil {
			return errors.New(errors.KsiInvalidArgumentError)
		}
		if c == nil {
			return errors.New(errors.KsiInvalidArgumentError).AppendMessage("Missing verification context base object.")
		}
		c.obj.userPublication = pub
		return nil
	}
}

// VerCtxOptPublicationsFile options enables verification process to be performed base on the provided publications file.
// If set, the VerCtxOptPublicationsFileHandler() option will be ignored.
func VerCtxOptPublicationsFile(pubFile *publications.File) VerCtxOption {
	return func(c *context) error {
		if pubFile == nil {
			return errors.New(errors.KsiInvalidArgumentError)
		}
		if c == nil {
			return errors.New(errors.KsiInvalidArgumentError).AppendMessage("Missing verification context base object.")
		}
		c.obj.userPublicationsFile = pubFile
		return nil
	}
}

func (c *VerificationContext) receiveCalendar(calLast time.Time) error {
	if c == nil {
		return errors.New(errors.KsiInvalidArgumentError)
	}

	if c.calProvider == nil {
		return errors.New(errors.KsiInvalidStateError).AppendMessage("Calendar provider is not configured.")
	}
	calFirst, err := c.signature.SigningTime()
	if err != nil {
		return err
	}
	calChain, err := c.calProvider.ReceiveCalendar(calFirst, calLast)
	if err != nil {
		return err
	}
	c.temp.extendedCalendar = calChain

	return nil
}

func (c *VerificationContext) extendedCalendarHashChain() (*pdu.CalendarChain, error) {
	if c == nil {
		return nil, errors.New(errors.KsiInvalidArgumentError)
	}

	if c.temp.extendedCalendar == nil {
		return nil, errors.New(errors.KsiInvalidStateError).AppendMessage("Calendar hash chain has not been received.")
	}

	return c.temp.extendedCalendar, nil
}

func (c *VerificationContext) aggregationHashChainOutputHash() (hash.Imprint, error) {
	if c == nil {
		return nil, errors.New(errors.KsiInvalidArgumentError)
	}

	var (
		outputHash hash.Imprint
		err        error
	)
	if len(c.temp.aggregationOutputHash) == 0 {
		outputHash, err = c.signature.AggregationHashChainListAggregate(c.inputHashLvl)
		if err != nil {
			return nil, err
		}
		c.temp.aggregationOutputHash = append([]byte(nil), outputHash...)
	} else {
		outputHash = append([]byte(nil), c.temp.aggregationOutputHash...)
	}

	return outputHash, nil
}

func (c *VerificationContext) publicationsFile() (*publications.File, error) {
	if c == nil || c.temp == nil {
		return nil, errors.New(errors.KsiInvalidArgumentError)
	}

	if c.temp.publicationsFile == nil {
		if c.userPublicationsFile != nil {
			log.Debug("Using user provided publications file.")
			c.temp.publicationsFile = c.userPublicationsFile
		} else {
			log.Debug("Receiving publications file.")

			if c.publicationsFileHandler == nil {
				return nil, errors.New(errors.KsiInvalidStateError).
					AppendMessage("Publications file handler is not provided.")
			}

			tmp, err := c.publicationsFileHandler.ReceiveFile()
			if err != nil {
				return nil, err
			}
			log.Debug("Verifying publications file.")
			if err := c.publicationsFileHandler.Verify(tmp); err != nil {
				return nil, err
			}
			c.temp.publicationsFile = tmp
		}
	}
	return c.temp.publicationsFile, nil
}

// Result returns verification result report.
func (c *VerificationContext) Result() (*VerificationResult, error) {
	if c == nil {
		return nil, errors.New(errors.KsiInvalidArgumentError)
	}
	return c.result, nil
}

// VerificationResult represents signature verification result report.
type VerificationResult struct {
	policyResult []*PolicyResult
	finalResult  *RuleResult
}

// String implements fmt.(Stringer) interface.
func (r *VerificationResult) String() string {
	if r == nil {
		return ""
	}
	var b strings.Builder
	for _, polRes := range r.policyResult {
		b.WriteString("Policy result: ")
		b.WriteString(polRes.policy.String())
		b.WriteString("\n")
		for _, ruleRes := range polRes.ruleResults {
			b.WriteString(ruleRes.String())
			b.WriteString("\n")
		}
	}
	b.WriteString("Final ")
	if r.finalResult != nil {
		b.WriteString(r.finalResult.String())
	} else {
		b.WriteString("<no final result>")
	}
	b.WriteString("\n")
	return b.String()
}

// Error returns error if the verification has failed (see VerificationResultCode), otherwise nil.
func (r *VerificationResult) Error() error {
	if r == nil || r.finalResult == nil {
		return errors.New(errors.KsiInvalidArgumentError)
	}

	if r.finalResult.resCode != result.OK {
		err := errors.New(errors.KsiVerificationFailure).SetExtErrorCode(int(r.finalResult.errCode)).
			AppendMessage("Signature verification failed.").
			AppendMessage(fmt.Sprintf("%s", r))
		log.Debug(err)
		return err
	}
	return nil
}

// PolicyResults returns policy results report.
func (r *VerificationResult) PolicyResults() []*PolicyResult {
	if r == nil {
		return nil
	}
	return r.policyResult
}

// FinalResult returns verification result report conclusion.
func (r *VerificationResult) FinalResult() *RuleResult {
	if r == nil {
		return nil
	}
	return r.finalResult
}

// PolicyResult represents policy verification result report.
type PolicyResult struct {
	policy      Policy
	ruleResults []*RuleResult
}

// PolicyName returns the policy name of the receiver policy verification report, or empty string in case of an error.
func (p *PolicyResult) PolicyName() string {
	if p == nil || p.policy == nil {
		return ""
	}
	return p.policy.String()
}

// RuleResults returns policy rules result report.
func (p *PolicyResult) RuleResults() []*RuleResult {
	if p == nil {
		return nil
	}
	return p.ruleResults
}

// RuleResult represents Rule result report.
type RuleResult struct {
	resCode result.Code // Verification result code.
	errCode reserr.Code // Verification error code.
	rule    Rule        // Verification rule.
	// Error that might have occurred during verification causing the given rule result. Provides additional information
	// for further processing (e.g. in case of inconclusive result when fetching some resources).
	statusErr error
}

func newRuleResult(rule Rule, resCode result.Code) *RuleResult {
	tmp := &RuleResult{
		resCode:   resCode,
		errCode:   reserr.ErrNA,
		rule:      rule,
		statusErr: nil,
	}
	return tmp
}

func (r *RuleResult) setStatusErr(e error) *RuleResult {
	if r != nil {
		r.statusErr = e
	}
	return r
}

func (r *RuleResult) setErrCode(c reserr.Code) *RuleResult {
	if r != nil {
		r.errCode = c
	}
	return r
}

// String implements fmt.(Stringer) interface.
func (r *RuleResult) String() string {
	if r == nil || r.rule == nil {
		return ""
	}

	// Set rule result.
	var b strings.Builder
	b.WriteString(fmt.Sprintf("%s: %s(%s)", r.rule, r.resCode, r.errCode))
	// Append additional status error info if present.
	if r.statusErr != nil {
		// Errors codes.
		err := errors.KsiErr(r.statusErr)
		b.WriteString(fmt.Sprintf(" :: [%04x/%d]", uint16(err.Code()), err.ExtCode()))
		// Descriptive messages.
		msg := err.Message()
		for i := len(msg); i > 0; i-- {
			b.WriteString(fmt.Sprintf(" %s", msg[i-1]))
		}
	}
	return b.String()
}

// ResultCode returns verification result code for the given Rule.
func (r *RuleResult) ResultCode() (result.Code, error) {
	if r == nil {
		return result.NA, errors.New(errors.KsiInvalidArgumentError)
	}
	return r.resCode, nil
}

// ErrorCode returns verification error code for the given Rule, or ErrNA if result is OK.
func (r *RuleResult) ErrorCode() (reserr.Code, error) {
	if r == nil {
		return reserr.ErrNA, errors.New(errors.KsiInvalidArgumentError)
	}
	return r.errCode, nil
}

// StatusErr returns the additional status error that might have occurred during verification causing the given rule result.
func (r *RuleResult) StatusErr() (error, error) {
	if r == nil {
		return nil, errors.New(errors.KsiInvalidArgumentError)
	}
	return r.statusErr, nil
}

// RuleName returns a string representation of the given verification Rule.
func (r *RuleResult) RuleName() string {
	if r == nil || r.rule == nil {
		return ""
	}
	return r.rule.String()
}
