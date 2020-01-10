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
	"reflect"
	"time"

	"github.com/guardtime/goksi/errors"
	"github.com/guardtime/goksi/hash"
	"github.com/guardtime/goksi/log"
	"github.com/guardtime/goksi/pdu"
	"github.com/guardtime/goksi/publications"
	"github.com/guardtime/goksi/signature/verify/reserr"
	"github.com/guardtime/goksi/signature/verify/result"
)

// Rule is the verification Rule common interface.
type Rule interface {
	fmt.Stringer
	// Verify performs Rule verification.
	Verify(*VerificationContext) (*RuleResult, error)
}

func getName(r interface{}) string {
	valueOf := reflect.ValueOf(r)
	if valueOf.Type().Kind() == reflect.Ptr {
		return reflect.Indirect(valueOf).Type().Name()
	}
	return valueOf.Type().Name()
}

/*
----------------------------------------
FailPolicy rules
----------------------------------------
*/

// FailRule always returns verification code 'FAIL(None)'.
type FailRule struct{}

func (r FailRule) errCode() reserr.Code { return reserr.ErrNA }
func (r FailRule) String() string       { return getName(r) }
func (r FailRule) Verify(context *VerificationContext) (*RuleResult, error) {
	return newRuleResult(r, result.FAIL).setErrCode(r.errCode()), nil
}

/*
----------------------------------------
SuccessPolicy rules
----------------------------------------
*/

// OkRule always returns verification code 'OK'.
type OkRule struct{}

func (r OkRule) errCode() reserr.Code { return reserr.ErrNA }
func (r OkRule) String() string       { return getName(r) }
func (r OkRule) Verify(context *VerificationContext) (*RuleResult, error) {
	return newRuleResult(r, result.OK), nil
}

/*
----------------------------------------
InternalVerificationPolicy rules
----------------------------------------
*/

// DocumentHashPresenceRule verifies that document hash has been provided.
// Returns OK or NA(None).
type DocumentHashPresenceRule struct{}

func (r DocumentHashPresenceRule) errCode() reserr.Code { return reserr.ErrNA }
func (r DocumentHashPresenceRule) String() string       { return getName(r) }
func (r DocumentHashPresenceRule) Verify(context *VerificationContext) (*RuleResult, error) {
	if context == nil {
		err := errors.New(errors.KsiInvalidArgumentError)
		return newRuleResult(r, result.NA).setErrCode(reserr.Gen02).setStatusErr(err), err
	}

	if context.documentHash == nil {
		return newRuleResult(r, result.NA).setErrCode(r.errCode()), nil
	}
	return newRuleResult(r, result.OK), nil
}

// DocumentHashAlgorithmVerificationRule verifies that provided document hash algorithm does match with
// the hash algorithm of the input hash of the first aggregation chain or RFC-3161 record if present.
// Returns OK or FAIL(GEN-04).
type DocumentHashAlgorithmVerificationRule struct{}

func (r DocumentHashAlgorithmVerificationRule) errCode() reserr.Code { return reserr.Gen04 }
func (r DocumentHashAlgorithmVerificationRule) String() string       { return getName(r) }
func (r DocumentHashAlgorithmVerificationRule) Verify(context *VerificationContext) (*RuleResult, error) {
	if context == nil || context.signature == nil {
		err := errors.New(errors.KsiInvalidArgumentError)
		return newRuleResult(r, result.NA).setErrCode(reserr.Gen02).setStatusErr(err), err
	}
	if context.documentHash == nil {
		err := errors.New(errors.KsiInvalidStateError)
		return newRuleResult(r, result.NA).setErrCode(reserr.Gen02).setStatusErr(err), err
	}

	sigDocHsh, err := context.signature.DocumentHash()
	if err != nil {
		err = errors.KsiErr(err).AppendMessage("Failed to get signature document hash.")
		return newRuleResult(r, result.NA).setErrCode(reserr.Gen02).setStatusErr(err), err
	}

	if context.documentHash.Algorithm() != sigDocHsh.Algorithm() {
		return newRuleResult(r, result.FAIL).setErrCode(r.errCode()), nil
	}
	return newRuleResult(r, result.OK), nil
}

// DocumentHashVerificationRule verifies that provided document hash does match with the input hash of
// the first aggregation hash chain or RFC-3161 record if present.
// Returns OK or FAIL(GEN-01).
type DocumentHashVerificationRule struct{}

func (r DocumentHashVerificationRule) errCode() reserr.Code { return reserr.Gen01 }
func (r DocumentHashVerificationRule) String() string       { return getName(r) }
func (r DocumentHashVerificationRule) Verify(context *VerificationContext) (*RuleResult, error) {
	if context == nil {
		err := errors.New(errors.KsiInvalidArgumentError)
		return newRuleResult(r, result.NA).setErrCode(reserr.Gen02).setStatusErr(err), err
	}
	if context.documentHash == nil {
		err := errors.New(errors.KsiInvalidStateError)
		return newRuleResult(r, result.NA).setErrCode(reserr.Gen02).setStatusErr(err), err
	}

	sigDocHsh, err := context.signature.DocumentHash()
	if err != nil {
		err = errors.KsiErr(err).AppendMessage("Failed to get signature document hash.")
		return newRuleResult(r, result.NA).setErrCode(reserr.Gen02).setStatusErr(err), err
	}

	if !hash.Equal(context.documentHash.Digest(), sigDocHsh.Digest()) {
		return newRuleResult(r, result.FAIL).setErrCode(r.errCode()), nil
	}
	return newRuleResult(r, result.OK), nil
}

// InputHashLevelVerificationRule verifies that document input level (default 0) is not greater than the
// initial level correction (always 0 for RFC-3161 record) of the first hash chain.
// Returns OK or FAIL(GEN-03).
type InputHashLevelVerificationRule struct{}

func (r InputHashLevelVerificationRule) errCode() reserr.Code { return reserr.Gen03 }
func (r InputHashLevelVerificationRule) String() string       { return getName(r) }
func (r InputHashLevelVerificationRule) Verify(context *VerificationContext) (*RuleResult, error) {
	if context == nil || context.signature == nil {
		err := errors.New(errors.KsiInvalidArgumentError)
		return newRuleResult(r, result.NA).setErrCode(reserr.Gen02).setStatusErr(err), err
	}

	// Check if RFC3161 record is present.
	rfc3161, err := context.signature.Rfc3161()
	if err != nil {
		err = errors.KsiErr(err).AppendMessage("Failed to get RFC3161 record.")
		return newRuleResult(r, result.NA).setErrCode(reserr.Gen02).setStatusErr(err), err
	}
	if rfc3161 != nil {
		// Document input level must be always 0 for RFC-3161 record.
		if context.inputHashLvl > 0 {
			return newRuleResult(r, result.FAIL).setErrCode(r.errCode()), nil
		}
		return newRuleResult(r, result.OK), nil
	}

	aggrChains, err := context.signature.AggregationHashChainList()
	if err != nil {
		err = errors.KsiErr(err).AppendMessage("Failed to get aggregation hash chain list.")
		return newRuleResult(r, result.NA).setErrCode(reserr.Gen02).setStatusErr(err), err
	}
	if aggrChains == nil || len(aggrChains) == 0 {
		err := errors.New(errors.KsiInvalidStateError).AppendMessage("Missing aggregation hash chain list.")
		return newRuleResult(r, result.NA).setErrCode(reserr.Gen02).setStatusErr(err), err
	}
	chainLinks, err := aggrChains[0].ChainLinks()
	if err != nil {
		err = errors.KsiErr(err).AppendMessage("Failed to get aggregation hash chain list first chain links.")
		return newRuleResult(r, result.NA).setErrCode(reserr.Gen02).setStatusErr(err), err
	}
	if chainLinks == nil || len(chainLinks) == 0 {
		err := errors.New(errors.KsiInvalidStateError).AppendMessage("Missing aggregation hash chain links.")
		return newRuleResult(r, result.NA).setErrCode(reserr.Gen02).setStatusErr(err), err
	}
	lvl, err := chainLinks[0].LevelCorrection()
	if err != nil {
		err = errors.KsiErr(err).AppendMessage("Failed to get link level correction.")
		return newRuleResult(r, result.NA).setErrCode(reserr.Gen02).setStatusErr(err), err
	}
	if lvl > 0xff {
		err := errors.New(errors.KsiInvalidFormatError).AppendMessage("Level correction is larger than 0xff.")
		return newRuleResult(r, result.NA).setErrCode(reserr.Gen02).setStatusErr(err), err
	}

	if byte(lvl) < context.inputHashLvl {
		return newRuleResult(r, result.FAIL).setErrCode(r.errCode()), nil
	}
	return newRuleResult(r, result.OK), nil
}

// InputHashAlgorithmVerificationRule verifies that the hash algorithm of the input hash of the signature
// (input hash of the first aggregation hash chain, or if present, the input hash of the RFC-3161 record)
// was trusted at the aggregation time (i.e. aggregation time in the current record).
// Returns OK or FAIL(INT-13).
type InputHashAlgorithmVerificationRule struct{}

func (r InputHashAlgorithmVerificationRule) errCode() reserr.Code { return reserr.Int13 }
func (r InputHashAlgorithmVerificationRule) String() string       { return getName(r) }
func (r InputHashAlgorithmVerificationRule) Verify(context *VerificationContext) (*RuleResult, error) {
	if context == nil || context.signature == nil {
		err := errors.New(errors.KsiInvalidArgumentError)
		return newRuleResult(r, result.NA).setErrCode(reserr.Gen02).setStatusErr(err), err
	}

	docHsh, err := context.signature.DocumentHash()
	if err != nil {
		err = errors.KsiErr(err).AppendMessage("Failed to get signature document hash.")
		return newRuleResult(r, result.NA).setErrCode(reserr.Gen02).setStatusErr(err), err
	}
	at, err := context.signature.SigningTime()
	if err != nil {
		return newRuleResult(r, result.NA).setErrCode(reserr.Gen02).setStatusErr(err), err
	}

	switch docHsh.Algorithm().StatusAt(at.Unix()) {
	case hash.Normal:
		return newRuleResult(r, result.OK), nil
	case hash.Deprecated, hash.Obsolete:
		return newRuleResult(r, result.FAIL).setErrCode(r.errCode()), nil
	case hash.Unknown:
		err := errors.New(errors.KsiUnknownHashAlgorithm).AppendMessage("Document hash algorithm is unknown.")
		return newRuleResult(r, result.NA).setErrCode(reserr.Gen02).setStatusErr(err), err
	default:
		err := errors.New(errors.KsiVerificationFailure).AppendMessage("Unhandled hash algorithm status.")
		return newRuleResult(r, result.NA).setErrCode(reserr.Gen02).setStatusErr(err), err
	}
}

// Rfc3161RecordPresenceRule verifies that the signature contains RFC3161 record.
// Returns OK or NA(None).
type Rfc3161RecordPresenceRule struct{}

func (r Rfc3161RecordPresenceRule) errCode() reserr.Code { return reserr.ErrNA }
func (r Rfc3161RecordPresenceRule) String() string       { return getName(r) }
func (r Rfc3161RecordPresenceRule) Verify(context *VerificationContext) (*RuleResult, error) {
	if context == nil {
		err := errors.New(errors.KsiInvalidArgumentError)
		return newRuleResult(r, result.NA).setErrCode(reserr.Gen02).setStatusErr(err), err
	}

	rfc3161, err := context.signature.Rfc3161()
	if err != nil {
		err = errors.KsiErr(err).AppendMessage("Failed to get RFC3161 record.")
		return newRuleResult(r, result.NA).setErrCode(reserr.Gen02).setStatusErr(err), err
	}

	if rfc3161 == nil {
		return newRuleResult(r, result.NA).setErrCode(r.errCode()), nil
	}
	return newRuleResult(r, result.OK), nil
}

// Rfc3161RecordHashAlgorithmVerificationRule verifies that the RFC-3161 record uses internally a hash function
// that was trusted at the aggregation time.
// Returns OK or FAIL(INT-14).
type Rfc3161RecordHashAlgorithmVerificationRule struct{}

func (r Rfc3161RecordHashAlgorithmVerificationRule) errCode() reserr.Code { return reserr.Int14 }
func (r Rfc3161RecordHashAlgorithmVerificationRule) String() string       { return getName(r) }
func (r Rfc3161RecordHashAlgorithmVerificationRule) Verify(context *VerificationContext) (*RuleResult, error) {
	if context == nil || context.signature == nil {
		err := errors.New(errors.KsiInvalidArgumentError)
		return newRuleResult(r, result.NA).setErrCode(reserr.Gen02).setStatusErr(err), err
	}

	rfc3161, err := context.signature.Rfc3161()
	if err != nil {
		err = errors.KsiErr(err).AppendMessage("Failed to get RFC3161 record.")
		return newRuleResult(r, result.NA).setErrCode(reserr.Gen02).setStatusErr(err), err
	}
	if rfc3161 == nil {
		err := errors.New(errors.KsiInvalidStateError).AppendMessage("Missing RFC3161 record.")
		return newRuleResult(r, result.NA).setErrCode(reserr.Gen02).setStatusErr(err), err
	}

	aggrTime, err := rfc3161.AggregationTime()
	if err != nil {
		err = errors.KsiErr(err).AppendMessage("Failed to get RFC3161 record aggregation time.")
		return newRuleResult(r, result.NA).setErrCode(reserr.Gen02).setStatusErr(err), err
	}
	tstInfoAlgo, err := rfc3161.TstInfoAlgo()
	if err != nil {
		err = errors.KsiErr(err).AppendMessage("Failed to get RFC3161 record tstinfo algorithm.")
		return newRuleResult(r, result.NA).setErrCode(reserr.Gen02).setStatusErr(err), err
	}
	sigAttrAlgo, err := rfc3161.SigAttrAlgo()
	if err != nil {
		err = errors.KsiErr(err).AppendMessage("Failed to get RFC3161 record signed attributes algorithm.")
		return newRuleResult(r, result.NA).setErrCode(reserr.Gen02).setStatusErr(err), err
	}

	status := tstInfoAlgo.StatusAt(aggrTime.Unix())
	switch status {
	case hash.Normal:
		// Do nothing. Verify also the sigAttrAlgo.
	case hash.Deprecated, hash.Obsolete:
		return newRuleResult(r, result.FAIL).setErrCode(r.errCode()), nil
	case hash.Unknown:
		err := errors.New(errors.KsiUnknownHashAlgorithm).AppendMessage("Unknown hash algorithm.")
		return newRuleResult(r, result.NA).setErrCode(reserr.Gen02).setStatusErr(err), err
	default:
		err := errors.New(errors.KsiVerificationFailure).AppendMessage("Unhandled hash algorithm state.")
		return newRuleResult(r, result.NA).setErrCode(reserr.Gen02).setStatusErr(err), err
	}

	status = sigAttrAlgo.StatusAt(aggrTime.Unix())
	switch status {
	case hash.Normal:
		return newRuleResult(r, result.OK), nil
	case hash.Deprecated, hash.Obsolete:
		return newRuleResult(r, result.FAIL).setErrCode(r.errCode()), nil
	case hash.Unknown:
		err := errors.New(errors.KsiUnknownHashAlgorithm).AppendMessage("Unknown hash algorithm.")
		return newRuleResult(r, result.NA).setErrCode(reserr.Gen02).setStatusErr(err), err
	default:
		err := errors.New(errors.KsiVerificationFailure).AppendMessage("Unhandled hash algorithm state.")
		return newRuleResult(r, result.NA).setErrCode(reserr.Gen02).setStatusErr(err), err
	}
}

// Rfc3161RecordOutputHashAlgorithmVerificationRule verifies that the RFC-3161 record output hash algorithm (taken from the
// input hash from the first aggregation hash chain) was trusted at the aggregation time.
// Returns OK or FAIL(INT-17).
type Rfc3161RecordOutputHashAlgorithmVerificationRule struct{}

func (r Rfc3161RecordOutputHashAlgorithmVerificationRule) errCode() reserr.Code { return reserr.Int17 }
func (r Rfc3161RecordOutputHashAlgorithmVerificationRule) String() string       { return getName(r) }
func (r Rfc3161RecordOutputHashAlgorithmVerificationRule) Verify(context *VerificationContext) (*RuleResult, error) {
	if context == nil || context.signature == nil {
		err := errors.New(errors.KsiInvalidArgumentError)
		return newRuleResult(r, result.NA).setErrCode(reserr.Gen02).setStatusErr(err), err
	}

	rfc3161, err := context.signature.Rfc3161()
	if err != nil {
		err = errors.KsiErr(err).AppendMessage("Failed to get RFC3161 record.")
		return newRuleResult(r, result.NA).setErrCode(reserr.Gen02).setStatusErr(err), err
	}
	if rfc3161 == nil {
		err := errors.New(errors.KsiInvalidStateError).AppendMessage("Missing RFC3161 record.")
		return newRuleResult(r, result.NA).setErrCode(reserr.Gen02).setStatusErr(err), err
	}

	aggrTime, err := rfc3161.AggregationTime()
	if err != nil {
		err = errors.KsiErr(err).AppendMessage("Failed to get RFC3161 record aggregation time.")
		return newRuleResult(r, result.NA).setErrCode(reserr.Gen02).setStatusErr(err), err
	}

	aggrChains, err := context.signature.AggregationHashChainList()
	if err != nil {
		err = errors.KsiErr(err).AppendMessage("Failed to get aggregation hash chain list.")
		return newRuleResult(r, result.NA).setErrCode(reserr.Gen02).setStatusErr(err), err
	}
	if aggrChains == nil || len(aggrChains) == 0 {
		err := errors.New(errors.KsiInvalidStateError).AppendMessage("Missing aggregation hash chain list.")
		return newRuleResult(r, result.NA).setErrCode(reserr.Gen02).setStatusErr(err), err
	}
	inputHash, err := aggrChains[0].InputHash()
	if err != nil {
		err = errors.KsiErr(err).AppendMessage("Failed to get aggregation hash chains input hash.")
		return newRuleResult(r, result.NA).setErrCode(reserr.Gen02).setStatusErr(err), err
	}

	status := inputHash.Algorithm().StatusAt(int64(aggrTime.Unix()))
	switch status {
	case hash.Normal:
		return newRuleResult(r, result.OK), nil
	case hash.Deprecated, hash.Obsolete:
		return newRuleResult(r, result.FAIL).setErrCode(r.errCode()), nil
	case hash.Unknown:
		err := errors.New(errors.KsiUnknownHashAlgorithm).AppendMessage("Unknown hash algorithm.")
		return newRuleResult(r, result.NA).setErrCode(reserr.Gen02).setStatusErr(err), err
	default:
		err := errors.New(errors.KsiVerificationFailure).AppendMessage("Unhandled hash algorithm state.")
		return newRuleResult(r, result.NA).setErrCode(reserr.Gen02).setStatusErr(err), err
	}
}

// AggregationHashChainIndexContinuationVerificationRule verifies that current chain index is the successor to the previous
// aggregation hash chain, or same as the chain index from the preceding RFC-3161 record.
// Returns OK or FAIL(INT-12).
type AggregationHashChainIndexContinuationVerificationRule struct{}

func (r AggregationHashChainIndexContinuationVerificationRule) errCode() reserr.Code {
	return reserr.Int12
}
func (r AggregationHashChainIndexContinuationVerificationRule) String() string { return getName(r) }
func (r AggregationHashChainIndexContinuationVerificationRule) Verify(context *VerificationContext) (*RuleResult, error) {
	if context == nil || context.signature == nil {
		err := errors.New(errors.KsiInvalidArgumentError)
		return newRuleResult(r, result.NA).setErrCode(reserr.Gen02).setStatusErr(err), err
	}

	aggrChains, err := context.signature.AggregationHashChainList()
	if err != nil {
		err = errors.KsiErr(err).AppendMessage("Failed to get aggregation hash chains.")
		return newRuleResult(r, result.NA).setErrCode(reserr.Gen02).setStatusErr(err), err
	}
	if aggrChains == nil || len(aggrChains) == 0 {
		err := errors.New(errors.KsiInvalidStateError).AppendMessage("Inconsistent aggregation hash chain.")
		return newRuleResult(r, result.NA).setErrCode(reserr.Gen02).setStatusErr(err), err
	}

	// Verify RFC3161 chain index.
	rfc3161, err := context.signature.Rfc3161()
	if err != nil {
		err = errors.KsiErr(err).AppendMessage("Failed to get RFC3161 record.")
		return newRuleResult(r, result.NA).setErrCode(reserr.Gen02).setStatusErr(err), err
	}
	if rfc3161 != nil {
		rfc3161ChainIndex, err := rfc3161.ChainIndex()
		if err != nil {
			err = errors.KsiErr(err).AppendMessage("Failed to get RFC3161 record chain index.")
			return newRuleResult(r, result.NA).setErrCode(reserr.Gen02).setStatusErr(err), err
		}
		if rfc3161ChainIndex == nil {
			err := errors.New(errors.KsiInvalidStateError).AppendMessage("Missing RFC3161 record chain index.")
			return newRuleResult(r, result.NA).setErrCode(reserr.Gen02).setStatusErr(err), err
		}

		aggrChainIndex, err := aggrChains[0].ChainIndex()
		if err != nil {
			err = errors.KsiErr(err).AppendMessage("Failed to get aggregation hash chains index.")
			return newRuleResult(r, result.NA).setErrCode(reserr.Gen02).setStatusErr(err), err
		}
		if aggrChainIndex == nil {
			err := errors.New(errors.KsiInvalidStateError).AppendMessage("Missing aggregation hash chain index.")
			return newRuleResult(r, result.NA).setErrCode(reserr.Gen02).setStatusErr(err), err
		}

		if len(rfc3161ChainIndex) != len(aggrChainIndex) {
			log.Info("Aggregation hash chain and RFC3161 chain index count mismatch.")
			return newRuleResult(r, result.FAIL).setErrCode(r.errCode()), nil
		}

		for i := 0; i < len(rfc3161ChainIndex); i++ {
			if rfc3161ChainIndex[i] != aggrChainIndex[i] {
				log.Info("Aggregation hash chain and RFC3161 chain index mismatch.")
				return newRuleResult(r, result.FAIL).setErrCode(r.errCode()), nil
			}
		}
	}

	var prevChain *pdu.AggregationChain
	for _, chain := range aggrChains {
		// Verify chain index length.
		if prevChain != nil {
			prevChainIndex, err := prevChain.ChainIndex()
			if err != nil {
				err = errors.KsiErr(err).AppendMessage("Failed to get aggregation hash chains index.")
				return newRuleResult(r, result.NA).setErrCode(reserr.Gen02).setStatusErr(err), err
			}
			curChainIndex, err := chain.ChainIndex()
			if err != nil {
				err = errors.KsiErr(err).AppendMessage("Failed to get aggregation hash chains index.")
				return newRuleResult(r, result.NA).setErrCode(reserr.Gen02).setStatusErr(err), err
			}

			if prevChainIndex == nil || curChainIndex == nil {
				err := errors.New(errors.KsiInvalidStateError).AppendMessage("Missing aggregation hash chain index.")
				return newRuleResult(r, result.NA).setErrCode(reserr.Gen02).setStatusErr(err), err
			}

			if len(prevChainIndex) != len(curChainIndex)+1 {
				log.Info("Unexpected chain index length in aggregation hash chain.")
				return newRuleResult(r, result.FAIL).setErrCode(r.errCode()), nil
			}

			for i := 0; i < len(curChainIndex); i++ {
				if (curChainIndex)[i] != (prevChainIndex)[i] {
					log.Info("Aggregation hash chain index is not continuation of previous chain index.")
					return newRuleResult(r, result.FAIL).setErrCode(r.errCode()), nil
				}
			}
		}
		prevChain = chain
	}
	return newRuleResult(r, result.OK), nil
}

// AggregationChainMetaDataVerificationRule verifies the meta-data structures in the aggregation hash chain.
// This includes padding of the meta-data and the fact that the meta-data can not be interpreted as an imprint.
// Returns OK or FAIL(INT-11).
type AggregationChainMetaDataVerificationRule struct{}

func (r AggregationChainMetaDataVerificationRule) errCode() reserr.Code { return reserr.Int11 }
func (r AggregationChainMetaDataVerificationRule) String() string       { return getName(r) }
func (r AggregationChainMetaDataVerificationRule) Verify(context *VerificationContext) (*RuleResult, error) {
	if context == nil || context.signature == nil {
		err := errors.New(errors.KsiInvalidArgumentError)
		return newRuleResult(r, result.NA).setErrCode(reserr.Gen02).setStatusErr(err), err
	}

	aggrChains, err := context.signature.AggregationHashChainList()
	if err != nil {
		err = errors.KsiErr(err).AppendMessage("Failed to get aggregation hash chains.")
		return newRuleResult(r, result.NA).setErrCode(reserr.Gen02).setStatusErr(err), err
	}
	if aggrChains == nil || len(aggrChains) == 0 {
		err := errors.New(errors.KsiInvalidStateError).AppendMessage("Missing aggregation hash chain.")
		return newRuleResult(r, result.NA).setErrCode(reserr.Gen02).setStatusErr(err), err
	}

	// Loop through all the aggregation hash chains.
	for _, chain := range aggrChains {
		chainLinks, err := chain.ChainLinks()
		if err != nil {
			err = errors.KsiErr(err).AppendMessage("Failed to extract aggregation chain links.")
			return newRuleResult(r, result.NA).setErrCode(reserr.Gen02).setStatusErr(err), err
		}
		if chainLinks == nil || len(chainLinks) == 0 {
			err := errors.New(errors.KsiInvalidStateError).
				AppendMessage("Inconsistent aggregation hash chain.").
				AppendMessage("Missing chain links.")
			return newRuleResult(r, result.NA).setErrCode(reserr.Gen02).setStatusErr(err), err
		}

		// Loop through all the links in the aggregation chain.
		for _, link := range chainLinks {
			metadata, err := link.MetaData()
			if err != nil {
				err = errors.KsiErr(err).AppendMessage("Failed to get link metadata.")
				return newRuleResult(r, result.NA).setErrCode(reserr.Gen02).setStatusErr(err), err
			}
			if metadata == nil {
				continue
			}
			metadataTlv, err := metadata.EncodeToTlv()
			if err != nil {
				err = errors.KsiErr(err).AppendMessage("Failed to get metadata TLV.")
				return newRuleResult(r, result.NA).setErrCode(reserr.Gen02).setStatusErr(err), err
			}

			if metadata.HasPadding() {
				// Verify padding element.
				padTlv, err := metadataTlv.Extract(uint16(0x1E))
				if err != nil {
					return newRuleResult(r, result.NA).setErrCode(reserr.Gen02).setStatusErr(err), err
				}

				// Metadata padding must be encoded in TLV8.
				if padTlv.Is16 {
					log.Info("Metadata padding not encoded as TLV8.")
					return newRuleResult(r, result.FAIL).setErrCode(r.errCode()), nil
				}

				// Metadata padding must have N and F flags set.
				if padTlv.NonCritical == false || padTlv.ForwardUnknown == false {
					log.Info("Metadata padding does not have N and F flags set.")
					return newRuleResult(r, result.FAIL).setErrCode(r.errCode()), nil
				}

				// Check that the metadata padding value is either 0x01 or 0x0101.
				switch len(padTlv.Value()) {
				case 2:
					if padTlv.Value()[1] != 0x01 {
						log.Info("Metadata padding has invalid value.")
						return newRuleResult(r, result.FAIL).setErrCode(r.errCode()), nil
					}
					fallthrough
				case 1:
					if padTlv.Value()[0] != 0x01 {
						log.Info("Metadata padding has invalid value.")
						return newRuleResult(r, result.FAIL).setErrCode(r.errCode()), nil
					}

				default:
					log.Info("Metadata padding has invalid length.")
					return newRuleResult(r, result.FAIL).setErrCode(r.errCode()), nil
				}

				// Verify that the total length of the metadata record is even.
				if len(metadataTlv.Value())%2 != 0 {
					log.Info("MetaData element is not even.")
					return newRuleResult(r, result.FAIL).setErrCode(r.errCode()), nil
				}
			} else {
				// Verify that the metadata record cannot be interpreted as a valid imprint.
				alg := hash.Imprint(metadataTlv.Value()).Algorithm()
				if alg != hash.SHA_NA && alg.Size()+1 == len(metadataTlv.Value()) {
					log.Info("Metadata could be interpreted as imprint.")
					return newRuleResult(r, result.FAIL).setErrCode(r.errCode()), nil
				}
			}
		}
	}
	return newRuleResult(r, result.OK), nil
}

// AggregationChainHashAlgorithmVerificationRule verifies that the aggregation hash chain uses hash algorithm that
// was trusted at the aggregation time to aggregate the sibling hashes.
// Returns OK or FAIL(INT-15).
type AggregationChainHashAlgorithmVerificationRule struct{}

func (r AggregationChainHashAlgorithmVerificationRule) errCode() reserr.Code { return reserr.Int15 }
func (r AggregationChainHashAlgorithmVerificationRule) String() string       { return getName(r) }
func (r AggregationChainHashAlgorithmVerificationRule) Verify(context *VerificationContext) (*RuleResult, error) {
	if context == nil || context.signature == nil {
		err := errors.New(errors.KsiInvalidArgumentError)
		return newRuleResult(r, result.NA).setErrCode(reserr.Gen02).setStatusErr(err), err
	}

	aggrChains, err := context.signature.AggregationHashChainList()
	if err != nil {
		err = errors.KsiErr(err).AppendMessage("Failed to get aggregation hash chains.")
		return newRuleResult(r, result.NA).setErrCode(reserr.Gen02).setStatusErr(err), err
	}
	if aggrChains == nil || len(aggrChains) == 0 {
		err := errors.New(errors.KsiInvalidStateError).AppendMessage("Missing aggregation hash chain.")
		return newRuleResult(r, result.NA).setErrCode(reserr.Gen02).setStatusErr(err), err
	}

	// Loop through all the aggregation hash chains.
	for _, chain := range aggrChains {
		aggrAlgo, err := chain.AggregationAlgo()
		if err != nil {
			err = errors.KsiErr(err).AppendMessage("Failed to get aggregation hash chains algorithm.")
			return newRuleResult(r, result.NA).setErrCode(reserr.Gen02).setStatusErr(err), err
		}
		aggrTime, err := chain.AggregationTime()
		if err != nil {
			err = errors.KsiErr(err).AppendMessage("Failed to get aggregation hash chains time.")
			return newRuleResult(r, result.NA).setErrCode(reserr.Gen02).setStatusErr(err), err
		}

		switch aggrAlgo.StatusAt(aggrTime.Unix()) {
		case hash.Normal:
			// do nothing
		case hash.Deprecated, hash.Obsolete:
			return newRuleResult(r, result.FAIL).setErrCode(r.errCode()), nil
		case hash.Unknown:
			err := errors.New(errors.KsiUnknownHashAlgorithm).AppendMessage("Unknown hash algorithm.")
			return newRuleResult(r, result.NA).setErrCode(reserr.Gen02).setStatusErr(err), err
		default:
			err := errors.New(errors.KsiVerificationFailure).AppendMessage("Unhandled hash algorithm state.")
			return newRuleResult(r, result.NA).setErrCode(reserr.Gen02).setStatusErr(err), err
		}
	}
	return newRuleResult(r, result.OK), nil
}

// AggregationHashChainConsistencyVerificationRule verifies that all aggregation hash chains are consistent (e.g. previous
// aggregation output hash equals to current aggregation chain input hash).
// Returns OK or FAIL(INT-01).
type AggregationHashChainConsistencyVerificationRule struct{}

func (r AggregationHashChainConsistencyVerificationRule) errCode() reserr.Code { return reserr.Int01 }
func (r AggregationHashChainConsistencyVerificationRule) String() string       { return getName(r) }
func (r AggregationHashChainConsistencyVerificationRule) Verify(context *VerificationContext) (*RuleResult, error) {
	if context == nil || context.signature == nil {
		err := errors.New(errors.KsiInvalidArgumentError)
		return newRuleResult(r, result.NA).setErrCode(reserr.Gen02).setStatusErr(err), err
	}

	var (
		hsh hash.Imprint
		lvl byte
		err error
	)

	aggrChains, err := context.signature.AggregationHashChainList()
	if err != nil {
		err = errors.KsiErr(err).AppendMessage("Failed to get aggregation hash chains.")
		return newRuleResult(r, result.NA).setErrCode(reserr.Gen02).setStatusErr(err), err
	}
	if aggrChains == nil || len(aggrChains) == 0 {
		err := errors.New(errors.KsiInvalidStateError).AppendMessage("Missing aggregation hash chain.")
		return newRuleResult(r, result.NA).setErrCode(reserr.Gen02).setStatusErr(err), err
	}
	rfc3161, err := context.signature.Rfc3161()
	if err != nil {
		err = errors.KsiErr(err).AppendMessage("Failed to get RFC3161 record.")
		return newRuleResult(r, result.NA).setErrCode(reserr.Gen02).setStatusErr(err), err
	}

	for i, chain := range aggrChains {
		inputHash, err := chain.InputHash()
		if err != nil {
			err = errors.KsiErr(err).AppendMessage("Failed to get aggregation hash chains input hash.")
			return newRuleResult(r, result.NA).setErrCode(reserr.Gen02).setStatusErr(err), err
		}
		if inputHash == nil {
			err := errors.New(errors.KsiInvalidStateError).
				AppendMessage("Inconsistent aggregation hash chain.").
				AppendMessage("Missing input hash.")
			return newRuleResult(r, result.NA).setErrCode(reserr.Gen02).setStatusErr(err), err
		}

		if i == 0 && rfc3161 != nil {
			if hsh, err = rfc3161.OutputHash(inputHash.Algorithm()); err != nil {
				msg := "Unable to get RFC3161 record output hash."
				log.Info(msg)
				err = errors.KsiErr(err).AppendMessage(msg)
				return newRuleResult(r, result.NA).setErrCode(reserr.Gen02).setStatusErr(err), err
			}
		}

		if len(hsh) != 0 {
			// Validate input hash.
			if !hash.Equal(hsh, inputHash) {
				log.Info(fmt.Sprintf("AggrChain[%d] input hash mismatch.", i))
				log.Info("... prev hash : ", hsh)
				log.Info("... input hash: ", inputHash)
				return newRuleResult(r, result.FAIL).setErrCode(r.errCode()), nil
			}
		}

		hsh, lvl, err = chain.Aggregate(lvl)
		if err != nil {
			return newRuleResult(r, result.NA).setErrCode(reserr.Gen02).setStatusErr(err), err
		}
	}
	context.temp.aggregationOutputHash = hsh
	return newRuleResult(r, result.OK), nil
}

// AggregationHashChainTimeConsistencyVerificationRule verifies that current aggregation chain's aggregation time match with
// time of the previous chain, or RFC-3161 record.
// Returns OK or FAIL(INT-02).
type AggregationHashChainTimeConsistencyVerificationRule struct{}

func (r AggregationHashChainTimeConsistencyVerificationRule) errCode() reserr.Code {
	return reserr.Int02
}
func (r AggregationHashChainTimeConsistencyVerificationRule) String() string { return getName(r) }
func (r AggregationHashChainTimeConsistencyVerificationRule) Verify(context *VerificationContext) (*RuleResult, error) {
	if context == nil || context.signature == nil {
		err := errors.New(errors.KsiInvalidArgumentError)
		return newRuleResult(r, result.NA).setErrCode(reserr.Gen02).setStatusErr(err), err
	}

	aggrChains, err := context.signature.AggregationHashChainList()
	if err != nil {
		err = errors.KsiErr(err).AppendMessage("Failed to get aggregation hash chains.")
		return newRuleResult(r, result.NA).setErrCode(reserr.Gen02).setStatusErr(err), err
	}
	if aggrChains == nil || len(aggrChains) == 0 {
		err := errors.New(errors.KsiInvalidStateError).AppendMessage("Missing aggregation hash chain.")
		return newRuleResult(r, result.NA).setErrCode(reserr.Gen02).setStatusErr(err), err
	}

	// Verify RFC3161 aggregation time.
	rfc3161, err := context.signature.Rfc3161()
	if err != nil {
		err = errors.KsiErr(err).AppendMessage("Failed to get RFC3161 record.")
		return newRuleResult(r, result.NA).setErrCode(reserr.Gen02).setStatusErr(err), err
	}
	if rfc3161 != nil {
		rfc3161AggrTime, err := rfc3161.AggregationTime()
		if err != nil {
			err = errors.KsiErr(err).AppendMessage("Failed to get RFC3161 record aggregation time.")
			return newRuleResult(r, result.NA).setErrCode(reserr.Gen02).setStatusErr(err), err
		}

		chainAggrTime, err := aggrChains[0].AggregationTime()
		if err != nil {
			err = errors.KsiErr(err).AppendMessage("Failed to get aggregation hash chain aggregation time.")
			return newRuleResult(r, result.NA).setErrCode(reserr.Gen02).setStatusErr(err), err
		}

		if !rfc3161AggrTime.Equal(chainAggrTime) {
			return newRuleResult(r, result.FAIL).setErrCode(r.errCode()), nil
		}
	}

	var prevChain *pdu.AggregationChain
	for _, chain := range aggrChains {
		if prevChain != nil {
			prevAggrTime, err := prevChain.AggregationTime()
			if err != nil {
				err = errors.KsiErr(err).AppendMessage("Failed to get aggregation hash chain aggregation time.")
				return newRuleResult(r, result.NA).setErrCode(reserr.Gen02).setStatusErr(err), err
			}
			curAggrTime, err := chain.AggregationTime()
			if err != nil {
				err = errors.KsiErr(err).AppendMessage("Failed to get aggregation hash chain aggregation time.")
				return newRuleResult(r, result.NA).setErrCode(reserr.Gen02).setStatusErr(err), err
			}

			// Verify aggregation time.
			if !prevAggrTime.Equal(curAggrTime) {
				log.Info("Aggregation hash chain's from different aggregation rounds.")
				return newRuleResult(r, result.FAIL).setErrCode(r.errCode()), nil
			}
		}
		prevChain = chain
	}
	return newRuleResult(r, result.OK), nil
}

// AggregationHashChainIndexConsistencyVerificationRule verifies that the shape of the aggregation hash chain match with
// the chain index.
// Returns OK or FAIL(INT-10).
type AggregationHashChainIndexConsistencyVerificationRule struct{}

func (r AggregationHashChainIndexConsistencyVerificationRule) errCode() reserr.Code {
	return reserr.Int10
}
func (r AggregationHashChainIndexConsistencyVerificationRule) String() string { return getName(r) }
func (r AggregationHashChainIndexConsistencyVerificationRule) Verify(context *VerificationContext) (*RuleResult, error) {
	if context == nil || context.signature == nil {
		err := errors.New(errors.KsiInvalidArgumentError)
		return newRuleResult(r, result.NA).setErrCode(reserr.Gen02).setStatusErr(err), err
	}

	aggrChains, err := context.signature.AggregationHashChainList()
	if err != nil {
		err = errors.KsiErr(err).AppendMessage("Failed to get aggregation hash chains.")
		return newRuleResult(r, result.NA).setErrCode(reserr.Gen02).setStatusErr(err), err
	}
	if aggrChains == nil || len(aggrChains) == 0 {
		err := errors.New(errors.KsiInvalidStateError).AppendMessage("Missing aggregation hash chain.")
		return newRuleResult(r, result.NA).setErrCode(reserr.Gen02).setStatusErr(err), err
	}

	for _, chain := range aggrChains {
		calcShape, err := chain.CalculateShape()
		if err != nil {
			err = errors.KsiErr(err).AppendMessage("Failed to calculate aggregation hash chain shape.")
			return newRuleResult(r, result.FAIL).setErrCode(r.errCode()).setStatusErr(err), nil
		}

		chainIndex, err := chain.ChainIndex()
		if err != nil {
			err = errors.KsiErr(err).AppendMessage("Failed to get chain index.")
			return newRuleResult(r, result.NA).setErrCode(reserr.Gen02).setStatusErr(err), err
		}

		if calcShape != chainIndex[len(chainIndex)-1] {
			log.Info("Aggregation hash chain index does not match with aggregation hash chain shape.")
			return newRuleResult(r, result.FAIL).setErrCode(r.errCode()), nil
		}
	}
	return newRuleResult(r, result.OK), nil
}

// CalendarHashChainPresenceRule verifies that the signature contains calendar hash chain.
// Returns OK or NA(None).
type CalendarHashChainPresenceRule struct{}

func (r CalendarHashChainPresenceRule) errCode() reserr.Code { return reserr.ErrNA }
func (r CalendarHashChainPresenceRule) String() string       { return getName(r) }
func (r CalendarHashChainPresenceRule) Verify(context *VerificationContext) (*RuleResult, error) {
	if context == nil || context.signature == nil {
		err := errors.New(errors.KsiInvalidArgumentError)
		return newRuleResult(r, result.NA).setErrCode(reserr.Gen02).setStatusErr(err), err
	}

	calChain, err := context.signature.CalendarChain()
	if err != nil {
		err = errors.KsiErr(err).AppendMessage("Failed to get calendar hash chains.")
		return newRuleResult(r, result.NA).setErrCode(reserr.Gen02).setStatusErr(err), err
	}

	if calChain == nil {
		return newRuleResult(r, result.NA).setErrCode(r.errCode()), nil
	}
	return newRuleResult(r, result.OK), nil
}

// CalendarHashChainInputHashVerificationRule verifies that calendar hash chain input hash does
// match with the aggregation hash chain list root hash.
// Returns OK or FAIL(INT-03).
type CalendarHashChainInputHashVerificationRule struct{}

func (r CalendarHashChainInputHashVerificationRule) errCode() reserr.Code {
	return reserr.Int03
}
func (r CalendarHashChainInputHashVerificationRule) String() string { return getName(r) }
func (r CalendarHashChainInputHashVerificationRule) Verify(context *VerificationContext) (*RuleResult, error) {
	if context == nil || context.signature == nil {
		err := errors.New(errors.KsiInvalidArgumentError)
		return newRuleResult(r, result.NA).setErrCode(reserr.Gen02).setStatusErr(err), err
	}

	calChain, err := context.signature.CalendarChain()
	if err != nil {
		err = errors.KsiErr(err).AppendMessage("Failed to get calendar chain.")
		return newRuleResult(r, result.NA).setErrCode(reserr.Gen02).setStatusErr(err), err
	}
	if calChain == nil {
		err := errors.New(errors.KsiInvalidStateError).AppendMessage("Missing calendar hash chain.")
		return newRuleResult(r, result.NA).setErrCode(reserr.Gen02).setStatusErr(err), err
	}

	calInputHash, err := calChain.InputHash()
	if err != nil {
		err = errors.KsiErr(err).AppendMessage("Failed to get calendar chain input hash.")
		return newRuleResult(r, result.NA).setErrCode(reserr.Gen02).setStatusErr(err), err
	}

	hsh, err := context.aggregationHashChainOutputHash()
	if err != nil {
		return newRuleResult(r, result.NA).setErrCode(reserr.Gen02).setStatusErr(err), err
	}

	if !hash.Equal(calInputHash, hsh) {
		return newRuleResult(r, result.FAIL).setErrCode(r.errCode()), nil
	}
	return newRuleResult(r, result.OK), nil
}

// CalendarHashChainAggregationTimeVerificationRule verifies that calendar hash chain aggregation
// time (if not present use publication time instead) does match with the last aggregation hash
// chain aggregation time.
// Returns OK or FAIL(INT-04).
type CalendarHashChainAggregationTimeVerificationRule struct{}

func (r CalendarHashChainAggregationTimeVerificationRule) errCode() reserr.Code {
	return reserr.Int04
}
func (r CalendarHashChainAggregationTimeVerificationRule) String() string { return getName(r) }
func (r CalendarHashChainAggregationTimeVerificationRule) Verify(context *VerificationContext) (*RuleResult, error) {
	if context == nil || context.signature == nil {
		err := errors.New(errors.KsiInvalidArgumentError)
		return newRuleResult(r, result.NA).setErrCode(reserr.Gen02).setStatusErr(err), err
	}

	calChain, err := context.signature.CalendarChain()
	if err != nil {
		err = errors.KsiErr(err).AppendMessage("Failed to get calendar chain.")
		return newRuleResult(r, result.NA).setErrCode(reserr.Gen02).setStatusErr(err), err
	}
	if calChain == nil {
		err := errors.New(errors.KsiInvalidStateError).AppendMessage("Missing calendar hash chain.")
		return newRuleResult(r, result.NA).setErrCode(reserr.Gen02).setStatusErr(err), err
	}

	calTime, err := calChain.AggregationTime()
	if err != nil {
		err = errors.KsiErr(err).AppendMessage("Failed to get calendar chain aggregation time.")
		return newRuleResult(r, result.NA).setErrCode(reserr.Gen02).setStatusErr(err), err
	}
	if calTime.IsZero() {
		calTime, err = calChain.PublicationTime()
		if err != nil {
			err = errors.KsiErr(err).AppendMessage("Failed to get calendar chain publication time.")
			return newRuleResult(r, result.NA).setErrCode(reserr.Gen02).setStatusErr(err), err
		}
	}

	aggrChains, err := context.signature.AggregationHashChainList()
	if err != nil {
		err = errors.KsiErr(err).AppendMessage("Failed to get aggregation hash chains.")
		return newRuleResult(r, result.NA).setErrCode(reserr.Gen02).setStatusErr(err), err
	}
	count := len(aggrChains)
	if aggrChains == nil || count == 0 {
		err := errors.New(errors.KsiInvalidStateError).AppendMessage("Missing aggregation hash chain.")
		return newRuleResult(r, result.NA).setErrCode(reserr.Gen02).setStatusErr(err), err
	}

	aggrTime, err := aggrChains[count-1].AggregationTime()
	if err != nil {
		err = errors.KsiErr(err).AppendMessage("Failed to get aggregation hash chain aggregation time.")
		return newRuleResult(r, result.NA).setErrCode(reserr.Gen02).setStatusErr(err), err
	}

	if !calTime.Equal(aggrTime) {
		return newRuleResult(r, result.FAIL).setErrCode(r.errCode()), nil
	}
	return newRuleResult(r, result.OK), nil
}

// CalendarHashChainRegistrationTimeVerificationRule verifies that calendar hash chain aggregation time and
// calculated aggregation time do match.
// Returns OK or FAIL(INT-05).
type CalendarHashChainRegistrationTimeVerificationRule struct{}

func (r CalendarHashChainRegistrationTimeVerificationRule) errCode() reserr.Code {
	return reserr.Int05
}
func (r CalendarHashChainRegistrationTimeVerificationRule) String() string { return getName(r) }
func (r CalendarHashChainRegistrationTimeVerificationRule) Verify(context *VerificationContext) (*RuleResult, error) {
	if context == nil || context.signature == nil {
		err := errors.New(errors.KsiInvalidArgumentError)
		return newRuleResult(r, result.NA).setErrCode(reserr.Gen02).setStatusErr(err), err
	}

	calChain, err := context.signature.CalendarChain()
	if err != nil {
		err = errors.KsiErr(err).AppendMessage("Failed to get calendar chain.")
		return newRuleResult(r, result.NA).setErrCode(reserr.Gen02).setStatusErr(err), err
	}
	if calChain == nil {
		err := errors.New(errors.KsiInvalidStateError).AppendMessage("Missing calendar hash chain.")
		return newRuleResult(r, result.NA).setErrCode(reserr.Gen02).setStatusErr(err), err
	}

	calcTime, err := calChain.CalculateAggregationTime()
	if err != nil {
		if errors.KsiErr(err).Code() == errors.KsiInvalidFormatError {
			err = errors.KsiErr(err).AppendMessage("Failed to calculate aggregation time.")
			return newRuleResult(r, result.FAIL).setErrCode(r.errCode()).setStatusErr(err), nil
		}
		return newRuleResult(r, result.NA).setErrCode(reserr.Gen02).setStatusErr(err), err
	}

	calTime, err := calChain.AggregationTime()
	if err != nil {
		err = errors.KsiErr(err).AppendMessage("Failed to get calendar chain aggregation time.")
		return newRuleResult(r, result.NA).setErrCode(reserr.Gen02).setStatusErr(err), err
	}
	if calTime.IsZero() {
		calTime, err = calChain.PublicationTime()
		if err != nil {
			err = errors.KsiErr(err).AppendMessage("Failed to get calendar chain publication time.")
			return newRuleResult(r, result.NA).setErrCode(reserr.Gen02).setStatusErr(err), err
		}
	}

	if !calTime.Equal(calcTime) {
		return newRuleResult(r, result.FAIL).setErrCode(r.errCode()), nil
	}
	return newRuleResult(r, result.OK), nil
}

// CalendarChainHashAlgorithmObsoleteAtPubTimeVerificationRule verifies that any of the calendar
// hash chain aggregation (see 'left link Rule' from the rfc) hash algorithms were trusted at
// the publication time.
// Returns OK or FAIL(INT-16).
type CalendarChainHashAlgorithmObsoleteAtPubTimeVerificationRule struct{}

func (r CalendarChainHashAlgorithmObsoleteAtPubTimeVerificationRule) errCode() reserr.Code {
	return reserr.Int16
}
func (r CalendarChainHashAlgorithmObsoleteAtPubTimeVerificationRule) String() string {
	return getName(r)
}
func (r CalendarChainHashAlgorithmObsoleteAtPubTimeVerificationRule) Verify(context *VerificationContext) (*RuleResult, error) {
	if context == nil || context.signature == nil {
		err := errors.New(errors.KsiInvalidArgumentError)
		return newRuleResult(r, result.NA).setErrCode(reserr.Gen02).setStatusErr(err), err
	}

	calChain, err := context.signature.CalendarChain()
	if err != nil {
		err = errors.KsiErr(err).AppendMessage("Failed to get calendar chain.")
		return newRuleResult(r, result.NA).setErrCode(reserr.Gen02).setStatusErr(err), err
	}
	if calChain == nil {
		err := errors.New(errors.KsiInvalidStateError).AppendMessage("Missing calendar hash chain.")
		return newRuleResult(r, result.NA).setErrCode(reserr.Gen02).setStatusErr(err), err
	}

	pubTime, err := calChain.PublicationTime()
	if err != nil {
		err = errors.KsiErr(err).AppendMessage("Failed to get calendar chain pub time.")
		return newRuleResult(r, result.NA).setErrCode(reserr.Gen02).setStatusErr(err), err
	}
	if pubTime.IsZero() {
		err := errors.New(errors.KsiInvalidFormatError).AppendMessage("Inconsistent calendar chain publication time.")
		return newRuleResult(r, result.NA).setErrCode(reserr.Gen02).setStatusErr(err), err
	}

	chainLinks, err := calChain.ChainLinks()
	if err != nil {
		err = errors.KsiErr(err).AppendMessage("Failed to get calendar chain links.")
		return newRuleResult(r, result.NA).setErrCode(reserr.Gen02).setStatusErr(err), err
	}
	if chainLinks == nil || len(chainLinks) == 0 {
		err := errors.New(errors.KsiInvalidStateError).AppendMessage("Missing calendar hash chain links.")
		return newRuleResult(r, result.NA).setErrCode(reserr.Gen02).setStatusErr(err), err
	}

	for _, link := range chainLinks {
		isLeft, err := link.IsLeft()
		if err != nil {
			err = errors.KsiErr(err).AppendMessage("Failed to get chain link side.")
			return newRuleResult(r, result.NA).setErrCode(reserr.Gen02).setStatusErr(err), err
		}
		if !isLeft {
			continue
		}

		siblingHash, err := link.SiblingHash()
		if err != nil {
			err = errors.KsiErr(err).AppendMessage("Failed to get link sibling hash.")
			return newRuleResult(r, result.NA).setErrCode(reserr.Gen02).setStatusErr(err), err
		}

		status := siblingHash.Algorithm().StatusAt(pubTime.Unix())
		if status == hash.Unknown {
			msg := fmt.Sprint("Calendar sibling hash contains unknown hash algorithm:", siblingHash)
			log.Info(msg)
			err := errors.New(errors.KsiUnknownHashAlgorithm).AppendMessage(msg)
			return newRuleResult(r, result.NA).setErrCode(reserr.Gen02).setStatusErr(err), err
		}
		if status == hash.Obsolete {
			return newRuleResult(r, result.FAIL).setErrCode(r.errCode()), nil
		}
	}
	return newRuleResult(r, result.OK), nil
}

// PublicationRecordPresenceRule verifies that the signature contains publication record.
// Returns OK or NA(None).
type PublicationRecordPresenceRule struct{}

func (r PublicationRecordPresenceRule) errCode() reserr.Code { return reserr.ErrNA }
func (r PublicationRecordPresenceRule) String() string       { return getName(r) }
func (r PublicationRecordPresenceRule) Verify(context *VerificationContext) (*RuleResult, error) {
	if context == nil || context.signature == nil {
		err := errors.New(errors.KsiInvalidArgumentError)
		return newRuleResult(r, result.NA).setErrCode(reserr.Gen02).setStatusErr(err), err
	}

	publication, err := context.signature.Publication()
	if err != nil {
		err = errors.KsiErr(err).AppendMessage("Failed to get publication record.")
		return newRuleResult(r, result.NA).setErrCode(reserr.Gen02).setStatusErr(err), err
	}

	if publication == nil {
		return newRuleResult(r, result.NA).setErrCode(r.errCode()), nil
	}
	return newRuleResult(r, result.OK), nil
}

// PublicationRecordPublicationTimeVerificationRule verifies that publication time from publication record and
// calendar hash chain publication time do match.
// Returns OK or FAIL(INT-07).
type PublicationRecordPublicationTimeVerificationRule struct{}

func (r PublicationRecordPublicationTimeVerificationRule) errCode() reserr.Code {
	return reserr.Int07
}
func (r PublicationRecordPublicationTimeVerificationRule) String() string { return getName(r) }
func (r PublicationRecordPublicationTimeVerificationRule) Verify(context *VerificationContext) (*RuleResult, error) {
	if context == nil || context.signature == nil {
		err := errors.New(errors.KsiInvalidArgumentError)
		return newRuleResult(r, result.NA).setErrCode(reserr.Gen02).setStatusErr(err), err
	}

	publication, err := context.signature.Publication()
	if err != nil {
		err = errors.KsiErr(err).AppendMessage("Failed to get publication record.")
		return newRuleResult(r, result.NA).setErrCode(reserr.Gen02).setStatusErr(err), err
	}
	if publication == nil {
		err := errors.New(errors.KsiInvalidStateError).AppendMessage("Missing publication record.")
		return newRuleResult(r, result.NA).setErrCode(reserr.Gen02).setStatusErr(err), err
	}

	pubData, err := publication.PublicationData()
	if err != nil {
		err = errors.KsiErr(err).AppendMessage("Failed to get publication data.")
		return newRuleResult(r, result.NA).setErrCode(reserr.Gen02).setStatusErr(err), err
	}
	pubTime, err := pubData.PublicationTime()
	if err != nil {
		err = errors.KsiErr(err).AppendMessage("Failed to get publication time.")
		return newRuleResult(r, result.NA).setErrCode(reserr.Gen02).setStatusErr(err), err
	}

	calChain, err := context.signature.CalendarChain()
	if err != nil {
		err = errors.KsiErr(err).AppendMessage("Failed to get calendar chain.")
		return newRuleResult(r, result.NA).setErrCode(reserr.Gen02).setStatusErr(err), err
	}
	if calChain == nil {
		err := errors.New(errors.KsiInvalidStateError).AppendMessage("Missing calendar hash chain.")
		return newRuleResult(r, result.NA).setErrCode(reserr.Gen02).setStatusErr(err), err
	}
	calTime, err := calChain.PublicationTime()
	if err != nil {
		err = errors.KsiErr(err).AppendMessage("Failed to get calendar chain pub time.")
		return newRuleResult(r, result.NA).setErrCode(reserr.Gen02).setStatusErr(err), err
	}

	if !calTime.Equal(pubTime) {
		return newRuleResult(r, result.FAIL).setErrCode(r.errCode()), nil
	}
	return newRuleResult(r, result.OK), nil
}

// PublicationRecordPublicationHashVerificationRule verifies that publication hash from publication record and
// calendar hash chain root hash do match.
// Returns OK or FAIL(INT-09).
type PublicationRecordPublicationHashVerificationRule struct{}

func (r PublicationRecordPublicationHashVerificationRule) errCode() reserr.Code {
	return reserr.Int09
}
func (r PublicationRecordPublicationHashVerificationRule) String() string { return getName(r) }
func (r PublicationRecordPublicationHashVerificationRule) Verify(context *VerificationContext) (*RuleResult, error) {
	if context == nil || context.signature == nil {
		err := errors.New(errors.KsiInvalidArgumentError)
		return newRuleResult(r, result.NA).setErrCode(reserr.Gen02).setStatusErr(err), err
	}

	publication, err := context.signature.Publication()
	if err != nil {
		err = errors.KsiErr(err).AppendMessage("Failed to get publication record.")
		return newRuleResult(r, result.NA).setErrCode(reserr.Gen02).setStatusErr(err), err
	}
	if publication == nil {
		err := errors.New(errors.KsiInvalidStateError).AppendMessage("Missing publication record.")
		return newRuleResult(r, result.NA).setErrCode(reserr.Gen02).setStatusErr(err), err
	}

	pubData, err := publication.PublicationData()
	if err != nil {
		err = errors.KsiErr(err).AppendMessage("Failed to get publication data.")
		return newRuleResult(r, result.NA).setErrCode(reserr.Gen02).setStatusErr(err), err
	}
	pubHash, err := pubData.PublishedHash()
	if err != nil {
		err = errors.KsiErr(err).AppendMessage("Failed to get published hash.")
		return newRuleResult(r, result.NA).setErrCode(reserr.Gen02).setStatusErr(err), err
	}

	calChain, err := context.signature.CalendarChain()
	if err != nil {
		err = errors.KsiErr(err).AppendMessage("Failed to get calendar chain.")
		return newRuleResult(r, result.NA).setErrCode(reserr.Gen02).setStatusErr(err), err
	}
	if calChain == nil {
		err := errors.New(errors.KsiInvalidStateError).AppendMessage("Missing calendar hash chain.")
		return newRuleResult(r, result.NA).setErrCode(reserr.Gen02).setStatusErr(err), err
	}

	// Calculate calendar aggregation root hash value.
	calcRoot, err := calChain.Aggregate()
	if err != nil {
		return newRuleResult(r, result.NA).setErrCode(reserr.Gen02).setStatusErr(err), err
	}

	if !hash.Equal(calcRoot, pubHash) {
		return newRuleResult(r, result.FAIL).setErrCode(r.errCode()), nil
	}
	return newRuleResult(r, result.OK), nil
}

// CalendarAuthRecordPresenceRule verifies that the signature contains calendar authentication record.
// Returns OK or NA(None).
type CalendarAuthRecordPresenceRule struct{}

func (r CalendarAuthRecordPresenceRule) errCode() reserr.Code { return reserr.ErrNA }
func (r CalendarAuthRecordPresenceRule) String() string       { return getName(r) }
func (r CalendarAuthRecordPresenceRule) Verify(context *VerificationContext) (*RuleResult, error) {
	if context == nil || context.signature == nil {
		err := errors.New(errors.KsiInvalidArgumentError)
		return newRuleResult(r, result.NA).setErrCode(reserr.Gen02).setStatusErr(err), err
	}

	calAuthRec, err := context.signature.CalendarAuthRec()
	if err != nil {
		err = errors.KsiErr(err).AppendMessage("Failed to get calendar auth record.")
		return newRuleResult(r, result.NA).setErrCode(reserr.Gen02).setStatusErr(err), err
	}

	if calAuthRec == nil {
		return newRuleResult(r, result.NA).setErrCode(r.errCode()), nil
	}
	return newRuleResult(r, result.OK), nil
}

// CalendarAuthenticationRecordAggregationTimeVerificationRule verifies that publication records time
// from calendar authentication record and calendar hash chain publication time do match.
// Returns OK or FAIL(INT-06).
type CalendarAuthenticationRecordAggregationTimeVerificationRule struct{}

func (r CalendarAuthenticationRecordAggregationTimeVerificationRule) errCode() reserr.Code {
	return reserr.Int06
}
func (r CalendarAuthenticationRecordAggregationTimeVerificationRule) String() string {
	return getName(r)
}
func (r CalendarAuthenticationRecordAggregationTimeVerificationRule) Verify(context *VerificationContext) (*RuleResult, error) {
	if context == nil || context.signature == nil {
		err := errors.New(errors.KsiInvalidArgumentError)
		return newRuleResult(r, result.NA).setErrCode(reserr.Gen02).setStatusErr(err), err
	}

	calAuthRec, err := context.signature.CalendarAuthRec()
	if err != nil {
		err = errors.KsiErr(err).AppendMessage("Failed to get calendar auth record.")
		return newRuleResult(r, result.NA).setErrCode(reserr.Gen02).setStatusErr(err), err
	}
	if calAuthRec == nil {
		err := errors.New(errors.KsiInvalidStateError).AppendMessage("Missing calendar authentication record.")
		return newRuleResult(r, result.NA).setErrCode(reserr.Gen02).setStatusErr(err), err
	}
	pubData, err := calAuthRec.PublicationData()
	if err != nil {
		err = errors.KsiErr(err).AppendMessage("Failed to get publication data.")
		return newRuleResult(r, result.NA).setErrCode(reserr.Gen02).setStatusErr(err), err
	}
	pubTime, err := pubData.PublicationTime()
	if err != nil {
		err = errors.KsiErr(err).AppendMessage("Failed to get publication time.")
		return newRuleResult(r, result.NA).setErrCode(reserr.Gen02).setStatusErr(err), err
	}

	calChain, err := context.signature.CalendarChain()
	if err != nil {
		err = errors.KsiErr(err).AppendMessage("Failed to get calendar chain.")
		return newRuleResult(r, result.NA).setErrCode(reserr.Gen02).setStatusErr(err), err
	}
	if calChain == nil {
		err := errors.New(errors.KsiInvalidStateError).AppendMessage("Missing calendar hash chain.")
		return newRuleResult(r, result.NA).setErrCode(reserr.Gen02).setStatusErr(err), err
	}
	calTime, err := calChain.PublicationTime()
	if err != nil {
		err := errors.KsiErr(err).AppendMessage("Failed to get calendar chain publication time.")
		return newRuleResult(r, result.NA).setErrCode(reserr.Gen02).setStatusErr(err), err
	}

	if !calTime.Equal(pubTime) {
		return newRuleResult(r, result.FAIL).setErrCode(r.errCode()), nil
	}
	return newRuleResult(r, result.OK), nil
}

// CalendarAuthenticationRecordAggregationHashVerificationRule verifies that publication hash
// from calendar authentication record and calendar hash chain root hash do match.
// Returns OK or FAIL(INT-08).
type CalendarAuthenticationRecordAggregationHashVerificationRule struct{}

func (r CalendarAuthenticationRecordAggregationHashVerificationRule) errCode() reserr.Code {
	return reserr.Int08
}
func (r CalendarAuthenticationRecordAggregationHashVerificationRule) String() string {
	return getName(r)
}
func (r CalendarAuthenticationRecordAggregationHashVerificationRule) Verify(context *VerificationContext) (*RuleResult, error) {
	if context == nil || context.signature == nil {
		err := errors.New(errors.KsiInvalidArgumentError)
		return newRuleResult(r, result.NA).setErrCode(reserr.Gen02).setStatusErr(err), err
	}

	calAuthRec, err := context.signature.CalendarAuthRec()
	if err != nil {
		err = errors.KsiErr(err).AppendMessage("Failed to get calendar auth record.")
		return newRuleResult(r, result.NA).setErrCode(reserr.Gen02).setStatusErr(err), err
	}
	if calAuthRec == nil {
		err := errors.New(errors.KsiInvalidStateError).AppendMessage("Missing calendar auth record.")
		return newRuleResult(r, result.NA).setErrCode(reserr.Gen02).setStatusErr(err), err
	}
	pubData, err := calAuthRec.PublicationData()
	if err != nil {
		err = errors.KsiErr(err).AppendMessage("Failed to get publication data.")
		return newRuleResult(r, result.NA).setErrCode(reserr.Gen02).setStatusErr(err), err
	}
	pubHash, err := pubData.PublishedHash()
	if err != nil {
		err = errors.KsiErr(err).AppendMessage("Failed to get published hash.")
		return newRuleResult(r, result.NA).setErrCode(reserr.Gen02).setStatusErr(err), err
	}

	calChain, err := context.signature.CalendarChain()
	if err != nil {
		err = errors.KsiErr(err).AppendMessage("Failed to get calendar chain.")
		return newRuleResult(r, result.NA).setErrCode(reserr.Gen02).setStatusErr(err), err
	}
	if calChain == nil {
		err := errors.New(errors.KsiInvalidStateError).AppendMessage("Missing calendar hash chain.")
		return newRuleResult(r, result.NA).setErrCode(reserr.Gen02).setStatusErr(err), err
	}

	// Calculate calendar aggregation root hash value.
	calcRoot, err := calChain.Aggregate()
	if err != nil {
		return newRuleResult(r, result.NA).setErrCode(reserr.Gen02).setStatusErr(err), err
	}

	if !hash.Equal(calcRoot, pubHash) {
		return newRuleResult(r, result.FAIL).setErrCode(r.errCode()), nil
	}
	return newRuleResult(r, result.OK), nil
}

/*
----------------------------------------
UserProvidedPublicationBasedVerificationPolicy
----------------------------------------
*/

// UserProvidedPublicationExistenceRule verifies that the user has provided a publication.
// Returns OK or NA(None).
type UserProvidedPublicationExistenceRule struct{}

func (r UserProvidedPublicationExistenceRule) errCode() reserr.Code { return reserr.ErrNA }
func (r UserProvidedPublicationExistenceRule) String() string       { return getName(r) }
func (r UserProvidedPublicationExistenceRule) Verify(context *VerificationContext) (*RuleResult, error) {
	if context == nil {
		err := errors.New(errors.KsiInvalidArgumentError)
		return newRuleResult(r, result.NA).setErrCode(reserr.Gen02).setStatusErr(err), err
	}

	if context.userPublication == nil {
		return newRuleResult(r, result.NA).setErrCode(r.errCode()), nil
	}
	return newRuleResult(r, result.OK), nil
}

// UserProvidedPublicationTimeVerificationRule verifies that the publication time of the user publication equals
// the signature publication time.
// Returns OK or NA(None).
type UserProvidedPublicationTimeVerificationRule struct{}

func (r UserProvidedPublicationTimeVerificationRule) errCode() reserr.Code { return reserr.ErrNA }
func (r UserProvidedPublicationTimeVerificationRule) String() string       { return getName(r) }
func (r UserProvidedPublicationTimeVerificationRule) Verify(context *VerificationContext) (*RuleResult, error) {
	if context == nil || context.signature == nil || context.userPublication == nil {
		err := errors.New(errors.KsiInvalidArgumentError)
		return newRuleResult(r, result.NA).setErrCode(reserr.Gen02).setStatusErr(err), err
	}

	publication, err := context.signature.Publication()
	if err != nil {
		err = errors.KsiErr(err).AppendMessage("Failed to get publication record.")
		return newRuleResult(r, result.NA).setErrCode(reserr.Gen02).setStatusErr(err), err
	}
	if publication == nil {
		err := errors.New(errors.KsiInvalidStateError).AppendMessage("Missing publication record.")
		return newRuleResult(r, result.NA).setErrCode(reserr.Gen02).setStatusErr(err), err
	}
	pubData, err := publication.PublicationData()
	if err != nil {
		err = errors.KsiErr(err).AppendMessage("Failed to get publication data.")
		return newRuleResult(r, result.NA).setErrCode(reserr.Gen02).setStatusErr(err), err
	}
	pubTime, err := pubData.PublicationTime()
	if err != nil {
		err = errors.KsiErr(err).AppendMessage("Failed to get publication time.")
		return newRuleResult(r, result.NA).setErrCode(reserr.Gen02).setStatusErr(err), err
	}

	usrPubTime, err := context.userPublication.PublicationTime()
	if err != nil {
		err = errors.KsiErr(err).AppendMessage("Failed to get user publication time.")
		return newRuleResult(r, result.NA).setErrCode(reserr.Gen02).setStatusErr(err), err
	}

	if !usrPubTime.Equal(pubTime) {
		return newRuleResult(r, result.NA).setErrCode(r.errCode()), nil
	}
	return newRuleResult(r, result.OK), nil
}

// UserProvidedPublicationHashVerificationRule verifies that the publication hash of the user publication equals
// to the signature publication record root hash.
// Returns OK or FAIL(PUB-4).
type UserProvidedPublicationHashVerificationRule struct{}

func (r UserProvidedPublicationHashVerificationRule) errCode() reserr.Code { return reserr.Pub04 }
func (r UserProvidedPublicationHashVerificationRule) String() string       { return getName(r) }
func (r UserProvidedPublicationHashVerificationRule) Verify(context *VerificationContext) (*RuleResult, error) {
	if context == nil || context.signature == nil || context.userPublication == nil {
		err := errors.New(errors.KsiInvalidArgumentError)
		return newRuleResult(r, result.NA).setErrCode(reserr.Gen02).setStatusErr(err), err
	}

	publication, err := context.signature.Publication()
	if err != nil {
		err = errors.KsiErr(err).AppendMessage("Failed to get publication record.")
		return newRuleResult(r, result.NA).setErrCode(reserr.Gen02).setStatusErr(err), err
	}
	if publication == nil {
		err := errors.New(errors.KsiInvalidStateError).AppendMessage("Missing publication record.")
		return newRuleResult(r, result.NA).setErrCode(reserr.Gen02).setStatusErr(err), err
	}
	pubData, err := publication.PublicationData()
	if err != nil {
		err = errors.KsiErr(err).AppendMessage("Failed to get publication data.")
		return newRuleResult(r, result.NA).setErrCode(reserr.Gen02).setStatusErr(err), err
	}
	pubHash, err := pubData.PublishedHash()
	if err != nil {
		err = errors.KsiErr(err).AppendMessage("Failed to get published hash.")
		return newRuleResult(r, result.NA).setErrCode(reserr.Gen02).setStatusErr(err), err
	}

	usrPubHash, err := context.userPublication.PublishedHash()
	if err != nil {
		err = errors.KsiErr(err).AppendMessage("Failed to get user provided publication hash.")
		return newRuleResult(r, result.NA).setErrCode(reserr.Gen02).setStatusErr(err), err
	}

	if !hash.Equal(usrPubHash, pubHash) {
		return newRuleResult(r, result.FAIL).setErrCode(r.errCode()), nil
	}
	return newRuleResult(r, result.OK), nil
}

// SignatureCalendarHashAlgorithmDeprecatedAtPubTimeVerificationRule verifies that any of the signature calendar
// hash chain aggregation hash algorithms (see 'left link Rule' from the rfc) were trusted at the publication time.
// Returns OK or NA(GEN-2).
type SignatureCalendarHashAlgorithmDeprecatedAtPubTimeVerificationRule struct{}

func (r SignatureCalendarHashAlgorithmDeprecatedAtPubTimeVerificationRule) errCode() reserr.Code {
	return reserr.Gen02
}
func (r SignatureCalendarHashAlgorithmDeprecatedAtPubTimeVerificationRule) String() string {
	return getName(r)
}
func (r SignatureCalendarHashAlgorithmDeprecatedAtPubTimeVerificationRule) Verify(context *VerificationContext) (*RuleResult, error) {
	if context == nil || context.signature == nil {
		err := errors.New(errors.KsiInvalidArgumentError)
		return newRuleResult(r, result.NA).setErrCode(reserr.Gen02).setStatusErr(err), err
	}

	calChain, err := context.signature.CalendarChain()
	if err != nil {
		err = errors.KsiErr(err).AppendMessage("Failed to get calendar chain.")
		return newRuleResult(r, result.NA).setErrCode(reserr.Gen02).setStatusErr(err), err
	}
	if calChain == nil {
		err := errors.New(errors.KsiInvalidStateError).AppendMessage("Missing calendar hash chain.")
		return newRuleResult(r, result.NA).setErrCode(reserr.Gen02).setStatusErr(err), err
	}

	if yes, err := calendarChainContainsDeprecatedAlgorithm(calChain); err != nil {
		return newRuleResult(r, result.NA).setErrCode(reserr.Gen02).setStatusErr(err), err
	} else if yes {
		return newRuleResult(r, result.NA).setErrCode(r.errCode()), nil
	}
	return newRuleResult(r, result.OK), nil
}

func calendarChainContainsDeprecatedAlgorithm(calendar *pdu.CalendarChain) (bool, error) {
	if calendar == nil {
		return true, errors.New(errors.KsiInvalidArgumentError)
	}

	chainLinks, err := calendar.ChainLinks()
	if err != nil {
		return true, errors.KsiErr(err).AppendMessage("Failed to get chain links.")
	}
	pubTime, err := calendar.PublicationTime()
	if err != nil {
		return true, errors.KsiErr(err).AppendMessage("Failed to get calendar publication time.")
	}

	for _, link := range chainLinks {
		isLeft, err := link.IsLeft()
		if err != nil {
			return true, errors.KsiErr(err).AppendMessage("Failed to get chain link side.")
		}
		if !isLeft {
			continue
		}

		siblingHash, err := link.SiblingHash()
		if err != nil {
			return true, errors.KsiErr(err).AppendMessage("Failed to get sibling hash.")
		}

		status := siblingHash.Algorithm().StatusAt(pubTime.Unix())
		if status == hash.Unknown {
			msg := fmt.Sprintf("Calendar sibling hash contains unknown hash algorithm: %x", siblingHash.Algorithm())
			log.Info(msg)
			return true, errors.New(errors.KsiUnknownHashAlgorithm).AppendMessage(msg)
		}
		if status == hash.Deprecated || status == hash.Obsolete {
			return true, nil
		}
	}
	return false, nil
}

// UserProvidedPublicationCreationTimeVerificationRule verifies that signature is not newer than user provided publication.
// Returns OK or NA(GEN-02).
type UserProvidedPublicationCreationTimeVerificationRule struct{}

func (r UserProvidedPublicationCreationTimeVerificationRule) errCode() reserr.Code {
	return reserr.Gen02
}
func (r UserProvidedPublicationCreationTimeVerificationRule) String() string { return getName(r) }
func (r UserProvidedPublicationCreationTimeVerificationRule) Verify(context *VerificationContext) (*RuleResult, error) {
	if context == nil || context.signature == nil || context.userPublication == nil {
		err := errors.New(errors.KsiInvalidArgumentError)
		return newRuleResult(r, result.NA).setErrCode(reserr.Gen02).setStatusErr(err), err
	}

	usrPubTime, err := context.userPublication.PublicationTime()
	if err != nil {
		err = errors.KsiErr(err).AppendMessage("Failed to get user publication time.")
		return newRuleResult(r, result.NA).setErrCode(reserr.Gen02).setStatusErr(err), err
	}
	if usrPubTime.IsZero() {
		err := errors.New(errors.KsiInvalidFormatError).AppendMessage("Inconsistent user provided publication time.")
		return newRuleResult(r, result.NA).setErrCode(reserr.Gen02).setStatusErr(err), err
	}

	calChain, err := context.signature.CalendarChain()
	if err != nil {
		err = errors.KsiErr(err).AppendMessage("Failed to get calendar chain.")
		return newRuleResult(r, result.NA).setErrCode(reserr.Gen02).setStatusErr(err), err
	}

	var aggrTime time.Time
	if calChain != nil {
		aggrTime, err = calChain.AggregationTime()
		if err != nil {
			err = errors.KsiErr(err).AppendMessage("Failed to get calendar chain aggregation time.")
			return newRuleResult(r, result.NA).setErrCode(reserr.Gen02).setStatusErr(err), err
		}
	}

	if aggrTime.IsZero() {
		aggrChainList, err := context.signature.AggregationHashChainList()
		if err != nil {
			err = errors.KsiErr(err).AppendMessage("Failed to get aggregation hash chains.")
			return newRuleResult(r, result.NA).setErrCode(reserr.Gen02).setStatusErr(err), err
		}
		if aggrChainList == nil || len(aggrChainList) == 0 {
			err := errors.New(errors.KsiInvalidStateError).AppendMessage("Missing aggregation hash chain.")
			return newRuleResult(r, result.NA).setErrCode(reserr.Gen02).setStatusErr(err), err
		}
		// Take the first aggregation hash chain, as all of the chain should have the same value for "aggregation time".
		aggrTime, err = aggrChainList[0].AggregationTime()
		if err != nil {
			err = errors.KsiErr(err).AppendMessage("Failed to get aggregation time.")
			return newRuleResult(r, result.NA).setErrCode(reserr.Gen02).setStatusErr(err), err
		}
	}

	if aggrTime.After(usrPubTime) {
		return newRuleResult(r, result.NA).setErrCode(r.errCode()), nil
	}
	return newRuleResult(r, result.OK), nil
}

// ExtendingPermittedRule verifies that signature extending is permitted.
// Returns OK or NA(GEN-02).
type ExtendingPermittedRule struct{}

func (r ExtendingPermittedRule) errCode() reserr.Code { return reserr.Gen02 }
func (r ExtendingPermittedRule) String() string       { return getName(r) }
func (r ExtendingPermittedRule) Verify(context *VerificationContext) (*RuleResult, error) {
	if context == nil || context.signature == nil {
		err := errors.New(errors.KsiInvalidArgumentError)
		return newRuleResult(r, result.NA).setErrCode(reserr.Gen02).setStatusErr(err), err
	}

	if !context.extendingPerm {
		return newRuleResult(r, result.NA).setErrCode(r.errCode()), nil
	}
	return newRuleResult(r, result.OK), nil
}

// UserProvidedPublicationExtendToPublication retrieves calendar hash chain for the time period
// from aggregation time to the time of user provided publication.
// Returns OK or NA(GEN-02).
type UserProvidedPublicationExtendToPublication struct{}

func (r UserProvidedPublicationExtendToPublication) errCode() reserr.Code { return reserr.Gen02 }
func (r UserProvidedPublicationExtendToPublication) String() string       { return getName(r) }
func (r UserProvidedPublicationExtendToPublication) Verify(context *VerificationContext) (*RuleResult, error) {
	if context == nil || context.signature == nil {
		err := errors.New(errors.KsiInvalidArgumentError)
		return newRuleResult(r, result.NA).setErrCode(reserr.Gen02).setStatusErr(err), err
	}

	pubTime, err := context.userPublication.PublicationTime()
	if err != nil {
		err = errors.KsiErr(err).AppendMessage("Failed to get publication time.")
		return newRuleResult(r, result.NA).setErrCode(reserr.Gen02).setStatusErr(err), err
	}
	if pubTime.IsZero() {
		err := errors.New(errors.KsiInvalidFormatError).AppendMessage("Inconsistent user publication data time.")
		return newRuleResult(r, result.NA).setErrCode(reserr.Gen02).setStatusErr(err), err
	}

	return receiveCalendar(r, context, pubTime)
}

func receiveCalendar(rule Rule, context *VerificationContext, to time.Time) (*RuleResult, error) {
	if context == nil {
		err := errors.New(errors.KsiInvalidArgumentError)
		return newRuleResult(rule, result.NA).setErrCode(reserr.Gen02).setStatusErr(err), err
	}

	if err := context.receiveCalendar(to); err != nil {
		err = errors.KsiErr(err).AppendMessage("Failed to receive calendar hash chain.")

		switch errors.KsiErr(err).Code() {
		case /* Whatever network errors. */
			errors.KsiNetworkError,
			errors.KsiHttpError,
			/* Whatever Extender service errors. */
			errors.KsiServiceInvalidRequest,
			errors.KsiServiceAuthenticationFailure,
			errors.KsiServiceInvalidPayload,
			errors.KsiServiceExtenderInvalidTimeRange,
			errors.KsiServiceExtenderRequestTimeTooOld,
			errors.KsiServiceExtenderRequestTimeTooNew,
			errors.KsiServiceExtenderRequestTimeInFuture,
			errors.KsiServiceInternalError,
			errors.KsiServiceExtenderDatabaseMissing,
			errors.KsiServiceExtenderDatabaseCorrupt,
			errors.KsiServiceUpstreamError,
			errors.KsiServiceUpstreamTimeout:
			return newRuleResult(rule, result.NA).setErrCode(reserr.Gen02).setStatusErr(err), nil
		default:
			return newRuleResult(rule, result.NA).setErrCode(reserr.Gen02).setStatusErr(err), err
		}
	}
	return newRuleResult(rule, result.OK), nil
}

// UserProvidedPublicationExtendedCalendarHashAlgorithmDeprecatedAtPubTimeVerificationRule verifies that all of the response
// calendar hash chain's aggregation algorithms (see 'left link Rule' from the rfc) were trusted at the publication time.
// Returns OK or NA(GEN-02).
type UserProvidedPublicationExtendedCalendarHashAlgorithmDeprecatedAtPubTimeVerificationRule struct{}

func (r UserProvidedPublicationExtendedCalendarHashAlgorithmDeprecatedAtPubTimeVerificationRule) errCode() reserr.Code {
	return reserr.Gen02
}
func (r UserProvidedPublicationExtendedCalendarHashAlgorithmDeprecatedAtPubTimeVerificationRule) String() string {
	return getName(r)
}
func (r UserProvidedPublicationExtendedCalendarHashAlgorithmDeprecatedAtPubTimeVerificationRule) Verify(context *VerificationContext) (*RuleResult, error) {
	if context == nil || context.signature == nil {
		err := errors.New(errors.KsiInvalidArgumentError)
		return newRuleResult(r, result.NA).setErrCode(reserr.Gen02).setStatusErr(err), err
	}

	resCode, err := extCalAlgorithmDeprecatedAtPubTimeVerification(context)
	if err != nil {
		return newRuleResult(r, result.NA).setErrCode(reserr.Gen02).setStatusErr(err), err
	}

	if resCode != result.OK {
		return newRuleResult(r, resCode).setErrCode(r.errCode()), nil
	}
	return newRuleResult(r, result.OK), nil
}

func extCalAlgorithmDeprecatedAtPubTimeVerification(context *VerificationContext) (result.Code, error) {
	if context == nil {
		return result.NA, errors.New(errors.KsiInvalidArgumentError)
	}

	calendar, err := context.extendedCalendarHashChain()
	if err != nil {
		return result.NA, err
	}

	if yes, err := calendarChainContainsDeprecatedAlgorithm(calendar); err != nil {
		return result.NA, err
	} else if yes {
		return result.NA, nil
	}
	return result.OK, nil
}

// UserProvidedPublicationHashMatchesExtendedResponseVerificationRule verifies that Extender response calendar root hash
// match with publication's hash.
// Returns OK or FAIL(PUB-01).
type UserProvidedPublicationHashMatchesExtendedResponseVerificationRule struct{}

func (r UserProvidedPublicationHashMatchesExtendedResponseVerificationRule) errCode() reserr.Code {
	return reserr.Pub01
}
func (r UserProvidedPublicationHashMatchesExtendedResponseVerificationRule) String() string {
	return getName(r)
}
func (r UserProvidedPublicationHashMatchesExtendedResponseVerificationRule) Verify(context *VerificationContext) (*RuleResult, error) {
	if context == nil || context.signature == nil {
		err := errors.New(errors.KsiInvalidArgumentError)
		return newRuleResult(r, result.NA).setErrCode(reserr.Gen02).setStatusErr(err), err
	}

	calendar, err := context.extendedCalendarHashChain()
	if err != nil {
		return newRuleResult(r, result.NA).setErrCode(reserr.Gen02).setStatusErr(err), err
	}

	hsh, err := calendar.Aggregate()
	if err != nil {
		return newRuleResult(r, result.NA).setErrCode(reserr.Gen02).setStatusErr(err), err
	}

	pubHash, err := context.userPublication.PublishedHash()
	if err != nil {
		err = errors.KsiErr(err).AppendMessage("Failed to get published hash.")
		return newRuleResult(r, result.NA).setErrCode(reserr.Gen02).setStatusErr(err), err
	}

	if !hash.Equal(hsh, pubHash) {
		return newRuleResult(r, result.FAIL).setErrCode(r.errCode()), nil
	}
	return newRuleResult(r, result.OK), nil
}

// UserProvidedPublicationTimeMatchesExtendedResponseVerificationRule verifies that Extender response hash chain shape does match
// with publication time.
// Returns OK or FAIL(PUB-02).
type UserProvidedPublicationTimeMatchesExtendedResponseVerificationRule struct{}

func (r UserProvidedPublicationTimeMatchesExtendedResponseVerificationRule) errCode() reserr.Code {
	return reserr.Pub02
}
func (r UserProvidedPublicationTimeMatchesExtendedResponseVerificationRule) String() string {
	return getName(r)
}
func (r UserProvidedPublicationTimeMatchesExtendedResponseVerificationRule) Verify(context *VerificationContext) (*RuleResult, error) {
	if context == nil || context.signature == nil || context.userPublication == nil {
		err := errors.New(errors.KsiInvalidArgumentError)
		return newRuleResult(r, result.NA).setErrCode(reserr.Gen02).setStatusErr(err), err
	}

	pubTime, err := context.userPublication.PublicationTime()
	if err != nil {
		err = errors.KsiErr(err).AppendMessage("Failed to get publication time.")
		return newRuleResult(r, result.NA).setErrCode(reserr.Gen02).setStatusErr(err), err
	}

	aggrChainList, err := context.signature.AggregationHashChainList()
	if err != nil {
		err = errors.KsiErr(err).AppendMessage("Failed to get aggregation hash chains.")
		return newRuleResult(r, result.NA).setErrCode(reserr.Gen02).setStatusErr(err), err
	}
	if aggrChainList == nil || len(aggrChainList) == 0 {
		err := errors.New(errors.KsiInvalidStateError).AppendMessage("Missing aggregation hash chain.")
		return newRuleResult(r, result.NA).setErrCode(reserr.Gen02).setStatusErr(err), err
	}
	aggrTime, err := aggrChainList[0].AggregationTime()
	if err != nil {
		err = errors.KsiErr(err).AppendMessage("Failed to get aggregation time.")
		return newRuleResult(r, result.NA).setErrCode(reserr.Gen02).setStatusErr(err), err
	}
	if aggrTime.IsZero() {
		err := errors.New(errors.KsiInvalidFormatError).AppendMessage("Inconsistent aggregation time.")
		return newRuleResult(r, result.NA).setErrCode(reserr.Gen02).setStatusErr(err), err
	}

	calendar, err := context.extendedCalendarHashChain()
	if err != nil {
		return newRuleResult(r, result.NA).setErrCode(reserr.Gen02).setStatusErr(err), err
	}
	calPubTime, err := calendar.PublicationTime()
	if err != nil {
		err = errors.KsiErr(err).AppendMessage("Failed to get publication time.")
		return newRuleResult(r, result.NA).setErrCode(reserr.Gen02).setStatusErr(err), err

	}

	if !pubTime.Equal(calPubTime) {
		log.Info("User provided publication time does not match Extender response time.")
		return newRuleResult(r, result.FAIL).setErrCode(r.errCode()), nil
	}

	calcTime, err := calendar.CalculateAggregationTime()
	if err != nil {
		return newRuleResult(r, result.NA).setErrCode(reserr.Gen02).setStatusErr(err), err
	}
	if calcTime.IsZero() {
		err := errors.New(errors.KsiInvalidFormatError).AppendMessage("Inconsistent calculated aggregation time.")
		return newRuleResult(r, result.NA).setErrCode(reserr.Gen02).setStatusErr(err), err
	}
	if !aggrTime.Equal(calcTime) {
		log.Info("Signature aggregation hash chain aggregation time does not math with Extender aggregation time.")
		return newRuleResult(r, result.FAIL).setErrCode(r.errCode()), nil
	}
	return newRuleResult(r, result.OK), nil
}

// UserProvidedPublicationExtendedSignatureInputHashVerificationRule if Extender response input hash does equal with
// signature aggregation root hash.
// Returns OK or FAIL(PUB-03).
type UserProvidedPublicationExtendedSignatureInputHashVerificationRule struct{}

func (r UserProvidedPublicationExtendedSignatureInputHashVerificationRule) errCode() reserr.Code {
	return reserr.Pub03
}
func (r UserProvidedPublicationExtendedSignatureInputHashVerificationRule) String() string {
	return getName(r)
}
func (r UserProvidedPublicationExtendedSignatureInputHashVerificationRule) Verify(context *VerificationContext) (*RuleResult, error) {
	if context == nil || context.signature == nil || context.userPublication == nil {
		err := errors.New(errors.KsiInvalidArgumentError)
		return newRuleResult(r, result.NA).setErrCode(reserr.Gen02).setStatusErr(err), err
	}

	calendar, err := context.extendedCalendarHashChain()
	if err != nil {
		return newRuleResult(r, result.NA).setErrCode(reserr.Gen02).setStatusErr(err), err
	}
	calInputHash, err := calendar.InputHash()
	if err != nil {
		err = errors.KsiErr(err).AppendMessage("Failed to get calendar chain input hash.")
		return newRuleResult(r, result.NA).setErrCode(reserr.Gen02).setStatusErr(err), err
	}

	aggrOutHsh, err := context.aggregationHashChainOutputHash()
	if err != nil {
		return newRuleResult(r, result.NA).setErrCode(reserr.Gen02).setStatusErr(err), err
	}

	if !hash.Equal(aggrOutHsh, calInputHash) {
		log.Info("Signature aggregation hash chain output hash does not match with extended calendar input hash.")
		return newRuleResult(r, result.FAIL).setErrCode(r.errCode()), nil
	}
	return newRuleResult(r, result.OK), nil
}

/*
----------------------------------------
PublicationsFileBasedVerificationPolicy
----------------------------------------
*/

// PublicationsFileContainsSignaturePublicationVerificationRule verifies that there is publication in the publications
// file with the same publication time as the signature publication record.
// Returns OK or NA(None).
type PublicationsFileContainsSignaturePublicationVerificationRule struct{}

func (r PublicationsFileContainsSignaturePublicationVerificationRule) errCode() reserr.Code {
	return reserr.ErrNA
}
func (r PublicationsFileContainsSignaturePublicationVerificationRule) String() string {
	return getName(r)
}
func (r PublicationsFileContainsSignaturePublicationVerificationRule) Verify(context *VerificationContext) (*RuleResult, error) {
	if context == nil || context.signature == nil {
		err := errors.New(errors.KsiInvalidArgumentError)
		return newRuleResult(r, result.NA).setErrCode(reserr.Gen02).setStatusErr(err), err
	}

	publication, err := context.signature.Publication()
	if err != nil {
		err = errors.KsiErr(err).AppendMessage("Failed to get publication record.")
		return newRuleResult(r, result.NA).setErrCode(reserr.Gen02).setStatusErr(err), err
	}
	pubData, err := publication.PublicationData()
	if err != nil {
		err = errors.KsiErr(err).AppendMessage("Failed to get publication data.")
		return newRuleResult(r, result.NA).setErrCode(reserr.Gen02).setStatusErr(err), err
	}
	pubTime, err := pubData.PublicationTime()
	if err != nil {
		err = errors.KsiErr(err).AppendMessage("Failed to get publication time.")
		return newRuleResult(r, result.NA).setErrCode(reserr.Gen02).setStatusErr(err), err
	}

	pubFile, err := context.publicationsFile()
	if err != nil {
		// Do not end with error. Give it a chance in a fallback policy.
		return newRuleResult(r, result.NA).setErrCode(reserr.Gen02).setStatusErr(err), nil
	}

	pubRec, err := pubFile.PublicationRec(publications.PubRecSearchByTime(pubTime))
	if err != nil {
		return newRuleResult(r, result.NA).setErrCode(reserr.Gen02).setStatusErr(err), err
	}
	if pubRec == nil {
		return newRuleResult(r, result.NA).setErrCode(r.errCode()), nil
	}
	return newRuleResult(r, result.OK), nil
}

// PublicationsFileSignaturePublicationHashVerificationRule verifies that the hashes of the publications file publication
// record and the signature publication record do match.
// Returns OK or FAIL(PUB-5).
type PublicationsFileSignaturePublicationHashVerificationRule struct{}

func (r PublicationsFileSignaturePublicationHashVerificationRule) errCode() reserr.Code {
	return reserr.Pub05
}
func (r PublicationsFileSignaturePublicationHashVerificationRule) String() string { return getName(r) }
func (r PublicationsFileSignaturePublicationHashVerificationRule) Verify(context *VerificationContext) (*RuleResult, error) {
	if context == nil || context.signature == nil {
		err := errors.New(errors.KsiInvalidArgumentError)
		return newRuleResult(r, result.NA).setErrCode(reserr.Gen02).setStatusErr(err), err
	}

	publication, err := context.signature.Publication()
	if err != nil {
		err = errors.KsiErr(err).AppendMessage("Failed to get publication record.")
		return newRuleResult(r, result.NA).setErrCode(reserr.Gen02).setStatusErr(err), err
	}
	pubData, err := publication.PublicationData()
	if err != nil {
		err = errors.KsiErr(err).AppendMessage("Failed to get publication data.")
		return newRuleResult(r, result.NA).setErrCode(reserr.Gen02).setStatusErr(err), err
	}

	pubFile, err := context.publicationsFile()
	if err != nil {
		// Do not end with error. Give it a chance in a fallback policy.
		return newRuleResult(r, result.NA).setErrCode(reserr.Gen02).setStatusErr(err), nil
	}

	pubRec, err := pubFile.PublicationRec(publications.PubRecSearchByPubData(pubData))
	if err != nil {
		return newRuleResult(r, result.NA).setErrCode(reserr.Gen02).setStatusErr(err), err
	}
	if pubRec == nil {
		log.Debug("Publications mismatch.")
		return newRuleResult(r, result.FAIL).setErrCode(r.errCode()), nil
	}
	return newRuleResult(r, result.OK), nil
}

// PublicationsFileContainsSuitablePublicationVerificationRule verifies that a suitable publication exists in the publications file
// (in order for the signature to be extended).
// Returns OK or NA(GEN-02).
type PublicationsFileContainsSuitablePublicationVerificationRule struct{}

func (r PublicationsFileContainsSuitablePublicationVerificationRule) errCode() reserr.Code {
	return reserr.Gen02
}
func (r PublicationsFileContainsSuitablePublicationVerificationRule) String() string {
	return getName(r)
}
func (r PublicationsFileContainsSuitablePublicationVerificationRule) Verify(context *VerificationContext) (*RuleResult, error) {
	if context == nil || context.signature == nil {
		err := errors.New(errors.KsiInvalidArgumentError)
		return newRuleResult(r, result.NA).setErrCode(reserr.Gen02).setStatusErr(err), err
	}

	pubFile, err := context.publicationsFile()
	if err != nil {
		// Do not end with error. Give it a chance in a fallback policy.
		return newRuleResult(r, result.NA).setErrCode(reserr.Gen02).setStatusErr(err), nil
	}

	sigTime, err := context.signature.SigningTime()
	if err != nil {
		return newRuleResult(r, result.NA).setErrCode(reserr.Gen02).setStatusErr(err), err
	}

	pubRec, err := pubFile.PublicationRec(publications.PubRecSearchNearest(sigTime))
	if err != nil {
		return newRuleResult(r, result.NA).setErrCode(reserr.Gen02).setStatusErr(err), err
	}
	if pubRec == nil {
		msg := "Suitable publication not found."
		log.Debug(msg)
		return newRuleResult(r, result.NA).setErrCode(r.errCode()), nil
	}

	return newRuleResult(r, result.OK), nil
}

// PublicationsFileExtendToPublication retrieves calendar hash chain for the time period from
// aggregation time to the time of nearest suitable publication from publications file.
// Returns OK or NA(GEN-02).
type PublicationsFileExtendToPublication struct{}

func (r PublicationsFileExtendToPublication) errCode() reserr.Code { return reserr.Gen02 }
func (r PublicationsFileExtendToPublication) String() string       { return getName(r) }
func (r PublicationsFileExtendToPublication) Verify(context *VerificationContext) (*RuleResult, error) {
	if context == nil || context.signature == nil {
		err := errors.New(errors.KsiInvalidArgumentError)
		return newRuleResult(r, result.NA).setErrCode(reserr.Gen02).setStatusErr(err), err
	}

	sigTime, err := context.signature.SigningTime()
	if err != nil {
		return newRuleResult(r, result.NA).setErrCode(reserr.Gen02).setStatusErr(err), err
	}
	pubFile, err := context.publicationsFile()
	if err != nil {
		// Do not end with error. Give it a chance in a fallback policy.
		return newRuleResult(r, result.NA).setErrCode(reserr.Gen02).setStatusErr(err), nil
	}
	pubRec, err := pubFile.PublicationRec(publications.PubRecSearchNearest(sigTime))
	if err != nil {
		return newRuleResult(r, result.NA).setErrCode(reserr.Gen02).setStatusErr(err), err
	}
	if pubRec == nil {
		return newRuleResult(r, result.NA).setErrCode(reserr.Gen02),
			errors.New(errors.KsiInvalidStateError).AppendMessage("Can not find suitable publication.")
	}
	pubData, err := pubRec.PublicationData()
	if err != nil {
		err = errors.KsiErr(err).AppendMessage("Failed to get publication data.")
		return newRuleResult(r, result.NA).setErrCode(reserr.Gen02).setStatusErr(err), err
	}
	if pubData == nil {
		err := errors.New(errors.KsiInvalidStateError).AppendMessage("Missing publication data.")
		return newRuleResult(r, result.NA).setErrCode(reserr.Gen02).setStatusErr(err), err
	}
	pubTime, err := pubData.PublicationTime()
	if err != nil {
		err = errors.KsiErr(err).AppendMessage("Failed to get publication time.")
		return newRuleResult(r, result.NA).setErrCode(reserr.Gen02).setStatusErr(err), err
	}
	if pubTime.IsZero() {
		err := errors.New(errors.KsiInvalidFormatError).AppendMessage("Missing publication time.")
		return newRuleResult(r, result.NA).setErrCode(reserr.Gen02).setStatusErr(err), err
	}

	return receiveCalendar(r, context, pubTime)
}

// PubFileExtendedCalendarHashAlgorithmDeprecatedAtPubTimeVerificationRule verifies that all of the signature calendar
// hash chain's aggregation algorithms (see 'left link Rule' from the rfc) were trusted at the publication time.
// Returns OK or NA(GEN-02).
type PubFileExtendedCalendarHashAlgorithmDeprecatedAtPubTimeVerificationRule struct{}

func (r PubFileExtendedCalendarHashAlgorithmDeprecatedAtPubTimeVerificationRule) errCode() reserr.Code {
	return reserr.Gen02
}
func (r PubFileExtendedCalendarHashAlgorithmDeprecatedAtPubTimeVerificationRule) String() string {
	return getName(r)
}
func (r PubFileExtendedCalendarHashAlgorithmDeprecatedAtPubTimeVerificationRule) Verify(context *VerificationContext) (*RuleResult, error) {
	if context == nil || context.signature == nil {
		err := errors.New(errors.KsiInvalidArgumentError)
		return newRuleResult(r, result.NA).setErrCode(reserr.Gen02).setStatusErr(err), err
	}

	if resCode, err := extCalAlgorithmDeprecatedAtPubTimeVerification(context); err != nil {
		return newRuleResult(r, result.NA).setErrCode(reserr.Gen02).setStatusErr(err), err
	} else if resCode != result.OK {
		return newRuleResult(r, resCode).setErrCode(r.errCode()), nil
	}
	return newRuleResult(r, result.OK), nil
}

// PublicationsFilePublicationHashMatchesExtenderResponseVerificationRule verifies that Extender response calendar root
// hash match with publication's hash.
// Returns OK or FAIL(PUB-01).
type PublicationsFilePublicationHashMatchesExtenderResponseVerificationRule struct{}

func (r PublicationsFilePublicationHashMatchesExtenderResponseVerificationRule) errCode() reserr.Code {
	return reserr.Pub01
}
func (r PublicationsFilePublicationHashMatchesExtenderResponseVerificationRule) String() string {
	return getName(r)
}
func (r PublicationsFilePublicationHashMatchesExtenderResponseVerificationRule) Verify(context *VerificationContext) (*RuleResult, error) {
	if context == nil || context.signature == nil {
		err := errors.New(errors.KsiInvalidArgumentError)
		return newRuleResult(r, result.NA).setErrCode(reserr.Gen02).setStatusErr(err), err
	}

	sigTime, err := context.signature.SigningTime()
	if err != nil {
		return newRuleResult(r, result.NA).setErrCode(reserr.Gen02).setStatusErr(err), err
	}
	pubFile, err := context.publicationsFile()
	if err != nil {
		// Do not end with error. Give it a chance in a fallback policy.
		return newRuleResult(r, result.NA).setErrCode(reserr.Gen02).setStatusErr(err), nil
	}
	pubRec, err := pubFile.PublicationRec(publications.PubRecSearchNearest(sigTime))
	if err != nil {
		return newRuleResult(r, result.NA).setErrCode(reserr.Gen02).setStatusErr(err), err
	}
	if pubRec == nil {
		err := errors.New(errors.KsiInvalidStateError).AppendMessage("Can not find suitable publication.")
		return newRuleResult(r, result.NA).setErrCode(reserr.Gen02).setStatusErr(err), err
	}
	pubData, err := pubRec.PublicationData()
	if err != nil {
		err = errors.KsiErr(err).AppendMessage("Failed to get publication data.")
		return newRuleResult(r, result.NA).setErrCode(reserr.Gen02).setStatusErr(err), err
	}
	pubHash, err := pubData.PublishedHash()
	if err != nil {
		err = errors.KsiErr(err).AppendMessage("Failed to get published hash.")
		return newRuleResult(r, result.NA).setErrCode(reserr.Gen02).setStatusErr(err), err
	}

	calendar, err := context.extendedCalendarHashChain()
	if err != nil {
		return newRuleResult(r, result.NA).setErrCode(reserr.Gen02).setStatusErr(err), err
	}
	rootHsh, err := calendar.Aggregate()
	if err != nil {
		return newRuleResult(r, result.NA).setErrCode(reserr.Gen02).setStatusErr(err), err
	}
	if hash.Equal(rootHsh, pubHash) != true {
		log.Info("Publications file publication hash does not match with Extender response calendar hash chain root hash.")
		return newRuleResult(r, result.FAIL).setErrCode(r.errCode()), nil
	}
	return newRuleResult(r, result.OK), nil
}

// PublicationsFilePublicationTimeMatchesExtendedResponseVerificationRule verifies that Extender response hash chain shape does match
// with the publication time.
// Returns OK or FAIL(PUB-02).
type PublicationsFilePublicationTimeMatchesExtendedResponseVerificationRule struct{}

func (r PublicationsFilePublicationTimeMatchesExtendedResponseVerificationRule) errCode() reserr.Code {
	return reserr.Pub02
}
func (r PublicationsFilePublicationTimeMatchesExtendedResponseVerificationRule) String() string {
	return getName(r)
}
func (r PublicationsFilePublicationTimeMatchesExtendedResponseVerificationRule) Verify(context *VerificationContext) (*RuleResult, error) {
	if context == nil || context.signature == nil {
		err := errors.New(errors.KsiInvalidArgumentError)
		return newRuleResult(r, result.NA).setErrCode(reserr.Gen02).setStatusErr(err), err
	}

	sigTime, err := context.signature.SigningTime()
	if err != nil {
		return newRuleResult(r, result.NA).setErrCode(reserr.Gen02).setStatusErr(err), err
	}
	pubFile, err := context.publicationsFile()
	if err != nil {
		// Do not end with error. Give it a chance in a fallback policy.
		return newRuleResult(r, result.NA).setErrCode(reserr.Gen02).setStatusErr(err), nil
	}
	pubRec, err := pubFile.PublicationRec(publications.PubRecSearchNearest(sigTime))
	if err != nil {
		return newRuleResult(r, result.NA).setErrCode(reserr.Gen02).setStatusErr(err), err
	}
	if pubRec == nil {
		err := errors.New(errors.KsiInvalidStateError).AppendMessage("Can not find suitable publication.")
		return newRuleResult(r, result.NA).setErrCode(reserr.Gen02).setStatusErr(err), err
	}
	pubData, err := pubRec.PublicationData()
	if err != nil {
		err = errors.KsiErr(err).AppendMessage("Failed to get publication data.")
		return newRuleResult(r, result.NA).setErrCode(reserr.Gen02).setStatusErr(err), err
	}
	pubTime, err := pubData.PublicationTime()
	if err != nil {
		err = errors.KsiErr(err).AppendMessage("Failed to get publication time.")
		return newRuleResult(r, result.NA).setErrCode(reserr.Gen02).setStatusErr(err), err
	}
	if pubTime.IsZero() {
		err := errors.New(errors.KsiInvalidFormatError).AppendMessage("Missing publication data time.")
		return newRuleResult(r, result.NA).setErrCode(reserr.Gen02).setStatusErr(err), err
	}

	calendar, err := context.extendedCalendarHashChain()
	if err != nil {
		return newRuleResult(r, result.NA).setErrCode(reserr.Gen02).setStatusErr(err), err
	}
	calPubTime, err := calendar.PublicationTime()
	if err != nil {
		err = errors.KsiErr(err).AppendMessage("Failed to get calendar publication time.")
		return newRuleResult(r, result.NA).setErrCode(reserr.Gen02).setStatusErr(err), err
	}

	if !calPubTime.Equal(pubTime) {
		log.Info("Publication time does not match extender response time.")
		return newRuleResult(r, result.FAIL).setErrCode(r.errCode()), nil
	}
	return newRuleResult(r, result.OK), nil
}

// PublicationsFileExtendedSignatureInputHashVerificationRule if Extender response input hash does equal with
// signature aggregation root hash.
// Returns OK or FAIL(PUB-03).
type PublicationsFileExtendedSignatureInputHashVerificationRule struct{}

func (r PublicationsFileExtendedSignatureInputHashVerificationRule) errCode() reserr.Code {
	return reserr.Pub03
}
func (r PublicationsFileExtendedSignatureInputHashVerificationRule) String() string {
	return getName(r)
}
func (r PublicationsFileExtendedSignatureInputHashVerificationRule) Verify(context *VerificationContext) (*RuleResult, error) {
	if context == nil || context.signature == nil {
		err := errors.New(errors.KsiInvalidArgumentError)
		return newRuleResult(r, result.NA).setErrCode(reserr.Gen02).setStatusErr(err), err
	}

	calendar, err := context.extendedCalendarHashChain()
	if err != nil {
		return newRuleResult(r, result.NA).setErrCode(reserr.Gen02).setStatusErr(err), err
	}
	inputHash, err := calendar.InputHash()
	if err != nil {
		err = errors.KsiErr(err).AppendMessage("Failed to get calendar input hash.")
		return newRuleResult(r, result.NA).setErrCode(reserr.Gen02).setStatusErr(err), err
	}

	aggrRootHsh, err := context.aggregationHashChainOutputHash()
	if err != nil {
		return newRuleResult(r, result.NA).setErrCode(reserr.Gen02).setStatusErr(err), err
	}

	if !hash.Equal(aggrRootHsh, inputHash) {
		return newRuleResult(r, result.FAIL).setErrCode(r.errCode()), nil
	}
	return newRuleResult(r, result.OK), nil
}

/*
----------------------------------------
KeyBasedVerificationPolicy rules
----------------------------------------
*/

// CalendarHashChainExistenceRule verifies that calendar chain is present.
// Returns OK or NA(GEN-2).
type CalendarHashChainExistenceRule struct{}

func (r CalendarHashChainExistenceRule) errCode() reserr.Code { return reserr.Gen02 }
func (r CalendarHashChainExistenceRule) String() string       { return getName(r) }
func (r CalendarHashChainExistenceRule) Verify(context *VerificationContext) (*RuleResult, error) {
	if context == nil || context.signature == nil {
		err := errors.New(errors.KsiInvalidArgumentError)
		return newRuleResult(r, result.NA).setErrCode(reserr.Gen02).setStatusErr(err), err
	}

	calChain, err := context.signature.CalendarChain()
	if err != nil {
		err = errors.KsiErr(err).AppendMessage("Failed to get calendar chain.")
		return newRuleResult(r, result.NA).setErrCode(reserr.Gen02).setStatusErr(err), err
	}

	if calChain == nil {
		return newRuleResult(r, result.NA).setErrCode(r.errCode()), nil
	}
	return newRuleResult(r, result.OK), nil
}

// CalendarHashChainAlgorithmDeprecatedRule verifies that all of the calendar hash chain's aggregation
// algorithms (see 'left link Rule' from the rfc) were trusted at the publication time.
// Returns OK or NA(GEN-2).
type CalendarHashChainAlgorithmDeprecatedRule struct{}

func (r CalendarHashChainAlgorithmDeprecatedRule) errCode() reserr.Code { return reserr.Gen02 }
func (r CalendarHashChainAlgorithmDeprecatedRule) String() string       { return getName(r) }
func (r CalendarHashChainAlgorithmDeprecatedRule) Verify(context *VerificationContext) (*RuleResult, error) {
	if context == nil || context.signature == nil {
		err := errors.New(errors.KsiInvalidArgumentError)
		return newRuleResult(r, result.NA).setErrCode(reserr.Gen02).setStatusErr(err), err
	}

	calChain, err := context.signature.CalendarChain()
	if err != nil {
		err = errors.KsiErr(err).AppendMessage("Failed to get calendar chain.")
		return newRuleResult(r, result.NA).setErrCode(reserr.Gen02).setStatusErr(err), err
	}
	if calChain == nil {
		err := errors.New(errors.KsiInvalidStateError).AppendMessage("Missing calendar chain.")
		return newRuleResult(r, result.NA).setErrCode(reserr.Gen02).setStatusErr(err), err
	}

	pubTime, err := calChain.PublicationTime()
	if err != nil {
		err = errors.KsiErr(err).AppendMessage("Failed to get publication time.")
		return newRuleResult(r, result.NA).setErrCode(reserr.Gen02).setStatusErr(err), err
	}

	chainLinks, err := calChain.ChainLinks()
	if err != nil {
		err = errors.KsiErr(err).AppendMessage("Failed to get calendar chain links.")
		return newRuleResult(r, result.NA).setErrCode(reserr.Gen02).setStatusErr(err), err
	}
	for _, link := range chainLinks {
		isLeft, err := link.IsLeft()
		if err != nil {
			err = errors.KsiErr(err).AppendMessage("Failed to get calendar chain link side.")
			return newRuleResult(r, result.NA).setErrCode(reserr.Gen02).setStatusErr(err), err
		}
		if !isLeft {
			continue
		}

		siblingHash, err := link.SiblingHash()
		if err != nil {
			err = errors.KsiErr(err).AppendMessage("Failed to get link sibling hash.")
			return newRuleResult(r, result.NA).setErrCode(reserr.Gen02).setStatusErr(err), err
		}
		if siblingHash == nil {
			err := errors.New(errors.KsiInvalidStateError).AppendMessage("Missing calendar chain link sibling.")
			return newRuleResult(r, result.NA).setErrCode(reserr.Gen02).setStatusErr(err), err
		}

		status := siblingHash.Algorithm().StatusAt(pubTime.Unix())
		if status == hash.Unknown {
			msg := fmt.Sprintf("Calendar sibling hash contains unknown hash algorithm: %x", siblingHash)
			log.Info(msg)
			err := errors.New(errors.KsiUnknownHashAlgorithm).AppendMessage(msg)
			return newRuleResult(r, result.NA).setErrCode(reserr.Gen02).setStatusErr(err), err
		}
		if status == hash.Deprecated || status == hash.Obsolete {
			return newRuleResult(r, result.NA).setErrCode(r.errCode()), nil
		}
	}
	return newRuleResult(r, result.OK), nil
}

// CalendarAuthenticationRecordExistenceRule verifies that calendar authentication record is present.
// Returns OK or NA(GEN-2).
type CalendarAuthenticationRecordExistenceRule struct{}

func (r CalendarAuthenticationRecordExistenceRule) errCode() reserr.Code {
	return reserr.Gen02
}
func (r CalendarAuthenticationRecordExistenceRule) String() string { return getName(r) }
func (r CalendarAuthenticationRecordExistenceRule) Verify(context *VerificationContext) (*RuleResult, error) {
	if context == nil || context.signature == nil {
		err := errors.New(errors.KsiInvalidArgumentError)
		return newRuleResult(r, result.NA).setErrCode(reserr.Gen02).setStatusErr(err), err
	}

	calAuthRec, err := context.signature.CalendarAuthRec()
	if err != nil {
		err = errors.KsiErr(err).AppendMessage("Failed to get calendar auth record.")
		return newRuleResult(r, result.NA).setErrCode(reserr.Gen02).setStatusErr(err), err
	}

	if calAuthRec == nil {
		return newRuleResult(r, result.NA).setErrCode(r.errCode()), nil
	}
	return newRuleResult(r, result.OK), nil
}

// CertificateExistenceRule verifies that certificate lookup was successful.
// Returns OK or NA(GEN-02).
type CertificateExistenceRule struct{}

func (r CertificateExistenceRule) errCode() reserr.Code { return reserr.Gen02 }
func (r CertificateExistenceRule) String() string       { return getName(r) }
func (r CertificateExistenceRule) Verify(context *VerificationContext) (*RuleResult, error) {
	if context == nil || context.signature == nil {
		err := errors.New(errors.KsiInvalidArgumentError)
		return newRuleResult(r, result.NA).setErrCode(reserr.Gen02).setStatusErr(err), err
	}

	calAuthRec, err := context.signature.CalendarAuthRec()
	if err != nil {
		err = errors.KsiErr(err).AppendMessage("Failed to get calendar auth record.")
		return newRuleResult(r, result.NA).setErrCode(reserr.Gen02).setStatusErr(err), err
	}
	if calAuthRec == nil {
		err := errors.New(errors.KsiInvalidStateError).AppendMessage("Missing calendar authentication record.")
		return newRuleResult(r, result.NA).setErrCode(reserr.Gen02).setStatusErr(err), err
	}
	sigData, err := calAuthRec.SignatureData()
	if err != nil {
		err = errors.KsiErr(err).AppendMessage("Failed to get calendar auth record signature data.")
		return newRuleResult(r, result.NA).setErrCode(reserr.Gen02).setStatusErr(err), err
	}
	if sigData == nil {
		err := errors.New(errors.KsiInvalidStateError).
			AppendMessage("Missing calendar authentication record signature data.")
		return newRuleResult(r, result.NA).setErrCode(reserr.Gen02).setStatusErr(err), err
	}
	certID, err := sigData.CertID()
	if err != nil {
		err = errors.KsiErr(err).AppendMessage("Failed to get certificate id.")
		return newRuleResult(r, result.NA).setErrCode(reserr.Gen02).setStatusErr(err), err
	}

	pubFile, err := context.publicationsFile()
	if err != nil {
		// Do not end with error. Give it a chance in a fallback policy.
		return newRuleResult(r, result.NA).setErrCode(reserr.Gen02).setStatusErr(err), nil
	}
	certRec, err := pubFile.Certificate(certID)
	if err != nil {
		return newRuleResult(r, result.NA).setErrCode(reserr.Gen02).setStatusErr(err), err
	}
	if certRec == nil {
		return newRuleResult(r, result.NA).setErrCode(r.errCode()), nil
	}
	return newRuleResult(r, result.OK), nil
}

// CertificateValidityRule verifies that certificate was valid at aggregation time (use calendar chain
// aggregation time, or if not present, default to calendar chain publication time).
// Returns OK or FAIL(KEY-03).
type CertificateValidityRule struct{}

func (r CertificateValidityRule) errCode() reserr.Code { return reserr.Key03 }
func (r CertificateValidityRule) String() string       { return getName(r) }
func (r CertificateValidityRule) Verify(context *VerificationContext) (*RuleResult, error) {
	if context == nil || context.signature == nil {
		err := errors.New(errors.KsiInvalidArgumentError)
		return newRuleResult(r, result.NA).setErrCode(reserr.Gen02).setStatusErr(err), err
	}

	calAuthRec, err := context.signature.CalendarAuthRec()
	if err != nil {
		err = errors.KsiErr(err).AppendMessage("Failed to get calendar auth record.")
		return newRuleResult(r, result.NA).setErrCode(reserr.Gen02).setStatusErr(err), err
	}
	if calAuthRec == nil {
		err := errors.New(errors.KsiInvalidStateError).AppendMessage("Missing calendar authentication record.")
		return newRuleResult(r, result.NA).setErrCode(reserr.Gen02).setStatusErr(err), err
	}
	sigData, err := calAuthRec.SignatureData()
	if err != nil {
		err = errors.KsiErr(err).AppendMessage("Failed to get calendar authentication record signature data.")
		return newRuleResult(r, result.NA).setErrCode(reserr.Gen02).setStatusErr(err), err
	}
	if sigData == nil {
		err := errors.New(errors.KsiInvalidStateError).
			AppendMessage("Missing calendar authentication record signature data.")
		return newRuleResult(r, result.NA).setErrCode(reserr.Gen02).setStatusErr(err), err
	}
	certID, err := sigData.CertID()
	if err != nil {
		err = errors.KsiErr(err).AppendMessage("Failed to get certificate id.")
		return newRuleResult(r, result.NA).setErrCode(reserr.Gen02).setStatusErr(err), err
	}

	pubFile, err := context.publicationsFile()
	if err != nil {
		// Do not end with error. Give it a chance in a fallback policy.
		return newRuleResult(r, result.NA).setErrCode(reserr.Gen02).setStatusErr(err), nil
	}
	certRec, err := pubFile.Certificate(certID)
	if err != nil {
		return newRuleResult(r, result.NA).setErrCode(reserr.Gen02).setStatusErr(err), err
	}
	if certRec == nil {
		err := errors.New(errors.KsiInvalidStateError).
			AppendMessage("Suitable PKI certificate not found in publications file.")
		return newRuleResult(r, result.NA).setErrCode(reserr.Gen02).setStatusErr(err), err
	}

	calChain, err := context.signature.CalendarChain()
	if err != nil {
		err = errors.KsiErr(err).AppendMessage("Failed to get calendar chain.")
		return newRuleResult(r, result.NA).setErrCode(reserr.Gen02).setStatusErr(err), err
	}
	if calChain == nil {
		err := errors.New(errors.KsiInvalidStateError).AppendMessage("Inconsistent calendar chain.")
		return newRuleResult(r, result.NA).setErrCode(reserr.Gen02).setStatusErr(err), err
	}
	calTime, err := calChain.AggregationTime()
	if err != nil {
		err = errors.KsiErr(err).AppendMessage("Failed to get calendar aggregation time.")
		return newRuleResult(r, result.NA).setErrCode(reserr.Gen02).setStatusErr(err), err
	}
	if calTime.IsZero() {
		calTime, err = calChain.PublicationTime()
		if err != nil {
			err = errors.KsiErr(err).AppendMessage("Failed to get calendar publication time.")
			return newRuleResult(r, result.NA).setErrCode(reserr.Gen02).setStatusErr(err), err
		}
	}

	isValid, err := certRec.IsValid(calTime)
	if err != nil {
		return newRuleResult(r, result.NA).setErrCode(reserr.Gen02).setStatusErr(err), err
	}
	if !isValid {
		return newRuleResult(r, result.FAIL).setErrCode(r.errCode()), nil
	}
	return newRuleResult(r, result.OK), nil
}

// CalendarAuthenticationRecordSignatureVerificationRule verifies PKI signature.
// Returns OK or FAIL(KEY-02).
type CalendarAuthenticationRecordSignatureVerificationRule struct{}

func (r CalendarAuthenticationRecordSignatureVerificationRule) errCode() reserr.Code {
	return reserr.Key02
}
func (r CalendarAuthenticationRecordSignatureVerificationRule) String() string { return getName(r) }
func (r CalendarAuthenticationRecordSignatureVerificationRule) Verify(context *VerificationContext) (*RuleResult, error) {
	if context == nil || context.signature == nil {
		err := errors.New(errors.KsiInvalidArgumentError)
		return newRuleResult(r, result.NA).setErrCode(reserr.Gen02).setStatusErr(err), err
	}

	calAuthRec, err := context.signature.CalendarAuthRec()
	if err != nil {
		err = errors.KsiErr(err).AppendMessage("Failed to get calendar auth record.")
		return newRuleResult(r, result.NA).setErrCode(reserr.Gen02).setStatusErr(err), err
	}
	if calAuthRec == nil {
		err := errors.New(errors.KsiInvalidStateError).AppendMessage("Missing calendar authentication record.")
		return newRuleResult(r, result.NA).setErrCode(reserr.Gen02).setStatusErr(err), err
	}

	pubFile, err := context.publicationsFile()
	if err != nil {
		// Do not end with error. Give it a chance in a fallback policy.
		return newRuleResult(r, result.NA).setErrCode(reserr.Gen02).setStatusErr(err), nil
	}

	if err := pubFile.VerifyRecord(calAuthRec); err != nil {
		if ksiErr := errors.KsiErr(err); ksiErr.Code() == errors.KsiInvalidPkiSignature {
			log.Info(ksiErr.AppendMessage("Calendar authentication record PKI signature verification failed.").Message())
			return newRuleResult(r, result.FAIL).setErrCode(r.errCode()).setStatusErr(ksiErr), nil
		}
		return newRuleResult(r, result.NA).setErrCode(reserr.Gen02).setStatusErr(err), err
	}
	return newRuleResult(r, result.OK), nil
}

/*
----------------------------------------
CalendarBasedVerificationPolicy rules
----------------------------------------
*/

// ExtendSignatureCalendarChainInputHashToHead retrieves calendar hash chain for the time period from aggregation
// time to the head of the calendar.
// Returns OK or NA(GEN-02).
type ExtendSignatureCalendarChainInputHashToHead struct{}

func (r ExtendSignatureCalendarChainInputHashToHead) errCode() reserr.Code { return reserr.Gen02 }
func (r ExtendSignatureCalendarChainInputHashToHead) String() string       { return getName(r) }
func (r ExtendSignatureCalendarChainInputHashToHead) Verify(context *VerificationContext) (*RuleResult, error) {
	if context == nil || context.signature == nil {
		err := errors.New(errors.KsiInvalidArgumentError)
		return newRuleResult(r, result.NA).setErrCode(reserr.Gen02).setStatusErr(err), err
	}

	return receiveCalendar(r, context, time.Time{})
}

// ExtendSignatureCalendarChainInputHashToSamePubTime retrieves calendar hash chain for the time period from aggregation
// time to the publication time of the current calendar hash chain.
// Returns OK or NA(GEN-02).
type ExtendSignatureCalendarChainInputHashToSamePubTime struct{}

func (r ExtendSignatureCalendarChainInputHashToSamePubTime) errCode() reserr.Code { return reserr.Gen02 }
func (r ExtendSignatureCalendarChainInputHashToSamePubTime) String() string       { return getName(r) }
func (r ExtendSignatureCalendarChainInputHashToSamePubTime) Verify(context *VerificationContext) (*RuleResult, error) {
	if context == nil || context.signature == nil {
		err := errors.New(errors.KsiInvalidArgumentError)
		return newRuleResult(r, result.NA).setErrCode(reserr.Gen02).setStatusErr(err), err
	}

	calChain, err := context.signature.CalendarChain()
	if err != nil {
		err = errors.KsiErr(err).AppendMessage("Failed to get calendar chain.")
		return newRuleResult(r, result.NA).setErrCode(reserr.Gen02).setStatusErr(err), err
	}
	if calChain == nil {
		err := errors.New(errors.KsiInvalidStateError).AppendMessage("Missing calendar chain.")
		return newRuleResult(r, result.NA).setErrCode(reserr.Gen02).setStatusErr(err), err
	}
	pubTime, err := calChain.PublicationTime()
	if err != nil {
		err = errors.KsiErr(err).AppendMessage("Failed to get calendar publication time.")
		return newRuleResult(r, result.NA).setErrCode(reserr.Gen02).setStatusErr(err), err
	}

	return receiveCalendar(r, context, pubTime)
}

// ExtendedSignatureCalendarChainInputHashVerificationRule verifies that response input hash and aggregation root hash do match.
// Returns OK or FAIL(CAL-02).
type ExtendedSignatureCalendarChainInputHashVerificationRule struct{}

func (r ExtendedSignatureCalendarChainInputHashVerificationRule) errCode() reserr.Code {
	return reserr.Cal02
}
func (r ExtendedSignatureCalendarChainInputHashVerificationRule) String() string { return getName(r) }
func (r ExtendedSignatureCalendarChainInputHashVerificationRule) Verify(context *VerificationContext) (*RuleResult, error) {
	if context == nil || context.signature == nil {
		err := errors.New(errors.KsiInvalidArgumentError)
		return newRuleResult(r, result.NA).setErrCode(reserr.Gen02).setStatusErr(err), err
	}

	extCalChain, err := context.extendedCalendarHashChain()
	if err != nil {
		return newRuleResult(r, result.NA).setErrCode(reserr.Gen02).setStatusErr(err), err
	}
	extInputHash, err := extCalChain.InputHash()
	if err != nil {
		err = errors.KsiErr(err).AppendMessage("Failed to get calendar chain input hash.")
		return newRuleResult(r, result.NA).setErrCode(reserr.Gen02).setStatusErr(err), err
	}

	hsh, err := context.aggregationHashChainOutputHash()
	if err != nil {
		return newRuleResult(r, result.NA).setErrCode(reserr.Gen02).setStatusErr(err), err
	}

	if !hash.Equal(extInputHash, hsh) {
		return newRuleResult(r, result.FAIL).setErrCode(r.errCode()), nil
	}
	return newRuleResult(r, result.OK), nil
}

// ExtendedSignatureCalendarChainAggregationTimeVerificationRule verifies that retrieved calendar hash chain's
// aggregation time does match with the signature's aggregation time.
// Returns OK or FAIL(CAL-03).
type ExtendedSignatureCalendarChainAggregationTimeVerificationRule struct{}

func (r ExtendedSignatureCalendarChainAggregationTimeVerificationRule) errCode() reserr.Code {
	return reserr.Cal03
}
func (r ExtendedSignatureCalendarChainAggregationTimeVerificationRule) String() string {
	return getName(r)
}
func (r ExtendedSignatureCalendarChainAggregationTimeVerificationRule) Verify(context *VerificationContext) (*RuleResult, error) {
	if context == nil || context.signature == nil {
		err := errors.New(errors.KsiInvalidArgumentError)
		return newRuleResult(r, result.NA).setErrCode(reserr.Gen02).setStatusErr(err), err
	}

	extCalChain, err := context.extendedCalendarHashChain()
	if err != nil {
		return newRuleResult(r, result.NA).setErrCode(reserr.Gen02).setStatusErr(err), err
	}

	extCalTime, err := extCalChain.AggregationTime()
	if err != nil {
		err = errors.KsiErr(err).AppendMessage("Failed to get calendar chain aggregation time.")
		return newRuleResult(r, result.NA).setErrCode(reserr.Gen02).setStatusErr(err), err
	}
	if extCalTime.IsZero() {
		extCalTime, err = extCalChain.PublicationTime()
		if err != nil {
			err = errors.KsiErr(err).AppendMessage("Failed to get calendar chain publication time.")
			return newRuleResult(r, result.NA).setErrCode(reserr.Gen02).setStatusErr(err), err
		}
	}

	aggrChainList, err := context.signature.AggregationHashChainList()
	if err != nil {
		err = errors.KsiErr(err).AppendMessage("Failed to get aggregation chain list.")
		return newRuleResult(r, result.NA).setErrCode(reserr.Gen02).setStatusErr(err), err
	}
	aggrTime, err := aggrChainList[0].AggregationTime()
	if err != nil {
		err = errors.KsiErr(err).AppendMessage("Failed to get aggregation time.")
		return newRuleResult(r, result.NA).setErrCode(reserr.Gen02).setStatusErr(err), err
	}

	if !extCalTime.Equal(aggrTime) {
		return newRuleResult(r, result.FAIL).setErrCode(r.errCode()), nil
	}
	return newRuleResult(r, result.OK), nil
}

// ExtendedSignatureCalendarChainRootHashVerificationRule verifies that retrieved calendar hash chain's
// root hash does match with the signature's calendar hash chain root hash. Note that root hash values
// are calculated.
// Returns OK or FAIL(CAL-01).
type ExtendedSignatureCalendarChainRootHashVerificationRule struct{}

func (r ExtendedSignatureCalendarChainRootHashVerificationRule) errCode() reserr.Code {
	return reserr.Cal01
}
func (r ExtendedSignatureCalendarChainRootHashVerificationRule) String() string { return getName(r) }
func (r ExtendedSignatureCalendarChainRootHashVerificationRule) Verify(context *VerificationContext) (*RuleResult, error) {
	if context == nil || context.signature == nil {
		err := errors.New(errors.KsiInvalidArgumentError)
		return newRuleResult(r, result.NA).setErrCode(reserr.Gen02).setStatusErr(err), err
	}

	calChain, err := context.signature.CalendarChain()
	if err != nil {
		err = errors.KsiErr(err).AppendMessage("Failed to get calendar chain.")
		return newRuleResult(r, result.NA).setErrCode(reserr.Gen02).setStatusErr(err), err
	}
	if calChain == nil {
		err := errors.New(errors.KsiInvalidStateError).AppendMessage("Missing calendar hash chain.")
		return newRuleResult(r, result.NA).setErrCode(reserr.Gen02).setStatusErr(err), err
	}
	calRoot, err := calChain.Aggregate()
	if err != nil {
		return newRuleResult(r, result.NA).setErrCode(reserr.Gen02).setStatusErr(err), err
	}

	extCalChain, err := context.extendedCalendarHashChain()
	if err != nil {
		return newRuleResult(r, result.NA).setErrCode(reserr.Gen02).setStatusErr(err), err
	}
	if extCalChain == nil {
		err := errors.New(errors.KsiInvalidStateError).AppendMessage("Missing extended calendar hash chain.")
		return newRuleResult(r, result.NA).setErrCode(reserr.Gen02).setStatusErr(err), err
	}
	extCalRoot, err := extCalChain.Aggregate()
	if err != nil {
		return newRuleResult(r, result.NA).setErrCode(reserr.Gen02).setStatusErr(err), err
	}

	if !hash.Equal(calRoot, extCalRoot) {
		return newRuleResult(r, result.FAIL).setErrCode(r.errCode()), nil
	}
	return newRuleResult(r, result.OK), nil
}

// ExtendedSignatureCalendarHashChainRightLinksMatchesVerificationRule verifies that the right link count and right link
// hashes in the calendar hash chains match with each other.
// Returns OK or FAIL (CAL-04).
type ExtendedSignatureCalendarHashChainRightLinksMatchesVerificationRule struct{}

func (r ExtendedSignatureCalendarHashChainRightLinksMatchesVerificationRule) errCode() reserr.Code {
	return reserr.Cal04
}
func (r ExtendedSignatureCalendarHashChainRightLinksMatchesVerificationRule) String() string {
	return getName(r)
}
func (r ExtendedSignatureCalendarHashChainRightLinksMatchesVerificationRule) Verify(context *VerificationContext) (*RuleResult, error) {
	if context == nil || context.signature == nil {
		err := errors.New(errors.KsiInvalidArgumentError)
		return newRuleResult(r, result.NA).setErrCode(reserr.Gen02).setStatusErr(err), err
	}

	calChain, err := context.signature.CalendarChain()
	if err != nil {
		err = errors.KsiErr(err).AppendMessage("Failed to get calendar chain.")
		return newRuleResult(r, result.NA).setErrCode(reserr.Gen02).setStatusErr(err), err
	}
	if calChain == nil {
		err := errors.New(errors.KsiInvalidStateError).AppendMessage("Missing calendar hash chain.")
		return newRuleResult(r, result.NA).setErrCode(reserr.Gen02).setStatusErr(err), err
	}

	extCalChain, err := context.extendedCalendarHashChain()
	if err != nil {
		return newRuleResult(r, result.NA).setErrCode(reserr.Gen02).setStatusErr(err), err
	}
	if extCalChain == nil {
		err := errors.New(errors.KsiInvalidStateError).AppendMessage("Missing extended calendar hash chain.")
		return newRuleResult(r, result.NA).setErrCode(reserr.Gen02).setStatusErr(err), err
	}

	if err := calChain.RightLinkMatch(extCalChain); err != nil {
		if ksiErr := errors.KsiErr(err); ksiErr.Code() == errors.KsiIncompatibleHashChain {
			log.Info(ksiErr.AppendMessage("Extender response calendar right link mismatch.").Message())
			return newRuleResult(r, result.FAIL).setErrCode(r.errCode()).setStatusErr(ksiErr), nil
		}
		return newRuleResult(r, result.NA).setErrCode(reserr.Gen02).setStatusErr(err), err
	}
	return newRuleResult(r, result.OK), nil
}
