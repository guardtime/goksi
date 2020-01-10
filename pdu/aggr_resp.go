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

package pdu

import (
	"bytes"
	"fmt"

	"github.com/guardtime/goksi/errors"
	"github.com/guardtime/goksi/hash"
	"github.com/guardtime/goksi/hmac"
	"github.com/guardtime/goksi/log"
	"github.com/guardtime/goksi/templates"
	"github.com/guardtime/goksi/tlv"
)

// AggregationResp returns aggregation response.
// Note that if the aggregator response does not contain aggregation response, nil is returned.
func (r *AggregatorResp) AggregationResp() (*AggrResp, error) {
	if r == nil {
		return nil, errors.New(errors.KsiInvalidArgumentError)
	}
	return r.aggrResp, nil
}

// RequestID returns aggregation response request identifier.
func (r *AggrResp) RequestID() (uint64, error) {
	if r == nil {
		return 0, errors.New(errors.KsiInvalidArgumentError)
	}
	if r.id == nil {
		return 0, errors.New(errors.KsiInvalidStateError)
	}
	return *r.id, nil
}

// Status returns aggregation response status code.
// In case the status is not 0, call (AggrResp).ErrorMsg() for description message.
func (r *AggrResp) Status() (uint64, error) {
	if r == nil {
		return 0, errors.New(errors.KsiInvalidArgumentError)
	}
	if r.status == nil {
		return 0, errors.New(errors.KsiInvalidStateError)
	}

	return *r.status, nil
}

// ErrorMsg returns aggregation response error message.
// See also (AggrResp).Status().
func (r *AggrResp) ErrorMsg() (string, error) {
	if r == nil {
		return "", errors.New(errors.KsiInvalidArgumentError)
	}
	if r.errorMsg == nil {
		return "", nil
	}
	return *r.errorMsg, nil
}

// Err returns aggregation response error if present, otherwise nil is returned.
func (r *AggrResp) Err() error {
	if r == nil {
		return errors.New(errors.KsiInvalidArgumentError)
	}
	if r.status == nil {
		return errors.New(errors.KsiInvalidStateError).
			AppendMessage("Inconsistent aggregation response.").
			AppendMessage("Missing response status.")
	}
	if err := aggregatorStatusToError(*r.status); err != nil {
		if r.errorMsg != nil {
			err = errors.KsiErr(err).AppendMessage(*r.errorMsg)
		}
		return err
	}
	return nil
}

// AggregationChainList returns aggregation chain list.
// If not present, an error is returned.
func (r *AggrResp) AggregationChainList() ([]*AggregationChain, error) {
	if r == nil {
		return nil, errors.New(errors.KsiInvalidArgumentError)
	}
	if err := r.Err(); err != nil {
		return nil, errors.KsiErr(err).AppendMessage("Aggregation response is invalid.")
	}

	if r.aggrChainList == nil {
		return nil, errors.New(errors.KsiInvalidStateError).
			AppendMessage("Inconsistent aggregation response.").
			AppendMessage("Missing aggregation chain list.")
	}
	return *r.aggrChainList, nil
}

// CalendarChain returns calendar hash chain.
// If not present, nil is returned.
func (r *AggrResp) CalendarChain() (*CalendarChain, error) {
	if r == nil {
		return nil, errors.New(errors.KsiInvalidArgumentError)
	}
	if err := r.Err(); err != nil {
		return nil, errors.KsiErr(err).AppendMessage("Aggregation response is invalid.")
	}

	return r.calChain, nil
}

// CalendarAuthRec returns calendar authentication record.
// If not present, nil is returned.
func (r *AggrResp) CalendarAuthRec() (*CalendarAuthRec, error) {
	if r == nil {
		return nil, errors.New(errors.KsiInvalidArgumentError)
	}
	if err := r.Err(); err != nil {
		return nil, errors.KsiErr(err).AppendMessage("Aggregation response is invalid.")
	}

	return r.calAuthRec, nil
}

// PublicationRec returns publication record.
// If not present, nil is returned.
func (r *AggrResp) PublicationRec() (*PublicationRec, error) {
	if r == nil {
		return nil, errors.New(errors.KsiInvalidArgumentError)
	}
	if err := r.Err(); err != nil {
		return nil, errors.KsiErr(err).AppendMessage("Aggregation response is invalid.")
	}

	return r.pubRec, nil
}

// RFC3161 returns RFC3161 record.
// If not present, nil is returned.
func (r *AggrResp) RFC3161() (*RFC3161, error) {
	if r == nil {
		return nil, errors.New(errors.KsiInvalidArgumentError)
	}
	if err := r.Err(); err != nil {
		return nil, errors.KsiErr(err).AppendMessage("Aggregation response is invalid.")
	}

	return r.rfc3161Rec, nil
}

// Verify verifies the aggregator response consistency. Returns an error in following cases:
//  - contains a service response error;
//  - the response is missing mandatory element;
//  - HMAC calculation result does not match with the response. The HMAC is calculated based on the provided hash
//    function ('alg') and the secret cryptographic key ('key').
func (r *AggregatorResp) Verify(alg hash.Algorithm, key string) error {
	if r == nil {
		return errors.New(errors.KsiInvalidArgumentError)
	}

	// Check if there are any response errors.
	if err := r.Err(); err != nil {
		return err
	}
	// Verify header existence.
	if r.header == nil {
		return errors.New(errors.KsiInvalidStateError).
			AppendMessage("Aggregation response must have a Header.")
	}
	// Verify payload existence.
	if r.aggrResp == nil && r.confResp == nil && r.aggrAck == nil {
		return errors.New(errors.KsiInvalidStateError).
			AppendMessage("Aggregator response must have a payload.")
	}
	// Verify HMAC.
	if r.mac == nil {
		return errors.New(errors.KsiInvalidStateError).
			AppendMessage("Aggregator response must have an HMAC.")
	}
	return r.verifyHmac(alg, key)
}

func (r *AggregatorResp) verifyHmac(alg hash.Algorithm, key string) error {
	if r == nil || r.mac == nil {
		return errors.New(errors.KsiInvalidArgumentError)
	}

	// The set algorithm must match with the response HMAC imprint algorithm.
	if (*r.mac).Algorithm() != alg {
		return errors.New(errors.KsiHmacAlgorithmMismatch).
			AppendMessage("Aggregator response HMAC algorithm mismatch.")
	}

	mac, err := r.calculateHmac(alg, key)
	if err != nil {
		return err
	}
	if !hash.Equal(*r.mac, mac) {
		return errors.New(errors.KsiHmacMismatch).AppendMessage("Aggregator response HMAC mismatch.")
	}

	return nil
}

// CalculateHmac returns newly calculated aggregator response HMAC.
func (r *AggregatorResp) calculateHmac(alg hash.Algorithm, key string) (hash.Imprint, error) {
	if r == nil {
		return nil, errors.New(errors.KsiInvalidArgumentError)
	}
	if !alg.Registered() {
		return nil, errors.New(errors.KsiUnknownHashAlgorithm).AppendMessage("Unable to calculate HMAC.")
	}

	raw, err := r.Encode()
	if err != nil {
		return nil, err
	}

	hsr, err := hmac.New(alg, []byte(key))
	if err != nil {
		return nil, err
	}
	// The MAC is computed over all PDU message bytes up to (but excluding) the hash value within the imprint in the MAC field:
	// 1. the TLV header of the PDU element itself;
	// 2. the complete header element (both the TLV header and the value of the element);
	// 3. the complete payload elements in the order in which they appear in the PDU;
	// 4. the TLV header of the MAC element;
	// 5. the hash algorithm identifier part of the imprint representing the MAC value.
	if _, err = hsr.Write(raw[:(len(raw) - alg.Size())]); err != nil {
		return nil, err
	}
	return hsr.Imprint()
}

// Err returns the response error if present, otherwise nil is returned.
func (r *AggregatorResp) Err() error {
	if r == nil {
		return errors.New(errors.KsiInvalidArgumentError)
	}

	// Check if the response contains reduced error PDU.
	if r.aggrErr != nil {
		if r.aggrErr.status == nil {
			return errors.New(errors.KsiInvalidStateError).
				AppendMessage("Inconsistent aggregation response error.").
				AppendMessage("Missing error status.")
		}
		if err := aggregatorStatusToError(*r.aggrErr.status); err != nil {
			if r.aggrErr.errorMsg != nil {
				err = errors.KsiErr(err).AppendMessage(*r.aggrErr.errorMsg)
			}
			return err
		}
	}
	// Check if aggregation response contains error fields.
	if r.aggrResp != nil {
		if err := r.aggrResp.Err(); err != nil {
			return err
		}
	}
	return nil
}

// aggregatorStatusToError converts aggregator status code to errors.(KsiError).
func aggregatorStatusToError(status uint64) error {
	switch status {
	case 0x00:
		return nil
	case 0x0101:
		return errors.New(errors.KsiServiceInvalidRequest).SetExtErrorCode(int(status))
	case 0x0102:
		return errors.New(errors.KsiServiceAuthenticationFailure).SetExtErrorCode(int(status))
	case 0x0103:
		return errors.New(errors.KsiServiceInvalidPayload).SetExtErrorCode(int(status))
	case 0x0104:
		return errors.New(errors.KsiServiceAggrRequestTooLarge).SetExtErrorCode(int(status))
	case 0x0105:
		return errors.New(errors.KsiServiceAggrRequestOverQuota).SetExtErrorCode(int(status))
	case 0x0106:
		return errors.New(errors.KsiServiceAggrTooManyRequests).SetExtErrorCode(int(status))
	case 0x0107:
		return errors.New(errors.KsiServiceAggrInputTooLong).SetExtErrorCode(int(status))
	case 0x0200:
		return errors.New(errors.KsiServiceInternalError).SetExtErrorCode(int(status))
	case 0x0300:
		return errors.New(errors.KsiServiceUpstreamError).SetExtErrorCode(int(status))
	case 0x0301:
		return errors.New(errors.KsiServiceUpstreamTimeout).SetExtErrorCode(int(status))
	default:
		return errors.New(errors.KsiServiceUnknownError).SetExtErrorCode(int(status))
	}
}

// Encode returns the serialized aggregator response.
func (r *AggregatorResp) Encode() ([]byte, error) {
	if r == nil {
		return nil, errors.New(errors.KsiInvalidArgumentError)
	}

	if r.rawTlv == nil {
		// Get template.
		pduTemplate, err := templates.Get("AggregatorResp")
		if err != nil {
			return nil, err
		}
		// Get TLV from template.
		rTlv, err := tlv.NewTlv(tlv.ConstructFromObject(r, pduTemplate))
		if err != nil {
			return nil, err
		}
		r.rawTlv = rTlv
	}

	log.Debug("Aggregation response:\n", r.rawTlv)
	return r.rawTlv.Raw, nil
}

// Decode de-serializes the raw TLV into the receiver aggregator response.
// Note that the AggregatorResp has to be created prior to calling this method.
func (r *AggregatorResp) Decode(raw []byte) error {
	if r == nil || len(raw) == 0 {
		return errors.New(errors.KsiInvalidArgumentError)
	}

	pduTemplate, err := templates.Get("AggregatorResp")
	if err != nil {
		return err
	}
	pduTlv, err := tlv.NewTlv(tlv.ConstructFromReader(bytes.NewReader(raw)))
	if err != nil {
		return err
	}
	if !pduTemplate.IsMatchingTag(pduTlv.Tag) {
		return errors.New(errors.KsiInvalidFormatError).AppendMessage(fmt.Sprintf("Unexpected aggregator response PDU type: 0x%x!", pduTlv.Tag))
	}
	if err := pduTlv.ParseNested(pduTemplate); err != nil {
		return errors.KsiErr(err).AppendMessage("Unable to parse aggregator response!")
	}

	log.Debug("Aggregation response:\n", pduTlv)
	return pduTlv.ToObject(r, pduTemplate, nil)
}

// Config returns configuration response, or nil if not present.
func (r *AggregatorResp) Config() (*Config, error) {
	if r == nil {
		return nil, errors.New(errors.KsiInvalidArgumentError)
	}
	return r.confResp, nil
}

// SetConfig sets new configuration instance into the response container.
func (r *AggregatorResp) SetConfig(c *Config) error {
	if r == nil {
		return errors.New(errors.KsiInvalidArgumentError)
	}
	r.confResp = c
	return nil
}

// Clone returns a deep copy of the origin, or nil in case of an error.
// Note that only response part of the AggregatorResp will be cloned, meaning header and HMAC are ignored.
func (r *AggregatorResp) Clone() (*AggregatorResp, error) {
	if r == nil {
		return nil, errors.New(errors.KsiInvalidArgumentError)
	}

	tmp := &AggregatorResp{}
	if r.aggrResp != nil {
		clone, err := clonePDU(r.aggrResp)
		if err != nil {
			return nil, err
		}
		tmp.aggrResp = clone.(*AggrResp)
	}
	if r.aggrErr != nil {
		clone, err := clonePDU(r.aggrErr)
		if err != nil {
			return nil, err
		}
		tmp.aggrErr = clone.(*Error)
	}
	if r.confResp != nil {
		clone, err := clonePDU(r.confResp)
		if err != nil {
			return nil, err
		}
		tmp.confResp = clone.(*Config)
	}
	if r.aggrAck != nil {
		clone, err := clonePDU(r.aggrAck)
		if err != nil {
			return nil, err
		}
		tmp.aggrAck = clone.(*AggrAck)
	}
	tmp.rawTlv = r.rawTlv

	return tmp, nil
}
