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

// ExtendingResp returns extending response.
// Note that if the extender response does not contain extending response, nil is returned.
func (r *ExtenderResp) ExtendingResp() (*ExtResp, error) {
	if r == nil {
		return nil, errors.New(errors.KsiInvalidArgumentError)
	}
	return r.extResp, nil

}

// RequestID returns extending response request identifier.
func (r *ExtResp) RequestID() (uint64, error) {
	if r == nil {
		return 0, errors.New(errors.KsiInvalidArgumentError)
	}
	if r.id == nil {
		return 0, errors.New(errors.KsiInvalidStateError)
	}
	return *r.id, nil
}

// Status returns extending response status code.
// In case the status is not 0, call (ExtResp).ErrorMsg() for description message.
func (r *ExtResp) Status() (uint64, error) {
	if r == nil {
		return 0, errors.New(errors.KsiInvalidArgumentError)
	}
	if r.status == nil {
		return 0, errors.New(errors.KsiInvalidStateError)
	}
	return *r.status, nil
}

// ErrorMsg returns extending response error message.
// See also (ExtResp).Status().
func (r *ExtResp) ErrorMsg() (string, error) {
	if r == nil {
		return "", errors.New(errors.KsiInvalidArgumentError)
	}
	if r.errorMsg == nil {
		return "", nil
	}
	return *r.errorMsg, nil
}

// Err returns extending response error if present, otherwise nil is returned.
func (r *ExtResp) Err() error {
	if r == nil {
		return errors.New(errors.KsiInvalidArgumentError)
	}
	if r.status == nil {
		return errors.New(errors.KsiInvalidStateError).
			AppendMessage("Inconsistent extender response error.").
			AppendMessage("Missing response status.")
	}
	if err := extenderStatusToError(*r.status); err != nil {
		if r.errorMsg != nil {
			err = errors.KsiErr(err).AppendMessage(*r.errorMsg)
		}
		return err
	}
	return nil
}

// CalendarLast returns aggregation time of the newest calendar record the extender has.
// If not present, 0 is returned.
func (r *ExtResp) CalendarLast() (uint64, error) {
	if r == nil {
		return 0, errors.New(errors.KsiInvalidArgumentError)
	}
	// Calendar last is only valid if the status is 0.
	if err := r.Err(); err != nil {
		return 0, errors.KsiErr(err).AppendMessage("Extending response is invalid.")
	}

	if r.calLast == nil {
		return 0, nil
	}
	return *r.calLast, nil
}

// CalendarChain returns a calendar hash chain that connects the global root hash value of the aggregation tree of the
// round specified in the request to the published hash value specified in the request.
func (r *ExtResp) CalendarChain() (*CalendarChain, error) {
	if r == nil {
		return nil, errors.New(errors.KsiInvalidArgumentError)
	}
	// Calendar chain is only valid if the status is 0.
	if err := r.Err(); err != nil {
		return nil, errors.KsiErr(err).AppendMessage("Extending response is invalid.")
	}

	if r.calChain == nil {
		return nil, errors.New(errors.KsiInvalidStateError).
			AppendMessage("Inconsistent extending response.").
			AppendMessage("Missing calendar chain.")
	}
	return r.calChain, nil
}

// Verify verifies the extender response consistency. Returns an error in following cases:
//   - contains a service response error;
//   - the response is missing mandatory element;
//   - HMAC calculation result does not match with the response. The HMAC is calculated based on the provided hash
//     function ('alg') and the secret cryptographic key ('key').
func (r *ExtenderResp) Verify(alg hash.Algorithm, key string) error {
	if r == nil {
		return errors.New(errors.KsiInvalidArgumentError)
	}

	// Check if there are any response errors.
	if err := r.Err(); err != nil {
		return err
	}
	// Verify header existence.
	if r.header == nil {
		return errors.New(errors.KsiInvalidStateError).AppendMessage("Extender response must have a Header.")
	}
	// Verify HMAC.
	if r.mac == nil {
		return errors.New(errors.KsiInvalidStateError).AppendMessage("Extender response must have an HMAC.")
	}

	return r.verifyHmac(alg, key)
}

func (r *ExtenderResp) verifyHmac(alg hash.Algorithm, key string) error {
	if r == nil || r.mac == nil {
		return errors.New(errors.KsiInvalidArgumentError)
	}

	if (*r.mac).Algorithm() != alg {
		return errors.New(errors.KsiHmacAlgorithmMismatch).AppendMessage("Response HMAC algorithm mismatch.")
	}

	mac, err := r.calculateHmac(alg, key)
	if err != nil {
		return err
	}
	if !hash.Equal(*r.mac, mac) {
		return errors.New(errors.KsiHmacMismatch).AppendMessage("Response HMAC mismatch.")
	}

	return nil
}

// CalculateHmac returns newly calculated response HMAC.
func (r *ExtenderResp) calculateHmac(alg hash.Algorithm, key string) (hash.Imprint, error) {
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
func (r *ExtenderResp) Err() error {
	if r == nil {
		return errors.New(errors.KsiInvalidArgumentError)
	}

	// Check if the response contains reduced error PDU.
	if r.extErr != nil {
		if r.extErr.status == nil {
			return errors.New(errors.KsiInvalidStateError).
				AppendMessage("Inconsistent extender response error.").
				AppendMessage("Missing error status.")
		}
		if err := extenderStatusToError(*r.extErr.status); err != nil {
			if r.extErr.errorMsg != nil {
				err = errors.KsiErr(err).AppendMessage(*r.extErr.errorMsg)
			}
			return err
		}
	}
	// Check if extend response contains error fields.
	if r.extResp != nil {
		if err := r.extResp.Err(); err != nil {
			return err
		}
	}
	return nil
}

// extenderStatusToError converts extender status code to errors.(KsiError)
func extenderStatusToError(status uint64) error {
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
		return errors.New(errors.KsiServiceExtenderInvalidTimeRange).SetExtErrorCode(int(status))
	case 0x0105:
		return errors.New(errors.KsiServiceExtenderRequestTimeTooOld).SetExtErrorCode(int(status))
	case 0x0106:
		return errors.New(errors.KsiServiceExtenderRequestTimeTooNew).SetExtErrorCode(int(status))
	case 0x0107:
		return errors.New(errors.KsiServiceExtenderRequestTimeInFuture).SetExtErrorCode(int(status))
	case 0x0200:
		return errors.New(errors.KsiServiceInternalError).SetExtErrorCode(int(status))
	case 0x0201:
		return errors.New(errors.KsiServiceExtenderDatabaseMissing).SetExtErrorCode(int(status))
	case 0x0202:
		return errors.New(errors.KsiServiceExtenderDatabaseCorrupt).SetExtErrorCode(int(status))
	case 0x0300:
		return errors.New(errors.KsiServiceUpstreamError).SetExtErrorCode(int(status))
	case 0x0301:
		return errors.New(errors.KsiServiceUpstreamTimeout).SetExtErrorCode(int(status))
	default:
		return errors.New(errors.KsiServiceUnknownError).SetExtErrorCode(int(status))
	}
}

// Encode returns the serialized extender response.
func (r *ExtenderResp) Encode() ([]byte, error) {
	if r == nil {
		return nil, errors.New(errors.KsiInvalidArgumentError)
	}

	if r.rawTlv == nil {
		// Get template.
		pduTemplate, err := templates.Get("ExtenderResp")
		if err != nil {
			return nil, err
		}

		// Get TLV from template.
		rTlv, err := tlv.NewTlv(tlv.ConstructFromObject(r, pduTemplate))
		if err != nil {
			return nil, err
		}
		log.Debug(rTlv)
		r.rawTlv = rTlv
	}
	return r.rawTlv.Raw, nil
}

// Decode de-serializes the raw TLV into the receiver extender response.
// Note that the ExtenderResp has to be created prior to calling this method.
func (r *ExtenderResp) Decode(raw []byte) error {
	if r == nil || len(raw) == 0 {
		return errors.New(errors.KsiInvalidArgumentError)
	}

	pduTemplate, err := templates.Get("ExtenderResp")
	if err != nil {
		return err
	}

	pduTlv, err := tlv.NewTlv(tlv.ConstructFromReader(bytes.NewReader(raw)))
	if err != nil {
		return err
	}

	if !pduTemplate.IsMatchingTag(pduTlv.Tag) {
		return errors.New(errors.KsiInvalidFormatError).AppendMessage(fmt.Sprintf("Unexpected extender response PDU type: 0x%x!", pduTlv.Tag))
	}

	if err := pduTlv.ParseNested(pduTemplate); err != nil {
		return errors.KsiErr(err).AppendMessage("Unable to parse extender response!")
	}
	log.Debug(fmt.Sprint("Extending response:\n", pduTlv))

	return pduTlv.ToObject(r, pduTemplate, nil)
}

// Config returns configuration response, or nil if not present.
func (r *ExtenderResp) Config() (*Config, error) {
	if r == nil {
		return nil, errors.New(errors.KsiInvalidArgumentError)
	}
	return r.confResp, nil
}

// SetConfig sets new configuration instance into the response container.
func (r *ExtenderResp) SetConfig(c *Config) error {
	if r == nil {
		return errors.New(errors.KsiInvalidArgumentError)
	}
	r.confResp = c
	return nil
}

// Clone returns a deep copy of the origin, or nil in case of an error.
// Note that only response part of the ExtenderResp will be cloned.
func (r *ExtenderResp) Clone() (*ExtenderResp, error) {
	if r == nil {
		return nil, errors.New(errors.KsiInvalidArgumentError)
	}

	tmp := &ExtenderResp{}
	if r.extResp != nil {
		clone, err := clonePDU(r.extResp)
		if err != nil {
			return nil, err
		}
		tmp.extResp = clone.(*ExtResp)
	}
	if r.extErr != nil {
		clone, err := clonePDU(r.extErr)
		if err != nil {
			return nil, err
		}
		tmp.extErr = clone.(*Error)
	}
	if r.confResp != nil {
		clone, err := clonePDU(r.confResp)
		if err != nil {
			return nil, err
		}
		tmp.confResp = clone.(*Config)
	}
	tmp.rawTlv = r.rawTlv

	return tmp, nil
}
