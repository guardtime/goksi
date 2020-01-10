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
	"context"
	"fmt"
	"time"

	"github.com/guardtime/goksi/errors"
	"github.com/guardtime/goksi/hash"
	"github.com/guardtime/goksi/hmac"
	"github.com/guardtime/goksi/log"
	"github.com/guardtime/goksi/templates"
	"github.com/guardtime/goksi/tlv"
)

// ExtendingReqSetting is functional option setter for extending request.
type (
	ExtendingReqSetting func(*extenderReq) error

	extenderReq struct {
		obj ExtenderReq
	}
)

// NewExtendingReq constructs a new extending request.
// Start parameter is the time of the aggregation round from which the calendar hash chain should start.
// Optionally additional configuration settings can be added via settings parameter.
func NewExtendingReq(start time.Time, settings ...ExtendingReqSetting) (*ExtenderReq, error) {

	tmp := extenderReq{obj: ExtenderReq{
		extReq: &ExtReq{
			id:       newUint64(0),
			aggrTime: newUint64(uint64(start.Unix())),
		},
	}}

	// Setup adjust settings with provided.
	for _, setter := range settings {
		if err := setter(&tmp); err != nil {
			return nil, errors.KsiErr(err).AppendMessage("Unable to setup extender request.")
		}
	}

	if tmp.obj.extReq.pubTime != nil {
		if *tmp.obj.extReq.pubTime < *tmp.obj.extReq.aggrTime {
			err := errors.New(errors.KsiServiceExtenderInvalidTimeRange).
				AppendMessage("The request asked for a hash chain going backwards in time.").
				AppendMessage(fmt.Sprintf("Aggregation time %v is more recent than publication time %v.", *tmp.obj.extReq.aggrTime, *tmp.obj.extReq.pubTime))

			return nil, err
		}
	}

	return &tmp.obj, nil
}

// ExtReqSetPubTime sets the time of the calendar root hash value to which the aggregation hash value should
// be connected by the calendar hash chain. Its absence means a request for a calendar hash chain from
// aggregation time to the most recent calendar record the server has (the 'calendar last time' field in the
// response and configuration messages).
func ExtReqSetPubTime(end time.Time) ExtendingReqSetting {
	return func(r *extenderReq) error {
		if r == nil || r.obj.extReq == nil {
			return errors.New(errors.KsiInvalidArgumentError).AppendMessage("Missing extending request base object.")
		}
		if !end.IsZero() {
			r.obj.extReq.pubTime = newUint64(uint64(end.Unix()))
		}
		return nil
	}
}

// ExtReqSetRequestID is aggregation request configuration method for setting request ID, a number used to establish
// a relation between the request and the corresponding responses.
// Should be used with care.
func ExtReqSetRequestID(id uint64) ExtendingReqSetting {
	return func(r *extenderReq) error {
		if r == nil || r.obj.extReq == nil {
			return errors.New(errors.KsiInvalidArgumentError).AppendMessage("Missing extending request base object.")
		}
		*r.obj.extReq.id = id
		return nil
	}
}

// SetHeader is request header setter.
func (r *ExtenderReq) SetHeader(hdr *Header) error {
	if r == nil {
		return errors.New(errors.KsiInvalidArgumentError)
	}
	r.header = hdr
	return nil
}

// UpdateHmac updates the request HMAC. The MAC is computed over all PDU message bytes up to (but excluding)
// the hash value within the imprint in the MAC field:
//  1. the TLV header of the PDU element itself;
//  2. the complete header element (both the TLV header and the value of the element);
//  3. the complete payload elements in the order in which they appear in the PDU;
//  4. the TLV header of the MAC element;
//  5. the hash algorithm identifier part of the imprint representing the MAC value.
func (r *ExtenderReq) UpdateHMAC(alg hash.Algorithm, key string) error {
	if r == nil {
		return errors.New(errors.KsiInvalidArgumentError)
	}
	if r.header == nil {
		return errors.New(errors.KsiInvalidFormatError).AppendMessage("Missing request header.")
	}
	if !alg.Registered() {
		return errors.New(errors.KsiUnknownHashAlgorithm).AppendMessage("Can not calculate HMAC using an unknown hash algorithm.")
	}
	if !alg.Trusted() {
		return errors.New(errors.KsiInvalidStateError).AppendMessage("Algorithm algorithm is not trusted.")
	}

	// Initialize the HMAC with a null digest.
	r.mac = newImprint(alg.ZeroImprint())

	raw, err := r.Encode()
	if err != nil {
		return err
	}

	hsr, err := hmac.New(alg, []byte(key))
	if err != nil {
		return err
	}
	if _, err := hsr.Write(raw[:(len(raw) - alg.Size())]); err != nil {
		return err
	}
	mac, err := hsr.Imprint()
	if err != nil {
		return err
	}

	r.mac = &mac
	return nil
}

// UpdateRequestID updates extending request ID in case it is not set explicitly.
func (r *ExtenderReq) UpdateRequestID(id uint64) error {
	if r == nil {
		return errors.New(errors.KsiInvalidArgumentError)
	}

	// Update the request in case of aggregation request.
	if r.extReq != nil {
		if r.extReq.id == nil || *r.extReq.id == 0 {
			r.extReq.id = &id
		}
	}
	return nil
}

// Encode serializes the extender request into binary TLV.
func (r *ExtenderReq) Encode() ([]byte, error) {
	if r == nil {
		return nil, errors.New(errors.KsiInvalidArgumentError)
	}

	pduTemplate, err := templates.Get("ExtenderReq")
	if err != nil {
		return nil, err
	}
	// Get TLV from template.
	rTlv, err := tlv.NewTlv(tlv.ConstructFromObject(r, pduTemplate))
	if err != nil {
		return nil, err
	}
	log.Debug(rTlv)
	return rTlv.Raw, nil
}

// Clone returns a deep copy of the origin, or nil in case of an error.
// Note that only request part of the ExtenderReq will be cloned, meaning header and HMAC are ignored.
func (r *ExtenderReq) Clone() (*ExtenderReq, error) {
	if r == nil {
		return nil, errors.New(errors.KsiInvalidArgumentError)
	}

	tmp := &ExtenderReq{}
	if r.extReq != nil {
		clone, err := clonePDU(r.extReq)
		if err != nil {
			return nil, err
		}
		tmp.extReq = clone.(*ExtReq)
	}
	if r.confReq != nil {
		clone, err := clonePDU(r.confReq)
		if err != nil {
			return nil, err
		}
		tmp.confReq = clone.(*Config)
	}

	return tmp, nil
}

// NewExtenderConfigReq constructs a new aggregator configuration request.
func NewExtenderConfigReq() (*ExtenderReq, error) {
	return &ExtenderReq{
		// Initialize the conf request with empty instance.
		confReq: &Config{},
	}, nil
}

// Config returns request config instance.
// Note that in case the configuration is not part of the request, nil is returned.
func (r *ExtenderReq) Config() (*Config, error) {
	if r == nil {
		return nil, errors.New(errors.KsiInvalidArgumentError)
	}
	return r.confReq, nil
}

// ExtendingReq returns extending request component from the receiver container.
// In case the extending request is missing, nil is returned.
func (r *ExtenderReq) ExtendingReq() (*ExtReq, error) {
	if r == nil {
		return nil, errors.New(errors.KsiInvalidArgumentError)
	}
	return r.extReq, nil
}

// AggregationTime returns the time of the aggregation round from which the calendar hash chain should start.
func (r *ExtReq) AggregationTime() (time.Time, error) {
	if r == nil {
		return time.Time{}, errors.New(errors.KsiInvalidArgumentError)
	}
	if r.aggrTime == nil {
		return time.Time{}, errors.New(errors.KsiInvalidStateError).AppendMessage("Inconsistent extending request.")
	}
	return time.Unix(int64(*r.aggrTime), 0), nil
}

// PublicationTime returns the time of the calendar root hash value to which the aggregation hash value should
// be connected by the calendar hash chain.
// If not present, 0 is returned (see time.(Time).IsZero()).
func (r *ExtReq) PublicationTime() (time.Time, error) {
	if r == nil {
		return time.Time{}, errors.New(errors.KsiInvalidArgumentError)
	}
	if r.pubTime == nil {
		return time.Time{}, nil
	}
	return time.Unix(int64(*r.pubTime), 0), nil
}

// RequestID returns the request identifier.
func (r *ExtReq) RequestID() (uint64, error) {
	if r == nil {
		return 0, errors.New(errors.KsiInvalidArgumentError)
	}
	if r.id == nil {
		return 0, nil
	}
	return *r.id, nil
}

// HMAC returns the request message authentication code, or nil if not present.
func (r *ExtenderReq) HMAC() (hash.Imprint, error) {
	if r == nil {
		return nil, errors.New(errors.KsiInvalidArgumentError)
	}
	return *r.mac, nil
}

// Header returns the request message header, or nil if not present.
func (r *ExtenderReq) Header() (*Header, error) {
	if r == nil {
		return nil, errors.New(errors.KsiInvalidArgumentError)
	}
	return r.header, nil
}

// WithContext returns the original r with its context changed to ctx.
// In case of an error, nil is returned.
func (r *ExtenderReq) WithContext(ctx context.Context) *ExtenderReq {
	if r == nil {
		return nil
	}

	switch {
	case ctx == nil:
		r.ctx = context.Background()
	default:
		r.ctx = ctx
	}
	return r
}

// Context returns the request's context.
//
// The returned context is always non-nil, it defaults to the background context.
func (r *ExtenderReq) Context() context.Context {
	if r.ctx != nil {
		return r.ctx
	}
	return context.Background()
}
