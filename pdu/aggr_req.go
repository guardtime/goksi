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

	"github.com/guardtime/goksi/errors"
	"github.com/guardtime/goksi/hash"
	"github.com/guardtime/goksi/hmac"
	"github.com/guardtime/goksi/templates"
	"github.com/guardtime/goksi/tlv"
)

// AggregationReqSetting is a functional option setter for various aggregation request settings.
type AggregationReqSetting func(*aggregatorReq) error
type aggregatorReq struct {
	obj AggregatorReq
}

// NewAggregationReq constructs a new aggregation request wrapped into the AggregatorReq container.
// Optionally additional configuration settings can be added via settings parameter.
func NewAggregationReq(requestHash hash.Imprint, settings ...AggregationReqSetting) (*AggregatorReq, error) {
	if !requestHash.IsValid() {
		return nil, errors.New(errors.KsiInvalidArgumentError)
	}

	tmp := aggregatorReq{obj: AggregatorReq{
		aggrReq: &AggrReq{
			id:   newUint64(0),
			hash: &requestHash,
		},
	}}

	// Setup adjust settings with provided.
	for _, setter := range settings {
		if err := setter(&tmp); err != nil {
			return nil, errors.KsiErr(err).AppendMessage("Unable to setup aggregation request.")
		}
	}

	return &tmp.obj, nil
}

// AggrReqSetRequestLevel is aggregation requests' configuration method for setting input hash input level.
func AggrReqSetRequestLevel(level byte) AggregationReqSetting {
	return func(r *aggregatorReq) error {
		if r == nil {
			return errors.New(errors.KsiInvalidArgumentError).AppendMessage("Missing aggregator request base object.")
		}
		if level > 0 {
			r.obj.aggrReq.level = newUint64(uint64(level))
		}
		return nil
	}
}

// AggrReqSetRequestID is aggregation requests' configuration method for setting request ID.
// Should be used with care.
func AggrReqSetRequestID(id uint64) AggregationReqSetting {
	return func(r *aggregatorReq) error {
		if r == nil {
			return errors.New(errors.KsiInvalidArgumentError).AppendMessage("Missing aggregator request base object.")
		}
		*r.obj.aggrReq.id = id
		return nil
	}
}

// AggregationReq returns aggregation request component from the receiver container.
// In case the aggregation request is missing, nil is returned.
func (r *AggregatorReq) AggregationReq() (*AggrReq, error) {
	if r == nil {
		return nil, errors.New(errors.KsiInvalidArgumentError)
	}
	return r.aggrReq, nil
}

// RequestHash returns aggregation request document hash.
// In case the request hash is missing, an error is returned.
func (r *AggrReq) RequestHash() (hash.Imprint, error) {
	if r == nil {
		return nil, errors.New(errors.KsiInvalidArgumentError)
	}
	if r.hash == nil {
		return nil, errors.New(errors.KsiInvalidStateError).AppendMessage("Missing request hash.")
	}
	return *r.hash, nil
}

// RequestLevel returns aggregation request input hash level.
// In case the aggregation request is missing, 0 is returned.
func (r *AggrReq) RequestLevel() (byte, error) {
	if r == nil {
		return 0, errors.New(errors.KsiInvalidArgumentError)
	}
	if r.level == nil {
		return 0, nil
	}
	if *r.level > 0xff {
		return 0, errors.New(errors.KsiInvalidFormatError).AppendMessage("Aggregation level can't be larger than 0xff.")
	}
	return byte(*r.level), nil
}

// RequestID returns aggregation request ID.
func (r *AggrReq) RequestID() (uint64, error) {
	if r == nil {
		return 0, errors.New(errors.KsiInvalidArgumentError)
	}
	if r.id == nil {
		return 0, errors.New(errors.KsiInvalidStateError).AppendMessage("Missing request ID.")
	}
	return *r.id, nil
}

// SetHeader is request header setter.
func (r *AggregatorReq) SetHeader(hdr *Header) error {
	if r == nil {
		return errors.New(errors.KsiInvalidArgumentError)
	}
	r.header = hdr
	return nil
}

// Header returns aggregator request header.
func (r *AggregatorReq) Header() (*Header, error) {
	if r == nil {
		return nil, errors.New(errors.KsiInvalidArgumentError)
	}
	return r.header, nil
}

// HMAC returns the request message authentication code, or nil if not present.
func (r *AggregatorReq) HMAC() (hash.Imprint, error) {
	if r == nil {
		return nil, errors.New(errors.KsiInvalidArgumentError)
	}
	return *r.mac, nil
}

// UpdateHMAC updates the request HMAC. The MAC is computed over all PDU message bytes up to (but excluding)
// the hash value within the imprint in the MAC field:
//  1. the TLV header of the PDU element itself;
//  2. the complete header element (both the TLV header and the value of the element);
//  3. the complete payload elements in the order in which they appear in the PDU;
//  4. the TLV header of the MAC element;
//  5. the hash algorithm identifier part of the imprint representing the MAC value.
func (r *AggregatorReq) UpdateHMAC(alg hash.Algorithm, key string) error {
	if r == nil {
		return errors.New(errors.KsiInvalidArgumentError)
	}
	if r.header == nil {
		return errors.New(errors.KsiInvalidFormatError).AppendMessage("Missing request header.")
	}
	if !alg.Registered() {
		return errors.New(errors.KsiUnknownHashAlgorithm).
			AppendMessage("Can not calculate HMAC using an unknown hash algorithm.")
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
	tmp, err := hsr.Imprint()
	if err != nil {
		return err
	}

	r.mac = &tmp
	return nil
}

// UpdateRequestID updates aggregation request ID in case it is not set explicitly.
// Note that if the aggregator request does not contain aggregation request component, no operation is performed.
func (r *AggregatorReq) UpdateRequestID(id uint64) error {
	if r == nil {
		return errors.New(errors.KsiInvalidArgumentError)
	}

	// Update the request in case of aggregation request.
	if r.aggrReq != nil {
		if r.aggrReq.id == nil || *r.aggrReq.id == 0 {
			r.aggrReq.id = &id
		}
	}
	return nil
}

// Encode serializes the aggregator request into TLV binary representation.
func (r *AggregatorReq) Encode() ([]byte, error) {
	if r == nil {
		return nil, errors.New(errors.KsiInvalidArgumentError)
	}

	// Get template.
	pduTemplate, err := templates.Get("AggregatorReq")
	if err != nil {
		return nil, err
	}
	// Get TLV from template.
	rTlv, err := tlv.NewTlv(tlv.ConstructFromObject(r, pduTemplate))
	if err != nil {
		return nil, err
	}
	// log.Debug(rTlv)
	return rTlv.Raw, nil
}

// Clone returns a deep copy of the origin, or nil in case of an error.
// Note that only request part of the AggregatorReq will be cloned, meaning header and HMAC are ignored.
func (r *AggregatorReq) Clone() (*AggregatorReq, error) {
	if r == nil {
		return nil, errors.New(errors.KsiInvalidArgumentError)
	}

	tmp := &AggregatorReq{}
	if r.aggrReq != nil {
		clone, err := clonePDU(r.aggrReq)
		if err != nil {
			return nil, err
		}
		tmp.aggrReq = clone.(*AggrReq)
	}
	if r.confReq != nil {
		clone, err := clonePDU(r.confReq)
		if err != nil {
			return nil, err
		}
		tmp.confReq = clone.(*Config)
	}
	if r.aggrAckReq != nil {
		clone, err := clonePDU(r.aggrAckReq)
		if err != nil {
			return nil, err
		}
		tmp.aggrAckReq = clone.(*AggrAck)
	}

	return tmp, nil
}

// NewAggregatorConfigReq constructs a new aggregator configuration request.
func NewAggregatorConfigReq() (*AggregatorReq, error) {
	return &AggregatorReq{
		// Initialize the conf request with empty instance.
		confReq: &Config{},
	}, nil
}

// Config returns request config instance.
// In case the configuration is not part of the request, nil is returned.
func (r *AggregatorReq) Config() (*Config, error) {
	if r == nil {
		return nil, errors.New(errors.KsiInvalidArgumentError)
	}
	return r.confReq, nil
}

// WithContext returns the original r with its context changed to ctx.
// In case of an error, nil is returned.
func (r *AggregatorReq) WithContext(ctx context.Context) *AggregatorReq {
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
func (r *AggregatorReq) Context() context.Context {
	if r.ctx != nil {
		return r.ctx
	}
	return context.Background()
}
