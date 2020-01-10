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

package service

import (
	"context"

	"github.com/guardtime/goksi/errors"
	"github.com/guardtime/goksi/hash"
	"github.com/guardtime/goksi/pdu"
)

// request is a wrapper for service requests.
// See pdu.(AggregatorReq), pdu.(ExtenderReq).
type request struct {
	// TODO! maybe use a common interface{} member
	aggrReq *pdu.AggregatorReq
	extReq  *pdu.ExtenderReq

	setHeader       func(*pdu.Header) error
	encode          func() ([]byte, error)
	updateRequestID func(uint64) error
	updateHMAC      func(hash.Algorithm, string) error
	config          func() (*pdu.Config, error)
	context         func() context.Context

	clone func() (*request, error)

	respType func() responseType
}

// requestType is a concrete wrapper implementation.
type requestType func(*request) error

func newRequest(from requestType) (*request, error) {
	tmp := &request{}
	if err := from(tmp); err != nil {
		return nil, err
	}
	return tmp, nil
}

// aggregatorRequest wraps the pdu.(AggregatorReq).
func aggregatorRequest(req *pdu.AggregatorReq) requestType {
	return func(r *request) error {
		if r == nil || req == nil {
			return errors.New(errors.KsiInvalidArgumentError)
		}
		r.aggrReq = req

		r.setHeader = func(h *pdu.Header) error { return r.aggrReq.SetHeader(h) }
		r.encode = func() ([]byte, error) { return r.aggrReq.Encode() }
		r.updateRequestID = func(id uint64) error { return r.aggrReq.UpdateRequestID(id) }
		r.updateHMAC = func(alg hash.Algorithm, key string) error { return r.aggrReq.UpdateHMAC(alg, key) }
		r.config = func() (*pdu.Config, error) { return r.aggrReq.Config() }
		r.context = func() context.Context { return r.aggrReq.Context() }

		r.clone = func() (*request, error) {
			reqClone, err := r.aggrReq.Clone()
			if err != nil {
				return nil, err
			}
			return newRequest(aggregatorRequest(reqClone))
		}

		r.respType = aggregatorResponse
		return nil
	}
}

// extenderRequest wraps the pdu.(ExtenderReq).
func extenderRequest(req *pdu.ExtenderReq) requestType {
	return func(r *request) error {
		if r == nil || req == nil {
			return errors.New(errors.KsiInvalidArgumentError)
		}
		r.extReq = req

		r.setHeader = func(h *pdu.Header) error { return r.extReq.SetHeader(h) }
		r.encode = func() ([]byte, error) { return r.extReq.Encode() }
		r.updateRequestID = func(id uint64) error { return r.extReq.UpdateRequestID(id) }
		r.updateHMAC = func(alg hash.Algorithm, key string) error { return r.extReq.UpdateHMAC(alg, key) }
		r.config = func() (*pdu.Config, error) { return r.extReq.Config() }
		r.context = func() context.Context { return r.extReq.Context() }

		r.clone = func() (*request, error) {
			reqClone, err := r.extReq.Clone()
			if err != nil {
				return nil, err
			}
			return newRequest(extenderRequest(reqClone))
		}

		r.respType = extenderResponse
		return nil
	}
}
