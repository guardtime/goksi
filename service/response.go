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
	"github.com/guardtime/goksi/errors"
	"github.com/guardtime/goksi/hash"
	"github.com/guardtime/goksi/pdu"
)

// response is a wrapper for service responses.
// See pdu.(AggregatorResp), pdu.(ExtenderResp).
type response struct {
	// TODO! maybe use a common interface{} member
	aggrResp *pdu.AggregatorResp
	extResp  *pdu.ExtenderResp

	decode      func([]byte) error
	verify      func(hash.Algorithm, string) error
	verifyReqId func(req *request) error
	config      func() (*pdu.Config, error)
	setConfig   func(*pdu.Config) error
}

// responseType is a concrete wrapper implementation.
type responseType func(*response) error

func newResponse(from responseType) (*response, error) {
	tmp := &response{}
	if err := from(tmp); err != nil {
		return nil, err
	}
	return tmp, nil
}

// aggregatorResponse wraps the pdu.(AggregatorResp).
func aggregatorResponse() responseType {
	return func(r *response) error {
		if r == nil {
			return errors.New(errors.KsiInvalidArgumentError)
		}
		r.aggrResp = &pdu.AggregatorResp{}

		r.decode = func(b []byte) error { return r.aggrResp.Decode(b) }
		r.verify = func(a hash.Algorithm, k string) error { return r.aggrResp.Verify(a, k) }
		r.verifyReqId = func(req *request) error { return verifyAggrRequestId(req.aggrReq, r.aggrResp) }
		r.config = func() (*pdu.Config, error) { return r.aggrResp.Config() }
		r.setConfig = func(c *pdu.Config) error { return r.aggrResp.SetConfig(c) }
		return nil
	}
}

// extenderResponse wraps the pdu.(ExtenderResp).
func extenderResponse() responseType {
	return func(r *response) error {
		if r == nil {
			return errors.New(errors.KsiInvalidArgumentError)
		}
		r.extResp = &pdu.ExtenderResp{}

		r.decode = func(b []byte) error { return r.extResp.Decode(b) }
		r.verify = func(a hash.Algorithm, k string) error { return r.extResp.Verify(a, k) }
		r.verifyReqId = func(req *request) error { return verifyExtRequestId(req.extReq, r.extResp) }
		r.config = func() (*pdu.Config, error) { return r.extResp.Config() }
		r.setConfig = func(c *pdu.Config) error { return r.extResp.SetConfig(c) }
		return nil
	}
}

// aggregatorResp returns Aggregator response.
func (r *response) aggregatorResp() (*pdu.AggregatorResp, error) {
	if r == nil {
		return nil, errors.New(errors.KsiInvalidArgumentError)
	}
	return r.aggrResp, nil
}

// extenderResp returns Extender response.
func (r *response) extenderResp() (*pdu.ExtenderResp, error) {
	if r == nil {
		return nil, errors.New(errors.KsiInvalidArgumentError)
	}
	return r.extResp, nil
}
