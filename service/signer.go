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
	"fmt"

	"github.com/guardtime/goksi/errors"
	"github.com/guardtime/goksi/hash"
	"github.com/guardtime/goksi/pdu"
	"github.com/guardtime/goksi/signature"
)

// Signer is the abstraction of the Aggregator basicService.
// An instance must not be shared between goroutines.
type Signer struct {
	service
}

// NewSigner creates a new signer instance.
func NewSigner(opts ...Option) (*Signer, error) {
	if len(opts) == 0 {
		return nil, errors.New(errors.KsiInvalidArgumentError)
	}

	srv, err := newService(opts...)
	if err != nil {
		return nil, err
	}

	return &Signer{
		service: srv,
	}, nil
}

// Send sends the Aggregator request and returns the response.
// For more information see pdu.(AggregatorReq) and pdu.(AggregatorResp)
func (s *Signer) Send(req *pdu.AggregatorReq) (*pdu.AggregatorResp, error) {
	if s == nil {
		return nil, errors.New(errors.KsiInvalidArgumentError)
	}

	if s.service == nil {
		return nil, errors.New(errors.KsiInvalidStateError)
	}

	srvReq, err := newRequest(aggregatorRequest(req))
	if err != nil {
		return nil, err
	}

	srvResp, err := s.send(srvReq)
	if err != nil {
		return nil, err
	}

	return srvResp.aggregatorResp()

}

// Sign composes a signing request message and returns the resulting signature.
// Request hash is the document hash imprint (see hash.(DataHasher)).
//
// Further optional setting can be applied via the opt parameter.
func (s *Signer) Sign(hash hash.Imprint, opt ...SignOption) (*signature.Signature, error) {
	if s == nil {
		return nil, errors.New(errors.KsiInvalidArgumentError)
	}

	// Resolve signing options.
	opts := signOptions{}
	for _, optResolver := range opt {
		if optResolver == nil {
			return nil, errors.New(errors.KsiInvalidArgumentError).AppendMessage("Provided option is nil.")
		}
		if err := optResolver(&opts); err != nil {
			return nil, errors.KsiErr(err).AppendMessage("Failed to resolve sign option.")
		}
	}

	sig, err := s.signWithOptions(hash, &opts)
	return sig, err
}

// SignOption is a signing option for extending the request.
type SignOption func(*signOptions) error

type signOptions struct {
	level     byte
	policy    signature.Policy
	verCtxOpt []signature.VerCtxOption
	context   context.Context
}

// SignOptionLevel Request level is the value of the aggregation tree node from which the request hash comes.
// Can be omitted in case the request hash is a direct hash of client data (see treebuilder.(Tree).Aggregate()).
func SignOptionLevel(l byte) SignOption {
	return func(o *signOptions) error {
		if o == nil {
			return errors.New(errors.KsiInvalidArgumentError).AppendMessage("Missing sign options object.")
		}
		o.level = l
		return nil
	}
}

// SignOptionVerificationPolicy enables the created signature based on the provided verification policy.
// The default is signature.InternalVerificationPolicy, which should be sufficient in most use cases.
func SignOptionVerificationPolicy(p signature.Policy) SignOption {
	return func(o *signOptions) error {
		if o == nil {
			return errors.New(errors.KsiInvalidArgumentError).AppendMessage("Missing sign options object.")
		}
		if p == nil {
			return errors.New(errors.KsiInvalidArgumentError).AppendMessage("Missing verification policy.")
		}
		o.policy = p
		return nil
	}
}

// SignOptionVerificationOptions sets the verification context options.
func SignOptionVerificationOptions(opts ...signature.VerCtxOption) SignOption {
	return func(o *signOptions) error {
		if o == nil {
			return errors.New(errors.KsiInvalidArgumentError).AppendMessage("Missing sign options object.")
		}
		if len(opts) == 0 {
			return errors.New(errors.KsiInvalidArgumentError).AppendMessage("Missing verification options.")
		}
		for i, o := range opts {
			if o == nil {
				return errors.New(errors.KsiInvalidArgumentError).
					AppendMessage(fmt.Sprintf("Verification option at %d is nil.", i))
			}
		}

		o.verCtxOpt = opts
		return nil
	}
}

// SignOptionWithContext sets a context for the request.
func SignOptionWithContext(c context.Context) SignOption {
	return func(o *signOptions) error {
		if o == nil {
			return errors.New(errors.KsiInvalidArgumentError).AppendMessage("Missing sign options object.")
		}
		if c == nil {
			return errors.New(errors.KsiInvalidArgumentError).AppendMessage("Missing context.")
		}
		o.context = c
		return nil
	}
}

// signWithPolicy performs signing of the document hash and additional verification based on the given policy.
// If the policy is nil, only signature internal consistency is verified.
// Returns KSI signature for the provided document hash and verification result, in case a policy is given.
func (s *Signer) signWithOptions(hash hash.Imprint, opts *signOptions) (*signature.Signature, error) {
	if s == nil {
		return nil, errors.New(errors.KsiInvalidArgumentError)
	}
	if opts == nil {
		return nil, errors.New(errors.KsiInvalidArgumentError).AppendMessage("Provided option is nil.")
	}

	req, err := pdu.NewAggregationReq(hash,
		pdu.AggrReqSetRequestLevel(opts.level),
	)
	if err != nil {
		return nil, err
	}

	resp, err := s.Send(req.WithContext(opts.context))
	if err != nil {
		return nil, err
	}

	if opts.policy != nil {
		sig, err := signature.New(signature.BuildNoVerify(signature.BuildFromAggregationResp(resp, opts.level)))
		if err != nil {
			return nil, err
		}

		// Append the document hash and input level verification options.
		opts.verCtxOpt = append(opts.verCtxOpt, signature.VerCtxOptDocumentHash(hash))
		opts.verCtxOpt = append(opts.verCtxOpt, signature.VerCtxOptInputHashLevel(opts.level))
		// Verify signature.
		if err = sig.Verify(opts.policy, opts.verCtxOpt...); err != nil {
			return nil, err
		}
		return sig, nil
	}
	return signature.New(signature.BuildFromAggregationResp(resp, opts.level))
}

func verifyAggrRequestId(req *pdu.AggregatorReq, resp *pdu.AggregatorResp) error {
	if req == nil || resp == nil {
		return errors.New(errors.KsiInvalidArgumentError)
	}

	aggrReq, err := req.AggregationReq()
	if err != nil {
		return err
	}
	aggrResp, err := resp.AggregationResp()
	if err != nil {
		return err
	}

	// Check if it is an aggregation request.
	if aggrReq == nil && aggrResp == nil {
		return nil
	}

	reqId, err := aggrReq.RequestID()
	if err != nil {
		return errors.KsiErr(err).AppendMessage("Failed to extract aggregation request ID.")
	}
	respId, err := aggrResp.RequestID()
	if err != nil {
		return errors.KsiErr(err).AppendMessage("Failed to extract aggregation response ID.")
	}

	if reqId != respId {
		return errors.New(errors.KsiRequestIdMismatch)
	}
	return nil
}

// Config requests configuration from server.
// Returns the received configuration.
func (s *Signer) Config() (*pdu.Config, error) {
	if s == nil || s.service == nil {
		return nil, errors.New(errors.KsiInvalidArgumentError)
	}

	req, err := pdu.NewAggregatorConfigReq()
	if err != nil {
		return nil, err
	}

	resp, err := s.Send(req)
	if err != nil {
		return nil, err
	}
	return resp.Config()
}
