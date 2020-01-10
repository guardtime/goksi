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
	"time"

	"github.com/guardtime/goksi/errors"
	"github.com/guardtime/goksi/log"
	"github.com/guardtime/goksi/pdu"
	"github.com/guardtime/goksi/publications"
	"github.com/guardtime/goksi/signature"
)

// Extender is the abstraction of the extender service.
type Extender struct {
	service

	// Publications file handler.
	pubFileHandler *publications.FileHandler
}

// NewExtender creates a new extender instance.
// Note that the publications file handler parameter h is optional. In case it is not set, the user will not be able to
// extend signatures to certain publications, only to the head of the calendar.
func NewExtender(h *publications.FileHandler, opts ...Option) (*Extender, error) {
	if len(opts) == 0 {
		return nil, errors.New(errors.KsiInvalidArgumentError)
	}

	srv, err := newService(opts...)
	if err != nil {
		return nil, err
	}

	return &Extender{
		service:        srv,
		pubFileHandler: h,
	}, nil
}

// Send sends the Extender request and returns the response.
// For more information see pdu.(ExtenderReq) and pdu.(ExtenderResp).
func (e *Extender) Send(req *pdu.ExtenderReq) (*pdu.ExtenderResp, error) {
	if e == nil {
		return nil, errors.New(errors.KsiInvalidArgumentError)
	}

	if e.service == nil {
		return nil, errors.New(errors.KsiInvalidStateError)
	}

	srvReq, err := newRequest(extenderRequest(req))
	if err != nil {
		return nil, err
	}

	srvResp, err := e.send(srvReq)
	if err != nil {
		return nil, err
	}

	return srvResp.extenderResp()
}

// Extend extends the signature to a certain time depending on the configuration:
//  - if the to-time is set (see ExtendOptionToTime() option), the signature
//    is extended to the exact time;
//  - if the to-time is not provided or is set to the zero time representation
//    (see (Time).IsZero()), the signature is extended to the head of the
//    calendar database;
//  - if the time is not set but the receiver Extender has a publications
//    file handler configured (see publications.(FileHandler)), the signature
//    is extended to the nearest publication found in the attached
//    publications file. Note that this is the recommended approach, as a
//    publication record will be attached to the resulting signature. A
//    publication record is to be considered as the strongest trust anchor
//    a signature can have.
//
// This function requires access to a working KSI Extender, or it will fail with network error.
func (e *Extender) Extend(sig *signature.Signature, opt ...ExtendOption) (*signature.Signature, error) {
	if e == nil || sig == nil {
		return nil, errors.New(errors.KsiInvalidArgumentError)
	}

	// Resolve extending options.
	opts := extendOptions{}
	for _, optResolver := range opt {
		if optResolver == nil {
			return nil, errors.New(errors.KsiInvalidArgumentError).AppendMessage("Provided option is nil.")
		}
		if err := optResolver(&opts); err != nil {
			return nil, errors.KsiErr(err).AppendMessage("Failed to resolve extend option.")
		}
	}

	signTime, err := sig.SigningTime()
	if err != nil {
		return nil, err
	}

	var (
		pubRec *pdu.PublicationRec
	)
	// If the to time was not provided, get it from a suitable publications.
	if opts.pubTime == nil {
		// Check if the publications file handler is configured.
		if e.pubFileHandler != nil {
			pubFile, err := e.pubFileHandler.ReceiveFile()
			if err != nil {
				return nil, err
			}
			if err := e.pubFileHandler.Verify(pubFile); err != nil {
				return nil, err
			}
			pubRec, err = pubFile.PublicationRec(publications.PubRecSearchNearest(signTime))
			if err != nil {
				return nil, err
			}
			if pubRec == nil {
				return nil, errors.New(errors.KsiExtendNoSuitablePublication)
			}

			pubData, err := pubRec.PublicationData()
			if err != nil {
				return nil, err
			}
			pubTime, err := pubData.PublicationTime()
			if err != nil {
				return nil, err
			}
			opts.pubTime = &pubTime
		}
	}

	resp, err := e.sendExtendingRequest(signTime, &opts)
	if err != nil {
		return nil, err
	}
	return signature.New(signature.BuildFromExtendingResp(resp, sig, pubRec))
}

// SignOption is a signing option for extending the request.
type (
	ExtendOption  func(*extendOptions) error
	extendOptions struct {
		pubTime *time.Time
		context context.Context
	}
)

// ExtendOptionToTime sets the time to which the signature should be extended to.
// If the time represents the zero time instant (see (Time).IsZero()), the signature is extended to the head of the
// calendar database.
// Note that using this option will leave the resulting signature without a publication record.
func ExtendOptionToTime(to time.Time) ExtendOption {
	return func(o *extendOptions) error {
		if o == nil {
			return errors.New(errors.KsiInvalidArgumentError).AppendMessage("Missing sign options object.")
		}
		o.pubTime = &to
		return nil
	}
}

// ExtendOptionWithContext sets a context for the request.
func ExtendOptionWithContext(c context.Context) ExtendOption {
	return func(o *extendOptions) error {
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

func (e *Extender) sendExtendingRequest(from time.Time, opts *extendOptions) (*pdu.ExtenderResp, error) {
	if e == nil {
		return nil, errors.New(errors.KsiInvalidArgumentError)
	}

	var pubTime time.Time
	if opts.pubTime != nil {
		pubTime = *opts.pubTime
	}
	log.Debug("Extending signature to: ", pubTime)
	req, err := pdu.NewExtendingReq(from, pdu.ExtReqSetPubTime(pubTime))
	if err != nil {
		return nil, err
	}

	resp, err := e.Send(req.WithContext(opts.context))
	if err != nil {
		return nil, err
	}

	return resp, nil
}

func verifyExtRequestId(req *pdu.ExtenderReq, resp *pdu.ExtenderResp) error {
	if req == nil || resp == nil {
		return errors.New(errors.KsiInvalidArgumentError)
	}

	extReq, err := req.ExtendingReq()
	if err != nil {
		return err
	}
	extResp, err := resp.ExtendingResp()
	if err != nil {
		return err
	}

	// Check if it is an aggregation request.
	if extReq == nil && extResp == nil {
		return nil
	}

	reqId, err := extReq.RequestID()
	if err != nil {
		return err
	}
	respId, err := extResp.RequestID()
	if err != nil {
		return err
	}

	if reqId != respId {
		return errors.New(errors.KsiRequestIdMismatch)
	}
	return nil
}

// Config requests configuration from server.
// Returns the received configuration.
func (e *Extender) Config() (*pdu.Config, error) {
	if e == nil {
		return nil, errors.New(errors.KsiInvalidArgumentError)
	}

	req, err := pdu.NewExtenderConfigReq()
	if err != nil {
		return nil, err
	}

	resp, err := e.Send(req)
	if err != nil {
		return nil, err
	}
	return resp.Config()
}

// ReceiveCalendar implements verify.(CalendarProvider) interface.
func (e *Extender) ReceiveCalendar(from, to time.Time) (*pdu.CalendarChain, error) {
	if e == nil || from.IsZero() {
		return nil, errors.New(errors.KsiInvalidArgumentError)
	}

	log.Debug("Receiving calendar from: ", from, " to: ", to)
	resp, err := e.sendExtendingRequest(from, &extendOptions{pubTime: &to})
	if err != nil {
		return nil, err
	}
	extResp, err := resp.ExtendingResp()
	if err != nil {
		return nil, err
	}

	return extResp.CalendarChain()
}
