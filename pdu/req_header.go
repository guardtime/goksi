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
	"github.com/guardtime/goksi/errors"
)

// RequestHeaderFunc is request header manipulation callback which is executed on every request prior to serializing
// and submitting the request. The callback should be used when additional data (i.e. session ID and message ID) should
// be added.
type RequestHeaderFunc func(*Header) error

// NewHeader returns PDU Header instance.
// Use parameter 'f' for applying optional Header values.
func NewHeader(loginID string, f RequestHeaderFunc) (*Header, error) {
	tmp := &Header{
		loginID: &loginID,
	}

	if f != nil {
		if err := f(tmp); err != nil {
			return nil, errors.KsiErr(err).AppendMessage("Request header callback returned error.")
		}
	}

	return tmp, nil
}

// SetInstID is setter for the header instance ID.
func (h *Header) SetInstID(id uint64) error {
	if h == nil {
		return errors.New(errors.KsiInvalidArgumentError)
	}
	h.instID = &id
	return nil
}

// SetMsgID setter to for the header message ID.
func (h *Header) SetMsgID(id uint64) error {
	if h == nil {
		return errors.New(errors.KsiInvalidArgumentError)
	}
	h.msgID = &id
	return nil
}

// LoginID returns the identifier of the client host for MAC key lookup.
// If not present, an error is returned.
func (h *Header) LoginID() (string, error) {
	if h == nil {
		return "", errors.New(errors.KsiInvalidArgumentError)
	}
	if h.loginID == nil {
		return "", errors.New(errors.KsiInvalidStateError).AppendMessage("Missing header login id.")
	}
	return *h.loginID, nil
}

// InstanceID returns a number identifying invocation of the sender.
// If not present, 0 is returned.
func (h *Header) InstanceID() (uint64, error) {
	if h == nil {
		return 0, errors.New(errors.KsiInvalidArgumentError)
	}
	if h.instID == nil {
		return 0, nil
	}
	return *h.instID, nil
}

// MessageID returns message number for duplicate filtering.
// If not present, 0 is returned.
func (h *Header) MessageID() (uint64, error) {
	if h == nil {
		return 0, errors.New(errors.KsiInvalidArgumentError)
	}
	if h.msgID == nil {
		return 0, nil
	}
	return *h.msgID, nil
}
