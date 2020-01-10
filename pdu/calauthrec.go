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

// PublicationData returns the published data, or error if not present.
func (c *CalendarAuthRec) PublicationData() (*PublicationData, error) {
	if c == nil {
		return nil, errors.New(errors.KsiInvalidArgumentError)
	}
	if c.pubData == nil {
		return nil, errors.New(errors.KsiInvalidStateError).AppendMessage("Publication data is missing.")
	}
	return c.pubData, nil
}

// SignatureData returns the signature data of the published data, or error if not present.
func (c *CalendarAuthRec) SignatureData() (*SignatureData, error) {
	if c == nil {
		return nil, errors.New(errors.KsiInvalidArgumentError)
	}
	if c.sigData == nil {
		return nil, errors.New(errors.KsiInvalidStateError).AppendMessage("Signature data is missing.")
	}
	return c.sigData, nil
}
