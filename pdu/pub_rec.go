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

// NewPublicationRec is the publication record constructor.
//
// A publication record represents the information related to a published hash value, possibly including the
// publication reference. Publication may also point (via a URI) to a hash database that is in electronic form and
// may contain several published hash values.
func NewPublicationRec(pubData *PublicationData, optionals ...PublicationRecOptional) (*PublicationRec, error) {
	if pubData == nil {
		return nil, errors.New(errors.KsiInvalidArgumentError)
	}

	tmp := publicationRec{obj: PublicationRec{
		pubData: pubData,
	}}
	for _, setter := range optionals {
		if setter == nil {
			return nil, errors.New(errors.KsiInvalidArgumentError).AppendMessage("Provided option is nil.")
		}
		if err := setter(&tmp); err != nil {
			return nil, errors.KsiErr(err).AppendMessage("Unable to initialize publication record.")
		}
	}
	return &tmp.obj, nil
}

// PublicationRecOptional is an optional functional parameter to be set while publication data construction.
type PublicationRecOptional func(r *publicationRec) error
type publicationRec struct {
	obj PublicationRec
}

// PubRecOptPublicationRef sets an UTF-8 string that contains the bibliographic reference to a media outlet where the
// publication appeared.
func PubRecOptPublicationRef(pubRef []string) PublicationRecOptional {
	return func(r *publicationRec) error {
		if len(pubRef) == 0 {
			return errors.New(errors.KsiInvalidArgumentError)
		}
		if r == nil {
			return errors.New(errors.KsiInvalidArgumentError).AppendMessage("Missing publication record base object.")
		}

		r.obj.pubRef = &pubRef
		return nil
	}
}

// PubRecOptPublicationRepURI sets the URI of a publication's repository.
func PubRecOptPublicationRepURI(pubRepURI []string) PublicationRecOptional {
	return func(r *publicationRec) error {
		if len(pubRepURI) == 0 {
			return errors.New(errors.KsiInvalidArgumentError)
		}
		if r == nil {
			return errors.New(errors.KsiInvalidArgumentError).AppendMessage("Missing publication record base object.")
		}

		r.obj.pubRepURI = &pubRepURI
		return nil
	}
}

// PublicationData returns the published data.
func (p *PublicationRec) PublicationData() (*PublicationData, error) {
	if p == nil {
		return nil, errors.New(errors.KsiInvalidArgumentError)
	}
	if p.pubData == nil {
		return nil, errors.New(errors.KsiInvalidStateError).AppendMessage("Inconsistent pub data.")
	}
	return p.pubData, nil
}

// PublicationRef returns an UTF-8 string that contains the bibliographic reference to a media outlet where the
// publication appeared.
func (p *PublicationRec) PublicationRef() ([]string, error) {
	if p == nil {
		return nil, errors.New(errors.KsiInvalidArgumentError)
	}
	if p.pubRef == nil {
		return nil, nil
	}

	return *p.pubRef, nil
}

// PublicationRepURI returns URI of a publication's repository (publication file).
func (p *PublicationRec) PublicationRepURI() ([]string, error) {
	if p == nil {
		return nil, errors.New(errors.KsiInvalidArgumentError)
	}
	if p.pubRepURI == nil {
		return nil, nil
	}
	return *p.pubRepURI, nil
}

// Clone returns a deep copy of the receiver publication record.
func (p *PublicationRec) Clone() (*PublicationRec, error) {
	if p == nil {
		return nil, errors.New(errors.KsiInvalidArgumentError)
	}
	clone, err := clonePDU(p)
	if err != nil {
		return nil, err
	}
	return clone.(*PublicationRec), nil
}
