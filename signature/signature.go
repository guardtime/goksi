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

// Package signature implements decoding and encoding of KSI signatures and signature verification handling.
//
// At the highest level of abstraction, a KSI Blockchain signature consists of a hash chain linking the signed document
// to the root hash value of the aggregation tree, followed by another hash chain linking the root hash value of the
// aggregation tree to the published trust anchor.
package signature

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"sort"
	"time"

	"github.com/guardtime/goksi/errors"
	"github.com/guardtime/goksi/hash"
	"github.com/guardtime/goksi/log"
	"github.com/guardtime/goksi/pdu"
	"github.com/guardtime/goksi/templates"
	"github.com/guardtime/goksi/tlv"
)

func init() {
	if err := templates.Register(&Signature{}, "", 0x800); err != nil {
		panic(errors.KsiErr(err).AppendMessage("Failed to initialize Signature template."))
	}
}

// Signature is the KSI signature
type Signature struct {
	// Flag for disabling signature verification during construction.
	noVerify bool
	// Signature verification result.
	verificationResult *VerificationResult

	// KSI elements.
	rfc3161       *pdu.RFC3161             `tlv:"806,nstd,C0_1"`
	aggrChainList *[]*pdu.AggregationChain `tlv:"801,nstd,C1_N"`
	calChain      *pdu.CalendarChain       `tlv:"802,nstd,C0_1,G0"`
	calAuthRec    *pdu.CalendarAuthRec     `tlv:"805,nstd,C0_1,G1,!G2,&G0"`
	publication   *pdu.PublicationRec      `tlv:"803,nstd,C0_1,G2,!G1,&G0"`
}

// New returns a new signature which was constructed based on the provided builder option.
func New(builder Builder) (*Signature, error) {
	if builder == nil {
		return nil, errors.New(errors.KsiInvalidArgumentError)
	}

	var tmp signature
	// Build signature.
	if err := builder(&tmp); err != nil {
		return nil, errors.KsiErr(err).AppendMessage("Unable to create KSI signature.")
	}
	if tmp.obj == nil {
		return nil, errors.New(errors.KsiInvalidStateError).AppendMessage("KSI signature was not constructed.")
	}

	if err := tmp.obj.Verify(InternalVerificationPolicy); err != nil {
		return nil, err
	}
	// Clear the no verify flag.
	tmp.obj.noVerify = false

	return tmp.obj, nil
}

type (
	// Builder is a signature initializer functional option.
	Builder func(*signature) error

	signature struct {
		obj *Signature
	}
)

// BuildNoVerify disables signature verification during initialization process.
// Should be used with care!
func BuildNoVerify(builder Builder) Builder {
	return func(s *signature) error {
		if builder == nil {
			return errors.New(errors.KsiInvalidArgumentError)
		}
		if s == nil {
			return errors.New(errors.KsiInvalidArgumentError).AppendMessage("Missing signature base object.")
		}

		if err := builder(s); err != nil {
			return err
		}
		if s.obj == nil {
			return errors.New(errors.KsiInvalidStateError).AppendMessage("Missing KSI signature.")
		}

		log.Info("Using no-verify initializer.")
		s.obj.noVerify = true

		return nil
	}
}

// BuildFromStream enables to initialize KSI signature from reader (binary stream).
func BuildFromStream(r io.Reader) Builder {
	return func(s *signature) error {
		if r == nil {
			return errors.New(errors.KsiInvalidArgumentError)
		}
		if s == nil {
			return errors.New(errors.KsiInvalidArgumentError).AppendMessage("Missing signature base object.")
		}

		s.obj = &Signature{}
		if err := s.obj.buildFromReader(r); err != nil {
			return err
		}

		if s.obj.aggrChainList == nil {
			return errors.New(errors.KsiInvalidFormatError).AppendMessage("Missing aggregation hash chain.")
		}
		// Make sure the aggregation hash chain list is sorted.
		sort.Sort(pdu.AggregationChainList(*s.obj.aggrChainList))

		return nil
	}
}

// BuildFromFile enables to initialize a signature from file on the filesystem.
func BuildFromFile(path string) Builder {
	return func(s *signature) error {
		if path == "" {
			return errors.New(errors.KsiInvalidArgumentError)
		}
		if s == nil {
			return errors.New(errors.KsiInvalidArgumentError).AppendMessage("Missing signature base object.")
		}

		log.Debug("Load signature file: ", path)
		f, err := os.Open(path)
		if err != nil {
			return errors.New(errors.KsiIoError).SetExtError(err).
				AppendMessage(fmt.Sprintf("Failed to open signature file: %s", path))
		}
		defer func() {
			if err := f.Close(); err != nil {
				log.Error("Failed to close file: ", err)
			}
		}()

		s.obj = &Signature{}
		if err := s.obj.buildFromReader(f); err != nil {
			return err
		}

		if s.obj.aggrChainList == nil {
			return errors.New(errors.KsiInvalidStateError).AppendMessage("Missing aggregation hash chain list.")
		}
		// Make sure the aggregation hash chain list is sorted.
		sort.Sort(pdu.AggregationChainList(*s.obj.aggrChainList))

		return nil
	}
}

func (s *Signature) buildFromReader(r io.Reader) error {
	if s == nil || r == nil {
		return errors.New(errors.KsiInvalidArgumentError)
	}

	pduTemplate, err := templates.Get("Signature")
	if err != nil {
		return err
	}
	pduTlv, err := tlv.NewTlv(tlv.ConstructFromReader(r))
	if err != nil {
		return err
	}
	if err := pduTlv.ParseNested(pduTemplate); err != nil {
		return err
	}
	log.Debug(pduTlv)

	return pduTlv.ToObject(s, pduTemplate, nil)
}

// BuildFromAggregationResp enables to initialize a signature from KSI aggregation response.
// Parameter level is the value of the aggregation tree node from which the 'request hash' comes (set to null if
// 'request hash' is a direct hash of client data (not an aggregation result).
func BuildFromAggregationResp(resp *pdu.AggregatorResp, level byte) Builder {
	return func(s *signature) error {
		if resp == nil {
			return errors.New(errors.KsiInvalidArgumentError)
		}
		if s == nil {
			return errors.New(errors.KsiInvalidArgumentError).AppendMessage("Missing signature base object.")
		}

		// Make a deep copy of the aggregation response.
		respClone, err := resp.Clone()
		if err != nil {
			return err
		}

		aggrResp, err := respClone.AggregationResp()
		if err != nil {
			return err
		}
		if aggrResp == nil {
			return errors.New(errors.KsiInvalidArgumentError).AppendMessage("Missing aggregation response.")
		}

		s.obj = &Signature{}
		// Copy signature components from aggregation response.
		if tmp, err := aggrResp.AggregationChainList(); err != nil {
			return err
		} else {
			// s.aggrChainList = new([]*pdu.AggregationChain)
			// *s.aggrChainList = tmp
			s.obj.aggrChainList = &tmp

			// Make sure the aggregation hash chain list is sorted.
			sort.Sort(pdu.AggregationChainList(*s.obj.aggrChainList))

			// Adjust level correction of the first chain link.
			if level != 0 {
				acb, err := pdu.NewAggregationChainBuilder(pdu.BuildFromAggregationChain((*s.obj.aggrChainList)[0]))
				if err != nil {
					return err
				}
				if err := acb.AdjustLevelCorrection(pdu.LevelAdd, level); err != nil {
					return errors.KsiErr(err).AppendMessage("Failed to build signature from aggregation response.")
				}
				ac, err := acb.Build()
				if err != nil {
					return err
				}
				(*s.obj.aggrChainList)[0] = ac
			}
		}
		if tmp, err := aggrResp.CalendarChain(); err != nil {
			return err
		} else {
			s.obj.calChain = tmp
		}
		if tmp, err := aggrResp.PublicationRec(); err != nil {
			return err
		} else {
			s.obj.publication = tmp
		}
		if tmp, err := aggrResp.CalendarAuthRec(); err != nil {
			return err
		} else {
			s.obj.calAuthRec = tmp
		}
		if tmp, err := aggrResp.RFC3161(); err != nil {
			return err
		} else {
			s.obj.rfc3161 = tmp
		}

		return nil
	}
}

// BuildFromExtendingResp enables to initialize a signature from KSI extending response. The new signature is based
// on a copy of the original KSI signature obj.
// The publication record parameter (pubRec) is optional, meaning it can be set to nil. As a consequence the publication
// record in the resulting signature will be left empty. If Calendar Authentication record exists, it is removed.
// The input parameters are not modified.
func BuildFromExtendingResp(resp *pdu.ExtenderResp, sig *Signature, pubRec *pdu.PublicationRec) Builder {
	return func(s *signature) error {
		if resp == nil || sig == nil {
			return errors.New(errors.KsiInvalidArgumentError)
		}
		if s == nil {
			return errors.New(errors.KsiInvalidArgumentError).AppendMessage("Missing signature base object.")
		}

		// Make a deep copy of the extending response.
		respClone, err := resp.Clone()
		if err != nil {
			return err
		}
		extResp, err := respClone.ExtendingResp()
		if err != nil {
			return err
		}
		if extResp == nil {
			return errors.New(errors.KsiInvalidStateError).AppendMessage("Inconsistent extending response.")
		}

		extCal, err := extResp.CalendarChain()
		if err != nil {
			return err
		}
		// Make sure that the new calendar hash chain is compatible with the old one.
		if sig.calChain != nil {
			if err := extCal.VerifyCompatibility(sig.calChain); err != nil {
				return errors.KsiErr(err).AppendMessage("Incompatible calendar hash chain.")
			}
		}
		extPubTime, err := extCal.PublicationTime()
		if err != nil {
			return err
		}
		extCalRoot, err := extCal.Aggregate()
		if err != nil {
			return err
		}

		// Make a deep copy of the original signature.
		s.obj, err = sig.Clone()
		if err != nil {
			return err
		}
		// Clear publication and calendar authentication records.
		s.obj.publication = nil
		s.obj.calAuthRec = nil
		// Apply the provided publication record.
		var tmpPubRec *pdu.PublicationRec
		if pubRec != nil {
			// Verify provided that publication record is compatible with the new calendar.
			pubData, err := pubRec.PublicationData()
			if err != nil {
				return err
			}
			pubDataTime, err := pubData.PublicationTime()
			if err != nil {
				return err
			}
			pubDataHsh, err := pubData.PublishedHash()
			if err != nil {
				return err
			}

			if !extPubTime.Equal(pubDataTime) || !hash.Equal(extCalRoot, pubDataHsh) {
				return errors.New(errors.KsiInvalidFormatError).
					AppendMessage("Publication record is not compatible with extending response.")
			}

			tmpPubRec, err = pubRec.Clone()
			if err != nil {
				return err
			}
		}

		s.obj.publication = tmpPubRec
		// Apply the extended calendar chain.
		s.obj.calChain = extCal

		log.Debug("Extended signature: ", s.obj)
		return nil
	}
}

// BuildWithAggrChain enables to append the provided aggregation hash chain aggrChain to the KSI signature obj.
// The aggregation hash chain is appended to the beginning of the signature chain list.
//
// Note that the provided signature is not modified.
func BuildWithAggrChain(sig *Signature, aggrChain *pdu.AggregationChain) Builder {
	return func(s *signature) error {
		if sig == nil || aggrChain == nil {
			return errors.New(errors.KsiInvalidArgumentError)
		}
		if s == nil {
			return errors.New(errors.KsiInvalidArgumentError).AppendMessage("Missing signature base object.")
		}

		// Aggregate the provided hash chain.
		rootHsh, rootLvl, err := aggrChain.Aggregate(0)
		if err != nil {
			return err
		}

		// Verify the continuation of the hash chains.
		docHsh, err := sig.DocumentHash()
		if err != nil {
			return err
		}
		if !hash.Equal(rootHsh, docHsh) {
			return errors.New(errors.KsiInvalidFormatError).AppendMessage("Root hash mismatch.")
		}

		// Make a deep copy of the provided signature.
		s.obj, err = sig.Clone()
		if err != nil {
			return err
		}

		aggrBuild, err := pdu.NewAggregationChainBuilder(pdu.BuildFromAggregationChain(aggrChain))
		if err != nil {
			return err
		}

		// Update aggregation time.
		if tmp, err := (*(*s.obj.aggrChainList)[0]).AggregationTime(); err != nil {
			return errors.KsiErr(err).AppendMessage("Inconsistent aggregation hash chain.")
		} else {
			if err := aggrBuild.SetAggregationTime(tmp); err != nil {
				return err
			}
		}
		// Update chain index.
		if tmp, err := (*(*s.obj.aggrChainList)[0]).ChainIndex(); err != nil {
			return errors.KsiErr(err).AppendMessage("Failed to extract aggregation hash chain indices.")
		} else {
			if err := aggrBuild.PrependChainIndex(tmp); err != nil {
				return err
			}
		}
		// Adjust the level correction of the signature first aggregation chain link.
		if rootLvl != 0 {
			acb, err := pdu.NewAggregationChainBuilder(pdu.BuildFromAggregationChain((*s.obj.aggrChainList)[0]))
			if err != nil {
				return err
			}
			if err := acb.AdjustLevelCorrection(pdu.LevelSubtract, rootLvl); err != nil {
				return errors.KsiErr(err).AppendMessage("Failed to build signature from aggregation response.")
			}
			ac, err := acb.Build()
			if err != nil {
				return err
			}
			(*s.obj.aggrChainList)[0] = ac
		}

		aggrChain, err = aggrBuild.Build()
		if err != nil {
			return err
		}

		// Prepend the aggregation chain to the existing list.
		*s.obj.aggrChainList = append(pdu.AggregationChainList{aggrChain}, *s.obj.aggrChainList...)

		log.Debug("Signature with aggregation chain: ", s.obj)
		return nil
	}
}

// Serialize returns a binary TLV representation of the KSI signature.
func (s *Signature) Serialize() ([]byte, error) {
	if s == nil {
		return nil, errors.New(errors.KsiInvalidArgumentError)
	}

	// Get template.
	templ, err := templates.Get("Signature")
	if err != nil {
		return nil, err
	}

	// Get TLV from template.
	rTlv, err := tlv.NewTlv(tlv.ConstructFromObject(s, templ))
	if err != nil {
		return nil, err
	}
	log.Debug(rTlv)
	return rTlv.Raw, nil
}

// Clone returns a deep copy of the original KSI signature.
func (s *Signature) Clone() (*Signature, error) {
	if s == nil {
		return nil, errors.New(errors.KsiInvalidArgumentError)
	}

	raw, err := s.Serialize()
	if err != nil {
		log.Error("Failed to serialize signature: ", err)
		return nil, err
	}
	log.Debug(hex.EncodeToString(raw))

	tmp, err := New(BuildFromStream(bytes.NewReader(raw)))
	if err != nil {
		log.Error("Failed to build signature: ", err)
		return nil, err
	}
	return tmp, nil
}

// Verify verifies the signature based on the provided parameters.
//
// See (Signature).VerificationResult() for reading verification report.
// See InternalVerificationPolicy.
func (s *Signature) Verify(policy Policy, opts ...VerCtxOption) error {
	if s == nil || policy == nil {
		return errors.New(errors.KsiInvalidArgumentError)
	}

	if s.noVerify {
		return nil
	}

	verCtx, err := NewVerificationContext(s, opts...)
	if err != nil {
		return err
	}

	_, err = policy.Verify(verCtx)
	if err != nil {
		return err
	}
	s.verificationResult = verCtx.result

	return verCtx.result.Error()
}

// VerificationResult returns signature verification report.
func (s *Signature) VerificationResult() (*VerificationResult, error) {
	if s == nil {
		return nil, errors.New(errors.KsiInvalidArgumentError)
	}
	return s.verificationResult, nil
}

// DocumentHash returns the signed document hash as imprint.
func (s *Signature) DocumentHash() (hash.Imprint, error) {
	if s == nil || s.aggrChainList == nil || len(*s.aggrChainList) == 0 {
		return nil, errors.New(errors.KsiInvalidArgumentError)
	}

	// Check if RFC3161 record is present. Then take the time from it.
	if s.rfc3161 != nil {
		tmp, err := s.rfc3161.InputHash()
		if err != nil {
			return nil, err
		}
		return tmp, nil
	}
	// Take the input hash from the first aggregation chain.
	tmp, err := (*(*s.aggrChainList)[0]).InputHash()
	if err != nil {
		return nil, err
	}

	return tmp, nil
}

// SigningTime return signing time. Time is expressed as the number of seconds since 1970-01-01 00:00:00 UTC.
func (s *Signature) SigningTime() (time.Time, error) {
	if s == nil || s.aggrChainList == nil {
		return time.Time{}, errors.New(errors.KsiInvalidArgumentError)
	}
	if s.aggrChainList == nil || len(*s.aggrChainList) == 0 {
		return time.Time{}, errors.New(errors.KsiInvalidStateError).
			AppendMessage("Missing aggregation hash chain list.")
	}

	var (
		tmp time.Time
		err error
	)
	if s.calChain != nil {
		// Aggregation time is optional.
		if tmp, err = s.calChain.AggregationTime(); err != nil {
			return time.Time{}, err
		}
		if !tmp.IsZero() {
			return tmp, nil
		}
		// Default to publication time.
		if tmp, err = s.calChain.PublicationTime(); err != nil {
			return time.Time{}, err
		}
		return tmp, nil
	}

	// Get the aggregation time from first aggregation chain.
	if tmp, err = (*(*s.aggrChainList)[0]).AggregationTime(); err != nil {
		return time.Time{}, errors.KsiErr(err).
			AppendMessage("Inconsistent aggregation hash chain.").
			AppendMessage("Missing aggregation time.")
	}
	return tmp, nil
}

// AggregationHashChainList returns aggregation hash chains if attached, otherwise an error.
func (s *Signature) AggregationHashChainList() ([]*pdu.AggregationChain, error) {
	if s == nil {
		return nil, errors.New(errors.KsiInvalidArgumentError)
	}
	if s.aggrChainList == nil || len(*s.aggrChainList) == 0 {
		return nil, errors.New(errors.KsiInvalidStateError).AppendMessage("Missing aggregation hash chain list.")
	}
	return *s.aggrChainList, nil
}

// AggregationHashChainIdentity returns a list of the identities present in all aggregation hash chains.
// The identities in the list are ordered - the upper-level Aggregator identity is before lower-level Aggregator identity.
func (s *Signature) AggregationHashChainIdentity() (pdu.HashChainLinkIdentityList, error) {
	if s == nil || s.aggrChainList == nil {
		return nil, errors.New(errors.KsiInvalidArgumentError)
	}
	return pdu.AggregationChainList(*s.aggrChainList).Identity()
}

// AggregationHashChainListAggregate aggregates the aggregation hash chain list and returns the result hash.
func (s *Signature) AggregationHashChainListAggregate(lvl byte) (hash.Imprint, error) {
	if s == nil || s.aggrChainList == nil {
		return nil, errors.New(errors.KsiInvalidArgumentError)
	}
	return pdu.AggregationChainList(*s.aggrChainList).Aggregate(lvl)
}

// CalendarChain returns calendar hash chain if attached, otherwise nil.
func (s *Signature) CalendarChain() (*pdu.CalendarChain, error) {
	if s == nil {
		return nil, errors.New(errors.KsiInvalidArgumentError)
	}
	return s.calChain, nil
}

// Publication returns publication record if attached, otherwise nil.
func (s *Signature) Publication() (*pdu.PublicationRec, error) {
	if s == nil {
		return nil, errors.New(errors.KsiInvalidArgumentError)
	}
	return s.publication, nil
}

// Rfc3161 returns RFC 3161 record if attached, otherwise nil.
func (s *Signature) Rfc3161() (*pdu.RFC3161, error) {
	if s == nil {
		return nil, errors.New(errors.KsiInvalidArgumentError)
	}
	return s.rfc3161, nil
}

// CalendarAuthRec returns calendar hash chain authentication record if attached, otherwise nil.
func (s *Signature) CalendarAuthRec() (*pdu.CalendarAuthRec, error) {
	if s == nil {
		return nil, errors.New(errors.KsiInvalidArgumentError)
	}
	return s.calAuthRec, nil
}

func (s *Signature) IsExtended() (bool, error) {
	if s == nil {
		return false, errors.New(errors.KsiInvalidArgumentError)
	}

	if s.calChain != nil {
		if s.publication != nil {
			return true, nil
		}

		aggrTime, err := s.calChain.AggregationTime()
		if err != nil {
			return false, err
		}
		pubTime, err := s.calChain.PublicationTime()
		if err != nil {
			return false, err
		}
		if aggrTime.Before(pubTime) {
			return true, nil
		}
	}
	return false, nil
}
