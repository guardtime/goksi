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
	"fmt"
	"strconv"
	"strings"

	"github.com/guardtime/goksi/errors"
)

// HashChainLinkIdentityType is hash chain link identity type.
type HashChainLinkIdentityType byte

const (
	// IdentityTypeUnknown is invalid type.
	IdentityTypeUnknown HashChainLinkIdentityType = iota
	// IdentityTypeLegacyID is Legacy client identifier.
	// A client identifier converted from a legacy signature.
	IdentityTypeLegacyID
	// IdentityTypeMetadata is a structure that provides the ability to incorporate client
	// identity and other information about the request into the hash chain.
	IdentityTypeMetadata
)

// HashChainLinkIdentity is hash chain link identity.
type HashChainLinkIdentity struct {
	idType      HashChainLinkIdentityType
	clientID    string
	machineID   string
	sequenceNr  uint64
	requestTime uint64
}

// String implements fmt.(Stringer) interface.
func (id *HashChainLinkIdentity) String() string {
	if id == nil {
		return ""
	}

	switch id.Type() {
	case IdentityTypeLegacyID:
		return fmt.Sprintf("'%s' (legacy)", id.clientID)
	case IdentityTypeMetadata:
		return fmt.Sprintf("Client ID: '%s'; Machine ID: '%s'; Sequence number: %d; Request time: %d",
			id.clientID, id.machineID, id.sequenceNr, id.requestTime)
	default:
		return "Unknown"
	}
}

// Type returns the link identity type.
func (id *HashChainLinkIdentity) Type() HashChainLinkIdentityType {
	if id == nil {
		return IdentityTypeUnknown
	}
	return id.idType
}

// ClientID returns (human-readable) textual representation of metadata client identity, or legacy ID.
func (id *HashChainLinkIdentity) ClientID() (string, error) {
	if id == nil {
		return "", errors.New(errors.KsiInvalidArgumentError)
	}
	return id.clientID, nil
}

// MachineID returns a (human-readable) identifier of the machine that requested the link structure
// (unique at least within the cluster that shares a 'client identifier').
// If not present, an empty string is returned.
func (id *HashChainLinkIdentity) MachineID() (string, error) {
	if id == nil {
		return "", errors.New(errors.KsiInvalidArgumentError)
	}
	return id.machineID, nil
}

// SequenceNr returns a local sequence number of a request assigned by the machine that created the
// link. Sequence numbers enable determination of the temporal order of requests processed by the same
// machine even within one aggregation round.
// If not present, 0 is returned.
func (id *HashChainLinkIdentity) SequenceNr() (uint64, error) {
	if id == nil {
		return 0, errors.New(errors.KsiInvalidArgumentError)
	}
	return id.sequenceNr, nil
}

// RequestTime returns the time when the server received the request from the client, recorded as precisely as
// the server's clock allows. This is another option for ordering of requests processed by the same machine
// within one aggregation round.
// If not present, 0 is returned.
func (id *HashChainLinkIdentity) RequestTime() (uint64, error) {
	if id == nil {
		return 0, errors.New(errors.KsiInvalidArgumentError)
	}
	return id.requestTime, nil
}

// HashChainLinkIdentityList is alias for []*HashChainLinkIdentity.
type HashChainLinkIdentityList []*HashChainLinkIdentity

// String implements fmt.(Stringer) interface.
func (l HashChainLinkIdentityList) String() string {
	if len(l) == 0 {
		return ""
	}

	var b strings.Builder
	for i, id := range l {
		b.WriteString(strconv.FormatInt(int64(i), 10))
		b.WriteString(". Identity: ")
		b.WriteString(id.String())
		b.WriteString("\n")
	}
	return b.String()
}
