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
	"strings"
	"testing"

	"github.com/guardtime/goksi/log"
	"github.com/guardtime/goksi/test"
)

func TestUnitHashChainId(t *testing.T) {
	logger, defFunc, err := test.InitLogger(t, testLogDir, log.DEBUG, t.Name())
	if err != nil {
		t.Fatal("Failed to initialize logger: ", err)
	}
	defer defFunc()
	// Apply logger.
	log.SetLogger(logger)

	test.Suite{
		{Func: testHashChainIdFunctionsWithNilReceiver},
		{Func: testHashChainIdFunctionsWithInvalidReceiver},
		{Func: testHashChainIdFunctionsWithOkChain},
		{Func: testHashChainLinkListIdentity},
	}.Runner(t)
}

func testHashChainIdFunctionsWithNilReceiver(t *testing.T, _ ...interface{}) {
	var (
		chainLinkIdentity *HashChainLinkIdentity
	)

	val := chainLinkIdentity.String()
	if val != "" {
		t.Fatal("Should not be possible to get string from nil hash chain link identity.")
	}

	linkType := chainLinkIdentity.Type()
	if linkType != IdentityTypeUnknown {
		t.Fatal("Should not be possible to get chainLinkIdentity type from nil hash chain link identity.")
	}

	if _, err := chainLinkIdentity.ClientID(); err == nil {
		t.Fatal("Should not be possible to get client id from nil hash chain link identity.")
	}

	if _, err := chainLinkIdentity.MachineID(); err == nil {
		t.Fatal("Should not be possible to get machine id from nil hash chain link identity.")
	}

	if _, err := chainLinkIdentity.SequenceNr(); err == nil {
		t.Fatal("Should not be possible to get sequence nr from nil hash chain link identity.")
	}

	if _, err := chainLinkIdentity.RequestTime(); err == nil {
		t.Fatal("Should not be possible to get request time from nil hash chain link identity.")
	}
}

func testHashChainIdFunctionsWithInvalidReceiver(t *testing.T, _ ...interface{}) {
	var (
		chainLinkIdentity HashChainLinkIdentity
	)

	if val := chainLinkIdentity.String(); val != "Unknown" {
		t.Fatal("Unexpected string from hash chain link identity: ", val)
	}

	linkType := chainLinkIdentity.Type()
	if linkType != IdentityTypeUnknown {
		t.Fatal("Unexpected type from hash chain link identity: ", linkType)
	}
}

func testHashChainIdFunctionsWithOkChain(t *testing.T, _ ...interface{}) {
	var (
		chainLinkIdentity HashChainLinkIdentity
	)

	clientId, err := chainLinkIdentity.ClientID()
	if err != nil {
		t.Fatal("Error getting the client Id from empty hash chain link identity: ", err)
	}
	if clientId != "" {
		t.Fatal("Unexpected client id: ", clientId)
	}

	machineId, err := chainLinkIdentity.MachineID()
	if err != nil {
		t.Fatal("Error getting the machine Id from empty hash chain link identity: ", err)
	}
	if machineId != "" {
		t.Fatal("Unexpected machine id: ", machineId)
	}

	seqNr, err := chainLinkIdentity.SequenceNr()
	if err != nil {
		t.Fatal("Error getting the sequence number from empty hash chain link identity: ", err)
	}
	if seqNr != uint64(0) {
		t.Fatal("Unexpected sequence number: ", seqNr)
	}

	reqTime, err := chainLinkIdentity.RequestTime()
	if err != nil {
		t.Fatal("Error getting the request time from empty hash chain link identity: ", err)
	}
	if reqTime != uint64(0) {
		t.Fatal("Unexpected request time: ", reqTime)
	}

	chainLinkIdentity = HashChainLinkIdentity{
		idType:      IdentityTypeLegacyID,
		clientID:    "Client...Id",
		machineID:   "Machine...Id",
		sequenceNr:  56,
		requestTime: 23,
	}

	val := chainLinkIdentity.String()
	if !strings.Contains(val, "(legacy)") {
		t.Fatal("Unexpected identity string: ", val)
	}

	chainLinkIdentity.idType = IdentityTypeMetadata
	val = chainLinkIdentity.String()
	if val != fmt.Sprintf("Client ID: '%s'; Machine ID: '%s'; Sequence number: %d; Request time: %d",
		chainLinkIdentity.clientID, chainLinkIdentity.machineID, chainLinkIdentity.sequenceNr, chainLinkIdentity.requestTime) {
		t.Fatal("Unexpected identity string: ", val)
	}

	clientId, err = chainLinkIdentity.ClientID()
	if err != nil {
		t.Fatal("Error getting the client Id from empty hash chain link identity: ", err)
	}
	if clientId != "Client...Id" {
		t.Fatal("Unexpected client id: ", clientId)
	}

	machineId, err = chainLinkIdentity.MachineID()
	if err != nil {
		t.Fatal("Error getting the machine Id from empty hash chain link identity: ", err)
	}
	if machineId != "Machine...Id" {
		t.Fatal("Unexpected machine id: ", machineId)
	}

	seqNr, err = chainLinkIdentity.SequenceNr()
	if err != nil {
		t.Fatal("Error getting the sequence number from empty hash chain link identity: ", err)
	}
	if seqNr != uint64(56) {
		t.Fatal("Unexpected sequence number: ", seqNr)
	}

	reqTime, err = chainLinkIdentity.RequestTime()
	if err != nil {
		t.Fatal("Error getting the request time from empty hash chain link identity: ", err)
	}
	if reqTime != uint64(23) {
		t.Fatal("Unexpected request time: ", reqTime)
	}
}

func testHashChainLinkListIdentity(t *testing.T, _ ...interface{}) {
	var (
		list HashChainLinkIdentityList
	)

	val := list.String()
	if val != "" {
		t.Fatal("Empty list did not return empty string: ", val)
	}

	chainLinkIdentity := &HashChainLinkIdentity{
		idType:      IdentityTypeMetadata,
		clientID:    "Client...Id",
		machineID:   "Machine...Id",
		sequenceNr:  56,
		requestTime: 23,
	}

	list = append(list, chainLinkIdentity)
	list = append(list, chainLinkIdentity)

	val = list.String()
	if !strings.Contains(val, fmt.Sprintf("0. Identity: Client ID: '%s'; Machine ID: '%s'; Sequence number: %d; Request time: %d",
		chainLinkIdentity.clientID, chainLinkIdentity.machineID, chainLinkIdentity.sequenceNr, chainLinkIdentity.requestTime)) {
		t.Fatal("Unexpected identity string: ", val)
	}
	if !strings.Contains(val, fmt.Sprintf("1. Identity: Client ID: '%s'; Machine ID: '%s'; Sequence number: %d; Request time: %d",
		chainLinkIdentity.clientID, chainLinkIdentity.machineID, chainLinkIdentity.sequenceNr, chainLinkIdentity.requestTime)) {
		t.Fatal("Unexpected identity string: ", val)
	}
}
