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
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/guardtime/goksi/hash"
	"github.com/guardtime/goksi/log"
	"github.com/guardtime/goksi/test"
	"github.com/guardtime/goksi/tlv"
)

func TestUnitChainLink(t *testing.T) {

	logger, defFunc, err := test.InitLogger(t, testLogDir, log.DEBUG, t.Name())
	if err != nil {
		t.Fatal("Failed to initialize logger: ", err)
	}
	defer defFunc()
	// Apply logger.
	log.SetLogger(logger)

	test.Suite{
		{Func: testChainLinkFunctionsWithNilReceiver},
		{Func: testAggrChainLinkFunctionsWithInvalidReceiver},
		{Func: testCalChainLinkFunctionsWithInvalidReceiver},
		{Func: testAggrChainLinkFunctionsWithOkChain},
		{Func: testAggrChainLinkIdentityWithLegacyId},
		{Func: testAggrChainLinkIdentityWithMetaData},
		{Func: testAggrChainLinkToStringWithSiblingHash},
		{Func: testAggrChainLinkToStringWithMetaData},
		{Func: testAggrChainLinkToStringWithLegacyId},
		{Func: testCalChainLinkFunctionsWithOkChain},
	}.Runner(t)
}

func testChainLinkFunctionsWithNilReceiver(t *testing.T, _ ...interface{}) {
	var (
		link   *ChainLink
		objTlv tlv.Tlv
	)
	if _, err := link.IsLeft(); err == nil {
		t.Fatal("Should not be possible to get direction from nil chain link.")
	}

	if _, err := link.SiblingHash(); err == nil {
		t.Fatal("Should not be possible to get sibling hash from nil chain link.")
	}

	if _, err := link.LevelCorrection(); err == nil {
		t.Fatal("Should not be possible to get level correction from nil chain link.")
	}

	if _, err := link.LegacyID(); err == nil {
		t.Fatal("Should not be possible to get legacy id from nil chain link.")
	}

	if _, err := link.MetaData(); err == nil {
		t.Fatal("Should not be possible to get metadata from nil chain link.")
	}

	if _, err := link.Identity(); err == nil {
		t.Fatal("Should not be possible to get identity from nil chain link.")
	}

	if link.String() != "" {
		t.Fatal("Should not be possible to get string from nil chain link.")
	}

	if err := link.FromTlv(&objTlv); err == nil {
		t.Fatal("Should not be possible to parse from tlv with nil chain link.")
	}
}

func testAggrChainLinkFunctionsWithInvalidReceiver(t *testing.T, _ ...interface{}) {
	var (
		lvl  = uint64(4)
		link = ChainLink{
			isLeft:    true,
			levelCorr: &lvl,
		}
	)

	if _, err := link.SiblingHash(); err != nil {
		t.Fatal("Should not be possible to get sibling hash from chain link.")
	}

	if _, err := link.LegacyID(); err != nil {
		t.Fatal("Should not be possible to get legacy id from chain link.")
	}

	if _, err := link.MetaData(); err != nil {
		t.Fatal("Should not be possible to get metadata from chain link.")
	}

	if err := link.FromTlv(nil); err == nil {
		t.Fatal("Should not be possible to parse from tlv with nil chain link.")
	}
}

func testCalChainLinkFunctionsWithInvalidReceiver(t *testing.T, _ ...interface{}) {
	var (
		lvl     = uint64(4)
		calLink = ChainLink{
			isCalendar: true,
			isLeft:     true,
			levelCorr:  &lvl,
		}
	)

	if _, err := calLink.SiblingHash(); err == nil {
		t.Fatal("Should not be possible to get sibling hash from calendar chain link.")
	}

	if err := calLink.FromTlv(nil); err == nil {
		t.Fatal("Should not be possible to parse from tlv with nil chain link.")
	}

	if _, err := calLink.LevelCorrection(); err == nil {
		t.Fatal("Should not be possible to request level correction from calendar chain link.")
	}

	if _, err := calLink.LegacyID(); err == nil {
		t.Fatal("Should not be possible to request legacy id from calendar chain link.")
	}

	if _, err := calLink.Identity(); err == nil {
		t.Fatal("Should not be possible to request identity from calendar chain link.")
	}

	if _, err := calLink.MetaData(); err == nil {
		t.Fatal("Should not be possible to request metadata from calendar chain link.")
	}
}

func testAggrChainLinkFunctionsWithOkChain(t *testing.T, _ ...interface{}) {
	var (
		hsh  = hash.Default.ZeroImprint()
		link = ChainLink{
			siblingHash: &hsh,
		}
		lvl = uint64(12)
	)
	val, err := link.IsLeft()
	if err != nil {
		t.Fatal("Failed to get link direction.")
	}
	if val {
		t.Fatal("Unexpected link direction, isLeft: ", val)
	}

	lvlCor, err := link.LevelCorrection()
	if err != nil {
		t.Fatal("Failed to get level correction: ", err)
	}
	if lvlCor != 0 {
		t.Fatal("Unexpected level correction value: ", lvl)
	}

	link.levelCorr = &lvl
	lvlCor, err = link.LevelCorrection()
	if err != nil {
		t.Fatal("Failed to get level correction: ", err)
	}
	if lvlCor != lvl {
		t.Fatal("Unexpected level correction value: ", lvl)
	}

	siblingHsh, err := link.SiblingHash()
	if err != nil {
		t.Fatal("Failed to get sibling hash: ", err)
	}
	if !hash.Equal(siblingHsh, hsh) {
		t.Fatal("Unexpected hash imprint: ", siblingHsh)
	}
}

func testAggrChainLinkIdentityWithLegacyId(t *testing.T, _ ...interface{}) {
	var (
		legacyId = LegacyID{
			str: "Legacy Id",
		}
		link = ChainLink{
			legacyID: &legacyId,
		}
	)

	linkIdentity, err := link.Identity()
	if err != nil {
		t.Fatal("Failed to get mdIdentity from link with legacy id: ", err)
	}
	legacyString := linkIdentity.String()
	if legacyString != "'Legacy Id' (legacy)" {
		t.Fatal("Expected and received identities do not match.")
	}
}

func testAggrChainLinkIdentityWithMetaData(t *testing.T, _ ...interface{}) {
	var (
		cId     = "Client Id"
		mId     = "Machine Id"
		reqTime = uint64(time.Now().Unix())
		seqTime = uint64(123456)
		md      = MetaData{
			clientID:   &cId,
			machineID:  &mId,
			sequenceNr: &seqTime,
			reqTime:    &reqTime,
		}
		link = ChainLink{
			metadata: &md,
		}
	)

	mdLinkIdentity, err := link.Identity()
	if err != nil {
		t.Fatal("Failed to get mdIdentity from link with metadata: ", err)
	}

	mdString := mdLinkIdentity.String()

	mdClientId, _ := md.ClientID()
	if !strings.Contains(mdString, mdClientId) {
		t.Fatal("Received identities does not contain expected client id:", mdString, mdClientId)
	}

	mdMachineId, _ := md.MachineID()
	if !strings.Contains(mdString, mdMachineId) {
		t.Fatal("Received identities does not contain expected machine id:", mdString, mdMachineId)
	}

	mdSeqNr, _ := md.SequenceNr()
	if !strings.Contains(mdString, strconv.FormatUint(mdSeqNr, 10)) {
		t.Fatal("Received identities does not contain expected sequence nr:", mdString, mdSeqNr)
	}

	mdReqTime, _ := md.ReqTime()
	if !strings.Contains(mdString, strconv.FormatUint(mdReqTime, 10)) {
		t.Fatal("Received identities does not contain expected request time: ", mdString, mdReqTime)
	}
}

func testAggrChainLinkToStringWithSiblingHash(t *testing.T, _ ...interface{}) {
	var (
		hsh  = hash.Default.ZeroImprint()
		link = ChainLink{
			siblingHash: &hsh,
			levelCorr:   newUint64(12),
		}
	)

	linkString := link.String()
	if linkString == "" {
		t.Fatal("Failed to get string from link with sibling hash.")
	}
	if !strings.Contains(linkString, "Link: ") {
		t.Fatal("Calendar chain link string contains unexpected 'Link: ': ", linkString)
	}

	if !strings.Contains(linkString, "R, ") {
		t.Fatal("Calendar chain link string contains unexpected 'R, ': ", linkString)
	}

	if !strings.Contains(linkString, "Algorithm") {
		t.Fatal("Calendar chain link string contains unexpected 'Algorithm': ", linkString)
	}

	if strings.Contains(linkString, "Identity: ") {
		t.Fatal("Calendar chain link string did not contain 'Identity: ': ", linkString)
	}

	if !strings.Contains(linkString, "LevelCorr: ") {
		t.Fatal("Calendar chain link string contains unexpected 'LevelCorr: ': ", linkString)
	}
}

func testAggrChainLinkToStringWithMetaData(t *testing.T, _ ...interface{}) {
	var (
		cId     = "Client Id"
		mId     = "Machine Id"
		reqTime = uint64(time.Now().Unix())
		seqTime = uint64(123456)
		md      = MetaData{
			clientID:   &cId,
			machineID:  &mId,
			sequenceNr: &seqTime,
			reqTime:    &reqTime,
		}
		link = ChainLink{
			metadata:  &md,
			levelCorr: newUint64(1),
		}
	)

	linkString := link.String()
	if linkString == "" {
		t.Fatal("Failed to get string from link with metadata.")
	}
	if !strings.Contains(linkString, "Link: ") {
		t.Fatal("Calendar chain link string contains unexpected 'Link: ': ", linkString)
	}

	if !strings.Contains(linkString, "R, ") {
		t.Fatal("Calendar chain link string contains unexpected 'R, ': ", linkString)
	}

	if strings.Contains(linkString, "Algorithm") {
		t.Fatal("Calendar chain link string did not contain 'Algorithm': ", linkString)
	}

	if !strings.Contains(linkString, "Identity: ") {
		t.Fatal("Calendar chain link string contains unexpected 'Identity: ': ", linkString)
	}

	if !strings.Contains(linkString, "LevelCorr: ") {
		t.Fatal("Calendar chain link string contains unexpected 'LevelCorr: ': ", linkString)
	}

	mdLinkIdentity, err := link.Identity()
	if err != nil {
		t.Fatal("Failed to get mdIdentity from link with metadata: ", err)
	}

	mdString := mdLinkIdentity.String()
	if !strings.Contains(linkString, mdString) {
		t.Fatal("Calendar chain link string contains unexpected metadata: ", linkString)
	}
}

func testAggrChainLinkToStringWithLegacyId(t *testing.T, _ ...interface{}) {
	var (
		legacyId = LegacyID{
			str: "Legacy Id",
		}
		link = ChainLink{
			legacyID:  &legacyId,
			levelCorr: newUint64(3),
		}
	)

	linkString := link.String()
	if linkString == "" {
		t.Fatal("Failed to get string from link with legacy id.")
	}
	if !strings.Contains(linkString, "Link: ") {
		t.Fatal("Calendar chain link string contains unexpected 'Link: ': ", linkString)
	}

	if !strings.Contains(linkString, "R, ") {
		t.Fatal("Calendar chain link string contains unexpected 'R, ': ", linkString)
	}

	if strings.Contains(linkString, "Algorithm") {
		t.Fatal("Calendar chain link string did not contain 'Algorithm': ", linkString)
	}

	if !strings.Contains(linkString, "Identity: ") {
		t.Fatal("Calendar chain link string contains unexpected 'Identity: ': ", linkString)
	}

	if !strings.Contains(linkString, "LevelCorr: ") {
		t.Fatal("Calendar chain link string contains unexpected 'LevelCorr: ': ", linkString)
	}

	if !strings.Contains(linkString, "Legacy Id") {
		t.Fatal("Calendar chain link string contains unexpected 'Legacy Id': ", linkString)
	}
}

func testCalChainLinkFunctionsWithOkChain(t *testing.T, _ ...interface{}) {
	var (
		hsh     = hash.Default.ZeroImprint()
		calLink = ChainLink{
			isLeft:      true,
			siblingHash: &hsh,
		}
	)

	val, err := calLink.IsLeft()
	if err != nil {
		t.Fatal("Failed to get link direction.")
	}
	if !val {
		t.Fatal("Unexpected link direction, isLeft: ", val)
	}

	linkString := calLink.String()
	if linkString == "" {
		t.Fatal("Failed to get string from link.")
	}
	if !strings.Contains(linkString, "Link: ") {
		t.Fatal("Calendar chain link string contains unexpected 'Link: ': ", linkString)
	}

	if !strings.Contains(linkString, "L, ") {
		t.Fatal("Calendar chain link string contains unexpected 'L, ': ", linkString)
	}

	if !strings.Contains(linkString, "Algorithm") {
		t.Fatal("Calendar chain link string contains unexpected 'Algorithm': ", linkString)
	}

	if strings.Contains(linkString, "Identity: ") {
		t.Fatal("Calendar chain link string did not contain 'Identity: ': ", linkString)
	}

	if strings.Contains(linkString, "LevelCorr: ") {
		t.Fatal("Calendar chain link string did not contain 'LevelCorr: ': ", linkString)
	}
}
