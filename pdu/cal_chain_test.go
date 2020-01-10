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
	"testing"
	"time"

	"github.com/guardtime/goksi/hash"
	"github.com/guardtime/goksi/log"
	"github.com/guardtime/goksi/test"
	"github.com/guardtime/goksi/test/utils"
)

func TestUnitCalChain(t *testing.T) {

	logger, defFunc, err := test.InitLogger(t, testLogDir, log.DEBUG, t.Name())
	if err != nil {
		t.Fatal("Failed to initialize logger: ", err)
	}
	defer defFunc()
	// Apply logger.
	log.SetLogger(logger)

	test.Suite{
		{Func: testCalendarChainFunctionsWithNilRceiver},
		{Func: testCalendarChainFunctionsWithInvalidReceiver},
		{Func: testVerifyCalendarChainCompatibilityWithInvalidInputs},
		{Func: testCalendarChainFunctionsOkCalendarChain},
	}.Runner(t)
}

func testCalendarChainFunctionsWithNilRceiver(t *testing.T, _ ...interface{}) {
	var (
		nilChain *CalendarChain
		chain    CalendarChain
	)
	if _, err := nilChain.PublicationTime(); err == nil {
		t.Fatal("Should not be possible to get publication time from nil calendar nilChain.")
	}

	if _, err := nilChain.AggregationTime(); err == nil {
		t.Fatal("Should not be possible to get aggregation time from nil calendar nilChain.")
	}

	if _, err := nilChain.InputHash(); err == nil {
		t.Fatal("Should not be possible to get input hash from nil calendar nilChain.")
	}

	if _, err := nilChain.ChainLinks(); err == nil {
		t.Fatal("Should not be possible to get nilChain links from nil calendar nilChain.")
	}

	if val := nilChain.String(); val != "" {
		t.Fatal("Should not be possible to get string from nil calendar nilChain.")
	}

	if _, err := nilChain.Aggregate(); err == nil {
		t.Fatal("Should not be possible to aggregate nil calendar nilChain.")
	}

	if _, err := nilChain.CalculateAggregationTime(); err == nil {
		t.Fatal("Should not be possible to calculate aggregation time from nil calendar nilChain.")
	}

	if err := nilChain.VerifyCompatibility(&chain); err == nil {
		t.Fatal("Should not be possible to verify compatibility of nil calendar nilChain.")
	}

	if err := nilChain.RightLinkMatch(&chain); err == nil {
		t.Fatal("Should not be possible to verify right link matching with nil calendar nilChain.")
	}
}

func testCalendarChainFunctionsWithInvalidReceiver(t *testing.T, _ ...interface{}) {
	var (
		uintTime         = uint64(1234)
		uintTime2        = uint64(12345)
		hsh1             = hash.SHA2_256.ZeroImprint()
		hsh2             = hash.SHA2_384.ZeroImprint()
		links            []*ChainLink
		chainNoInputHash = CalendarChain{
			inputHash:  nil,
			chainLinks: &links,
			aggrTime:   &uintTime,
			pubTime:    &uintTime,
		}
		chainNoLinks = CalendarChain{
			inputHash:  &hsh1,
			chainLinks: nil,
			aggrTime:   &uintTime2,
			pubTime:    &uintTime,
		}
		chainNoPubTime = CalendarChain{
			inputHash:  &hsh2,
			chainLinks: &links,
			aggrTime:   &uintTime,
			pubTime:    nil,
		}
		chainNoAggrTime = CalendarChain{
			inputHash:  &hsh1,
			chainLinks: &links,
			aggrTime:   nil,
			pubTime:    &uintTime,
		}
		nilChain *CalendarChain
	)

	aggrTime, err := chainNoAggrTime.AggregationTime()
	if err != nil {
		t.Fatal("Failed to get aggregation time from calendar chain: ", err)
	}
	if !aggrTime.IsZero() {
		t.Fatal("No aggregation time should default to zero time, but found: ", aggrTime)
	}

	if err = chainNoInputHash.RightLinkMatch(nilChain); err == nil {
		t.Fatal("Right link matching should fail if input chain is nil.")
	}

	if _, err = chainNoInputHash.InputHash(); err == nil {
		t.Fatal("Should not be possible to get input hash from chain that has no input hash.")
	}

	if _, err = chainNoInputHash.Aggregate(); err == nil {
		t.Fatal("Aggregation should fail with chain that has no input hash.")
	}

	if _, err = chainNoPubTime.PublicationTime(); err == nil {
		t.Fatal("Should not be possible to get publication time from chain that has no publication time.")
	}

	if _, err = chainNoPubTime.CalculateAggregationTime(); err == nil {
		t.Fatal("Aggregation time calculation should fail with chain that has no publication time.")
	}

	if _, err = chainNoLinks.CalculateAggregationTime(); err == nil {
		t.Fatal("Aggregation time calculation should fail with chain that has no links.")
	}

	if _, err = chainNoLinks.Aggregate(); err == nil {
		t.Fatal("Aggregation should fail with chain that has no links.")
	}

	if _, err = chainNoLinks.ChainLinks(); err == nil {
		t.Fatal("Should not be possible to get chain links from chain that has no chain links.")
	}
}

func testVerifyCalendarChainCompatibilityWithInvalidInputs(t *testing.T, _ ...interface{}) {
	var (
		uintTime         = uint64(1234)
		uintTime2        = uint64(12345)
		hsh1             = hash.SHA2_256.ZeroImprint()
		hsh2             = hash.SHA2_384.ZeroImprint()
		link             = ChainLink{siblingHash: &hsh1}
		links            []*ChainLink
		chainNoInputHash = CalendarChain{
			inputHash:  nil,
			chainLinks: &links,
			aggrTime:   &uintTime,
			pubTime:    &uintTime,
		}
		chainNoLinks = CalendarChain{
			inputHash:  &hsh1,
			chainLinks: nil,
			aggrTime:   &uintTime2,
			pubTime:    &uintTime,
		}
		chainNoPubTime = CalendarChain{
			inputHash:  &hsh2,
			chainLinks: &links,
			aggrTime:   &uintTime,
			pubTime:    nil,
		}
		chainNoAggrTime = CalendarChain{
			inputHash:  &hsh1,
			chainLinks: &links,
			aggrTime:   nil,
			pubTime:    &uintTime,
		}
		nilChain *CalendarChain
	)

	if err := chainNoPubTime.VerifyCompatibility(&chainNoAggrTime); err == nil {
		t.Fatal("Compatibility verification should fail with calendar chain that has no aggregation time.")
	}

	if err := chainNoLinks.VerifyCompatibility(&chainNoPubTime); err == nil {
		t.Fatal("Compatibility verification should fail with calendar chains that have different aggregation times.")
	}

	if err := chainNoInputHash.VerifyCompatibility(&chainNoPubTime); err == nil {
		t.Fatal("Compatibility verification should fail with calendar chain that has no input hash.")
	}

	if err := chainNoPubTime.VerifyCompatibility(&chainNoInputHash); err == nil {
		t.Fatal("Compatibility verification should fail with calendar chain that has no input hash.")
	}

	chainNoLinks.aggrTime = &uintTime
	if err := chainNoLinks.VerifyCompatibility(&chainNoPubTime); err == nil {
		t.Fatal("Compatibility verification should fail with calendar chains that have different input hashes.")
	}

	chainNoPubTime.inputHash = &hsh1
	if err := chainNoLinks.VerifyCompatibility(&chainNoPubTime); err == nil {
		t.Fatal("Compatibility verification should fail with calendar chain that has no links.")
	}

	if err := chainNoPubTime.VerifyCompatibility(&chainNoLinks); err == nil {
		t.Fatal("Compatibility verification should fail with calendar chain that has no links.")
	}

	chainNoLinks.chainLinks = &links
	linksList := append(links, &link)
	chainNoPubTime.chainLinks = &linksList
	if err := chainNoLinks.VerifyCompatibility(&chainNoPubTime); err == nil {
		t.Fatal("Compatibility verification should fail if chains have uneven count of links.")
	}

	if err := chainNoInputHash.VerifyCompatibility(nilChain); err == nil {
		t.Fatal("Compatibility verification should fail if input chain is nil.")
	}

	if err := chainNoAggrTime.VerifyCompatibility(&chainNoPubTime); err == nil {
		t.Fatal("Compatibility verification should fail with calendar chain that has no aggregation time.")
	}
}

func testCalendarChainFunctionsOkCalendarChain(t *testing.T, _ ...interface{}) {
	var (
		hsh1     = newImprint(utils.StringToBin("0109a9fe430803d8984273324cf462e40a875d483de6dd0d86bc6dff4d27c9d853"))
		uintTime = uint64(1024)
		links    = []*ChainLink{{siblingHash: hsh1}}

		calChain = CalendarChain{
			inputHash:  hsh1,
			chainLinks: &links,
			aggrTime:   &uintTime,
			pubTime:    &uintTime,
		}
	)

	pubTime, err := calChain.PublicationTime()
	if err != nil {
		t.Fatal("Failed to get publication time: ", err)
	}
	if !pubTime.Equal(time.Unix(int64(uintTime), 0)) {
		t.Fatal("Unexpected publication time: ", pubTime)
	}

	aggrTime, err := calChain.AggregationTime()
	if err != nil {
		t.Fatal("Failed to get aggregation time: ", err)
	}
	if !aggrTime.Equal(time.Unix(int64(uintTime), 0)) {
		t.Fatal("Unexpected aggregation time: ", aggrTime)
	}

	inputHash, err := calChain.InputHash()
	if err != nil {
		t.Fatal("Failed to get input hash: ", err)
	}
	if inputHash == nil || !hash.Equal(inputHash, *hsh1) {
		t.Fatal("Unexpected input hash value: ", inputHash)
	}

	chainLinks, err := calChain.ChainLinks()
	if err != nil {
		t.Fatal("Failed to get calChain links: ", err)
	}
	if chainLinks == nil || len(chainLinks) != len(links) {
		t.Fatal("Failed to get chain links.")
	}

	if calChain.String() == "" {
		t.Fatal("Should have been empty string.")
	}

	root, err := calChain.Aggregate()
	if err != nil {
		t.Fatal("Failed to aggregate: ", err)
	}
	if root == nil {
		t.Fatal("Failed to get calendar chains root.")
	}

	aggrTime, err = calChain.CalculateAggregationTime()
	if err != nil {
		t.Fatal("Failed to calculate aggregation time: ", err)
	}
	if !aggrTime.Equal(time.Unix(int64(uintTime), 0)) {
		t.Fatal("Unexpected aggregation time: ", aggrTime)
	}

	if err = calChain.VerifyCompatibility(&calChain); err != nil {
		t.Fatal("Failed to verify compatibility: ", err)
	}

	if err = calChain.RightLinkMatch(&calChain); err != nil {
		t.Fatal("Failed to verify right link matching: ", err)
	}
}
