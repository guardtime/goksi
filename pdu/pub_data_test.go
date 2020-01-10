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
	"strings"
	"testing"
	"time"

	"github.com/guardtime/goksi/errors"
	"github.com/guardtime/goksi/hash"
	"github.com/guardtime/goksi/log"
	"github.com/guardtime/goksi/templates"
	"github.com/guardtime/goksi/test"
	"github.com/guardtime/goksi/test/utils"
	"github.com/guardtime/goksi/tlv"
)

func TestUnitPublicationData(t *testing.T) {

	logger, defFunc, err := test.InitLogger(t, testLogDir, log.DEBUG, t.Name())
	if err != nil {
		t.Fatal("Failed to initialize logger: ", err)
	}
	defer defFunc()
	// Apply logger.
	log.SetLogger(logger)

	test.Suite{
		{Func: testPubDataFunctionsWithOkInput},
		{Func: testPubDataFunctionsWithInvalidReceiver},
		{Func: testPubDataFunctionsWithNokInput},
		{Func: testPubDataCreationsWithOkInput},
		{Func: testPubDataCreationsWithNokInput},
		{Func: testPubDataFromBase32Doc},
		{Func: testPubDataFromBase32},
		{Func: testPubDataToBase32},
		{Func: testPubDataBytes},
	}.Runner(t)
}

func testPubDataFunctionsWithOkInput(t *testing.T, _ ...interface{}) {
	var (
		testPtime = time.Now()
		testHsh   = hash.SHA2_256.ZeroImprint()
	)

	data, err := NewPublicationData(PubDataFromImprint(testPtime, testHsh))
	if err != nil {
		t.Fatal("Failed to create publication data.")
	}

	pubBase32, err := data.Base32()
	if err != nil {
		t.Fatal("Failed to get base32 form publication data: ", err)
	}
	if pubBase32 == "" {
		t.Fatal("Empty base32 was returned: ", pubBase32)
	}

	if !data.Equal(data) {
		t.Fatal("Publication data did not uint64SliceEqual to itself.")
	}

	pubTime, err := data.PublicationTime()
	if err != nil {
		t.Fatal("Failed to get publication time: ", err)
	}
	if pubTime.Equal(testPtime) {
		t.Fatal("Unexpected publication time: ", pubTime.Unix(), testPtime.Unix())
	}

	pubHsh, err := data.PublishedHash()
	if err != nil {
		t.Fatal("Failed to get publication hash: ", err)
	}
	if !hash.Equal(pubHsh, testHsh) {
		t.Fatal("Unexpected publication hash: ", pubHsh)
	}

	pubBytes, err := data.Bytes()
	if err != nil {
		t.Fatal("Failed to get publication data bytes: ", err)
	}
	if pubBytes == nil {
		t.Fatal("publication data bytes was not returned.")
	}

	pubString := data.String()
	if pubString == "" {
		t.Fatal("Empty publication string was returned.")
	}
	if !strings.Contains(pubString, "Publication time: ") || !strings.Contains(pubString, "Published hash  :") {
		t.Fatal("Expected content was not found from publication data string: ", pubString)
	}
}

func testPubDataFunctionsWithInvalidReceiver(t *testing.T, _ ...interface{}) {
	var (
		pubDataNoTime = PublicationData{
			pubHash: newImprint(hash.SHA2_256.ZeroImprint()),
		}
		pubDataNoHash = PublicationData{
			pubTime: newUint64(1234),
		}
	)

	if _, err := pubDataNoHash.Base32(); err == nil {
		t.Fatal("Should not be possible to get base32 from publication data that has no publication hash.")
	}

	if _, err := pubDataNoTime.Base32(); err == nil {
		t.Fatal("Should not be possible to get base32 from publication data that has no publication time.")
	}

	if _, err := pubDataNoTime.PublicationTime(); err == nil {
		t.Fatal("Should not be possible to get publication time from publication data that does not have it.")
	}

	if _, err := pubDataNoHash.PublishedHash(); err == nil {
		t.Fatal("Should not be possible to publication hash from publication data that does not have it.")
	}

	if _, err := pubDataNoTime.Bytes(); err == nil {
		t.Fatal("Should not be possible to bytes from publication data that is missing raw bytes.")
	}

	if _, err := pubDataNoHash.Bytes(); err == nil {
		t.Fatal("Should not be possible to bytes from publication data that is missing raw bytes.")
	}
}

func testPubDataFunctionsWithNokInput(t *testing.T, _ ...interface{}) {
	var (
		nilPubData *PublicationData
		pubData    PublicationData
	)
	if _, err := nilPubData.Base32(); err == nil {
		t.Fatal("Should not be possible to get base32 from nil publication data.")
	}

	if nilPubData.Equal(&pubData) {
		t.Fatal("Should not be possible to compare nil publication data.")
	}

	if pubData.Equal(nilPubData) {
		t.Fatal("Should not be possible to compare with nil publication data.")
	}

	if _, err := nilPubData.PublicationTime(); err == nil {
		t.Fatal("Should not be possible to get publication time from nil publication data.")
	}

	if _, err := nilPubData.PublishedHash(); err == nil {
		t.Fatal("Should not be possible to publication hash from nil publication data.")
	}

	_, err := nilPubData.Bytes()
	if err == nil {
		t.Fatal("Should not be possible to bytes from nil publication data.")
	}

	if nilPubData.String() != "" {
		t.Fatal("Should not be possible to get string from nil publication data.")
	}
}

func testPubDataCreationsWithOkInput(t *testing.T, _ ...interface{}) {
	var (
		testPubStr = "AAAAAA-CJS5NQ-AAPOD6-6I7U75-PD6RDO-PCM7PZ-V4RWCG-Y4LPSE-6AQKXC-YUDHET-M4WE23-XFPW6G"
		testPtime  = time.Now()
		testHsh    = hash.SHA2_256.ZeroImprint()
	)

	bldr := PubDataFromString(testPubStr)
	data, err := NewPublicationData(bldr)
	if err != nil {
		t.Fatal("Failed to build from string: ", err)
	}
	pubString, err := data.Base32()
	if err != nil {
		t.Fatal("Failed to get base32 from publication data: ", err)
	}
	if pubString != testPubStr {
		t.Fatal("Unexpected publication string from publication data: ", pubString)
	}

	bldr = PubDataFromImprint(testPtime, testHsh)
	data, err = NewPublicationData(bldr)
	if err != nil {
		t.Fatal("Failed to build from imprint: ", err)
	}
	pubHsh, err := data.PublishedHash()
	if err != nil {
		t.Fatal("Failed to get publication hash from publication data: ", err)
	}
	if !hash.Equal(pubHsh, testHsh) {
		t.Fatal("Provided hash do not match with received publication hash from publication data: ", pubHsh)
	}

	pubTime, err := data.PublicationTime()
	if err != nil {
		t.Fatal("Failed to get publication time from publication data: ", err)
	}
	if pubTime.Equal(testPtime) {
		t.Fatal("Publication time from publication data does not match with provided time: ", pubTime.Unix())
	}
}

func testPubDataCreationsWithNokInput(t *testing.T, _ ...interface{}) {
	var (
		testPubStr  = "AAAAAA-CJS5NQ-AAPOD6-6I7U75-PD6RDO-PCM7PZ-V4RWCG-Y4LPSE-6AQKXC-YUDHET-M4WE23-XFPW6G"
		zeroTime    = time.Time{}
		ptime       = time.Now()
		hsh         = hash.SHA2_256.ZeroImprint()
		pData       publicationData
		unknownHash = newImprint([]byte{0x36, 0x23, 0x56, 0x4f, 0xa5, 0x02, 0x12})
		invalidHash = newImprint([]byte{0x01, 0xc4, 0xbb, 0xcb, 0x1f, 0xbe, 0xc9, 0x9d, 0x65, 0xbf, 0x59, 0xd8, 0x5c, 0x8c, 0xb6, 0x2e, 0xe2})
	)

	if _, err := NewPublicationData(nil); err == nil {
		t.Fatal("Should not be possible to build publication data with nil builder.")
	}

	if _, err := NewPublicationData(func(fail bool) PublicationDataBuilder {
		return func(_ *publicationData) error {
			if fail {
				return errors.New(errors.KsiInvalidArgumentError)
			}
			return nil
		}
	}(true)); err == nil {
		t.Fatal("Should not be possible to build publication data if one of the options returns error.")
	}

	bldr := PubDataFromString(testPubStr)
	if err := bldr(nil); err == nil {
		t.Fatal("Should not be possible to build publication data with nil publication data base object.")
	}

	bldr = PubDataFromString("D6RDPCM7V4R")
	if err := bldr(&pData); err == nil {
		t.Fatal("Should not be possible to build from invalid string.")
	}

	bldr = PubDataFromString("")
	if err := bldr(&pData); err == nil {
		t.Fatal("Should not be possible to build from empty string.")
	}

	bldr = PubDataFromImprint(ptime, hsh)
	if err := bldr(nil); err == nil {
		t.Fatal("Should not be possible to build publication data with nil publication data base object.")
	}

	bldr = PubDataFromImprint(zeroTime, hsh)
	if err := bldr(&pData); err == nil {
		t.Fatal("Should not be possible to build from time that is zero.")
	}

	bldr = PubDataFromImprint(zeroTime, *unknownHash)
	if err := bldr(&pData); err == nil {
		t.Fatal("Should not be possible to build from unknown hash.")
	}

	bldr = PubDataFromImprint(zeroTime, *invalidHash)
	if err := bldr(&pData); err == nil {
		t.Fatal("Should not be possible to build from invalid hash.")
	}
}

func testPubDataBytes(t *testing.T, _ ...interface{}) {
	var (
		testPubStr = "AAAAAA-CJS5NQ-AAPOD6-6I7U75-PD6RDO-PCM7PZV4RWCG-Y4LPSE-6AQKXC-YUDHET-M4WE23-XFPW6G"
	)

	pubData, err := NewPublicationData(PubDataFromString(testPubStr))
	if err != nil {
		t.Fatal("Failed to create publication data from string: ", err)
	}

	raw, err := pubData.Bytes()
	if err != nil {
		t.Fatal("Failed to get bytes: ", err)
	}

	template, err := templates.Get("PublicationData")
	if err != nil {
		t.Fatal("Failed to get template: ", err)
	}

	pubDataTlv, err := tlv.NewTlv(tlv.ConstructFromSlice(raw))
	if err != nil {
		t.Fatal("Failed to parse serialized publication data: ", err)
	}

	err = pubDataTlv.ParseNested(template)
	if err != nil {
		t.Fatal("Failed to parse TLV: ", err)
	}

	recreated := &PublicationData{}

	if err = pubDataTlv.ToObject(recreated, template, nil); err != nil {
		t.Fatal("Failed to create new object from serialized data: ", err)
	}

	if !pubData.Equal(recreated) {
		t.Fatalf("Publication data must be equal to original one.\nExpecting\n%s\nBut got:\n%s", pubData, recreated)
	}
}

func testPubDataFromBase32Doc(t *testing.T, _ ...interface{}) {

	var (
		testPubStr = "AAAAAA-CJS5NQ-AAPOD6-6I7U75-PD6RDO-PCM7PZ-V4RWCG-Y4LPSE-6AQKXC-YUDHET-M4WE23-XFPW6G"
		testPubHsh = "01EE1FBC8FD3FD78FD11B9E267DF9AF23611B1C5BE44F020AB8B1419C93672C4D6"
	)

	pubData, err := NewPublicationData(PubDataFromString(testPubStr))
	if err != nil {
		t.Fatal("Failed to create publication data from string: ", err)
	}
	if pubData.pubTime == nil || *pubData.pubTime != 1234656000 {
		t.Error("Publication time mismatch.")
	}

	if pubData.pubHash == nil || !hash.Equal(*pubData.pubHash, utils.StringToBin(testPubHsh)) {
		t.Error("Publication hash mismatch.")
	}
}

func testPubDataFromBase32(t *testing.T, _ ...interface{}) {

	var (
		testPubStr  = "AAAAAA-CZSI4Y-AAJL7M-IXUCZV-PZYX7U-AMW3NT-4Z2DXN-VYDNE5-QY762F-STUGRA-LTV3ZZ-U5KYKA"
		testPubHsh  = "012bfb117a0b357e717fd00cb6db3e6743bb6b81b49d863fed1653a1a205cebbce"
		testPubTime = time.Unix(1502755200, 0)
	)

	pubData, err := NewPublicationData(PubDataFromString(testPubStr))
	if err != nil {
		t.Fatal("Failed to create publication data from string: ", err)
	}
	if pubData.pubTime == nil || !testPubTime.Equal(time.Unix(int64(*pubData.pubTime), 0)) {
		t.Error("Publication time mismatch.")
	}

	if pubData.pubHash == nil || !hash.Equal(*pubData.pubHash, utils.StringToBin(testPubHsh)) {
		t.Error("Publication hash mismatch.")
	}
}

func testPubDataToBase32(t *testing.T, _ ...interface{}) {

	var (
		testPubStr  = "AAAAAA-CZSI4Y-AAJL7M-IXUCZV-PZYX7U-AMW3NT-4Z2DXN-VYDNE5-QY762F-STUGRA-LTV3ZZ-U5KYKA"
		testPubTime = time.Unix(1502755200, 0)
		testPubHsh  = "012bfb117a0b357e717fd00cb6db3e6743bb6b81b49d863fed1653a1a205cebbce"
	)

	pubData, err := NewPublicationData(PubDataFromImprint(testPubTime, utils.StringToBin(testPubHsh)))
	if err != nil {
		t.Fatal("Failed to create publication data from imprint: ", err)
	}

	pubStr, err := pubData.Base32()
	if err != nil {
		t.Fatal("Failed to create publication string: ", err)
	}

	if pubStr != testPubStr {
		t.Fatal("Publications strings mismatch.")
	}
}
