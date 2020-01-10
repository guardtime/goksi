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

	"github.com/guardtime/goksi/errors"
	"github.com/guardtime/goksi/hash"
	"github.com/guardtime/goksi/log"
	"github.com/guardtime/goksi/test"
)

func TestUnitPublicationRec(t *testing.T) {

	logger, defFunc, err := test.InitLogger(t, testLogDir, log.DEBUG, t.Name())
	if err != nil {
		t.Fatal("Failed to initialize logger: ", err)
	}
	defer defFunc()
	// Apply logger.
	log.SetLogger(logger)

	test.Suite{
		{Func: testPubRecFunctionsWithInvalidReceiver},
		{Func: testPubRecFunctionsWithNilReceiver},
		{Func: testPubRecCreationsWithOkInput},
		{Func: testPubRecCreationsWithNokInput},
		{Func: testPubRecDefault},
		{Func: testPubRecWithOptions},
		{Func: testPubRecDefaultClone},
		{Func: testPubRecClone},
		{Func: testPubRecWithOptionsClone},
		{Func: testPubRecCreationsWithNilOption},
	}.Runner(t)
}

func testPubRecFunctionsWithInvalidReceiver(t *testing.T, _ ...interface{}) {
	var (
		pubRec PublicationRec
	)

	if _, err := pubRec.PublicationData(); err == nil {
		t.Fatal("Should not be possible to get publication data from empty publication record.")
	}

	if _, err := pubRec.Clone(); err == nil {
		t.Fatal("Should not be possible to clone empty publication record.")
	}
}

func testPubRecFunctionsWithNilReceiver(t *testing.T, _ ...interface{}) {
	var (
		pubRec *PublicationRec
	)

	if _, err := pubRec.PublicationData(); err == nil {
		t.Fatal("Should not be possible to get publication data from nil publication record.")
	}

	if _, err := pubRec.Clone(); err == nil {
		t.Fatal("Should not be possible to clone nil publication record.")
	}

	if _, err := pubRec.PublicationRef(); err == nil {
		t.Fatal("Should not be possible to get publication reference from nil publication record.")
	}

	if _, err := pubRec.PublicationRepURI(); err == nil {
		t.Fatal("Should not be possible to get publication uri from nil publication record.")
	}

}

func testPubRecCreationsWithOkInput(t *testing.T, _ ...interface{}) {
	var (
		testRepUriList = []string{"RepUri", "UriRep"}
		testRefList    = []string{"RefOne", "RefTwo"}
	)
	data, err := NewPublicationData(PubDataFromImprint(time.Now(), hash.Default.ZeroImprint()))
	if err != nil {
		t.Fatal("Failed to create publication data: ", err)
	}

	pubRec, err := NewPublicationRec(data, PubRecOptPublicationRepURI(testRepUriList), PubRecOptPublicationRef(testRefList))
	if err != nil {
		t.Fatal("Failed to create publication record: ", err)
	}
	if pubRec == nil {
		t.Fatal("Nil publication record was returned.")
	}

	pubData, err := pubRec.PublicationData()
	if err != nil {
		t.Fatal("Failed to get publication data from publication record: ", err)
	}
	if pubData != data {
		t.Fatal("Unexpected publication data: ", pubData)
	}

	uris, err := pubRec.PublicationRepURI()
	if err != nil {
		t.Fatal("Failed to get publication rep uris: ", err)
	}
	for i, v := range uris {
		if v != testRepUriList[i] {
			t.Fatal("Unexpected uri in received uri list: ", v)
		}
	}

	refs, err := pubRec.PublicationRef()
	if err != nil {
		t.Fatal("Failed to get publication refs: ", err)
	}
	for i, v := range refs {
		if v != testRefList[i] {
			t.Fatal("Unexpected uri in received uri list: ", v)
		}
	}

	clone, err := pubRec.Clone()
	if err != nil {
		t.Fatal("Failed to clone publication record: ", err)
	}
	if clone == nil {
		t.Fatal("Nil clone was returned.")
	}
}

func testPubRecCreationsWithNokInput(t *testing.T, _ ...interface{}) {
	var (
		listOne   = []string{"Abc", "123"}
		emptyList []string
		pubRec    publicationRec
		data      PublicationData
	)

	bldr := PubRecOptPublicationRef(listOne)
	if err := bldr(nil); err == nil {
		t.Fatal("Should not be possible to configure publication record builder with nil publication record base object.")
	}

	bldr = PubRecOptPublicationRepURI(listOne)
	if err := bldr(nil); err == nil {
		t.Fatal("Should not be possible to configure publication record builder with nil publication record base object.")
	}

	bldr = PubRecOptPublicationRef(emptyList)
	if err := bldr(&pubRec); err == nil {
		t.Fatal("Should not be possible to configure publication record builder with empty reference list.")
	}

	bldr = PubRecOptPublicationRepURI(emptyList)
	if err := bldr(&pubRec); err == nil {
		t.Fatal("Should not be possible to configure publication record builder with empty rep uri list.")
	}

	if _, err := NewPublicationRec(nil); err == nil {
		t.Fatal("Should not be possible to create publication record with nil publication data.")
	}

	if _, err := NewPublicationRec(&data, func(fail bool) PublicationRecOptional {
		return func(_ *publicationRec) error {
			if fail {
				return errors.New(errors.KsiInvalidArgumentError)
			}
			return nil
		}
	}(true)); err == nil {
		t.Fatal("Should not be possible to create publication record if one of the options returns error.")
	}
}

func testPubRecDefault(t *testing.T, _ ...interface{}) {
	rec, err := NewPublicationRec(&PublicationData{})
	if err != nil {
		t.Fatal("Failed to create record: ", err)
	}
	if rec == nil {
		t.Fatal("Must return new publication record instance.")
	}
	if rec.pubData == nil {
		t.Fatal("Missing publication data instance.")
	}

	ref, err := rec.PublicationRef()
	if err != nil {
		t.Fatal("Failed to extract pub ref:", err)
	}
	if ref != nil {
		t.Fatal("Pub ref is not present the record.")
	}

	uri, err := rec.PublicationRepURI()
	if err != nil {
		t.Fatal("Failed to extract pub rep uri:", err)
	}
	if uri != nil {
		t.Fatal("Pub rep uri is not present the record.")
	}
}

func testPubRecWithOptions(t *testing.T, _ ...interface{}) {
	var (
		testPubTime = time.Unix(1502755200, 0)
		testImprint = hash.Imprint{0x01,
			0xc4, 0xbb, 0xcb, 0x1f, 0xbe, 0xc9, 0x9d, 0x65, 0xbf, 0x59, 0xd8, 0x5c, 0x8c, 0xb6, 0x2e, 0xe2,
			0xdb, 0x96, 0x3f, 0x0f, 0xe1, 0x06, 0xf4, 0x83, 0xd9, 0xaf, 0xa7, 0x3b, 0xd4, 0xe3, 0x9a, 0x8a,
		}
		testRefs = []string{"ref1", "ref2", "ref3"}
		testUris = []string{"some.host1.uri", "some.host1.uri", "some.host1.uri"}
	)

	pubData, err := NewPublicationData(PubDataFromImprint(testPubTime, testImprint))
	if err != nil {
		t.Fatal("Failed to create publication data from imprint: ", err)
	}

	rec, err := NewPublicationRec(pubData,
		PubRecOptPublicationRef(testRefs),
		PubRecOptPublicationRepURI(testUris),
	)
	if err != nil {
		t.Fatal("Failed to create record: ", err)
	}

	if rec.pubData == nil {
		t.Fatal("Missing publication data instance.")
	}
	if rec.pubData.pubTime == nil || *rec.pubData.pubTime != uint64(testPubTime.Unix()) {
		t.Fatal("Publication time mismatch.")
	}
	if rec.pubData.pubHash == nil || !hash.Equal(*rec.pubData.pubHash, testImprint) {
		t.Fatal("Publication hash mismatch.")
	}

	if len(*rec.pubRef) != len(testRefs) {
		t.Fatal("Publication references mismatch.")
	}
	if len(*rec.pubRepURI) != len(testUris) {
		t.Fatal("Publication URIs mismatch.")
	}

	ref, err := rec.PublicationRef()
	if err != nil {
		t.Fatal("Failed to extract pub ref:", err)
	}
	if ref == nil || len(ref) != len(testRefs) {
		t.Fatal("Pub ref mismatch.")
	}

	uri, err := rec.PublicationRepURI()
	if err != nil {
		t.Fatal("Failed to extract pub rep uri:", err)
	}
	if uri == nil || len(uri) != len(testUris) {
		t.Fatal("Pub rep uri mismatch.")
	}
}

func testPubRecDefaultClone(t *testing.T, _ ...interface{}) {
	rec, err := NewPublicationRec(&PublicationData{})
	if err != nil {
		t.Fatal("Failed to create record: ", err)
	}
	if rec == nil {
		t.Fatal("Must return new publication record instance.")
	}
	if rec.pubData == nil {
		t.Fatal("Missing publication data instance.")
	}

	if _, err := rec.Clone(); err == nil {
		t.Fatal("Must fail cloning with empty pub data.")
	}
}

func testPubRecClone(t *testing.T, _ ...interface{}) {
	var (
		testPubTime = time.Unix(1502755200, 0)
		testImprint = hash.Imprint{0x01,
			0xc4, 0xbb, 0xcb, 0x1f, 0xbe, 0xc9, 0x9d, 0x65, 0xbf, 0x59, 0xd8, 0x5c, 0x8c, 0xb6, 0x2e, 0xe2,
			0xdb, 0x96, 0x3f, 0x0f, 0xe1, 0x06, 0xf4, 0x83, 0xd9, 0xaf, 0xa7, 0x3b, 0xd4, 0xe3, 0x9a, 0x8a,
		}
		testRefs = []string{"ref1", "ref2", "ref3"}
		testUris = []string{"some.host1.uri", "some.host1.uri", "some.host1.uri"}
	)

	pubData, err := NewPublicationData(PubDataFromImprint(testPubTime, testImprint))
	if err != nil {
		t.Fatal("Failed to create publication data from imprint: ", err)
	}

	rec, err := NewPublicationRec(pubData,
		PubRecOptPublicationRef(testRefs),
		PubRecOptPublicationRepURI(testUris),
	)
	if err != nil {
		t.Fatal("Failed to create record: ", err)
	}

	clone, err := rec.Clone()
	if err != nil {
		t.Fatal("Failed to clone:", err)
	}

	if clone.pubData == nil {
		t.Fatal("Missing publication data instance.")
	}
	if clone.pubData.pubTime == nil || *clone.pubData.pubTime != uint64(testPubTime.Unix()) {
		t.Fatal("Publication time mismatch.")
	}
	if clone.pubData.pubHash == nil || !hash.Equal(*clone.pubData.pubHash, testImprint) {
		t.Fatal("Publication hash mismatch.")
	}
}

func testPubRecWithOptionsClone(t *testing.T, _ ...interface{}) {
	var (
		testPubTime = time.Unix(1502755200, 0)
		testImprint = hash.Imprint{0x01,
			0xc4, 0xbb, 0xcb, 0x1f, 0xbe, 0xc9, 0x9d, 0x65, 0xbf, 0x59, 0xd8, 0x5c, 0x8c, 0xb6, 0x2e, 0xe2,
			0xdb, 0x96, 0x3f, 0x0f, 0xe1, 0x06, 0xf4, 0x83, 0xd9, 0xaf, 0xa7, 0x3b, 0xd4, 0xe3, 0x9a, 0x8a,
		}
		testRefs = []string{"ref1", "ref2", "ref3"}
		testUris = []string{"some.host1.uri", "some.host1.uri", "some.host1.uri"}
	)

	pubData, err := NewPublicationData(PubDataFromImprint(testPubTime, testImprint))
	if err != nil {
		t.Fatal("Failed to create publication data from imprint: ", err)
	}

	rec, err := NewPublicationRec(pubData,
		PubRecOptPublicationRef(testRefs),
		PubRecOptPublicationRepURI(testUris),
	)
	if err != nil {
		t.Fatal("Failed to create record: ", err)
	}

	clone, err := rec.Clone()
	if err != nil {
		t.Fatal("Failed to clone:", err)
	}

	if len(*clone.pubRef) != len(testRefs) {
		t.Fatal("Publication references mismatch.")
	}
	if len(*clone.pubRepURI) != len(testUris) {
		t.Fatal("Publication URIs mismatch.")
	}
}

func testPubRecCreationsWithNilOption(t *testing.T, _ ...interface{}) {
	var (
		testRepUriList = []string{"RepUri", "UriRep"}
	)
	data, err := NewPublicationData(PubDataFromImprint(time.Now(), hash.Default.ZeroImprint()))
	if err != nil {
		t.Fatal("Failed to create publication data: ", err)
	}

	pubRec, err := NewPublicationRec(data, PubRecOptPublicationRepURI(testRepUriList), nil)
	if err == nil {
		t.Fatal("Should not be possible to create publication record with nil option.")
	}
	if pubRec != nil {
		t.Fatal("Nil publication record must be returned if there was an error at its creation.")
	}
}
