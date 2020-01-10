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

package signature

import (
	"bytes"
	"io"
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/guardtime/goksi/errors"
	"github.com/guardtime/goksi/hash"
	"github.com/guardtime/goksi/log"
	"github.com/guardtime/goksi/pdu"
	"github.com/guardtime/goksi/publications"
	"github.com/guardtime/goksi/signature/verify/result"
	"github.com/guardtime/goksi/test"
	"github.com/guardtime/goksi/test/utils"
	"github.com/guardtime/goksi/treebuilder"
)

func TestUnitSignature(t *testing.T) {

	logger, defFunc, err := test.InitLogger(t, testLogDir, log.DEBUG, t.Name())
	if err != nil {
		t.Fatal("Failed to initialize logger: ", err)
	}
	defer defFunc()
	// Apply logger.
	log.SetLogger(logger)

	test.Suite{
		{Func: testNewSignatureInputNil},
		{Func: testNewHandlesBuilderError},
		{Func: testBuildFromNotAccessibleFile},
		{Func: testBuildFromNotDefinedFile},
		{Func: testBuildFromAggregationRespNilInput},
		{Func: testBuildFromAggregationRespNotInitializedInput},
		{Func: testBuildFromAggregationRespLevelTooLarge},
		{Func: testBuildFromExtendingRespWithNilInputs},
		{Func: testBuildFromExtendingRespWithNotInitializedInputs},
		{Func: testBuildWithAggrChainNilInputs},
		{Func: testBuildWithAggrChainNotInitializedInputs},
		{Func: testBuildWithAggrChainWithSignatureNil},
		{Func: testBuildFromAggregationRespWithSignatureNil},
		{Func: testBuildFromExtendingRespWithSignatureNil},
		{Func: testBuildFromStreamWithSignatureNil},
		{Func: testBuildNoVerifyWithSignatureNil},
		{Func: testBuildFromFileWithSignatureNil},
		{Func: testSerializeNilSignature},
		{Func: testSerializeInvalidReceiver},
		{Func: testCloneNilSignature},
		{Func: testCloneInvalidReceiver},
		{Func: testVerifyNilSignature},
		{Func: testVerifyInvalidReceiver},
		{Func: testGetVerificationResultFromNilReceiver},
		{Func: testGetVerificationResultFromInvalidReceiver},
		{Func: testGetDocumentHashFromNilReciver},
		{Func: testGetDocumentHashFromInvalidReceiver},
		{Func: testGetSigningTimeFromNilReceiver},
		{Func: testGetSigningTimeFromInvalidReceiver},
		{Func: testGetAggregationHashChainListFromNilReceiver},
		{Func: testGetAggregationHashChainListFromInvalidReceiver},
		{Func: testGetAggregationHashChainIdentityFromNilReceiver},
		{Func: testGetAggregationHashChainIdentityFromInvalidReceiver},
		{Func: testGetAggregationHashChainListAggregateFromNilReceiver},
		{Func: testGetAggregationHashChainListAggregateFromInvalidReceiver},
		{Func: testGetCalendarChainFromNilReceiver},
		{Func: testGetCalendarChainFromInvalidReceiver},
		{Func: testGetPublicationFromNilReceiver},
		{Func: testGetPublicationFromInvalidReceiver},
		{Func: testGetRfc3161FromNilReceiver},
		{Func: testGetRfc3161FromInvalidReceiver},
		{Func: testGetCalendarAuthRecFromNilReceiver},
		{Func: testGetCalendarAuthRecFromInvalidReceiver},
		{Func: testIsExtendedNilSignature},
		{Func: testIsExtendedInvalidReceiver},
		{Func: testSignatureInitializerFail},
		{Func: testSignatureFromReaderNoVerify},
		{Func: testSignatureFromFileNoVerify},
		{Func: testSignatureClone},
		{Func: testSignatureCloneWithMetadata},
		{Func: testSignatureFromAggrResponseNoVerify},
		{Func: testSignatureFromExtResponseNoVerify},
		{Func: testSignatureFromExtResponseWithExtendedSigNoVerify},
		{Func: testSignatureWithAggrChainNoVerify},
		{Func: testSignatureSerialize},
		{Func: testSignatureTryToCorruptViaAggrChain},
		{Func: testSignatureParsingDoesNotChangeMetaDataFlags},
		{Func: testVerifySignatureWithNilPolicy},
		{Func: testVerifySignatureWithNilOption},
	}.Runner(t)
}

func testNewSignatureInputNil(t *testing.T, _ ...interface{}) {
	_, err := New(nil)
	if err == nil {
		t.Fatal("It should not be possible to create signature with nil builder.")
	}
}

func testNewHandlesBuilderError(t *testing.T, _ ...interface{}) {
	sig, err := New(BuildFromFile("SomeFile.yes"))
	if err == nil || sig != nil {
		t.Fatal("Builder error was not handled correctly.")
	}
	if strings.Contains(err.(*errors.KsiError).Message()[0], "Unable to create KSI signature.") {
		t.Fatal("Unexpected error message: ", err.(*errors.KsiError).Message())
	}
}

func testBuildFromNotAccessibleFile(t *testing.T, _ ...interface{}) {
	var sig signature
	builder := BuildFromFile("SomeFile.yes")
	err := builder(&sig)
	if err == nil {
		t.Fatal("It should not be possible to create signature from not existing file.")
	}
}

func testBuildFromNotDefinedFile(t *testing.T, _ ...interface{}) {
	var sig signature
	builder := BuildFromFile("")
	err := builder(&sig)
	if err == nil {
		t.Fatal("It should not be possible to create signature from not existing file.")
	}
}

func testBuildFromAggregationRespNilInput(t *testing.T, _ ...interface{}) {
	var sig signature
	builder := BuildFromAggregationResp(nil, 0)
	err := builder(&sig)
	if err == nil {
		t.Fatal("It should not be possible to create signature from nil aggregation response.")
	}
}

func testBuildFromAggregationRespNotInitializedInput(t *testing.T, _ ...interface{}) {
	var (
		aggrResp pdu.AggregatorResp
		sig      signature
	)
	builder := BuildFromAggregationResp(&aggrResp, 0)
	err := builder(&sig)
	if err == nil {
		t.Fatal("It should not be possible to create signature from not initialized aggregation response.")
	}
}

func testBuildFromAggregationRespLevelTooLarge(t *testing.T, _ ...interface{}) {
	var sig signature
	resp := createAggregationResponse(t)
	builder := BuildFromAggregationResp(&resp, 255)
	err := builder(&sig)
	if err != nil {
		t.Fatal("Failed to set input level.")
	}
	_, err = New(builder)
	if err == nil {
		t.Fatal("Should not be possible to create signature with too high level.")
	}
}

func testBuildFromExtendingRespWithNilInputs(t *testing.T, _ ...interface{}) {
	var sig signature
	extResp, okSig := createExtenderResponseAndSig(t)

	builder := BuildFromExtendingResp(nil, okSig, nil)
	err := builder(&sig)
	if err == nil {
		t.Fatal("It should not be possible to create builder from nil extension response.")
	}

	builder = BuildFromExtendingResp(&extResp, nil, nil)
	err = builder(&sig)
	if err == nil {
		t.Fatal("It should not be possible to create builder from nil signature.")
	}
}

func testBuildFromExtendingRespWithNotInitializedInputs(t *testing.T, _ ...interface{}) {
	var (
		testSigFile  = filepath.Join(testSigDir, "ok-sig-2014-04-30.1.ksig")
		testRespFile = filepath.Join(testTlvDir, "ok-sig-2014-04-30.1-extend_response.tlv")

		sig                   signature
		notInitializedExtResp pdu.ExtenderResp
		notInitializedSig     Signature
		notInitializedPubRec  pdu.PublicationRec
		reader                io.Reader
	)

	raw, err := ioutil.ReadFile(testRespFile)
	if err != nil {
		t.Fatal("Failed to open aggregation response file.")
	}

	extResp := pdu.ExtenderResp{}
	if err := extResp.Decode(raw); err != nil {
		t.Fatal("Failed to initialize aggregation response.")
	}

	okSig, err := New(BuildNoVerify(BuildFromFile(testSigFile)))
	if err != nil {
		t.Fatal("Failed to create ksi signature from file: ", err)
	}

	failingBuilders := []struct {
		builder Builder
		errMsg  string
	}{
		{BuildFromExtendingResp(&notInitializedExtResp, okSig, nil), "It should not be possible to create builder from not initialized extension response."},
		{BuildFromExtendingResp(&extResp, &notInitializedSig, nil), "It should not be possible to create builder from not initialized signature."},
		{BuildFromExtendingResp(&extResp, okSig, &notInitializedPubRec), "It should not be possible to create builder from not initialized publication record."},
		{BuildFromStream(reader), "It should not be possible to build from nil stream."},
		{BuildNoVerify(nil), "It should not be possible to create from nil builder."},
	}

	for _, data := range failingBuilders {
		if err = data.builder(&sig); err == nil {
			t.Fatal(data.errMsg)
		}
	}
}

func testBuildWithAggrChainNilInputs(t *testing.T, _ ...interface{}) {
	var sig signature
	rootSig, aggrChain := createRootSigAndChain(t)

	builder := BuildWithAggrChain(nil, aggrChain)
	if err := builder(&sig); err == nil {
		t.Fatal("Should not create with nil signature.")
	}

	builder = BuildWithAggrChain(rootSig, nil)
	if err := builder(&sig); err == nil {
		t.Fatal("Should not create with nil aggregation chain.")
	}
}

func testBuildWithAggrChainNotInitializedInputs(t *testing.T, _ ...interface{}) {
	var (
		sig     Signature
		baseSig signature
		chain   pdu.AggregationChain
	)

	rootSig, aggrChain := createRootSigAndChain(t)

	builder := BuildWithAggrChain(&sig, aggrChain)
	if err := builder(&baseSig); err == nil {
		t.Fatal("Should not create with not initialized signature.")
	}

	builder = BuildWithAggrChain(rootSig, &chain)

	if err := builder(&baseSig); err == nil {
		t.Fatal("Should not create with not initialized aggregation chain.")
	}
}

func testBuildWithAggrChainWithSignatureNil(t *testing.T, _ ...interface{}) {
	rootSig, aggrChain := createRootSigAndChain(t)
	builder := BuildWithAggrChain(rootSig, aggrChain)

	if err := builder(nil); err == nil {
		t.Fatal("Should not create with not initialized signature.")
	}
}

func testBuildFromAggregationRespWithSignatureNil(t *testing.T, _ ...interface{}) {
	aggrResp := createAggregationResponse(t)
	builder := BuildFromAggregationResp(&aggrResp, 0)

	if err := builder(nil); err == nil {
		t.Fatal("Should not create with not initialized signature.")
	}
}

func testBuildFromExtendingRespWithSignatureNil(t *testing.T, _ ...interface{}) {
	resp, signature := createExtenderResponseAndSig(t)
	builder := BuildFromExtendingResp(&resp, signature, nil)

	if err := builder(nil); err == nil {
		t.Fatal("Should not create with not initialized signature.")
	}
}

func testBuildFromStreamWithSignatureNil(t *testing.T, _ ...interface{}) {
	var (
		reader io.Reader
	)
	builder := BuildFromStream(reader)

	if err := builder(nil); err == nil {
		t.Fatal("Should not create with not initialized signature.")
	}
}

func testBuildNoVerifyWithSignatureNil(t *testing.T, _ ...interface{}) {
	builder := BuildNoVerify(BuildFromFile("Some.file"))

	if err := builder(nil); err == nil {
		t.Fatal("Should not create with not initialized signature.")
	}
}
func testBuildFromFileWithSignatureNil(t *testing.T, _ ...interface{}) {
	builder := BuildFromFile("Some.file")

	if err := builder(nil); err == nil {
		t.Fatal("Should not create with not initialized signature.")
	}
}

func testSerializeNilSignature(t *testing.T, _ ...interface{}) {
	var sig *Signature
	if _, err := sig.Serialize(); err == nil {
		t.Fatal("It is not possible to serialize nil signature.")
	}
}

func testSerializeInvalidReceiver(t *testing.T, _ ...interface{}) {
	var sig Signature
	if _, err := sig.Serialize(); err == nil {
		t.Fatal("It is not possible to serialize not initialized signature.")
	}
}

func testCloneNilSignature(t *testing.T, _ ...interface{}) {
	var sig *Signature
	if _, err := sig.Clone(); err == nil {
		t.Fatal("It is not possible to clone nil signature.")
	}
}

func testCloneInvalidReceiver(t *testing.T, _ ...interface{}) {
	var sig Signature
	if _, err := sig.Clone(); err == nil {
		t.Fatal("It is not possible to clone not initialized signature.")
	}
}

func testVerifyNilSignature(t *testing.T, _ ...interface{}) {
	var sig *Signature
	err := sig.Verify(PublicationsFileBasedVerificationPolicy)
	if err == nil {
		t.Fatal("It is not possible to verify nil signature.")
	}
}

func testVerifyInvalidReceiver(t *testing.T, _ ...interface{}) {
	var sig Signature
	if err := sig.Verify(PublicationsFileBasedVerificationPolicy); err == nil {
		t.Fatal("It is not possible to verify not initialized signature.")
	}
}

func testGetVerificationResultFromNilReceiver(t *testing.T, _ ...interface{}) {
	var sig *Signature
	if _, err := sig.VerificationResult(); err == nil {
		t.Fatal("It is not possible to get verification results from nil signature.")
	}
}

func testGetVerificationResultFromInvalidReceiver(t *testing.T, _ ...interface{}) {
	var sig Signature
	val, err := sig.VerificationResult()
	if err != nil || val != nil {
		t.Fatal("It is not possible to get verification results from not initialized signature.")
	}
}

func testGetDocumentHashFromNilReciver(t *testing.T, _ ...interface{}) {
	var sig *Signature
	if _, err := sig.DocumentHash(); err == nil {
		t.Fatal("It is not possible to get document hash from not initialized signature.")
	}
}

func testGetDocumentHashFromInvalidReceiver(t *testing.T, _ ...interface{}) {
	var sig Signature
	if _, err := sig.DocumentHash(); err == nil {
		t.Fatal("It is not possible to get document hash from not initialized signature.")
	}
}

func testGetSigningTimeFromNilReceiver(t *testing.T, _ ...interface{}) {
	var sig *Signature
	if _, err := sig.SigningTime(); err == nil {
		t.Fatal("It is not possible to get signing time from nil signature.")
	}
}

func testGetSigningTimeFromInvalidReceiver(t *testing.T, _ ...interface{}) {
	var sig Signature
	_, err := sig.SigningTime()
	if err == nil {
		t.Fatal("It is not possible to get signing time from not initialized signature.")
	}
}

func testGetAggregationHashChainListFromNilReceiver(t *testing.T, _ ...interface{}) {
	var sig *Signature
	if _, err := sig.AggregationHashChainList(); err == nil {
		t.Fatal("It is not possible to get aggregation hash chain list from nil signature.")
	}
}

func testGetAggregationHashChainListFromInvalidReceiver(t *testing.T, _ ...interface{}) {
	var sig Signature
	if _, err := sig.AggregationHashChainList(); err == nil {
		t.Fatal("It is not possible to get aggregation hash chain list from not initialized signature.")
	}
}

func testGetAggregationHashChainIdentityFromNilReceiver(t *testing.T, _ ...interface{}) {
	var sig *Signature
	if _, err := sig.AggregationHashChainIdentity(); err == nil {
		t.Fatal("It is not possible to get aggregation hash chain identity from nil signature.")
	}
}
func testGetAggregationHashChainIdentityFromInvalidReceiver(t *testing.T, _ ...interface{}) {
	var sig Signature
	if _, err := sig.AggregationHashChainIdentity(); err == nil {
		t.Fatal("It is not possible to get aggregation hash chain identity from not initialized signature.")
	}
}

func testGetAggregationHashChainListAggregateFromNilReceiver(t *testing.T, _ ...interface{}) {
	var sig *Signature
	if _, err := sig.AggregationHashChainListAggregate(0); err == nil {
		t.Fatal("It is not possible to aggregate nil signature's aggregation hash chain.")
	}
}

func testGetAggregationHashChainListAggregateFromInvalidReceiver(t *testing.T, _ ...interface{}) {
	var sig Signature
	if _, err := sig.AggregationHashChainListAggregate(0); err == nil {
		t.Fatal("It is not possible to aggregate not initialized signature's aggregation hash chain.")
	}
}

func testGetCalendarChainFromNilReceiver(t *testing.T, _ ...interface{}) {
	var sig *Signature
	if _, err := sig.CalendarChain(); err == nil {
		t.Fatal("It is not possible to get calendar hash chain from nil signature.")
	}
}

func testGetCalendarChainFromInvalidReceiver(t *testing.T, _ ...interface{}) {
	var sig Signature
	val, err := sig.CalendarChain()
	if err != nil || val != nil {
		t.Fatal("Calendar hash chain is optional, no errors should occur when requesting it.")
	}
}

func testGetPublicationFromNilReceiver(t *testing.T, _ ...interface{}) {
	var sig *Signature
	if _, err := sig.Publication(); err == nil {
		t.Fatal("It is not possible to get publication from nil signature.")
	}
}

func testGetPublicationFromInvalidReceiver(t *testing.T, _ ...interface{}) {
	var sig Signature
	if val, err := sig.Publication(); err != nil || val != nil {
		t.Fatal("Publication record is optional, no errors should occur when requesting it.")
	}
}

func testGetRfc3161FromNilReceiver(t *testing.T, _ ...interface{}) {
	var sig *Signature
	if _, err := sig.Rfc3161(); err == nil {
		t.Fatal("It is not possible to get rfc3161 record from nil signature.")
	}
}

func testGetRfc3161FromInvalidReceiver(t *testing.T, _ ...interface{}) {
	var sig Signature
	val, err := sig.Rfc3161()
	if err != nil || val != nil {
		t.Fatal("Rfc3161 record is optional, no errors should occur when requesting it.")
	}
}
func testGetCalendarAuthRecFromNilReceiver(t *testing.T, _ ...interface{}) {
	var sig *Signature
	if _, err := sig.CalendarAuthRec(); err == nil {
		t.Fatal("It is not possible to get calendar authentication record from nil signature.")
	}
}

func testGetCalendarAuthRecFromInvalidReceiver(t *testing.T, _ ...interface{}) {
	var sig Signature
	val, err := sig.CalendarAuthRec()
	if err != nil || val != nil {
		t.Fatal("Calendar authentication record is optional, no errors should occur when requesting it.")
	}
}

func testIsExtendedNilSignature(t *testing.T, _ ...interface{}) {
	var sig *Signature
	if _, err := sig.IsExtended(); err == nil {
		t.Fatal("It is not possible to get extended status from nil signature.")
	}
}

func testIsExtendedInvalidReceiver(t *testing.T, _ ...interface{}) {
	var sig Signature
	val, err := sig.IsExtended()
	if err != nil || val != false {
		t.Fatal("Signature is always either extended or not, in this case false.")
	}
}

func testSignatureInitializerFail(t *testing.T, _ ...interface{}) {
	sig, err := New(BuildNoVerify(BuildFromFile(filepath.Join("dummy", "path", "to", "signature"))))
	if err == nil {
		t.Error("Must ", err)
	} else if _, ok := err.(*errors.KsiError); !ok {
		t.Error("KSI error must be returned.")
	}
	if sig != nil {
		t.Error("Nothing should be returned")
	}
}

func testSignatureFromReaderNoVerify(t *testing.T, _ ...interface{}) {
	var (
		testSigFile = filepath.Join(testSigDir, "ok-sig-2014-08-01.1.ksig")
	)

	f, err := os.Open(testSigFile)
	if err != nil {
		t.Fatal("Failed to open file: ", err)
	}
	defer func() {
		if err := f.Close(); err != nil {
			t.Fatal("Failed to close file: ", err)
		}
	}()

	sig, err := New(BuildNoVerify(BuildFromStream(f)))
	if err != nil {
		t.Fatal("Failed to create ksi signature from file: ", err)
	}
	if sig == nil {
		t.Fatal("Signature must be returned")
	}
	log.Debug(sig)
}

func testSignatureFromFileNoVerify(t *testing.T, _ ...interface{}) {
	var (
		testSigFile = filepath.Join(testSigDir, "ok-sig-2014-08-01.1.ksig")
	)

	sig, err := New(BuildNoVerify(BuildFromFile(testSigFile)))
	if err != nil {
		t.Fatal("Failed to create ksi signature from file: ", err)
	}
	if sig == nil {
		t.Fatal("Signature must be returned")
	}
	log.Debug(sig)
}

func testSignatureClone(t *testing.T, _ ...interface{}) {
	var (
		testSigFile = filepath.Join(testSigDir, "ok-sig-2014-08-01.1.ksig")
	)

	sig, err := New(BuildFromFile(testSigFile))
	if err != nil {
		t.Fatal("Failed to create ksi signature from file: ", err)
	}

	sigClone, err := sig.Clone()
	if err != nil {
		t.Fatal("Failed to clone signature: ", err)
	}
	if sigClone == nil {
		t.Fatal("Must return a valid signature.")
	}
}

func testSignatureCloneWithMetadata(t *testing.T, _ ...interface{}) {
	var (
		testSigFile = filepath.Join(testSigDir, "ok-sig-2018-06-15.1.ksig")
	)

	sig, err := New(BuildFromFile(testSigFile))
	if err != nil {
		t.Fatal("Failed to create ksi signature from file: ", err)
	}

	sigClone, err := sig.Clone()
	if err != nil {
		t.Fatal("Failed to clone signature: ", err)
	}
	if sigClone == nil {
		t.Fatal("Must return a valid signature.")
	}
}

func testSignatureFromAggrResponseNoVerify(t *testing.T, _ ...interface{}) {
	var (
		testRespFile = filepath.Join(testTlvDir, "ok-sig-2014-07-01.1-aggr_response.tlv")
	)

	raw, err := ioutil.ReadFile(testRespFile)
	if err != nil {
		t.Fatal("Failed to open aggregation response file.")
	}

	resp := pdu.AggregatorResp{}
	if err := resp.Decode(raw); err != nil {
		t.Fatal("Failed to initialize aggregation response.")
	}

	sig, err := New(BuildFromAggregationResp(&resp, 0))
	if err != nil {
		t.Fatal("Failed to create ksi signature from file: ", err)
	}
	if sig == nil {
		t.Fatal("Signature must be returned")
	}
	log.Debug(sig)

}

func testSignatureFromExtResponseNoVerify(t *testing.T, _ ...interface{}) {
	var (
		testSigFile  = filepath.Join(testSigDir, "ok-sig-2014-04-30.1.ksig")
		testRespFile = filepath.Join(testTlvDir, "ok-sig-2014-04-30.1-extend_response.tlv")
	)

	raw, err := ioutil.ReadFile(testRespFile)
	if err != nil {
		t.Fatal("Failed to open aggregation response file.")
	}

	resp := pdu.ExtenderResp{}
	if err := resp.Decode(raw); err != nil {
		t.Fatal("Failed to initialize aggregation response.")
	}

	sig, err := New(BuildNoVerify(BuildFromFile(testSigFile)))
	if err != nil {
		t.Fatal("Failed to create ksi signature from file: ", err)
	}

	if sig.calAuthRec == nil {
		t.Fatal("Unexpected, Calendar Authentication Record is nil!")
	}

	extSig, err := New(BuildFromExtendingResp(&resp, sig, nil))
	if err != nil {
		t.Fatal("Failed to create ksi signature from file: ", err)
	}
	if extSig.calAuthRec != nil {
		t.Fatal("After extending Calendar Authentication Record must be removed!")
	}
	if extSig.publication != nil {
		t.Fatal("After extending without specific publication record, its value must be nil!")
	}
	if extSig == nil {
		t.Fatal("Signature must be returned")
	}
	log.Debug(extSig)

}

func testSignatureFromExtResponseWithExtendedSigNoVerify(t *testing.T, _ ...interface{}) {
	var (
		testSigFile  = filepath.Join(testSigDir, "ok-sig-2014-04-30.1-extended.ksig")
		testRespFile = filepath.Join(testTlvDir, "ok-sig-2014-04-30.1-extend_response.tlv")
	)

	raw, err := ioutil.ReadFile(testRespFile)
	if err != nil {
		t.Fatal("Failed to open aggregation response file.")
	}

	resp := pdu.ExtenderResp{}
	if err := resp.Decode(raw); err != nil {
		t.Fatal("Failed to initialize aggregation response.")
	}

	sig, err := New(BuildNoVerify(BuildFromFile(testSigFile)))
	if err != nil {
		t.Fatal("Failed to create ksi signature from file: ", err)
	}

	pub, err := sig.Publication()
	if err != nil {
		t.Fatal("Failed to extract publication record: ", err)
	}

	extSig, err := New(BuildFromExtendingResp(&resp, sig, pub))
	if err != nil {
		t.Fatal("Failed to create ksi signature from file: ", err)
	}
	if extSig == nil {
		t.Fatal("Signature must be returned")
	}
	log.Debug(extSig)

}

func testSignatureWithAggrChainNoVerify(t *testing.T, _ ...interface{}) {
	var (
		testRespFile = filepath.Join(testTlvDir, "ok-sig-2018-10-22.1-aggr_response-loc_aggr.tlv")
		testLeafs    = []string{
			"0109A9FE430803D8984273324CF462E40A875D483DE6DD0D86BC6DFF4D27C9D853",
			"01BEC84E1F95F729F4482338E781341B1615F5B0A882231AE6C0FAEF7D0E6121D5",
			"01C734EEFE09B6B717B0BA6997CA634ADB93E2F227BEB785BBB8B4472651084509",
			"01B0CF0A7E6E0420D27CDFA11BDFAC4AA9BC777AE4D6C0211816BCB91DE7C920AD",
			"01BB95E9B09E7F6BC95533D805739E26510A05F9788A86C7F81BA8F81E0E6C43DA",
			"017943B1F4521425E11B461A76B9F46B08980FFD04CD080497D55A8C063E6DCDF7",
			"0123C4ADE3B64A45694088FD427399D3C2EC120BB0D5DF8C5212B1562F8D821902",
			"01A360BBAE9A0215196449971E57EB91B6C9B39725408324BE325D40C254353FBF",
			"010347A3E6C16B743473CECD6CAAD813464F8B8BD03829F649DD2FD3BA60D02ECD",
			"0178C63034846B2C6E67218FBD9F583330442A99D7165492FA5732024F27FE7FFA",
			"010579A776558FE48456A30E56B9BF58E595FF7D4DF049275C0D0ED5B361E91382",
		}
	)

	tree, err := treebuilder.New()
	if err != nil {
		t.Fatal("Failed to create tree builder: ", err)
	}

	for _, l := range testLeafs {
		if err = tree.AddNode(utils.StringToBin(l)); err != nil {
			t.Fatal("Failed to add tree node: ", err)
		}
	}
	_, rootLvl, err := tree.Aggregate()
	if err != nil {
		t.Fatal("Failed to close tree: ", err)
	}

	raw, err := ioutil.ReadFile(testRespFile)
	if err != nil {
		t.Fatal("Failed to open aggregation response file.")
	}
	resp := pdu.AggregatorResp{}
	if err := resp.Decode(raw); err != nil {
		t.Fatal("Failed to initialize aggregation response.")
	}
	rootSig, err := New(BuildFromAggregationResp(&resp, rootLvl))
	if err != nil {
		t.Fatal("Failed to create ksi signature from file: ", err)
	}

	leafs, err := tree.Leafs()
	if err != nil {
		t.Fatal("Failed to get tree leafs: ", err)
	}

	aggrChain, err := leafs[0].AggregationChain()
	if err != nil {
		t.Fatal("Failed to get leaf aggregation hash chain: ", err)
	}
	aggrSig, err := New(BuildWithAggrChain(rootSig, aggrChain))
	if err != nil {
		t.Fatal("Failed to build signature: ", err)
	}
	if aggrSig == nil {
		t.Fatal("Signature must be returned")
	}
	log.Debug(aggrSig)
}

func testSignatureSerialize(t *testing.T, _ ...interface{}) {
	var (
		testSigFile = filepath.Join(testSigDir, "ok-sig-2018-06-15.1.ksig")
		testPubFile = filepath.Join(testPubDir, "ksi-publications.bin")
		testPolicy  = DefaultVerificationPolicy
	)

	pubFile, err := publications.NewFile(publications.FileFromFile(testPubFile))
	if err != nil {
		t.Fatal("Failed to initialize publications file: ", err)
	}

	sig, err := New(BuildFromFile(testSigFile))
	if err != nil {
		t.Fatal("Failed to create ksi signature from file: ", err)
	}
	if err = sig.Verify(testPolicy, VerCtxOptPublicationsFile(pubFile)); err != nil {
		t.Fatal("Initial signature verification failed: ", err)
	}

	bin, err := sig.Serialize()
	if err != nil {
		t.Fatal("Failed to serialize signature: ", err)
	}

	sig, err = New(BuildFromStream(bytes.NewReader(bin)))
	if err != nil {
		t.Fatal("Failed to create ksi signature from file: ", err)
	}
	if sig == nil {
		t.Fatal("Signature must be returned.")
	}
	if err = sig.Verify(testPolicy, VerCtxOptPublicationsFile(pubFile)); err != nil {
		t.Fatal("De-serialized signature verification failed: ", err)
	}
}

func assertSignatureImmutability(t *testing.T, sig *Signature, verCtx *VerificationContext, rawRef []byte) {
	var (
		testPolicy = UserProvidedPublicationBasedVerificationPolicy
	)

	raw, err := sig.Serialize()
	if err != nil || len(raw) == 0 {
		t.Fatal("Failed to serialize signature: ", err)
	}

	if !bytes.Equal(raw, rawRef) {
		t.Fatal("Re-serialized signature has changed!")
	}

	res, err := testPolicy.Verify(verCtx)
	if err != nil {
		t.Fatal(testPolicy, " returned error: ", err)
	}

	if res != result.OK {
		verRes, _ := verCtx.Result()
		t.Error(testPolicy, "Verify result: ", res)
		t.Error(testPolicy, "Final  result: ", verRes.FinalResult())
	}

}

func testSignatureTryToCorruptViaAggrChain(t *testing.T, _ ...interface{}) {
	var (
		testSigFile = filepath.Join(testSigDir, "ok-sig-2014-06-2-extended.ksig")
		testPubStr  = "AAAAAA-CUCYWA-AAOBM6-PNYLRK-EPI3VG-2PJGCF-Y5QHV3-XURLI2-GRFBK4-VHBED2-Q37QIB-UE3ENA"
	)

	sig, err := New(BuildNoVerify(BuildFromFile(testSigFile)))
	usrPub, err := pdu.NewPublicationData(pdu.PubDataFromString(testPubStr))
	if err != nil {
		t.Fatal("Failed to parse publication string: ", err)
	}

	verCtx, err := NewVerificationContext(sig,
		VerCtxOptUserPublication(usrPub),
	)

	raw, err := sig.Serialize()
	if err != nil || len(raw) == 0 {
		t.Fatal("Failed to serialize signature: ", err)
	}

	aggrChain, err := sig.AggregationHashChainList()
	if err != nil {
		t.Fatal("Unable to get aggregation hash chain.", err)
	}
	if len(aggrChain) == 0 {
		t.Fatal("Aggregation hash chain list must not be empty.")
	}

	/* Try to corrupt signature with aggregation chain builder. */
	for _, ach := range aggrChain {
		builder, err := pdu.NewAggregationChainBuilder(pdu.BuildFromAggregationChain(ach))

		if err != nil {
			t.Fatal("Unable to open builder.")
		}

		corrupter := []uint64{1, 2, 3}

		err = builder.PrependChainIndex(corrupter)
		if err != nil {
			t.Fatal("Unable corrupt chain index.")
		}

		err = builder.SetAggregationTime(time.Date(1988, time.May, 21, 23, 0, 0, 0, time.UTC))
		if err != nil {
			t.Fatal("Unable to corrupt aggrgeation time.")
		}

		_, err = builder.Build()
		if err != nil {
			t.Fatal("Unable to close builder.")
		}
	}

	assertSignatureImmutability(t, sig, verCtx, raw)
}

func createAggregationResponse(t *testing.T) pdu.AggregatorResp {
	var (
		testRespFile = filepath.Join(testTlvDir, "ok-sig-2014-07-01.1-aggr_response.tlv")
	)

	raw, err := ioutil.ReadFile(testRespFile)
	if err != nil {
		t.Fatal("Failed to open aggregation response file.")
	}

	resp := pdu.AggregatorResp{}
	if err := resp.Decode(raw); err != nil {
		t.Fatal("Failed to initialize aggregation response.")
	}

	return resp
}

func createRootSigAndChain(t *testing.T) (*Signature, *pdu.AggregationChain) {
	var (
		testRespFile = filepath.Join(testTlvDir, "ok-sig-2018-10-22.1-aggr_response-loc_aggr.tlv")
		testLeafs    = []string{
			"0109A9FE430803D8984273324CF462E40A875D483DE6DD0D86BC6DFF4D27C9D853",
			"01BEC84E1F95F729F4482338E781341B1615F5B0A882231AE6C0FAEF7D0E6121D5",
			"01C734EEFE09B6B717B0BA6997CA634ADB93E2F227BEB785BBB8B4472651084509",
			"01B0CF0A7E6E0420D27CDFA11BDFAC4AA9BC777AE4D6C0211816BCB91DE7C920AD",
			"01BB95E9B09E7F6BC95533D805739E26510A05F9788A86C7F81BA8F81E0E6C43DA",
			"017943B1F4521425E11B461A76B9F46B08980FFD04CD080497D55A8C063E6DCDF7",
			"0123C4ADE3B64A45694088FD427399D3C2EC120BB0D5DF8C5212B1562F8D821902",
			"01A360BBAE9A0215196449971E57EB91B6C9B39725408324BE325D40C254353FBF",
			"010347A3E6C16B743473CECD6CAAD813464F8B8BD03829F649DD2FD3BA60D02ECD",
			"0178C63034846B2C6E67218FBD9F583330442A99D7165492FA5732024F27FE7FFA",
			"010579A776558FE48456A30E56B9BF58E595FF7D4DF049275C0D0ED5B361E91382",
		}
	)

	tree, err := treebuilder.New()
	if err != nil {
		t.Fatal("Failed to create tree builder: ", err)
	}

	for _, l := range testLeafs {
		h := utils.StringToBin(l)
		if err := tree.AddNode(h); err != nil {
			t.Fatal("Failed to add tree node: ", err)
		}
	}
	_, rootLvl, err := tree.Aggregate()
	if err != nil {
		t.Fatal("Failed to close tree: ", err)
	}

	raw, err := ioutil.ReadFile(testRespFile)
	if err != nil {
		t.Fatal("Failed to open aggregation response file.")
	}
	resp := pdu.AggregatorResp{}
	if err := resp.Decode(raw); err != nil {
		t.Fatal("Failed to initialize aggregation response.")
	}
	rootSig, err := New(BuildFromAggregationResp(&resp, rootLvl))
	if err != nil {
		t.Fatal("Failed to create ksi signature from file: ", err)
	}

	leafs, err := tree.Leafs()
	if err != nil {
		t.Fatal("Failed to get tree leafs: ", err)
	}

	aggrChain, err := leafs[0].AggregationChain()
	if err != nil {
		t.Fatal("Failed to get leaf aggregation hash chain: ", err)
	}

	return rootSig, aggrChain
}

func createSignature(t *testing.T) *Signature {
	var testSigFile = filepath.Join(testSigDir, "ok-sig-2014-04-30.1.ksig")

	sig, err := New(BuildNoVerify(BuildFromFile(testSigFile)))
	if err != nil {
		t.Fatal("Failed to create ksi signature from file: ", err)
	}

	return sig
}

func createExtenderResponseAndSig(t *testing.T) (pdu.ExtenderResp, *Signature) {
	var testRespFile = filepath.Join(testTlvDir, "ok-sig-2014-04-30.1-extend_response.tlv")

	raw, err := ioutil.ReadFile(testRespFile)
	if err != nil {
		t.Fatal("Failed to open aggregation response file.")
	}

	extResp := pdu.ExtenderResp{}
	if err := extResp.Decode(raw); err != nil {
		t.Fatal("Failed to initialize aggregation response.")
	}

	return extResp, createSignature(t)
}

func testSignatureParsingDoesNotChangeMetaDataFlags(t *testing.T, _ ...interface{}) {
	var (
		testData = []struct {
			sigFile  string
			rootHash string
		}{
			{sigFile: filepath.Join(testSigDir, "metadataFlags/forward-flag-for-client-id.tlv"),
				rootHash: "010066a5245bafcdd93d1eb99215b6fcb4deeb64cf4f037677337bbf762a20b868"},
			{sigFile: filepath.Join(testSigDir, "metadataFlags/forward-flag-for-client-machine-id.tlv"),
				rootHash: "01fb2aa052267a158eda0897635cbc78b6df1c914f5dfbc58df5bec0ef521633b2"},
			{sigFile: filepath.Join(testSigDir, "metadataFlags/forward-flag-for-client-sequence-number.tlv"),
				rootHash: "01d038302867637a51fa3abecff486c8ee4e023a208b4f3f6e7fef13ec2ec40064"},
			{sigFile: filepath.Join(testSigDir, "metadataFlags/forward-flag-for-client-request-time.tlv"),
				rootHash: "015e34e39d2d5244baa7393bf4e31954ba9cbe7cd42c13ef71588076b19d6bc7d9"},
			{sigFile: filepath.Join(testSigDir, "metadataFlags/no-flags.tlv"),
				rootHash: "013a8830fadcd5fe0dc656ff7e999a38648c719a97f5a94e29fb74b25a4afb3146"},
			{sigFile: filepath.Join(testSigDir, "metadataFlags/non-critical-flag-for-client-id.tlv"),
				rootHash: "01470c9b32f21a3d6a920e2910da727667925f197c881b9a7fca23857536001c18"},
			{sigFile: filepath.Join(testSigDir, "metadataFlags/non-critical-flag-for-client-machine-id.tlv"),
				rootHash: "012610cec94d5cefd8aef74ef452c3de659f90e38c03397080339b36803005e5b6"},
			{sigFile: filepath.Join(testSigDir, "metadataFlags/non-critical-flag-for-client-sequence-number.tlv"),
				rootHash: "0180abe0ebb4b98d1c586b891fb0a41d703aa072ba635bd14f35b952a38350bc67"},
			{sigFile: filepath.Join(testSigDir, "metadataFlags/non-critical-flag-for-client-request-time.tlv"),
				rootHash: "01b9db897b8634ff64c07a30ba9e023f7a67f554eafffbef2bf2c2c75e00c85cc7"},
		}
	)

	for _, data := range testData {
		sig, err := New(BuildFromFile(data.sigFile))
		if err != nil {
			t.Fatal("Failed to create ksi signature from file: ", err, data.sigFile)
		}

		rootHash, err := sig.AggregationHashChainListAggregate(0)
		if err != nil {
			t.Fatal("Failed to aggregate chain: ", err, data.sigFile)
		}

		if !hash.Equal(rootHash, utils.StringToBin(data.rootHash)) {
			t.Fatal("Actual and expected root hashes do not match: ", rootHash.String(), data.rootHash)
		}
	}
}

func testVerifySignatureWithNilPolicy(t *testing.T, _ ...interface{}) {
	var (
		testSigFile = filepath.Join(testSigDir, "ok-sig-2018-06-15.1.ksig")
	)

	sig, err := New(BuildFromFile(testSigFile))
	if err != nil {
		t.Fatal("Failed to create ksi signature from file: ", err)
	}

	if err := sig.Verify(nil); err == nil || errors.KsiErr(err).Code() != errors.KsiInvalidArgumentError {
		t.Fatal("It is not possible to verify with nil policy.")
	}
}

func testVerifySignatureWithNilOption(t *testing.T, _ ...interface{}) {
	var (
		testSigFile = filepath.Join(testSigDir, "ok-sig-2018-06-15.1.ksig")
	)

	sig, err := New(BuildFromFile(testSigFile))
	if err != nil {
		t.Fatal("Failed to create ksi signature from file: ", err)
	}

	if err := sig.Verify(InternalVerificationPolicy, nil); err == nil || errors.KsiErr(err).Code() != errors.KsiInvalidArgumentError {
		t.Fatal("It is not possible to verify with nil option.")
	}
}
