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

	"github.com/guardtime/goksi/errors"
	"github.com/guardtime/goksi/log"
	"github.com/guardtime/goksi/test"
	"github.com/guardtime/goksi/tlv"
)

func TestUnitMetadata(t *testing.T) {
	logger, defFunc, err := test.InitLogger(t, testLogDir, log.DEBUG, t.Name())
	if err != nil {
		t.Fatal("Failed to initialize logger: ", err)
	}
	defer defFunc()
	// Apply logger.
	log.SetLogger(logger)

	test.Suite{
		{Func: testReserializedMetadataTlvIsNotChanged},
		{Func: testMetaDataFunctionsWithNilReceiver},
		{Func: testMetaDataFunctionsWithInvalidReceiver},
		{Func: testMetaDataFunctionsWithOkMetadata},
		{Func: testMetaDataFunctionsWithDefaultValues},
		{Func: testMetaDataCreationWithInvalidInput},
		{Func: testMetaDataCreation},
		{Func: testMetadataNew},
		{Func: testMetaDataWithNilOption},
	}.Runner(t)
}

func testMetadataNew(t *testing.T, _ ...interface{}) {
	type testTable struct {
		clientId   string
		machineId  string
		sequenceNr int64
		reqTime    int64
	}

	var (
		table = []testTable{
			{clientId: "Test Client", machineId: "", sequenceNr: 0, reqTime: 0},
			{clientId: "Test Client", machineId: "Test Machine", sequenceNr: -1, reqTime: -1},
			{clientId: "Test Client", machineId: "Test Machine", sequenceNr: 10, reqTime: -1},
			{clientId: "Test Client", machineId: "Test Machine", sequenceNr: 10, reqTime: 20},
			{clientId: "Test Client", machineId: "", sequenceNr: 10, reqTime: 20},
			{clientId: "Test Client", machineId: "", sequenceNr: 10, reqTime: -1},
			{clientId: "Test Client", machineId: "", sequenceNr: -1, reqTime: 20},
		}
	)

	for _, testCase := range table {
		var options []MetaDataOptional

		if testCase.machineId != "" {
			options = append(options, MetaDataMachineID(testCase.machineId))
		}

		if testCase.sequenceNr >= 0 {
			options = append(options, MetaDataSequenceNr(uint64(testCase.sequenceNr)))
		}

		if testCase.reqTime >= 0 {
			options = append(options, MetaDataReqTime(uint64(testCase.reqTime)))
		}

		mdata, err := NewMetaData(testCase.clientId, options...)
		if err != nil {
			t.Fatal("Failed to create metadata structure: ", err)
		}

		if mdata.clientID == nil {
			t.Fatal("Client ID is nil!")
		} else if *mdata.clientID != testCase.clientId {
			t.Fatalf("Client ID mismatch. Expecting %v but got %v!", testCase.clientId, mdata.clientID)
		}

		if testCase.machineId != "" {
			if mdata.machineID == nil {
				t.Fatal("Machine ID is nil!")
			} else if *mdata.machineID != testCase.machineId {
				t.Fatalf("Machine ID mismatch. Expecting %v but got %v!", testCase.machineId, *mdata.machineID)
			}
		}

		if testCase.sequenceNr != -1 {
			if mdata.sequenceNr == nil {
				t.Fatal("Sequence nr is nil!")
			} else if *mdata.sequenceNr != uint64(testCase.sequenceNr) {
				t.Fatalf("Sequence nr mismatch. Expecting %v but got %v!", testCase.sequenceNr, *mdata.sequenceNr)
			}
		}

		if testCase.reqTime != -1 {
			if mdata.reqTime == nil {
				t.Fatal("Request time is nil!")
			} else if *mdata.reqTime != uint64(testCase.reqTime) {
				t.Fatalf("Request time mismatch. Expecting %v but got %v!", testCase.reqTime, *mdata.reqTime)
			}
		}

	}
}

func flipTlvHeaderFlags(t *tlv.Tlv) error {
	if t == nil {
		return errors.New(errors.KsiIncompatibleHashChain)
	}

	t.ForwardUnknown = t.ForwardUnknown != true
	t.Raw[0] ^= byte(tlv.HeaderFlagF)

	t.NonCritical = t.NonCritical != true
	t.Raw[0] ^= byte(tlv.HeaderFlagN)

	return nil
}

func testReserializedMetadataTlvIsNotChanged(t *testing.T, _ ...interface{}) {
	var options = []MetaDataOptional{MetaDataMachineID("Machine"), MetaDataSequenceNr(1), MetaDataReqTime(2)}

	meta, err := NewMetaData("ClientID", options...)
	if err != nil {
		t.Fatal("Failed to create metadata structure: ", err)
	}

	/* Create similar metadata object. */
	metaClone, err := NewMetaData("ClientID", options...)
	if err != nil {
		t.Fatal("Failed to create metadata structure: ", err)
	}

	/* Encode Metadata TLV - it should be formatted by goksi template. */
	encoded, err := meta.EncodeToTlv()
	if err != nil {
		t.Fatal("Failed Encode medata as TLV: ", err)
	}

	if meta.rawTlv.String() != metaClone.rawTlv.String() {
		t.Fatal("Unexpected - base tlv values must equal!")
	}

	/* Get machine_id, sequence nr and request time tlv values. Flip their N and F flags
	   to simulate a case where API receives a metadata record from another system that
	   has different policy on how and when to set F and N. Reserialized metadata must
	   have its original form as it affects KSI signature verification.*/

	machineIdTlv, err := encoded.Extract(2)
	if err != nil {
		t.Fatal("Failed to get metadata TLV.", err)
	}

	if err := flipTlvHeaderFlags(machineIdTlv); err != nil {
		t.Fatal("Unable to flip F and N flags.", err)
	}

	sequenceNrTlv, err := encoded.Extract(3)
	if err != nil {
		t.Fatal("Failed to get metadata TLV.", err)
	}

	if err := flipTlvHeaderFlags(sequenceNrTlv); err != nil {
		t.Fatal("Unable to flip F and N flags.", err)
	}

	requestTimeTlv, err := encoded.Extract(4)
	if err != nil {
		t.Fatal("Failed to get metadata TLV.", err)
	}

	if err := flipTlvHeaderFlags(requestTimeTlv); err != nil {
		t.Fatal("Unable to flip F and N flags.", err)
	}

	/* Check that the TLV is actually altered. */
	if meta.rawTlv.String() == metaClone.rawTlv.String() {
		t.Fatal("Unexpected - one base TLV must be different!")
	}

	/* Re-serialize the metadata object and check if its binary representation is not changed! */
	tlvReSerialized, err := meta.EncodeToTlv()
	if err != nil {
		t.Fatal("Unable to serialize TLV.", err)
	}

	if meta.rawTlv.String() != tlvReSerialized.String() {
		t.Fatal("Unexpected - re-serialized TLV must have EXACT same binary representation!")
	}
}

func testMetaDataFunctionsWithNilReceiver(t *testing.T, _ ...interface{}) {
	var (
		md     *MetaData
		objTlv tlv.Tlv
		enc    tlv.Encoder
	)

	if _, err := md.EncodeToTlv(); err == nil {
		t.Fatal("Should not be possible to encode nil metadata to tlv.")
	}

	if _, err := md.Encode(); err == nil {
		t.Fatal("Should not be possible to encode nil metadata.")
	}

	if _, err := md.ClientID(); err == nil {
		t.Fatal("Should not be possible to get client id from nil metadata.")
	}

	if _, err := md.MachineID(); err == nil {
		t.Fatal("Should not be possible to get machine id from nil metadata.")
	}

	if _, err := md.SequenceNr(); err == nil {
		t.Fatal("Should not be possible to get sequence nr from nil metadata.")
	}

	if _, err := md.ReqTime(); err == nil {
		t.Fatal("Should not be possible to get request time from nil metadata.")
	}

	hasPadding := md.HasPadding()
	if hasPadding {
		t.Fatal("Nil metadata can not have padding.")
	}

	if err := md.FromTlv(&objTlv); err == nil {
		t.Fatal("Should not be possible to configure nil metadata.")
	}

	if _, err := md.ToTlv(&enc); err == nil {
		t.Fatal("Should not be possible to encode nil metadata.")
	}
}

func testMetaDataFunctionsWithInvalidReceiver(t *testing.T, _ ...interface{}) {
	var (
		md  MetaData
		enc tlv.Encoder
	)

	if _, err := md.EncodeToTlv(); err == nil {
		t.Fatal("Should not be possible to encode empty metadata to tlv.")
	}

	if _, err := md.Encode(); err == nil {
		t.Fatal("Should not be possible to encode empty metadata.")
	}

	if _, err := md.ClientID(); err == nil {
		t.Fatal("Should not be possible to get client id from metadata that does not have mandatory client id.")
	}

	if err := md.FromTlv(nil); err == nil {
		t.Fatal("Should not be possible to configure with nil tlv object.")
	}

	if _, err := md.ToTlv(&enc); err == nil {
		t.Fatal("Should not be possible to encode metadata that has no raw tlv.")
	}
}

func testMetaDataFunctionsWithOkMetadata(t *testing.T, _ ...interface{}) {
	var (
		clientId  = "Client...ID"
		machineId = "Machine...ID"
		md        = &MetaData{
			reqTime:    newUint64(6353),
			clientID:   &clientId,
			machineID:  &machineId,
			sequenceNr: newUint64(234),
		}
	)

	mdTlv, err := md.EncodeToTlv()
	if err != nil {
		t.Fatal("Failed to encode to tlv: ", err)
	}
	if mdTlv == nil {
		t.Fatal("Returned tlv can not be nil.")
	}

	mdBytes, err := md.Encode()
	if err != nil {
		t.Fatal("Failed to encode: ", err)
	}
	if mdBytes == nil {
		t.Fatal("Encoded metadata can not be nil.")
	}

	id, err := md.ClientID()
	if err != nil {
		t.Fatal("Failed to get client ID: ", err)
	}
	if id != clientId {
		t.Fatal("Unexpected client id: ", id)
	}

	id, err = md.MachineID()
	if err != nil {
		t.Fatal("Failed to get machine id: ", err)
	}
	if id != machineId {
		t.Fatal("Unexpected machine id: ", id)
	}

	nr, err := md.SequenceNr()
	if err != nil {
		t.Fatal("Failed to get sequence number: ", err)
	}
	if nr != uint64(234) {
		t.Fatal("Unexpected sequence number: ", nr)
	}

	nr, err = md.ReqTime()
	if err != nil {
		t.Fatal("Failed to get request time: ", err)
	}
	if nr != uint64(6353) {
		t.Fatal("Unexpected request time: ", nr)
	}
}

func testMetaDataFunctionsWithDefaultValues(t *testing.T, _ ...interface{}) {
	var (
		clientId     = "Client...ID"
		paddingBytes = []byte{0x1, 0x1}
		md           = &MetaData{
			reqTime:    nil,
			clientID:   &clientId,
			machineID:  nil,
			sequenceNr: nil,
			padding:    nil,
		}
	)
	//Check default values
	mId, err := md.MachineID()
	if err != nil {
		t.Fatal("Failed to get machine id: ", err)
	}
	if mId != "" {
		t.Fatal("Unexpected machine id: ", mId)
	}

	nr, err := md.SequenceNr()
	if err != nil {
		t.Fatal("Failed to get sequence number: ", err)
	}
	if nr != uint64(0) {
		t.Fatal("Unexpected sequence number: ", nr)
	}

	nr, err = md.ReqTime()
	if err != nil {
		t.Fatal("Failed to get request time: ", err)
	}
	if nr != uint64(0) {
		t.Fatal("Unexpected request time: ", nr)
	}

	hasPadding := md.HasPadding()
	if hasPadding {
		t.Fatal("Unexpected padding flag in metadata: ", hasPadding)
	}

	md.padding = &paddingBytes
	hasPadding = md.HasPadding()
	if !hasPadding {
		t.Fatal("Unexpected padding flag in metadata: ", hasPadding)
	}

	paddingBytes = []byte{0x1}
	md.padding = &paddingBytes
	hasPadding = md.HasPadding()
	if !hasPadding {
		t.Fatal("Unexpected padding flag in metadata: ", hasPadding)
	}
}

func testMetaDataCreationWithInvalidInput(t *testing.T, _ ...interface{}) {
	if _, err := NewMetaData("id", func(fail bool) MetaDataOptional {
		return func(_ *metaData) error {
			if fail {
				return errors.New(errors.KsiInvalidArgumentError).AppendMessage("Failed metadata option.")
			}
			return nil
		}
	}(true)); err == nil {
		t.Fatal("Should not be possible to create metadata when one of it's options fails.")
	}

	opt := MetaDataMachineID("Machine .. id")
	if err := opt(nil); err == nil {
		t.Fatal("Should not be possible to set option to nil metadata.")
	}

	opt = MetaDataSequenceNr(uint64(1234))
	if err := opt(nil); err == nil {
		t.Fatal("Should not be possible to set option to nil metadata.")
	}

	opt = MetaDataReqTime(uint64(1234))
	if err := opt(nil); err == nil {
		t.Fatal("Should not be possible to set option to nil metadata.")
	}
}

func testMetaDataCreation(t *testing.T, _ ...interface{}) {
	var (
		md, err = NewMetaData("Client .. Id",
			MetaDataMachineID("Machine .. Id"),
			MetaDataSequenceNr(uint64(456)),
			MetaDataReqTime(uint64(789)))
	)
	if err != nil {
		t.Fatal("Failed to create metadata: ", err)
	}
	if md == nil {
		t.Fatal("Nil metadata was returned.")
	}

	clientId, err := md.ClientID()
	if err != nil {
		t.Fatal("Failed to get client id from metadata: ", err)
	}
	if clientId != "Client .. Id" {
		t.Fatal("Unexpected client id in metadata: ", clientId)
	}

	machineId, err := md.MachineID()
	if err != nil {
		t.Fatal("Failed to get machine id from metadata: ", err)
	}
	if machineId != "Machine .. Id" {
		t.Fatal("Unexpected machine id in metadata: ", machineId)
	}

	seqNr, err := md.SequenceNr()
	if err != nil {
		t.Fatal("Failed to get sequence number from metadata: ", err)
	}
	if seqNr != uint64(456) {
		t.Fatal("Unexpected sequence number in metadata: ", seqNr)
	}

	reqTime, err := md.ReqTime()
	if err != nil {
		t.Fatal("Failed to get request time from metadata: ", err)
	}
	if reqTime != uint64(789) {
		t.Fatal("Unexpected request time in metadata: ", reqTime)
	}

	hasPdding := md.HasPadding()
	if !hasPdding {
		t.Fatal("Metadata must be created with padding.")
	}
}

func testMetaDataWithNilOption(t *testing.T, _ ...interface{}) {
	if md, err := NewMetaData("Client .. Id", nil); err == nil || md != nil {
		t.Fatal("Should not be possible to create metadata with nil option.")
	}
}
