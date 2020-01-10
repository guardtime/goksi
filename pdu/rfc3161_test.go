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
	"bytes"
	"testing"
	"time"

	"github.com/guardtime/goksi/hash"
	"github.com/guardtime/goksi/log"
	"github.com/guardtime/goksi/test"
)

func TestUnitRfc3161(t *testing.T) {
	logger, defFunc, err := test.InitLogger(t, testLogDir, log.DEBUG, t.Name())
	if err != nil {
		t.Fatal("Failed to initialize logger: ", err)
	}
	defer defFunc()
	// Apply logger.
	log.SetLogger(logger)

	test.Suite{
		{Func: testRfc3161FunctionsWithNilReceiver},
		{Func: testRfc3161FunctionsWithNotInitializedState},
		{Func: testRfc3161FunctionsWithInvalidReceiver},
		{Func: testRfc3161FunctionsWithOkRecord},
	}.Runner(t)
}

func testRfc3161FunctionsWithNilReceiver(t *testing.T, _ ...interface{}) {
	var (
		rec *RFC3161
	)

	if _, err := rec.AggregationTime(); err == nil {
		t.Fatal("Should not be possible to get aggregation time from nil rfc3161 record.")
	}

	if _, err := rec.ChainIndex(); err == nil {
		t.Fatal("Should not be possible to get chain index from nil rfc3161 record.")
	}

	if _, err := rec.InputData(); err == nil {
		t.Fatal("Should not be possible to get input data from nil rfc3161 record.")
	}

	if _, err := rec.InputHash(); err == nil {
		t.Fatal("Should not be possible to get input hash from nil rfc3161 record.")
	}

	if _, err := rec.OutputHash(hash.SHA2_256); err == nil {
		t.Fatal("Should not be possible to calculate output hash from nil rfc3161 record.")
	}

	if _, err := rec.SigAttrAlgo(); err == nil {
		t.Fatal("Should not be possible to get signed attributes algorithm from nil rfc3161 record.")
	}

	if _, err := rec.TstInfoAlgo(); err == nil {
		t.Fatal("Should not be possible to get tst info algorithm from nil rfc3161 record.")
	}
}

func testRfc3161FunctionsWithNotInitializedState(t *testing.T, _ ...interface{}) {
	var (
		rec RFC3161
	)

	if _, err := rec.AggregationTime(); err == nil {
		t.Fatal("Should not be possible to get aggregation time from rfc3161 record that is missing mandatory element.")
	}

	if _, err := rec.ChainIndex(); err == nil {
		t.Fatal("Should not be possible to get chain index from rfc3161 record that is missing mandatory element.")
	}

	if _, err := rec.InputHash(); err == nil {
		t.Fatal("Should not be possible to get input hash from rfc3161 record that is missing mandatory element.")
	}

	if _, err := rec.OutputHash(hash.SHA2_256); err == nil {
		t.Fatal("Should not be possible to calculate output hash from rfc3161 record that is missing .")
	}

	if _, err := rec.SigAttrAlgo(); err == nil {
		t.Fatal("Should not be possible to get signed attributes algorithm from rfc3161 record that is missing mandatory element.")
	}

	if _, err := rec.TstInfoAlgo(); err == nil {
		t.Fatal("Should not be possible to get tst info algorithm from rfc3161 record that is missing mandatory element.")
	}
}

func testRfc3161FunctionsWithInvalidReceiver(t *testing.T, _ ...interface{}) {
	var (
		index       = []uint64{uint64(12), uint64(8)}
		inData      = []byte{0x23, 0x56, 0x12, 0xa6, 0x9f, 0x11}
		tstPre      = []byte{0x12, 0x13}
		tstSuf      = []byte{0x34, 0x45}
		attrPre     = []byte{0xa1, 0xb4}
		attrSuf     = []byte{0x1a, 0x2b}
		tstInfoAlgo = newUint64(5)
		sigAttrAlgo = newUint64(4)

		rfc = RFC3161{
			aggrTime:      newUint64(123456),
			chainIndex:    &index,
			inputData:     &inData,
			tstInfoPrefix: &tstPre,
			tstInfoSuffix: &tstSuf,
			tstInfoAlgo:   tstInfoAlgo,
			sigAttrPrefix: &attrPre,
			sigAttrSuffix: &attrSuf,
			sigAttrAlgo:   sigAttrAlgo,
		}
	)

	if _, err := rfc.OutputHash(hash.Algorithm(0x1)); err == nil {
		t.Fatal("Must not be possible to calculate output hash if input hash is missing.")
	}
	rfc.inputHash = newImprint(hash.Default.ZeroImprint())

	if _, err := rfc.OutputHash(hash.Algorithm(0x8)); err == nil {
		t.Fatal("Must not be possible to calculate output hash if give algorithm is not implemented.")
	}

	if _, err := rfc.OutputHash(hash.Algorithm(0x3)); err == nil {
		t.Fatal("Must not be possible to calculate output hash if given algorithm is unknown.")
	}

	rfc.tstInfoAlgo = nil
	if _, err := rfc.OutputHash(hash.Algorithm(0x1)); err == nil {
		t.Fatal("Must not be possible to calculate output hash if tst info algorithm is missing.")
	}

	rfc.tstInfoAlgo = newUint64(3)
	if _, err := rfc.OutputHash(hash.Algorithm(0x1)); err == nil {
		t.Fatal("Must not be possible to calculate output hash if tst info algorithm is unknown.")
	}
	rfc.tstInfoAlgo = tstInfoAlgo

	rfc.tstInfoPrefix = nil
	if _, err := rfc.OutputHash(hash.Algorithm(0x1)); err == nil {
		t.Fatal("Must not be possible to calculate output hash if tst info prefix is missing.")
	}
	rfc.tstInfoPrefix = &tstPre

	rfc.tstInfoSuffix = nil
	if _, err := rfc.OutputHash(hash.Algorithm(0x1)); err == nil {
		t.Fatal("Must not be possible to calculate output hash if tst info suffix is missing.")
	}
	rfc.tstInfoSuffix = &tstSuf

	rfc.sigAttrAlgo = nil
	if _, err := rfc.OutputHash(hash.Algorithm(0x1)); err == nil {
		t.Fatal("Must not be possible to calculate output hash if signed attributes algorithm is missing.")
	}

	rfc.sigAttrAlgo = newUint64(3)
	if _, err := rfc.OutputHash(hash.Algorithm(0x1)); err == nil {
		t.Fatal("Must not be possible to calculate output hash if signed attributes algorithm unknown.")
	}
	rfc.sigAttrAlgo = sigAttrAlgo

	rfc.sigAttrPrefix = nil
	if _, err := rfc.OutputHash(hash.Algorithm(0x1)); err == nil {
		t.Fatal("Must not be possible to calculate output hash if signed attributes prefix is missing.")
	}
	rfc.sigAttrPrefix = &attrPre

	rfc.sigAttrSuffix = nil
	if _, err := rfc.OutputHash(hash.Algorithm(0x1)); err == nil {
		t.Fatal("Must not be possible to calculate output hash if signed attributes suffix is missing.")
	}
	rfc.sigAttrSuffix = &attrSuf

}

func testRfc3161FunctionsWithOkRecord(t *testing.T, _ ...interface{}) {
	var (
		index       = []uint64{uint64(12), uint64(8)}
		inData      = []byte{0x23, 0x56, 0x12, 0xa6, 0x9f, 0x11}
		tstPre      = []byte{0x12, 0x13}
		tstSuf      = []byte{0x34, 0x45}
		attrPre     = []byte{0xa1, 0xb4}
		attrSuf     = []byte{0x1a, 0x2b}
		tstInfoAlgo = uint64(5)
		sigAttrAlgo = uint64(4)

		rec = RFC3161{
			aggrTime:      newUint64(123456),
			chainIndex:    &index,
			inputData:     &inData,
			inputHash:     newImprint(hash.SHA2_256.ZeroImprint()),
			tstInfoPrefix: &tstPre,
			tstInfoSuffix: &tstSuf,
			tstInfoAlgo:   &tstInfoAlgo,
			sigAttrPrefix: &attrPre,
			sigAttrSuffix: &attrSuf,
			sigAttrAlgo:   &sigAttrAlgo,
		}
	)

	aggrTime, err := rec.AggregationTime()
	if err != nil {
		t.Fatal("Failed to get aggregation time: ", err)
	}
	if aggrTime != time.Unix(int64(123456), 0) {
		t.Fatal("Unexpected aggregation time from rfc3161 record: ", aggrTime)
	}

	chainIndex, err := rec.ChainIndex()
	if err != nil {
		t.Fatal("Failed to get chain index: ", err)
	}
	if !uint64SliceEqual(chainIndex, index) {
		t.Fatal("Unexpected chain index from rfc3161 record: ", chainIndex)
	}

	inputData, err := rec.InputData()
	if err != nil {
		t.Fatal("Failed to get input data: ", err)
	}
	if !bytes.Equal(inputData, inData) {
		t.Fatal("Unexpected input data from rfc3161 record: ", inputData)
	}

	rec.inputData = nil
	inputData, err = rec.InputData()
	if err != nil {
		t.Fatal("Failed to get input data: ", err)
	}
	if inputData != nil {
		t.Fatal("Rfc3161 input data must be nil, but was not: ", inputData)
	}

	inputHash, err := rec.InputHash()
	if err != nil {
		t.Fatal("Failed to get input hash: ", err)
	}
	if !hash.Equal(inputHash, hash.SHA2_256.ZeroImprint()) {
		t.Fatal("Unexpected input hash from rfc3161 record: ", inputHash)
	}

	outputHash, err := rec.OutputHash(hash.SHA2_256)
	if err != nil {
		t.Fatal("Failed to get output hash: ", err)
	}
	if outputHash == nil {
		t.Fatal("Output hash was not returned.")
	}

	infoAlgo, err := rec.TstInfoAlgo()
	if err != nil {
		t.Fatal("Failed to get tst info algorithm: ", err)
	}
	if infoAlgo != hash.Algorithm(tstInfoAlgo) {
		t.Fatal("Unexpected tst info algorithm from rfc3161 record: ", infoAlgo)
	}

	attrAlgo, err := rec.SigAttrAlgo()
	if err != nil {
		t.Fatal("Failed to get signed attributes algorithm: ", err)
	}
	if attrAlgo != hash.Algorithm(sigAttrAlgo) {
		t.Fatal("Unexpected signed attributes algorithm from rfc3161 record: ", attrAlgo)
	}
}

func uint64SliceEqual(a, b []uint64) bool {
	if len(a) != len(b) {
		return false
	}
	for i, v := range a {
		if v != b[i] {
			return false
		}
	}
	return true
}
