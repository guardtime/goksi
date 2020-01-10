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

	"github.com/guardtime/goksi/log"
	"github.com/guardtime/goksi/test"
)

func TestUniSigData(t *testing.T) {
	logger, defFunc, err := test.InitLogger(t, testLogDir, log.DEBUG, t.Name())
	if err != nil {
		t.Fatal("Failed to initialize logger: ", err)
	}
	defer defFunc()
	// Apply logger.
	log.SetLogger(logger)

	test.Suite{
		{Func: testSigDataFunctionsWithNilReceiver},
		{Func: testSigDataFunctionsWithInvalidReceiver},
		{Func: testSigDataFunctionsWithOkSigData},
	}.Runner(t)
}

func testSigDataFunctionsWithNilReceiver(t *testing.T, _ ...interface{}) {
	var (
		sigData *SignatureData
	)
	_, err := sigData.SignatureType()
	if err == nil {
		t.Fatal("Should not be possible to get signature type from nil signature data.")
	}

	_, err = sigData.SignatureValue()
	if err == nil {
		t.Fatal("Should not be possible to get signature value from nil signature data.")
	}

	_, err = sigData.CertID()
	if err == nil {
		t.Fatal("Should not be possible to cert ID from nil signature data.")
	}

	_, err = sigData.CertRepURI()
	if err == nil {
		t.Fatal("Should not be possible to get cert repository URI from nil signature data.")
	}
}

func testSigDataFunctionsWithInvalidReceiver(t *testing.T, _ ...interface{}) {
	var (
		sigData SignatureData
	)
	if _, err := sigData.SignatureType(); err == nil {
		t.Fatal("Should not be possible to get signature type from signature data that is missing mandatory element.")
	}

	if _, err := sigData.SignatureValue(); err == nil {
		t.Fatal("Should not be possible to get signature value from signature data that is missing mandatory element.")
	}

	if _, err := sigData.CertID(); err == nil {
		t.Fatal("Should not be possible to get cert ID from signature data that is missing mandatory element.")
	}
}

func testSigDataFunctionsWithOkSigData(t *testing.T, _ ...interface{}) {
	var (
		sType   = "Signature type."
		sValue  = []byte{0x12, 0x54, 0x45, 0x76, 0x43}
		cId     = []byte{0x65, 0xa4, 0xbb}
		cRepUri = "Certificate repository URI."

		sigData = &SignatureData{
			sigType:    &sType,
			sigValue:   &sValue,
			certID:     &cId,
			certRepURI: &cRepUri,
		}
	)

	sigType, err := sigData.SignatureType()
	if err != nil {
		t.Fatal("Should not be possible to get signature type from signature data that is missing mandatory element.")
	}
	if sigType != sType {
		t.Fatal("Unexpected signature type: ", sigType)
	}

	sigValue, err := sigData.SignatureValue()
	if err != nil {
		t.Fatal("Should not be possible to get signature type from signature data that is missing mandatory element.")
	}
	if !bytes.Equal(sigValue, sValue) {
		t.Fatal("Unexpected signature value: ", sigValue)
	}

	certId, err := sigData.CertID()
	if err != nil {
		t.Fatal("Should not be possible to get signature type from signature data that is missing mandatory element.")
	}
	if !bytes.Equal(certId, cId) {
		t.Fatal("Unexpected cert ID: ", certId)
	}

	certRepuri, err := sigData.CertRepURI()
	if err != nil {
		t.Fatal("Should not be possible to get cert repository URI from nil signature data.")
	}
	if certRepuri != cRepUri {
		t.Fatal("Unexpected certificate repository URI: ", certRepuri)
	}

	sigData.certRepURI = nil
	certRepuri, err = sigData.CertRepURI()
	if err != nil {
		t.Fatal("Should not be possible to get cert repository URI from nil signature data:", err)
	}
	if certRepuri != "" {
		t.Fatal("Certificate repository URI did not default to empty string: ", certRepuri)
	}
}
