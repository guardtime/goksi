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

	"github.com/guardtime/goksi/log"
	"github.com/guardtime/goksi/test"
)

func TestUnitCertRec(t *testing.T) {

	logger, defFunc, err := test.InitLogger(t, testLogDir, log.DEBUG, t.Name())
	if err != nil {
		t.Fatal("Failed to initialize logger: ", err)
	}
	defer defFunc()
	// Apply logger.
	log.SetLogger(logger)

	test.Suite{
		{Func: testCertRecordFunctionsWithNilReceiver},
		{Func: testCertRecordFunctionsWithInvalidReceiver},
	}.Runner(t)
}

func testCertRecordFunctionsWithNilReceiver(t *testing.T, _ ...interface{}) {
	var (
		certRec *CertificateRecord
	)
	if _, err := certRec.CertID(); err == nil {
		t.Fatal("Should not be possible to get cert id from nil certificate record.")
	}

	if _, err := certRec.Cert(); err == nil {
		t.Fatal("Should not be possible to get cert from nil certificate record.")
	}

	if _, err := certRec.IsValid(time.Now()); err == nil {
		t.Fatal("Should not be possible to cert validity from nil certificate record.")
	}

	if err := certRec.VerifySigType(""); err == nil {
		t.Fatal("Should not be possible to verify nil certificate record's signature type.")
	}
}

func testCertRecordFunctionsWithInvalidReceiver(t *testing.T, _ ...interface{}) {
	var (
		certRec CertificateRecord
	)
	if _, err := certRec.CertID(); err == nil {
		t.Fatal("Should not be possible to get cert id from empty certificate record.")
	}

	if _, err := certRec.Cert(); err == nil {
		t.Fatal("Should not be possible to get cert from empty certificate record.")
	}

	if _, err := certRec.IsValid(time.Now()); err == nil {
		t.Fatal("Should not be possible to cert validity from empty certificate record.")
	}

	if err := certRec.VerifySigType(""); err == nil {
		t.Fatal("Should not be possible to verify empty certificate record's signature type.")
	}

	cert := []byte{}
	certRec.cert = &cert
	if err := certRec.VerifySigType(""); err == nil {
		t.Fatal("Should not be possible to verify empty certificate record's signature type")
	}
}
