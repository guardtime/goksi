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

	"github.com/guardtime/goksi/log"
	"github.com/guardtime/goksi/test"
	"github.com/guardtime/goksi/tlv"
)

func TestUnitLegacyId(t *testing.T) {
	logger, defFunc, err := test.InitLogger(t, testLogDir, log.DEBUG, t.Name())
	if err != nil {
		t.Fatal("Failed to initialize logger: ", err)
	}
	defer defFunc()
	// Apply logger.
	log.SetLogger(logger)

	test.Suite{
		{Func: testLegacyIdFunctionsWithNilReceiver},
		{Func: testLegacyIdFunctionsWithInvalidReceiver},
	}.Runner(t)
}

func testLegacyIdFunctionsWithNilReceiver(t *testing.T, _ ...interface{}) {
	var (
		id     *LegacyID
		objTlv tlv.Tlv
	)

	if _, err := id.ClientID(); err == nil {
		t.Fatal("Should not be possible to get client id from nil Legacy id.")
	}

	if _, err := id.Bytes(); err == nil {
		t.Fatal("Should not be possible to get raw bytes from nil Legacy id.")
	}

	if err := id.FromTlv(&objTlv); err == nil {
		t.Fatal("Should not be possible to configure nil Legacy id.")
	}

	enc, err := tlv.NewEncoder()
	if err != nil {
		t.Fatal("Failed to create encoder: ", err)
	}

	if _, err = id.ToTlv(enc); err == nil {
		t.Fatal("Should not be possible to encode nil Legacy id to tlv.")
	}
}

func testLegacyIdFunctionsWithInvalidReceiver(t *testing.T, _ ...interface{}) {
	var (
		id LegacyID
	)

	if _, err := id.Bytes(); err == nil {
		t.Fatal("Should not be possible to get raw bytes from Legacy id with no raw data.")
	}

	if err := id.FromTlv(nil); err == nil {
		t.Fatal("Should not be possible to configure with nil tlv object.")
	}

	enc, err := tlv.NewEncoder()
	if err != nil {
		t.Fatal("Failed to create encoder: ", err)
	}

	if _, err = id.ToTlv(enc); err == nil {
		t.Fatal("Should not be possible to encode Legacy id that has no raw tlv.")
	}

}
