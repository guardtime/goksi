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
	stderrors "errors"
	"testing"

	"github.com/guardtime/goksi/errors"
	"github.com/guardtime/goksi/log"
	"github.com/guardtime/goksi/test"
)

func TestUnitRequestHeader(t *testing.T) {

	logger, defFunc, err := test.InitLogger(t, testLogDir, log.DEBUG, t.Name())
	if err != nil {
		t.Fatal("Failed to initialize logger: ", err)
	}
	defer defFunc()
	// Apply logger.
	log.SetLogger(logger)

	test.Suite{
		{Func: testHeaderDefault},
		{Func: testHeaderUseFunc},
		{Func: testHeaderWithNilReceiver},
		{Func: testHeaderFuncFail},
		{Func: testHeaderFuncFailExtError},
	}.Runner(t)
}

func testHeaderDefault(t *testing.T, _ ...interface{}) {
	var (
		testLoginID = "test"
	)

	hdr, err := NewHeader(testLoginID, nil)
	if err != nil {
		t.Fatal("Failed to create header: ", err)
	}

	if hdr.loginID == nil || *hdr.loginID != testLoginID {
		t.Fatal("Header login id mismatch.")
	}
	if hdr.instID != nil || hdr.msgID != nil {
		t.Fatal("Unexpected data in header.")
	}
}

func testHeaderWithNilReceiver(t *testing.T, _ ...interface{}) {
	var (
		nilHeader *Header
	)
	if _, err := nilHeader.InstanceID(); err == nil {
		t.Fatal("Should not be possible to get instance id from nil header.")
	}

	if _, err := nilHeader.LoginID(); err == nil {
		t.Fatal("Should not be possible to get login id from nil header.")
	}

	if _, err := nilHeader.MessageID(); err == nil {
		t.Fatal("Should not be possible to get message id from nil header.")
	}

	if err := nilHeader.SetInstID(uint64(1)); err == nil {
		t.Fatal("Should not be possible to set instance id to nil header.")
	}

	if err := nilHeader.SetMsgID(uint64(1)); err == nil {
		t.Fatal("Should not be possible to set message id to nil header.")
	}
}

func testHeaderFuncFail(t *testing.T, _ ...interface{}) {
	var (
		testLoginID   = "test"
		invalidHeader Header
	)

	hdr, err := NewHeader(testLoginID,
		func(h *Header) error {
			return errors.New(errors.KsiNotImplemented)
		})
	if err == nil {
		t.Fatal("Header construction must fail.")
	}
	if hdr != nil {
		t.Fatal("Failed constructor should not return an object.")
	}

	if _, err := invalidHeader.LoginID(); err == nil {
		t.Fatal("Getting login ID must fail as it is mandatory and is missing.")
	}
}

func testHeaderUseFunc(t *testing.T, _ ...interface{}) {
	var (
		testLoginID = "test"
		testInstID  = uint64(10)
		testMsgID   = uint64(100)
	)

	hdr, err := NewHeader(testLoginID,
		func(h *Header) error {
			if h == nil {
				return errors.New(errors.KsiInvalidArgumentError)
			}
			if err := h.SetInstID(testInstID); err != nil {
				return err
			}
			if err := h.SetMsgID(testMsgID); err != nil {
				return err
			}
			return nil
		})
	if err != nil {
		t.Fatal("Failed to create header: ", err)
	}

	lId, err := hdr.LoginID()
	if err != nil {
		t.Fatal("Failed to get login id: ", err)
	}
	if lId != testLoginID {
		t.Fatal("Header login id mismatch.")
	}

	iId, err := hdr.InstanceID()
	if err != nil {
		t.Fatal("Failed to get instance id: ", err)
	}
	if iId != testInstID {
		t.Fatal("Header instance id mismatch.")
	}

	mId, err := hdr.MessageID()
	if err != nil {
		t.Fatal("Failed to get message id: ", err)
	}
	if mId != testMsgID {
		t.Fatal("Header message id mismatch.")
	}
}

func testHeaderDefaults(t *testing.T, _ ...interface{}) {
	var (
		testLoginID = "Test Login ID"
	)
	hdr, err := NewHeader(testLoginID, nil)
	if err != nil {
		t.Fatal("Failed to create header: ", err)
	}

	iId, err := hdr.InstanceID()
	if err != nil {
		t.Fatal("Failed to get instance ID: ", err)
	}
	if iId != uint64(0) {
		t.Fatal("Header instance id mismatch, instance id did not default to zero: ", iId)
	}

	mId, err := hdr.MessageID()
	if err != nil {
		t.Fatal("Failed to get message ID: ", err)
	}
	if mId != uint64(0) {
		t.Fatal("Header message id mismatch, message id did not default to zero: ", mId)
	}

}

func testHeaderFuncFailExtError(t *testing.T, _ ...interface{}) {
	var (
		testLoginID = "test"
	)

	hdr, err := NewHeader(testLoginID,
		func(h *Header) error {
			return stderrors.New("std error")
		})
	if err == nil {
		t.Fatal("Header construction must fail.")
	}
	if hdr != nil {
		t.Fatal("Failed constructor should not return an object.")
	}
}
