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

package errors

import (
	"errors"
	"fmt"
	"reflect"
	"strconv"
	"strings"
	"testing"
)

func TestUnitNewError(t *testing.T) {
	e := New(KsiNetworkError)
	if e.errorCode != KsiNetworkError {
		t.Error("Error code mismatch.")
	}
	if !strings.Contains(e.Error(), KsiNetworkError.String()) {
		t.Error("Error() output must contain error string.")
	}
}

func TestUnitErrorStack(t *testing.T) {
	e := New(KsiNotImplemented).AppendMessage("KSI").AppendMessage("Blockchain")
	if e.Stack() == "" {
		t.Error("Error stack must be returned.")
	}
}

func TestUnitErrorSetters(t *testing.T) {
	const (
		errCode        = KsiNotImplemented
		msg            = "This is custom error message"
		extErrMsg      = "this is ext error"
		extErrCode int = 12345
	)
	e := New(errCode).AppendMessage(msg).SetExtError(errors.New(extErrMsg)).SetExtErrorCode(extErrCode)

	eString := e.Error()
	if !strings.Contains(eString, errCode.String()) {
		t.Error("Error() output must contain error string.")
	}
	if !strings.Contains(eString, msg) {
		t.Error("Error() output must contain message string.")
	}
	if !strings.Contains(eString, extErrMsg) {
		t.Error("Error() output must contain ext error string.")
	}
	if !strings.Contains(eString, strconv.Itoa(extErrCode)) {
		t.Error("Error() output must contain ext error code.")
	}
}

func TestUnitErrorAppendMessage(t *testing.T) {
	e := New(KsiNotImplemented).AppendMessage("KSI").AppendMessage("Blockchain")
	eString := e.Error()
	if !(strings.Contains(eString, "1: KSI") && strings.Contains(eString, "2: Blockchain")) {
		t.Error("Error() output error message mismatch.")
	}
}

func TestUnitErrorConvertKsiError(t *testing.T) {
	original := New(KsiInvalidArgumentError).AppendMessage("Dummy")
	processed := KsiErr(original)

	if original != processed {
		t.Error("KsiError pumped through KsiErr function must be exactly the same object but pointer values are different!")
	}

	messageListLen := len(processed.Message())
	if messageListLen != 1 {
		t.Fatal("Size of the message list is altered! Expected size is 1 but got %i!", messageListLen)
	}

	if processed.Code() != KsiInvalidArgumentError {
		t.Fatal("Error code is altered. Expecting %i but got %i", int(KsiInvalidArgumentError), int(processed.Code()))
	}

	if processed.ExtError() != nil {
		t.Fatal("It should have no external error appended but got: ", processed.ExtError())
	}
}

type MyError struct {
	errmsg string
}

func (e MyError) Error() string {
	return e.errmsg
}

func TestUnitErrorConvertExternalError(t *testing.T) {
	myerr := &MyError{"Dummy"}
	ksierr := KsiErr(myerr)

	if ksierr.ExtError() == nil {
		t.Fatal("External error must not be nil!")
	}

	myExtError, ok := ksierr.ExtError().(*MyError)
	if !ok {
		t.Fatal("Unexpected external error type. Expecting MyError but got ", reflect.TypeOf(ksierr.ExtError()))
	}

	if myExtError != myerr {
		t.Fatal("External error is not exactly the same object that was originally used!")
	}

	if myExtError.Error() != "Dummy" {
		msg := fmt.Sprintf("External error was altered. Expecting %s but got %s!", "Dummy", myExtError.Error())
		t.Fatal(msg)
	}

	if ksierr.Code() != KsiExternalError {
		t.Fatal("Error code does not match. Expecting %i but got %i", int(KsiExternalError), int(ksierr.Code()))
	}
}

func TestKsiErrWithNil(t *testing.T) {
	ksierr := KsiErr(nil)

	if ksierr != nil {
		t.Fatal("In case of nil input KsiErr must return nil!")
	}
}

func TestKsiErrWithMultipleCodes(t *testing.T) {
	dummyErr := &MyError{"Dummy"}
	ksiErr := KsiErr(dummyErr, KsiInvalidArgumentError, KsiInvalidStateError, KsiHmacMismatch)
	if ksiErr.Code() != KsiInvalidArgumentError {
		t.Fatal("Incorrect error code: ", ksiErr.Code())
	}
}

func TestErrWithMultipleCodes(t *testing.T) {
	dummyErr := New(KsiCryptoFailure)
	ksiErr := KsiErr(dummyErr, KsiInvalidArgumentError, KsiInvalidStateError, KsiHmacMismatch)
	if ksiErr.Code() != KsiCryptoFailure {
		t.Fatal("Incorrect error code: ", ksiErr.Code())
	}
}

func TestNilKsiError(t *testing.T) {
	var nilErr *KsiError
	val := nilErr.Error()
	if val != "" {
		t.Fatal("Unexpected error: ", val)
	}
}

func TestAppendMessageToNilKsiError(t *testing.T) {
	var nilErr *KsiError
	err := nilErr.AppendMessage("Some msg.")
	if err != nil {
		t.Fatal("It was possible to append message to nil ksi error: ", err)
	}
}

func TestSetExtErrorToNilKsiError(t *testing.T) {
	var nilErr *KsiError
	dummyErr := &MyError{"Dummy"}
	err := nilErr.SetExtError(dummyErr)
	if err != nil {
		t.Fatal("It was possible to set additional low level error to nil ksi error: ", err)
	}
}

func TestSetExtErrorCodeToNilKsiError(t *testing.T) {
	var nilErr *KsiError
	err := nilErr.SetExtErrorCode(15)
	if err != nil {
		t.Fatal("It was possible to set additional low level error code to nil ksi error: ", err)
	}
}

func TestGetCodeFromNilKsiError(t *testing.T) {
	var nilErr *KsiError
	err := nilErr.Code()
	if err != KsiNoError {
		t.Fatal("Unexpected error code: ", err)
	}
}

func TestGetStackFromNilKsiError(t *testing.T) {
	var nilErr *KsiError
	stack := nilErr.Stack()
	if stack != "" {
		t.Fatal("Stack should be empty but is not: ", stack)
	}
}

func TestGetExtCodeFromNilKsiError(t *testing.T) {
	var nilErr *KsiError
	extCode := nilErr.ExtCode()
	if extCode != 0 {
		t.Fatal("Unexpected ext code from nil ksi error: ", extCode)
	}
}

func TestGetExtErrorFromNilKsiError(t *testing.T) {
	var nilErr *KsiError
	extErr := nilErr.ExtError()
	if extErr != nil {
		t.Fatal("Unexpected ext error from nil ksi error: ", extErr)
	}
}

func TestGetMessageFromNilKsiError(t *testing.T) {
	var nilErr *KsiError
	msg := nilErr.Message()
	if msg != nil {
		t.Fatal("Message should be empty but was not: ", msg)
	}
}
