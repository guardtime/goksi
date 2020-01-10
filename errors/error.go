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

// Package errors implements functions to manipulate KSI errors.
//
//
package errors

import (
	"fmt"
	"runtime"
	"strings"
)

// KsiError ...
type KsiError struct {
	errorCode    ErrorCode
	message      []string
	extError     error
	extErrorCode int
	errorStack   string
}

// New construct a new KsiError.
func New(code ErrorCode) *KsiError {
	return &KsiError{
		errorCode:  code,
		errorStack: stack(),
	}
}

// KsiErr wraps the provided error into KsiError, if the input is not KsiError. By default the error code is set to
// KsiExternalError. In case the 'err' parameter is of type KsiError, the original error is returned without any modification.
//
// Optionally an error code can be provided, which will be applied in case of external error. Note, despite the fact
// that 'code' parameter is a variadic value, only one error code should be provided.
func KsiErr(err error, code ...ErrorCode) *KsiError {
	if err == nil {
		return nil
	}

	errCode := KsiExternalError
	if len(code) != 0 {
		errCode = code[0]
	}

	ksiErr, ok := err.(*KsiError)
	if !ok {
		ksiErr = New(errCode).SetExtError(err)
	}
	return ksiErr
}

func stack() string {
	buf := make([]byte, 1024)
	n := 0
	for {
		n = runtime.Stack(buf, false)
		if n < len(buf) {
			break
		}
		buf = make([]byte, 2*len(buf))
	}

	return string(buf[:n])
}

// Error implements error interface.
func (e *KsiError) Error() string {
	if e == nil {
		return ""
	}

	var b strings.Builder
	b.WriteString(fmt.Sprintf("[%04x/%d] %s.\n", uint16(e.errorCode), e.extErrorCode, e.errorCode.String()))

	if len(e.message) > 0 {
		b.WriteString("Error message:")
		for i := len(e.message); i > 0; i-- {
			b.WriteString(fmt.Sprintf("\n  %d: %s", i, e.message[i-1]))
		}
		b.WriteString("\n")
	}

	if e.extError != nil {
		b.WriteString(fmt.Sprintf("Extended error: %s\n", e.extError))
	}

	if len(e.errorStack) != 0 {
		b.WriteString(fmt.Sprintf("%s", e.errorStack))
	}

	b.WriteString("\n")
	return b.String()
}

// AppendMessage allows to add an additional descriptive message to the error.
// Returns an updated reference of the receiver KsiError.
func (e *KsiError) AppendMessage(msg string) *KsiError {
	if e == nil {
		return nil
	}
	e.message = append(e.message, msg)
	return e
}

// SetExtError allows to set an additional low-level error.
// Returns an updated reference of the receiver KsiError.
func (e *KsiError) SetExtError(err error) *KsiError {
	if e == nil {
		return nil
	}
	e.extError = err
	return e
}

// SetExtErrorCode allows to set an additional low-level error code.
// Returns an updated reference of the receiver KsiError.
func (e *KsiError) SetExtErrorCode(c int) *KsiError {
	if e == nil {
		return nil
	}
	e.extErrorCode = c
	return e
}

// Code returns the error code.
func (e *KsiError) Code() ErrorCode {
	if e == nil {
		return KsiNoError
	}
	return e.errorCode
}

// Stack returns the stack trace where the error occurred.
func (e *KsiError) Stack() string {
	if e == nil {
		return ""
	}
	return e.errorStack
}

// ExtCode returns extended error code.
func (e *KsiError) ExtCode() int {
	if e == nil {
		return 0
	}
	return e.extErrorCode
}

// ExtError returns extended error.
func (e *KsiError) ExtError() error {
	if e == nil {
		return nil
	}
	return e.extError
}

// Message returns additional appended messages.
func (e *KsiError) Message() []string {
	if e == nil {
		return nil
	}
	return e.message
}
