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

package log

import (
	"bytes"
	"strings"
	"testing"
)

func TestUnitSetLogger(t *testing.T) {
	if logger != nil {
		t.Fatal("Default logger must be disabled.")
	}

	b := new(bytes.Buffer)
	l, err := New(DEBUG, b)
	if err != nil {
		t.Fatal("Failed to create new logger:", err)
	}
	SetLogger(l)
	if logger == nil || logger != l {
		t.Fatal("Logger mismatch.")
	}

	SetLogger(nil)
	if logger != nil {
		t.Fatal("Default logger must be disabled.")
	}
}

func TestUnitDisabled(t *testing.T) {
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("Disabled logger must not fail: %s.", r)
		}
	}()

	SetLogger(nil)

	tmp := "This is a Log message."
	Debug(tmp)
	Info(tmp)
	Notice(tmp)
	Warning(tmp)
	Error(tmp)
}

func TestUnitDebug(t *testing.T) {
	var b bytes.Buffer
	l, err := New(DEBUG, &b)
	if err != nil {
		t.Fatal("Failed to create new logger:", err)
	}
	SetLogger(l)

	tmp := "This is a Debug message."
	Debug(tmp)
	if !(strings.Contains(b.String(), "[D]") && strings.Contains(b.String(), tmp)) {
		t.Error("Failed to find debug message.")
	}
	tmp = "This is a Info message."
	Info(tmp)
	if !(strings.Contains(b.String(), "[I]") && strings.Contains(b.String(), tmp)) {
		t.Error("Failed to find info message.")
	}
	tmp = "This is a Notice message."
	Notice(tmp)
	if !(strings.Contains(b.String(), "[N]") && strings.Contains(b.String(), tmp)) {
		t.Error("Failed to find notice message.")
	}
	tmp = "This is a Warning message."
	Warning(tmp)
	if !(strings.Contains(b.String(), "[W]") && strings.Contains(b.String(), tmp)) {
		t.Error("Failed to find Warning message.")
	}
	tmp = "This is a Error message."
	Error(tmp)
	if !(strings.Contains(b.String(), "[E]") && strings.Contains(b.String(), tmp)) {
		t.Error("Failed to find Error message.")
	}
}

func TestUnitError(t *testing.T) {
	var b bytes.Buffer
	l, err := New(ERROR, &b)
	if err != nil {
		t.Fatal("Failed to create new logger:", err)
	}
	SetLogger(l)

	tmp := "This is a Debug message."
	Debug(tmp)
	if strings.Contains(b.String(), "[D]") && strings.Contains(b.String(), tmp) {
		t.Error("Debug message must not be added.")
	}
	tmp = "This is a Info message."
	Info(tmp)
	if strings.Contains(b.String(), "[I]") && strings.Contains(b.String(), tmp) {
		t.Error("Info message must not be added.")
	}
	tmp = "This is a Notice message."
	Notice(tmp)
	if strings.Contains(b.String(), "[N]") && strings.Contains(b.String(), tmp) {
		t.Error("Notice message must not be added.")
	}
	tmp = "This is a Warning message."
	Warning(tmp)
	if strings.Contains(b.String(), "[W]") && strings.Contains(b.String(), tmp) {
		t.Error("Warning message must not be added.")
	}
	tmp = "This is a Error message."
	Error(tmp)
	if !(strings.Contains(b.String(), "[E]") && strings.Contains(b.String(), tmp)) {
		t.Error("Failed to find Error message.")
	}
}
