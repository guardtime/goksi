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

package test

import (
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"testing"

	"github.com/guardtime/goksi/log"
)

// Case is a test case.
type Case struct {
	Func func(t *testing.T, opts ...interface{})
}

// Suite is a collection of test cases.
type Suite []Case

// Runner runs every test case in the receiver test suite.
func (ts Suite) Runner(t *testing.T, opts ...interface{}) {
	t.Helper()

	for _, tc := range ts {
		tcName := runtime.FuncForPC(reflect.ValueOf(tc.Func).Pointer()).Name()
		log.Debug("---- :::: Run test case: ", tcName, " :::: ----")
		t.Run(tcName, func(t *testing.T) { tc.Func(t, opts...) })
	}
}

func InitLogger(t *testing.T, path string, level log.Priority, name string) (logger log.Logger, fClose func(), err error) {
	t.Helper()

	defer func() {
		if err != nil && fClose != nil {
			fClose()
			fClose = nil
		}
	}()

	// Initialize test output directory.
	err = os.MkdirAll(path, os.ModePerm)
	if err != nil {
		return
	}
	// Create log file.
	logFile, err := os.Create(filepath.Join(path, strings.Join([]string{name, "log"}, ".")))
	if err != nil {
		return
	}
	fClose = func() { _ = logFile.Close() }
	// Initialize logger.
	logger, err = log.New(level, logFile)
	if err != nil {
		return
	}
	return
}
