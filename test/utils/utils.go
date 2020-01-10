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

package utils

import (
	"encoding/hex"
	"os"
	"testing"

	"github.com/guardtime/goksi/test/sysconf"
)

func StringToBin(s string) []byte {
	if s == "" {
		panic("String is empty!")
	}
	h, err := hex.DecodeString(s)
	if err != nil {
		panic(err)
	}
	return h
}

func LoadConfigFile(t *testing.T, testConfFile string) *sysconf.Configuration {
	if _, err := os.Stat(testConfFile); err != nil {
		t.Skip("Skipping test: system test config file not found.")
	}

	cfg, err := sysconf.New(testConfFile)
	if err != nil {
		t.Fatal("Failed to load configuration: ", err)
	}
	return cfg
}
