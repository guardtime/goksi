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

package publications

import (
	"path/filepath"
	"testing"

	"github.com/guardtime/goksi/log"
	"github.com/guardtime/goksi/test"
	"github.com/guardtime/goksi/test/sysconf"
	"github.com/guardtime/goksi/test/utils"
)

var (
	testConfFile = filepath.Join(testRoot, "systest.conf.json")
)

func TestSysFileHTTP(t *testing.T) {
	logger, defFunc, err := test.InitLogger(t, testLogDir, log.DEBUG, t.Name())
	if err != nil {
		t.Fatal("Failed to initialize logger: ", err)
	}
	defer defFunc()
	// Apply logger.
	log.SetLogger(logger)

	// Check if system test config is present and load it.
	cfg := utils.LoadConfigFile(t, testConfFile)

	pfh, err := NewFileHandler(
		FileHandlerSetPublicationsURL(cfg.Pubfile.Url),
		FileHandlerSetFileCertConstraints(cfg.Pubfile.Constraints()),
	)
	if err != nil {
		t.Fatal("Failed to initialize publications file handler: ", err)
	}

	test.Suite{
		{Func: testPubFileFromURL},
		{Func: testPubFileReceive},
		{Func: testPubFileReceiveWithinTTL},
		{Func: testPubFileReceiveInvalidCnstr},
	}.Runner(t, pfh, &cfg.Pubfile)
}

const (
	pfTestOptPfh = iota
	pfTestOptPfc
)

func testPubFileFromURL(t *testing.T, opt ...interface{}) {
	var (
		testPubFileCfg = opt[pfTestOptPfc].(*sysconf.Pubfile)
	)

	pubFile, err := NewFile(FileFromURL(testPubFileCfg.Url))
	if err != nil {
		t.Fatal("Failed to create publications file: ", err)
	}

	if pubFile == nil {
		t.Fatal("No file returned.")
	}

	if err := opt[pfTestOptPfh].(*FileHandler).Verify(pubFile); err != nil {
		t.Fatal("Failed to verify publications file: ", err)
	}
}

func testPubFileReceive(t *testing.T, opt ...interface{}) {
	pfh := opt[pfTestOptPfh].(*FileHandler)
	pubFile, err := pfh.ReceiveFile()
	if err != nil {
		t.Fatal("Failed to create publications file: ", err)
	}
	if pubFile == nil {
		t.Fatal("No file returned.")
	}

	if err := pfh.Verify(pubFile); err != nil {
		t.Fatal("Failed to verify publications file: ", err)
	}
}

func testPubFileReceiveInvalidCnstr(t *testing.T, opt ...interface{}) {

	pfh, err := NewFileHandler(
		FileHandlerSetPublicationsURL(opt[pfTestOptPfc].(*sysconf.Pubfile).Url),
		FileHandlerSetFileCertConstraint(OidEmail, "its@not.working"),
	)
	if err != nil {
		t.Fatal("Failed to initialize publications file handler: ", err)
	}

	pubFile, err := pfh.ReceiveFile()
	if err != nil {
		t.Fatal("Failed to create publications file: ", err)
	}
	if pubFile == nil {
		t.Fatal("No file returned.")
	}

	if err := pfh.Verify(pubFile); err == nil {
		t.Fatal("Publications file verification must fail.")
	}
}

func testPubFileReceiveWithinTTL(t *testing.T, opt ...interface{}) {
	pfh := opt[pfTestOptPfh].(*FileHandler)
	pubFile1, err := pfh.ReceiveFile()
	if err != nil {
		t.Fatal("Failed to create publications file: ", err)
	}

	pubFile2, err := pfh.ReceiveFile()
	if err != nil {
		t.Fatal("Failed to create publications file: ", err)
	}

	if pubFile1 == nil || pubFile2 == nil {
		t.Fatal("No file returned.")
	}

	if pubFile1 != pubFile2 {
		t.Fatal("Same file must be returned.")
	}
}
