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

package service

import (
	"testing"

	"github.com/guardtime/goksi/hash"
	"github.com/guardtime/goksi/log"
	"github.com/guardtime/goksi/test"
	"github.com/guardtime/goksi/test/utils/mock"
)

func TestUnitService(t *testing.T) {

	logger, defFunc, err := test.InitLogger(t, testLogDir, log.DEBUG, t.Name())
	if err != nil {
		t.Fatal("Failed to initialize logger: ", err)
	}
	defer defFunc()
	// Apply logger.
	log.SetLogger(logger)

	test.Suite{
		{Func: testServiceDefaultSettings},
		{Func: testServiceOptNetClient},
		{Func: testServiceOptEndpoint},
		{Func: testServiceCustomHmacAlgorithm},
		{Func: testServiceCustomHmacAlgorithmUnsupported},
	}.Runner(t)
}

func testServiceDefaultSettings(t *testing.T, _ ...interface{}) {
	srv, err := newBasicService()
	if err != nil {
		t.Fatal("Failed to create basicService: ", err)
	}

	if err := srv.initialize(srvOptNetClient(&mock.RequestCounterClient{})); err != nil {
		t.Fatal("Failed to initialize basicService: ", err)
	}

	if srv.hmacAlgo != hash.Default {
		t.Error("Default hash algorithm mismatch.")
	}
}

func testServiceOptNetClient(t *testing.T, _ ...interface{}) {
	srv, err := newBasicService()
	if err != nil {
		t.Fatal("Failed to create basicService: ", err)
	}

	if err := srv.initialize(srvOptNetClient(&mock.RequestCounterClient{})); err != nil {
		t.Fatal("Failed to create basicService: ", err)
	}

	if _, ok := srv.netClient.(*mock.RequestCounterClient); !ok {
		t.Error("Network client mismatch.")
	}
}

func testServiceOptEndpoint(t *testing.T, _ ...interface{}) {
	srv, err := newBasicService()
	if err != nil {
		t.Fatal("Failed to create basicService: ", err)
	}

	if err := srv.initialize(srvOptEndpoint("ksi+http://some.url", "usr", "key")); err != nil {
		t.Fatal("Failed to initialize basicService: ", err)
	}
}

func testServiceCustomHmacAlgorithm(t *testing.T, _ ...interface{}) {
	var (
		testAlgo = hash.SHA2_512
	)
	if testAlgo == hash.Default {
		t.Fatal("Test algorithm is defined as default: ", testAlgo)
	}

	srv, err := newBasicService()
	if err != nil {
		t.Fatal("Failed to create basicService: ", err)
	}
	err = srv.initialize(
		srvOptNetClient(&mock.RequestCounterClient{}),
		srvOptHmacAlgorithm(testAlgo),
	)
	if err != nil {
		t.Fatal("Failed to initialize basicService: ", err)
	}

	if srv.hmacAlgo != testAlgo {
		t.Error("basicService hmac algorithm mismatch.")
	}
}

func testServiceCustomHmacAlgorithmUnsupported(t *testing.T, _ ...interface{}) {
	var (
		testAlgo = hash.SHA_NA
	)

	srv, err := newBasicService()
	if err != nil {
		t.Fatal("Failed to create basicService: ", err)
	}
	err = srv.initialize(
		srvOptNetClient(&mock.RequestCounterClient{}),
		srvOptHmacAlgorithm(testAlgo),
	)
	if err == nil {
		t.Fatal("Initializer must fail.")
	}
}
