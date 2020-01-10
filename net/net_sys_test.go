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

package net

import (
	"fmt"
	"path/filepath"
	"testing"
	"time"

	"github.com/guardtime/goksi/errors"
	"github.com/guardtime/goksi/test/sysconf"
	"github.com/guardtime/goksi/test/utils"
)

var (
	testRoot     = filepath.Join("..", "test")
	testConfFile = filepath.Join(testRoot, "systest.conf.json")
)

func TestSysHTTPClientRequest(t *testing.T) {
	// Check if system test config is present and load it.
	cfg := utils.LoadConfigFile(t, testConfFile)

	client, err := NewClient(cfg.Aggregator.BuildURI(cfg.Schema.Http), cfg.Aggregator.User, cfg.Aggregator.Pass)
	if err != nil {
		t.Fatal("Failed to create network client: ", err)
	}
	if client == nil {
		t.Fatal("Valid network client must be returned.")
	}
	if _, ok := client.(*httpClient); !ok {
		t.Fatal("Wrong network client returned.")
	}

	resp, err := client.Receive(nil, []byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9})
	if err == nil {
		t.Error("The HTTP request with HTTP error code.")
	}
	ksiErr, ok := err.(*errors.KsiError)
	if !ok {
		t.Fatal("Must fail with KsiError.")
	}
	if ksiErr.Code() != errors.KsiHttpError {
		t.Error("Error code mismatch: ", ksiErr)
	}
	if resp == nil {
		t.Error("A reduced error PDU must have been received.")
	}
}

func TestSysHTTPClientGet(t *testing.T) {
	// Check if system test config is present and load it.
	cfg := utils.LoadConfigFile(t, testConfFile)

	client := newHTTPClient(cfg.Pubfile.Url, false)
	if client == nil {
		t.Fatal("Valid network client must be returned.")
	}

	resp, err := client.Receive(nil, nil)
	if err != nil {
		t.Fatal("HTTP request failed:", err)
	}
	if resp == nil {
		t.Error("File must have been received.")
	}
}

func TestSysTCPClient(t *testing.T) {
	// Check if system test config is present and load it.
	cfg := utils.LoadConfigFile(t, testConfFile)

	client, err := NewClient(cfg.Aggregator.BuildURI(cfg.Schema.Tcp), cfg.Aggregator.User, cfg.Aggregator.Pass)
	if err != nil {
		t.Fatal("Failed to create network client: ", err)
	}
	if client == nil {
		t.Fatal("Valid network client must be returned.")
	}
	if _, ok := client.(*tcpClient); !ok {
		t.Fatal("Wrong network client returned.")
	}

	resp, err := client.Receive(nil, []byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9})
	if err != nil {
		t.Error("TCP should not return with error: ", err)
	}
	if resp == nil {
		t.Error("A reduced error PDU must have been received.")
	}
}

func TestSysHTTPClientLimit(t *testing.T) {
	// Check if system test config is present and load it.
	cfg := utils.LoadConfigFile(t, testConfFile)

	client := newHTTPClient(cfg.Pubfile.Url, false)
	if client == nil {
		t.Fatal("Valid network client must be returned.")
	}
	client.readLimit = 10
	_ = client.SetVerifier(nil)

	resp, err := client.Receive(nil, nil)
	if err != nil {
		t.Fatal("HTTP request failed:", err)
	}
	if resp == nil {
		t.Error("File must have been received.")
	}
	if len(resp) != 10 {
		t.Fatal(fmt.Sprintf("Expecting 10 bytes of data but got %v!", len(resp)))
	}
}

func TestSysTCPClientLimit(t *testing.T) {
	// Check if system test config is present and load it.
	cfg := utils.LoadConfigFile(t, testConfFile)

	client, err := NewClient(cfg.Aggregator.BuildURI(cfg.Schema.Tcp), cfg.Aggregator.User, cfg.Aggregator.Pass,
		ClientOptReadLimit(10),
		ClientOptDatagramVerifier(nil))
	if err != nil || client == nil {
		t.Fatal("Failed to create network client: ", err)
	}

	resp, err := client.Receive(nil, []byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9})
	if err != nil {
		t.Error("TCP should not return with error: ", err)
	}
	if resp == nil {
		t.Error("Response must not be nil.")
	}
	if len(resp) != 10 {
		t.Fatal(fmt.Sprintf("Expecting 10 bytes of data but got %v!", len(resp)))
	}
}

func TestSysTCPClientCustomVerifier(t *testing.T) {
	// Check if system test config is present and load it.
	cfg := utils.LoadConfigFile(t, testConfFile)

	client, err := NewClient(cfg.Aggregator.BuildURI(cfg.Schema.Tcp), cfg.Aggregator.User, cfg.Aggregator.Pass,
		ClientOptReadLimit(10),
		ClientOptDatagramVerifier(func(_ []byte) (bool, error) {
			return false, errors.New(errors.KsiNotImplemented)
		}),
	)
	if err != nil || client == nil {
		t.Fatal("Failed to create network client: ", err)
	}
	testClientCustomVerifier(t, client)
}

func TestSysHTTPClientCustomVerifier(t *testing.T) {
	// Check if system test config is present and load it.
	cfg := utils.LoadConfigFile(t, testConfFile)

	client, err := NewClient(cfg.Aggregator.BuildURI(cfg.Schema.Http), cfg.Aggregator.User, cfg.Aggregator.Pass,
		ClientOptReadLimit(10),
		ClientOptDatagramVerifier(func(_ []byte) (bool, error) {
			return false, errors.New(errors.KsiNotImplemented)
		}),
	)
	if err != nil || client == nil {
		t.Fatal("Failed to create network client: ", err)
	}
	testClientCustomVerifier(t, client)
}

func testClientCustomVerifier(t *testing.T, client Client) {
	resp, err := client.Receive(nil, []byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9})
	if err == nil {
		t.Error("Error must be returned")
	}
	if resp != nil {
		t.Error("No response should be returned.")
	}
	if err.(*errors.KsiError).ExtError().(*errors.KsiError).Code() != errors.KsiNotImplemented {
		t.Error("Wrong error returned from datagram verifier: ", err)
	}
}

func TestSysHTTPClientTimeout(t *testing.T) {
	cfg := utils.LoadConfigFile(t, testConfFile)

	testClientRequestTimeout(t, cfg, cfg.Schema.Http)
}

func TestSysTCPClientTimeout(t *testing.T) {
	cfg := utils.LoadConfigFile(t, testConfFile)

	testClientRequestTimeout(t, cfg, cfg.Schema.Tcp)
}

func testClientRequestTimeout(t *testing.T, cfg *sysconf.Configuration, schema string) {
	testTimeouts := []byte{0, 1, 10, 100}

	for _, timeout := range testTimeouts {
		client, err := NewClient(cfg.Aggregator.BuildURI(schema), cfg.Aggregator.User, cfg.Aggregator.Pass,
			ClientOptRequestTimeout(timeout),
		)
		if err != nil {
			t.Fatal("Failed to create network client: ", err)
		}
		var implTimeout time.Duration
		switch impl := client.(type) {
		case *tcpClient:
			implTimeout = impl.timeout
		case *httpClient:
			implTimeout = impl.timeout
		default:
			t.Fatal("Wrong network client returned.")
		}
		if implTimeout != time.Duration(timeout)*time.Second {
			t.Fatal("Network client timeout mismatch.")
		}
	}
}
