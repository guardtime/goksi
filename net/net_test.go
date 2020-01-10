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
	"testing"

	"github.com/guardtime/goksi/pdu"
)

func TestUnitNetClientHTTP(t *testing.T) {
	client, err := NewClient("ksi+http://some.url", "user", "pass")
	if err != nil {
		t.Fatal("Failed to create network client: ", err)
	}
	if client == nil {
		t.Fatal("Valid network client must be returned.")
	}
	if _, ok := client.(*httpClient); !ok {
		t.Fatal("Wrong network client returned.")
	}
}

func TestUnitNetClientHTTPreadLimitOpt(t *testing.T) {
	client, err := NewClient("ksi+http://some.url", "user", "pass", ClientOptReadLimit(4000))
	if err != nil {
		t.Fatal("Failed to create network client: ", err)
	}
	if client == nil {
		t.Fatal("Valid network client must be returned.")
	}

	c, ok := client.(*httpClient)
	if !ok {
		t.Fatal("Wrong network client returned.")
	}

	if c.readLimit != 4000 {
		t.Fatal(fmt.Sprintf("Size limit is %v but expecting 4000!", c.readLimit))
	}
}

func TestUnitNetClientUsrInfFromURI(t *testing.T) {
	client, err := NewClient("ksi+http://lid:key@some.url", "", "")
	if err != nil {
		t.Fatal("Failed to create network client: ", err)
	}
	if client.LoginID() != "lid" || client.Key() != "key" {
		t.Fatal("Wrong credentials.")
	}
}

func TestUnitNetTcpClientUsrInfFromURI(t *testing.T) {
	client, err := NewClient("ksi+tcp://lid:key@some.url", "", "")
	if err != nil {
		t.Fatal("Failed to create network client: ", err)
	}
	if client.LoginID() != "lid" || client.Key() != "key" {
		t.Fatal("Wrong credentials.")
	}
}

func TestUnitNetHttpClientUri(t *testing.T) {
	var (
		httpUri = "http://lid:key@some.url"
	)
	client, err := NewClient("ksi+"+httpUri, "", "")
	if err != nil {
		t.Fatal("Failed to create network client: ", err)
	}
	if client.URI() != httpUri {
		t.Fatal("Wrong URI: ", client.URI())
	}
}

func TestUnitNetClientTCP(t *testing.T) {
	client, err := NewClient("ksi+tcp://some.url", "user", "pass")
	if err != nil {
		t.Fatal("Failed to create network client: ", err)
	}
	if client == nil {
		t.Fatal("Valid network client must be returned.")
	}
	c, ok := client.(*tcpClient)
	if !ok {
		t.Fatal("Wrong network client returned.")
	}
	if c.readLimit != uint32(pdu.MaxSize) {
		t.Fatal("Read limit was not set to max: ", c.readLimit)
	}
}

func TestUnitNetClientTCPreadLimitOpt(t *testing.T) {
	client, err := NewClient("ksi+tcp://some.url", "user", "pass", ClientOptReadLimit(4000))
	if err != nil {
		t.Fatal("Failed to create network client: ", err)
	}
	if client == nil {
		t.Fatal("Valid network client must be returned.")
	}

	c, ok := client.(*tcpClient)
	if !ok {
		t.Fatal("Wrong network client returned.")
	}

	if c.readLimit != 4000 {
		t.Fatal(fmt.Sprintf("Size limit is %v but expecting 4000!", c.readLimit))
	}
}

func TestUnitNetClientOptionNil(t *testing.T) {
	client, err := NewClient("http://some.url", "user", "pass", nil)
	if err == nil {
		t.Fatal("Nil option must fail.")
	}
	if client != nil {
		t.Fatal("Network client must be nil.")
	}
}

func TestUnitNetClientOptionListEmpty(t *testing.T) {
	var options []ClientOpt
	client, err := NewClient("http://some.url", "user", "pass", options...)
	if err != nil {
		t.Fatal("Failed to create network client: ", err)
	}
	if client == nil {
		t.Fatal("Valid network client must be returned.")
	}
}

func TestUnitNetOptionReadLimitWithNilReceiver(t *testing.T) {
	opt := ClientOptReadLimit(123456)
	if err := opt(nil); err == nil {
		t.Fatal("Should not be possible to set read limit to nil client.")
	}
}

func TestUnitNetOptionReadLimitWithNotInitializedClient(t *testing.T) {
	var client Client
	opt := ClientOptReadLimit(123456)
	if err := opt(client); err == nil {
		t.Fatal("Should not be possible to set read limit to not initialized.")
	}
}

func TestUnitNetClientUrls(t *testing.T) {
	var (
		testData = []struct {
			url string
			usr string
			key string
		}{
			{"ksi+http://some.url", "user", "pass"},
			{"http://some.url", "user", "pass"},
			{"ksi+http://some.url:1234", "user", "pass"},
			{"ksi+http://u:k@some.url:1234", "user", "pass"},
			{"ksi+http://u:k@some.url:1234", "", ""},
			{"ksi+tcp://some.url", "user", "pass"},
			{"tcp://some.url", "user", "pass"},
		}
	)

	for _, d := range testData {
		client, err := NewClient(d.url, d.usr, d.key)
		if err != nil {
			t.Fatal("Failed to create network client: ", err)
		}
		if client == nil {
			t.Fatal("Valid network client must be returned.")
		}
	}
}

func TestUnitNetClientFailUrls(t *testing.T) {
	var (
		testData = []struct {
			url string
			usr string
			key string
		}{
			{"http//some.url", "user", "pass"},
			{"u:k:some.url", "user", "pass"},
			{"htt://some.url", "user", "pass"},
			{"test://some.url", "user", "pass"},
			{"some.url", "user", "pass"},
			{"", "user", "pass"},
			{"not url", "user", "pass"},
			{"notEscapedSymbol:!&\"#(/)=;_%'*", "user", "pass"},
			{string([]byte{10, 20, 30, 40, 50, 60, 70, 80, 90, 100}), "user", "pass"},
		}
	)

	for _, d := range testData {
		client, err := NewClient(d.url, d.usr, d.key)
		if err == nil {
			t.Error("Constructor must fail.")
		}
		if client != nil {
			t.Fatal("Failed constructor must not return client.")
		}
	}
}

func TestUnitTcpClientRequestCountFromNilClient(t *testing.T) {
	var client *tcpClient
	if val := client.RequestCount(); val != 0 {
		t.Fatal("Should not be possible to get request count from nil client.")
	}
}

func TestUnitTcpClientURIFromNilClient(t *testing.T) {
	var client *tcpClient
	if val := client.URI(); val != "" {
		t.Fatal("Should not be possible to get uri from nil client.")
	}
}

func TestUnitTcpClientURI(t *testing.T) {
	client := newTCPClient("tcp://some.url", "1234")
	if val := client.URI(); val != "" {
		t.Fatal("TCP client URI must be empty.")
	}
}

func TestUnitTcpClientLoginIdFromNilClient(t *testing.T) {
	var client *tcpClient
	if val := client.LoginID(); val != "" {
		t.Fatal("Should not be possible to get login id from nil client.")
	}
}

func TestUnitTcpClientKeyFromNilClient(t *testing.T) {
	var client *tcpClient
	if val := client.Key(); val != "" {
		t.Fatal("Should not be possible to get key from nil client.")
	}
}

func TestUnitTcpClientSetReadLimitToNilClient(t *testing.T) {
	var client *tcpClient
	if err := client.SetReadLimit(123); err == nil {
		t.Fatal("Should not be possible to set read limit to nil client.")
	}
}

func TestUnitHttpClientRequestCountFromNilClient(t *testing.T) {
	var client *httpClient
	if val := client.RequestCount(); val != 0 {
		t.Fatal("Should not be possible to get request count from nil client.")
	}
}

func TestUnitHttpClientURIFromNilClient(t *testing.T) {
	var client *httpClient
	if val := client.URI(); val != "" {
		t.Fatal("Should not be possible to get uri from nil client.")
	}
}

func TestUnitHttpClientLoginIdFromNilClient(t *testing.T) {
	var client *httpClient
	if val := client.LoginID(); val != "" {
		t.Fatal("Should not be possible to get login id from nil client.")
	}
}

func TestUnitHttpClientKeyFromNilClient(t *testing.T) {
	var client *httpClient
	if val := client.Key(); val != "" {
		t.Fatal("Should not be possible to get key from nil client.")
	}
}

func TestUnitHttpClientSetReadLimitToNilClient(t *testing.T) {
	var client *httpClient
	if err := client.SetReadLimit(123); err == nil {
		t.Fatal("Should not be possible to set read limit to nil client.")
	}
}

func TestUnitHttpClientReceiveFromNilClient(t *testing.T) {
	var client *httpClient
	if _, err := client.Receive(nil, []byte{0x12}); err == nil {
		t.Fatal("Should not be possible to Receive with nil client.")
	}
}

func TestUnitTcpClientReceiveFromNilClient(t *testing.T) {
	var client *tcpClient
	if _, err := client.Receive(nil, []byte{0x12}); err == nil {
		t.Fatal("Should not be possible to Receive with nil client.")
	}
}

func TestUnitHttpClientReceiveFromNotExistingEndpoint(t *testing.T) {
	client := newHTTPClient("http://some.url", false)
	if _, err := client.Receive(nil, []byte{0x12}); err == nil {
		t.Fatal("Should not be possible to Receive from not existing endpoint.")
	}
}

func TestUnitTcpClientReceiveFromNotExistingEndpoint(t *testing.T) {
	client := newTCPClient("http://some.url", "1234")
	if _, err := client.Receive(nil, []byte{0x12}); err == nil {
		t.Fatal("Should not be possible to Receive from not existing endpoint.")
	}
}
