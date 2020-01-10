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

package mock

import (
	"context"
	"io/ioutil"
	"sync/atomic"

	"github.com/guardtime/goksi/log"
)

// RequestCounterClient implements net.(Client) interface.
// Only increases the request counter atomically.
type RequestCounterClient struct {
	count uint64
	resp  []byte
}

func (c *RequestCounterClient) RequestCount() uint64 { return atomic.AddUint64(&c.count, 1) }
func (c *RequestCounterClient) URI() string          { return "" }
func (c *RequestCounterClient) LoginID() string      { return "MockUser" }
func (c *RequestCounterClient) Key() string          { return "MockPass" }
func (c *RequestCounterClient) Receive(_ context.Context, _ []byte) ([]byte, error) {
	return c.resp, nil
}

// Helper methods for setting desired response to be returned via Receive() method.
func (c *RequestCounterClient) SetResp(r []byte) { c.resp = r }

// FileReaderClient implements net.(Client) interface. Enables to return binary responses from files on the filesystem.
// The request counter is always 1.
type FileReaderClient struct {
	uri string
	usr string
	key string
}

func NewFileReaderClient(path, user, pass string) *FileReaderClient {
	return &FileReaderClient{
		uri: path,
		usr: user,
		key: pass,
	}
}

func (c *FileReaderClient) RequestCount() uint64 { return 1 }
func (c *FileReaderClient) URI() string          { return c.uri }
func (c *FileReaderClient) LoginID() string      { return c.usr }
func (c *FileReaderClient) Key() string          { return c.key }
func (c *FileReaderClient) Receive(_ context.Context, _ []byte) ([]byte, error) {
	log.Debug("Response path: ", c.uri)
	return ioutil.ReadFile(c.uri)
}
