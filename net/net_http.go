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
	"bytes"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net/http"
	"sync/atomic"
	"time"

	"github.com/guardtime/goksi/errors"
	"github.com/guardtime/goksi/log"
)

type httpClient struct {
	url          string
	loginID      string
	key          string
	timeout      time.Duration
	ksi          bool
	requestCount uint64
	readLimit    uint32
	isComplete   ResponseVerifierFunc
}

func newHTTPClient(url string, isKSI bool) *httpClient {
	return &httpClient{
		url:        url,
		timeout:    defaultRequestTimeout * time.Second,
		ksi:        isKSI,
		readLimit:  0,
		isComplete: isTlvComplete,
	}
}

// setupClient returns a new HTTP Client.
//
// ## Proxy Configuration ##
// To use a proxy, you need to configure the proxy on your operating system.
// Set the system environment variable: `http_proxy=user:pass@server:port`.
//
// In the Windows control panel:
//  1. Find the 'System' page and select 'Advanced system settings';
//  2. Select 'Environment Variables...';
//  3. Select 'New...' to create a new system variable;
//  4. Enter `http_proxy` in the name field and add proxy configuration (see above) in the value field.
//
// In Linux add the system variable to `/etc/bashrc`:
// 	`export http_proxy=user:pass@server:port`
func (c *httpClient) setupClient() (*http.Client, error) {
	if c == nil {
		return nil, errors.New(errors.KsiInvalidArgumentError)
	}

	// Adding the Transport object to the HTTP Client.
	client := &http.Client{
		Timeout: time.Duration(c.timeout),
		// Adding the proxy settings to the Transport object.
		Transport: &http.Transport{
			// DisableKeepAlives: true, using 'httpReq.Close = true' fro now
			Proxy:           http.ProxyFromEnvironment,
			TLSClientConfig: &tls.Config{},
		},
	}

	return client, nil
}

// Receive implements Client.Receive().
func (c *httpClient) Receive(ctx context.Context, request []byte) (b []byte, e error) {
	if c == nil {
		return nil, errors.New(errors.KsiInvalidArgumentError)
	}

	var (
		httpReq *http.Request
		err     error
	)
	if request != nil {
		log.Debug(fmt.Sprintf("HTTP send (%s): %x", c.url, request))

		if httpReq, err = http.NewRequest(http.MethodPost, c.url, bytes.NewBuffer(request)); err != nil {
			return nil, errors.New(errors.KsiNetworkError).SetExtError(err)
		}
		// Update header in case of KSI endpoint.
		if c.ksi {
			httpReq.Header.Set("User-Agent", "KSI HTTP Client")
			httpReq.Header.Set("Content-Type", "application/ksi-request")
		}
	} else {
		if httpReq, err = http.NewRequest(http.MethodGet, c.url, nil); err != nil {
			return nil, errors.New(errors.KsiNetworkError).SetExtError(err)
		}
	}
	// HTTP server might keep the connection open with "keep-alive" option, otherwise server could run out of sockets.
	httpReq.Close = true

	if ctx == nil {
		ctx = context.Background()
	}
	// Create a deadline Context for the request.
	if c.timeout > 0 {
		// Check that no deadline is already set.
		if _, ok := ctx.Deadline(); !ok {
			var reqCancel context.CancelFunc
			ctx, reqCancel = context.WithTimeout(ctx, c.timeout)
			defer reqCancel()
		}
		httpReq = httpReq.WithContext(ctx)
	}

	// Create a new HTTP Client.
	client, err := c.setupClient()
	if err != nil {
		return nil, err
	}

	resp, err := client.Do(httpReq)
	if err != nil {
		return nil, errors.New(errors.KsiNetworkError).SetExtError(err)
	}
	defer func() {
		if err := resp.Body.Close(); err != nil {
			log.Error("Closing HTTP response body returned error: ", err)
		}
	}()

	// Create a data buffer and, if specified, the limit of data to be read.
	buf := bytes.Buffer{}
	reader := io.Reader(resp.Body)
	// (Buffer).ReadFrom can panic if the amount of data gets to large.
	defer func() {
		if r := recover(); r != nil {
			ksiErr := errors.New(errors.KsiNetworkError).AppendMessage("Panic while reading HTTP response.")
			if err, ok := r.(error); ok {
				e = ksiErr.SetExtError(err)
			} else {
				e = ksiErr.AppendMessage(fmt.Sprintf("%s", r))
			}
		}
	}()
	if c.readLimit > 0 {
		reader = io.LimitReader(resp.Body, int64(c.readLimit))
	}
	if _, err = buf.ReadFrom(reader); err != nil {
		return nil, errors.New(errors.KsiNetworkError).SetExtError(err).
			AppendMessage("Failed to read response body")
	}
	if c.isComplete != nil {
		if ok, err := c.isComplete(buf.Bytes()); !ok {
			log.Error(fmt.Sprintf("Failed to read PDU from HTTP connection (%s): %x", c.url, buf.Bytes()))
			return nil, errors.New(errors.KsiNetworkError).SetExtError(err).
				AppendMessage("Failed to read data from HTTP connection")
		}
	}
	log.Debug(fmt.Sprintf("HTTP received (%s): %x", c.url, buf.Bytes()))

	var respErr error
	if resp.StatusCode >= 400 && resp.StatusCode < 600 {
		// All client request errors (error codes 01xx in hexadecimal) should trigger the HTTP status code 400 (Bad
		// Request), with the appropriate KSIAP or KSIEP response PDU in the HTTP response body. All other 4xx HTTP
		// status codes should be used only for error conditions in the HTTP transport layer. In particular, a KSI
		// authentication failure should not be mapped to the HTTP status code 401 (Unauthorized), as this may mislead
		// the client application to believe an HTTP gateway or reverse proxy between the KSI client and the KSI server
		// requires authentication.
		// All errors related to the KSI server state and upstream service access (error codes 02xx and 03xx in
		// hexadecimal) should trigger the HTTP status code 500 (Server Internal Error), with the appropriate KSIAP or
		// KSIEP response PDU in the HTTP response body.
		// Client applications should always parse the KSI error code and message from the HTTP response body if there
		// is one, and only fall back to the HTTP status code if the HTTP response has no body or the HTTP response
		// body is not a KSI response PDU.
		respErr = errors.New(errors.KsiHttpError).SetExtErrorCode(resp.StatusCode).
			AppendMessage(resp.Status)
	}
	return buf.Bytes(), respErr
}

// Receive implements Client.RequestCount().
func (c *httpClient) RequestCount() uint64 {
	if c == nil {
		return 0
	}
	return atomic.AddUint64(&c.requestCount, 1)
}

// URI implements Endpoint.URI().
func (c *httpClient) URI() string {
	if c == nil {
		return ""
	}
	return c.url
}

// LoginID implements Endpoint.LoginID().
func (c *httpClient) LoginID() string {
	if c == nil {
		return ""
	}
	return c.loginID
}

// Key implements Endpoint.Key().
func (c *httpClient) Key() string {
	if c == nil {
		return ""
	}
	return c.key
}

// SetReadLimit implements ReadLimiter interface.
func (c *httpClient) SetReadLimit(limit uint32) error {
	if c == nil || limit < 0 {
		return errors.New(errors.KsiInvalidArgumentError)
	}

	c.readLimit = limit

	return nil
}

// SetTimeout implements RequestTimeouter interface.
func (c *httpClient) SetTimeout(d byte) error {
	if c == nil {
		return errors.New(errors.KsiInvalidArgumentError)
	}
	c.timeout = time.Duration(d) * time.Second
	return nil
}

// SetVerifier implements ResponseVerifier interface.
func (c *httpClient) SetVerifier(v ResponseVerifierFunc) error {
	if c == nil {
		return errors.New(errors.KsiInvalidArgumentError)
	}
	c.isComplete = v
	return nil
}
