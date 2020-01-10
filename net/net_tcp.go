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
	"fmt"
	"net"
	"sync/atomic"
	"time"

	"github.com/guardtime/goksi/errors"
	"github.com/guardtime/goksi/log"
	"github.com/guardtime/goksi/pdu"
)

type tcpClient struct {
	host         string
	port         string
	loginID      string
	key          string
	timeout      time.Duration
	requestCount uint64
	readLimit    uint32
	isComplete   ResponseVerifierFunc
}

func newTCPClient(host, port string) *tcpClient {
	return &tcpClient{
		host:       host,
		port:       port,
		timeout:    defaultRequestTimeout * time.Second,
		readLimit:  pdu.MaxSize,
		isComplete: isTlvComplete,
	}
}

// Receive implements Client.Receive().
func (c *tcpClient) Receive(ctx context.Context, request []byte) (b []byte, e error) {
	if c == nil {
		return nil, errors.New(errors.KsiInvalidArgumentError).AppendMessage("Invalid method receiver")
	}

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
	}

	// Create a TCP connection.
	dialer := net.Dialer{
		KeepAlive: -1,
	}
	conn, err := dialer.DialContext(ctx, "tcp", net.JoinHostPort(c.host, c.port))
	if err != nil {
		return nil, errors.New(errors.KsiNetworkError).SetExtError(err)
	}
	defer func() {
		if err := conn.Close(); err != nil {
			log.Error("Closing TCP connection returned error: ", err)
		}
	}()

	// Send the request.
	log.Debug(fmt.Sprintf("TCP send (%s:%s): %x", c.host, c.port, request))
	if _, err = conn.Write(request); err != nil {
		return nil, errors.New(errors.KsiNetworkError).SetExtError(err)
	}

	// Receive response.
	var response []byte
	if c.readLimit > 0 {
		var readTotal uint32
		for {
			var responsePart = make([]byte, c.readLimit-readTotal)
			// Read blocks until a response part has been received.
			// The EOF (and read=0) is only received when the connection is closed.
			read, err := conn.Read(responsePart)
			if err != nil {
				log.Error(fmt.Sprintf("Failed to read PDU from TCP connection (%s:%s): %x", c.host, c.port, response))
				return nil, errors.New(errors.KsiNetworkError).SetExtError(err).
					AppendMessage("Failed to read data from TCP connection.")
			}
			readTotal += uint32(read)
			response = append(response, responsePart[:read]...)
			if c.isComplete == nil {
				break
			}
			if ok, err := c.isComplete(response); ok {
				break
			} else if err != nil {
				return nil, errors.New(errors.KsiNetworkError).SetExtError(err).
					AppendMessage("Failed to read data from TCP connection.")
			}
			log.Debug(fmt.Sprintf("TCP  received  PDU part (%s:%s): [%d] %x", c.host, c.port, read, responsePart))
		}
	} else {
		// Using a reader interface will affect the performance, as the EOF flag
		// is not set immediately after response has been received.

		buf := bytes.Buffer{}
		// (Buffer).ReadFrom can panic if the amount of data gets too large.
		defer func() {
			if r := recover(); r != nil {
				ksiErr := errors.New(errors.KsiNetworkError).AppendMessage("Panic while reading TCP response.")
				if err, ok := r.(error); ok {
					e = ksiErr.SetExtError(err)
				} else {
					e = ksiErr.AppendMessage(fmt.Sprintf("%s", r))
				}
			}
		}()
		if _, err = buf.ReadFrom(conn); err != nil {
			return nil, errors.New(errors.KsiNetworkError).SetExtError(err).
				AppendMessage("Failed to read response.")
		}
		response = buf.Bytes()
		if c.isComplete != nil {
			if ok, err := c.isComplete(buf.Bytes()); !ok {
				log.Error(fmt.Sprintf("Failed to read PDU from TCP connection (%s:%s): %x", c.host, c.port, response))
				return nil, errors.New(errors.KsiNetworkError).SetExtError(err).
					AppendMessage("Failed to read data from TCP connection.")
			}
		}
	}
	log.Debug(fmt.Sprintf("TCP received (%s:%s): %x", c.host, c.port, response))
	return response, nil
}

// Receive implements Client.RequestCount().
func (c *tcpClient) RequestCount() uint64 {
	if c == nil {
		return 0
	}
	return atomic.AddUint64(&c.requestCount, 1)
}

// URI implements Endpoint.URI().
func (c *tcpClient) URI() string {
	return ""
}

// LoginID implements Endpoint.LoginID().
func (c *tcpClient) LoginID() string {
	if c == nil {
		return ""
	}
	return c.loginID
}

// Key implements Endpoint.Key().
func (c *tcpClient) Key() string {
	if c == nil {
		return ""
	}
	return c.key
}

// SetReadLimit implements ReadLimiter interface.
func (c *tcpClient) SetReadLimit(limit uint32) error {
	if c == nil {
		return errors.New(errors.KsiInvalidArgumentError)
	}

	c.readLimit = limit
	return nil
}

// SetTimeout implements RequestTimeouter interface.
func (c *tcpClient) SetTimeout(d byte) error {
	if c == nil {
		return errors.New(errors.KsiInvalidArgumentError)
	}
	c.timeout = time.Duration(d) * time.Second
	return nil
}

// SetVerifier implements ResponseVerifier interface.
func (c *tcpClient) SetVerifier(v ResponseVerifierFunc) error {
	if c == nil {
		return errors.New(errors.KsiInvalidArgumentError)
	}
	c.isComplete = v
	return nil
}
