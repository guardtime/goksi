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

// Package net provides an interface for network I/O.
package net

import (
	"context"
	"fmt"
	"net/url"
	"reflect"

	"github.com/guardtime/goksi/errors"
	"github.com/guardtime/goksi/tlv"
)

// Client is abstract network client.
type Client interface {
	Endpoint

	// RequestCount returns next available request ID value.
	RequestCount() uint64
	// Receive places the request towards an endpoint and returns the response.
	// In case the context does not have a deadline set, the Client's default timeout is used.
	Receive(context.Context, []byte) ([]byte, error)
}

// Endpoint is the abstract network endpoint.
type Endpoint interface {
	URI() string
	// LoginID is identifier of the client host for MAC key lookup.
	LoginID() string
	// Key is HMAC shared secret.
	Key() string
}

// ClientOpt is the configuration option for the network provider.
type ClientOpt func(Client) error

// ReadLimiter is interface for network clients whose read data amount can be limited.
type ReadLimiter interface {
	// SetReadLimit sets a read limit in bytes for a network client.
	//
	// In order to disable the limiter, set 'limit' to 0.
	// Note that disabling the read limit can effect network transaction performance.
	SetReadLimit(uint32) error
}

// RequestTimeouter is interface for network client whose request time can be limited.
type RequestTimeouter interface {
	// SetTimeout sets the request timeout in seconds.
	//
	// In order to disable the timeout, set the duration to 0.
	SetTimeout(byte) error
}

// ResponseVerifier is interface for network client whose read data should be verified.
//
// The provided function verifies whether the read byte stream contains a complete datagram. If in case of a false
// result the optional error is set, it will be returned from the network client as errors.KsiNetworkError with
// the extended error set (see (KsiError).ExtError()).
//
// In order to disable the consistency verification, set the verification function to nil.
type ResponseVerifier interface {
	// SetVerifier applies the verifier function.
	SetVerifier(ResponseVerifierFunc) error
}

// ResponseVerifierFunc is the function header definition for using in response consistency verification.
// The input is a byte stream to be verified. Output is the verification result and an optional error for failure details.
type ResponseVerifierFunc func([]byte) (bool, error)

// In case of KSI scheme return adjusted scheme string and the flag set to true,
// otherwise the input string is returned and flag is false.
func adjustScheme(scheme string) (string, bool) {
	switch scheme {
	case "ksi", "ksi+http":
		return "http", true
	case "ksi+https":
		return "https", true
	case "ksi+tcp":
		return "tcp", true
	}
	return scheme, false
}

// NewClient returns a new network client instance.
func NewClient(uri, loginID, key string, options ...ClientOpt) (Client, error) {
	if len(uri) == 0 {
		return nil, errors.New(errors.KsiInvalidFormatError).AppendMessage("Missing endpoint URI.")
	}

	u, err := url.Parse(uri)
	if err != nil {
		return nil, errors.New(errors.KsiNetworkError).SetExtError(err).
			AppendMessage("Unable to parse URI")
	}

	schm, isKsi := adjustScheme(u.Scheme)
	u.Scheme = schm

	// Select loginId and key.
	var l, k string
	if loginID != "" {
		l = loginID
	} else {
		l = u.User.Username()
	}
	if key != "" {
		k = key
	} else {
		if pass, isSet := u.User.Password(); isSet {
			k = pass
		}
	}

	var tmp Client

	switch u.Scheme {
	case "http", "https":
		httpClient := newHTTPClient(u.String(), isKsi)
		httpClient.loginID = l
		httpClient.key = k
		tmp = httpClient
	case "tcp":
		tcpClient := newTCPClient(u.Hostname(), u.Port())
		tcpClient.loginID = l
		tcpClient.key = k
		tmp = tcpClient
	default:
		return nil, errors.New(errors.KsiInvalidFormatError).AppendMessage("Unknown URI scheme")
	}

	// Apply options.
	for _, setter := range options {
		if err := setOption(tmp, setter); err != nil {
			return nil, err
		}
	}

	return tmp, nil
}

func setOption(t Client, opt ClientOpt) error {
	if t == nil {
		return errors.New(errors.KsiInvalidArgumentError)
	}
	if opt == nil {
		return errors.New(errors.KsiInvalidArgumentError).AppendMessage("Provided option is nil.")
	}

	if err := opt(t); err != nil {
		return errors.KsiErr(err).AppendMessage("Unable to apply network option.")
	}
	return nil
}

// ClientOptReadLimit is option that specifies the limit for the amount of data received.
//
// Note that network client must implement ReadLimiter interface.
func ClientOptReadLimit(limit uint32) ClientOpt {
	return func(t Client) error {
		if t == nil {
			return errors.New(errors.KsiInvalidArgumentError).AppendMessage("Missing network client base object.")
		}

		c, ok := t.(ReadLimiter)
		if !ok {
			return errors.New(errors.KsiNotImplemented).AppendMessage(
				fmt.Sprintf("Newtwork client %s does not implement ReadLimiter interface.", reflect.TypeOf(t)))
		}
		if err := c.SetReadLimit(limit); err != nil {
			return errors.KsiErr(err).AppendMessage("Unable to set read limit.")
		}

		return nil
	}
}

// Specifies the default request timeout in seconds.
// If changed, update the doc under ClientOptRequestTimeout.
const defaultRequestTimeout = 10

// ClientOptRequestTimeout is option that specifies request timeout duration in seconds.
// A default request timeout duration is 10 seconds.
//
// Note that network client must implement RequestTimeouter interface.
func ClientOptRequestTimeout(timeout byte) ClientOpt {
	return func(t Client) error {
		if t == nil {
			return errors.New(errors.KsiInvalidArgumentError).AppendMessage("Missing network client base object.")
		}

		c, ok := t.(RequestTimeouter)
		if !ok {
			return errors.New(errors.KsiNotImplemented).AppendMessage(
				fmt.Sprintf("Network client %s does not implement RequestTimeouter interface.", reflect.TypeOf(t)))
		}
		if err := c.SetTimeout(timeout); err != nil {
			return errors.KsiErr(err).AppendMessage("Unable to set timeout.")
		}
		return nil
	}
}

// ClientOptDataGramVerifier is option that specifies the datagram completeness verifier.
//
// Setting the verifier to nil will disable the completeness verification for read data. In that case the received data
// part is returned immediately. It is user responsibility to verify the received parts and concatenate to a complete
// PDU.
//
// The default verifier ensures TLV completeness (see tlv.IsConsistent()).
//
// Note that network client must implement ResponseVerifier interface.
func ClientOptDatagramVerifier(verifier ResponseVerifierFunc) ClientOpt {
	return func(t Client) error {
		if t == nil {
			return errors.New(errors.KsiInvalidArgumentError).AppendMessage("Missing network client base object.")
		}

		c, ok := t.(ResponseVerifier)
		if !ok {
			return errors.New(errors.KsiNotImplemented).AppendMessage(
				fmt.Sprintf("Newtwork client %s does not support datagram verification.", reflect.TypeOf(t)))
		}
		if err := c.SetVerifier(verifier); err != nil {
			return errors.KsiErr(err).AppendMessage("Unable to set verifier.")
		}
		return nil
	}
}

func isTlvComplete(datagram []byte) (bool, error) {
	return tlv.IsConsistent(datagram), nil
}
