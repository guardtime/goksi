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
	"fmt"

	"github.com/guardtime/goksi/errors"
	"github.com/guardtime/goksi/hash"
	"github.com/guardtime/goksi/net"
	"github.com/guardtime/goksi/pdu"
)

type (
	// ConfigListener is a server configuration response listener.
	ConfigListener func(*pdu.Config) error

	service interface {
		send(*request) (*response, error)
	}

	factory struct {
		// Reference to the service under initialization.
		// factory.initialize() is performed on this reference.
		active *basicService

		srv *basicService
		ha  *highAvailabilityService
	}
)

// Factory method for service construction. Returns new service instance that implements service interface.
func newService(opts ...Option) (service, error) {
	if len(opts) == 0 {
		return nil, errors.New(errors.KsiInvalidArgumentError)
	}

	f := factory{}
	if err := f.initialize(opts...); err != nil {
		return nil, err
	}

	// Only one service can be constructed.
	if (f.srv != nil && f.ha != nil) ||
		(f.srv == nil && f.ha == nil) {
		return nil, errors.New(errors.KsiInvalidStateError).AppendMessage("Initialization of multiple services.")
	}
	if f.srv != nil {
		return f.srv, nil
	}
	return f.ha, nil
}

func (f *factory) initialize(opts ...Option) error {
	if f == nil {
		return errors.New(errors.KsiInvalidArgumentError)
	}

	// Apply options.
	for _, optSetter := range opts {
		if optSetter == nil {
			return errors.New(errors.KsiInvalidArgumentError).AppendMessage("Provided option is nil.")
		}
		if err := optSetter(f); err != nil {
			return errors.KsiErr(err).AppendMessage("Unable to initialize new service.")
		}
	}
	return nil
}

func (f *factory) initActiveService() error {
	if f == nil {
		return errors.New(errors.KsiInvalidArgumentError)
	}

	if f.active == nil {
		srv, err := newBasicService()
		if err != nil {
			return nil
		}
		f.srv = srv
		f.active = f.srv
	}
	return nil
}

// Option service is functional option setter.
type Option func(*factory) error

// OptHighAvailability is a wrapper option for a high availability (HA) sub-service endpoint.
// Can be used up to MaxHighAvailabilitySubServices times for defining for than one sub-service.
func OptHighAvailability(opts ...Option) Option {
	return func(f *factory) error {
		if f == nil {
			return errors.New(errors.KsiInvalidArgumentError).AppendMessage("Missing service factory base object.")
		}

		var (
			ha     *highAvailabilityService
			err    error
			subSrv *basicService
		)

		// Initialize new basicService, that will be registered by the HA service
		subSrv, err = newBasicService()
		if err != nil {
			return err
		}

		f.active = subSrv
		if err = f.initialize(opts...); err != nil {
			return err
		}

		// Initialize HA service if it is the first option call.
		if f.ha == nil {
			if ha, err = newHighAvailabilityService(); err != nil {
				return err
			}
			f.ha = ha
		}
		// Register the sub-service.
		if err := f.ha.addSubService(subSrv); err != nil {
			return err
		}
		f.active = nil
		return nil
	}
}

// OptEndpoint is configuration method for the service endpoint.
//  * uri is the endpoint server URI. Supported are following formats:
//    - schema://some.url:1234 - in this case loginID and key parameters need to be provided,
//    - schema://logID:key@some.url:1234 - in this case if loginID and key are provided, they will be over written.
//  * loginID is the service client identifier.
//  * key is the authentication key for HMAC computation.
func OptEndpoint(uri, loginID, key string) Option {
	return func(f *factory) error {
		if f == nil {
			return errors.New(errors.KsiInvalidArgumentError).AppendMessage("Missing service factory base object.")
		}

		if err := f.initActiveService(); err != nil {
			return nil
		}

		client, err := net.NewClient(uri, loginID, key)
		if err != nil {
			return err
		}
		if err := f.active.initialize(srvOptNetClient(client)); err != nil {
			return err
		}

		return nil
	}
}

// OptNetClient is setter for the custom network client which implements the net.Client interface.
// For alternative, see OptEndpoint.
func OptNetClient(client net.Client) Option {
	return func(f *factory) error {
		if client == nil {
			return errors.New(errors.KsiInvalidArgumentError)
		}
		if f == nil {
			return errors.New(errors.KsiInvalidArgumentError).AppendMessage("Missing service factory base object.")
		}

		if err := f.initActiveService(); err != nil {
			return nil
		}

		return f.active.initialize(srvOptNetClient(client))
	}
}

// OptHmacAlgorithm is setter for the hash algorithm to be used for HMAC calculations.
// The used algorithm must be registered and trusted.
// For me information on the hash algorithm state see hash.(Algorithm).Registered() and hash.(Algorithm).Trusted()
func OptHmacAlgorithm(algorithm hash.Algorithm) Option {
	return func(f *factory) error {
		if f == nil {
			return errors.New(errors.KsiInvalidArgumentError).AppendMessage("Missing service factory base object.")
		}
		if !algorithm.Registered() {
			return errors.New(errors.KsiUnknownHashAlgorithm).
				AppendMessage(fmt.Sprintf("Algorithm is not supported: %x.", algorithm))
		}
		if !algorithm.Trusted() {
			return errors.New(errors.KsiInvalidStateError).
				AppendMessage(fmt.Sprintf("Algorithm is not trusted: %s.", algorithm))
		}

		if err := f.initActiveService(); err != nil {
			return nil
		}

		return f.active.initialize(srvOptHmacAlgorithm(algorithm))
	}
}

// OptRequestHeaderFunc setter for the request header manipulation function.
// The callback is invoked every time a new service request message is constructed.
func OptRequestHeaderFunc(callback pdu.RequestHeaderFunc) Option {
	return func(f *factory) error {
		if f == nil {
			return errors.New(errors.KsiInvalidArgumentError).AppendMessage("Missing service factory base object.")
		}

		if err := f.initActiveService(); err != nil {
			return nil
		}

		return f.active.initialize(srvOptRequestHeaderFunc(callback))
	}
}

// OptConfigListener is setter for the server configuration response listener.
// The callback is invoked every time a push configuration message is received.
func OptConfigListener(callback ConfigListener) Option {
	return func(f *factory) error {
		if f == nil {
			return errors.New(errors.KsiInvalidStateError).AppendMessage("Missing service factory base object.")
		}

		if err := f.initActiveService(); err != nil {
			return nil
		}

		return f.active.initialize(srvOptConfigListener(callback))
	}
}
