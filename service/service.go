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

// basicService is the abstraction of the KSI service.
type basicService struct {
	// Service endpoint.
	netClient net.Client
	// Hash algorithm to be used for HMAC computation.
	hmacAlgo hash.Algorithm

	// Request header callback.
	reqHeaderFunc pdu.RequestHeaderFunc
	// Server push configuration listener callback.
	confListener ConfigListener
}

func newBasicService() (*basicService, error) {
	return &basicService{
		hmacAlgo: hash.Default,
	}, nil
}

// basicService option.
type srvOption func(*basicService) error

func (s *basicService) initialize(opts ...srvOption) error {
	if s == nil {
		return errors.New(errors.KsiInvalidArgumentError)
	}

	// Apply options.
	for _, optSetter := range opts {
		if optSetter == nil {
			return errors.New(errors.KsiInvalidArgumentError).AppendMessage("Provided option is nil.")
		}
		if err := optSetter(s); err != nil {
			return errors.KsiErr(err).AppendMessage("Unable to apply factory option.")
		}
	}

	// Network client is mandatory.
	if s.netClient == nil {
		return errors.New(errors.KsiInvalidStateError).AppendMessage("Network client has not been created.")
	}

	return nil
}

// srvOptEndpoint is configuration method for the basicService endpoint.
func srvOptEndpoint(uri, loginID, key string) srvOption {
	return func(s *basicService) error {
		if s == nil {
			return errors.New(errors.KsiInvalidArgumentError)
		}

		client, err := net.NewClient(uri, loginID, key)
		if err != nil {
			return err
		}
		s.netClient = client
		return nil
	}
}

// srvOptNetClient is setter for the custom network client.
func srvOptNetClient(client net.Client) srvOption {
	return func(s *basicService) error {
		if s == nil || client == nil {
			return errors.New(errors.KsiInvalidArgumentError)
		}
		s.netClient = client
		return nil
	}
}

// srvOptHmacAlgorithm is setter for the hash algorithm to be used for HMAC calculations.
// Fails if the hash algorithm is not supported (see hash.Registered()).
func srvOptHmacAlgorithm(algorithm hash.Algorithm) srvOption {
	return func(s *basicService) error {
		if s == nil {
			return errors.New(errors.KsiInvalidArgumentError)
		}
		if !algorithm.Registered() {
			return errors.New(errors.KsiUnknownHashAlgorithm).
				AppendMessage(fmt.Sprintf("Algorithm is not supported: %x.", algorithm))
		}
		if !algorithm.Trusted() {
			return errors.New(errors.KsiInvalidStateError).
				AppendMessage(fmt.Sprintf("Algorithm is not trusted: %s.", algorithm))
		}
		s.hmacAlgo = algorithm
		return nil
	}
}

// srvOptRequestHeaderFunc is setter for the request header manipulation function.
func srvOptRequestHeaderFunc(f pdu.RequestHeaderFunc) srvOption {
	return func(s *basicService) error {
		if s == nil {
			return errors.New(errors.KsiInvalidArgumentError)
		}
		s.reqHeaderFunc = f
		return nil
	}
}

// srvOptConfigListener is setter server configuration response listener.
// Note that the implementation must be thread safe.
func srvOptConfigListener(l ConfigListener) srvOption {
	return func(s *basicService) error {
		if s == nil {
			return errors.New(errors.KsiInvalidArgumentError)
		}
		s.confListener = l
		return nil
	}
}

func (s *basicService) SetConfigListener(f ConfigListener) error {
	if s == nil {
		return errors.New(errors.KsiInvalidArgumentError)
	}
	s.confListener = f
	return nil
}

// send sends the request and returns a response.
func (s *basicService) send(req *request) (*response, error) {
	if s == nil || s.netClient == nil {
		return nil, errors.New(errors.KsiInvalidArgumentError)
	}

	// Initialize request header.
	hdr, err := pdu.NewHeader(s.netClient.LoginID(), s.reqHeaderFunc)
	if err != nil {
		return nil, err
	}
	if err := req.setHeader(hdr); err != nil {
		return nil, err
	}

	// Update request ID in case of aggregation request.
	if err := req.updateRequestID(s.netClient.RequestCount()); err != nil {
		return nil, err
	}

	// Calculate HMAC for the request.
	if err := req.updateHMAC(s.hmacAlgo, s.netClient.Key()); err != nil {
		return nil, err
	}

	// Serialize the request.
	reqRaw, err := req.encode()
	if err != nil {
		return nil, err
	}

	resp, err := newResponse(req.respType())
	if err != nil {
		return nil, err
	}

	// Client applications should always parse the KSI error code and message from the HTTP response body if there
	// is one, and only fall back to the HTTP status code if the HTTP response has no body or the HTTP response
	// body is not a KSI response PDU.
	repsRaw, respErr := s.netClient.Receive(req.context(), reqRaw)
	// Deserialize the response.
	if err := resp.decode(repsRaw); err != nil {
		if respErr != nil {
			return nil, errors.KsiErr(respErr, errors.KsiNetworkError).AppendMessage("Network client returned error.")
		}
		return nil, err
	}

	if err := resp.verify(s.hmacAlgo, s.netClient.Key()); err != nil {
		return nil, err
	}

	if err := resp.verifyReqId(req); err != nil {
		return nil, err
	}

	if err := s.handleConfig(req, resp); err != nil {
		return nil, err
	}

	return resp, nil
}

func (s *basicService) handleConfig(req *request, resp *response) error {
	if s == nil || req == nil || resp == nil {
		return errors.New(errors.KsiInvalidArgumentError)
	}

	respConf, err := resp.config()
	if err != nil {
		return err
	}

	if respConf != nil {
		reqConf, err := req.config()
		if err != nil {
			return err
		}

		// Check if the config has been requested, or is it a server push conf.
		if reqConf == nil && s.confListener != nil {
			// Invoke the config listener callback.
			if err := s.confListener(respConf); err != nil {
				return errors.KsiErr(err).AppendMessage("Config listener returned error.")
			}
			// Reset config to avoid double handling of the same data.
			return resp.setConfig(nil)
		}
	}
	return nil
}
