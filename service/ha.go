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
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/guardtime/goksi/errors"
	"github.com/guardtime/goksi/hash"
	"github.com/guardtime/goksi/log"
	"github.com/guardtime/goksi/pdu"
)

const (
	// MaxHighAvailabilitySubServices is the maximum number of sub-services that can be configured for using by a high
	// availability service.
	MaxHighAvailabilitySubServices = 3
)

var (
	// Default sub-service config consolidation limits.
	haConfigLimits = pdu.ConfigLimits{
		MaxLevelLow:    1,
		MaxLevelHigh:   20,
		AggrPeriodLow:  100,
		AggrPeriodHigh: 20000,
		MaxReqLow:      1,
		MaxReqHigh:     16000,
		CalFirstLow:    1136073600,
	}
	// Default sub-service config consolidation strategy.
	haConfigLogic = pdu.ConfigConsStrategy{
		// maximum level: the largest value is taken.
		MaxLevelKeepLargest: true,
		// aggregation algorithm: any non-null value is preferred to null.
		AggrAlgorithm: hash.SHA_NA,
		// aggregation period: the smallest value is taken.
		AggrPeriodKeepLargest: false,
		// maximum requests: the largest value is taken.
		MaxRequestsKeepLargest: true,
		// parent URI: any non-null value is preferred to null.
		ParentUriAppend: false,
		// calendar first: the earliest value is taken, but not before 1136073600 epoch time.
		CalFirstKeepEarliest: true,
	}
)

type highAvailabilityService struct {
	// High availability service sub-services.
	services []*basicService

	// Consolidated configuration.
	conf *pdu.Config
	// Push config message listener.
	confListener ConfigListener

	// Message header instance ID value.
	instanceID uint64
	// Message counter.
	messageCount uint64

	// Maximum number of sub-services allowed.
	maxServices int
}

func newHighAvailabilityService() (*highAvailabilityService, error) {
	return &highAvailabilityService{
		instanceID:  uint64(time.Now().UnixNano()),
		conf:        &pdu.Config{},
		maxServices: MaxHighAvailabilitySubServices,
	}, nil
}

// Returns HA sub-service push config listener callback function.
func (ha *highAvailabilityService) subSrvConfigListener() (ConfigListener, error) {
	if ha == nil {
		return nil, errors.New(errors.KsiInvalidArgumentError)
	}

	return func(cfg *pdu.Config) error {
		if cfg == nil {
			return errors.New(errors.KsiInvalidArgumentError)
		}
		// Consolidate the received config with available parameters.
		if err := ha.conf.Consolidate(cfg, haConfigLimits, haConfigLogic); err != nil {
			return err
		}
		// Invoke user configured callback with the consolidated configuration.
		return ha.confListener(ha.conf)
	}, nil
}

func (ha *highAvailabilityService) addSubService(srv *basicService) error {
	if ha == nil || srv == nil {
		return errors.New(errors.KsiInvalidArgumentError)
	}
	// Verify that the maximum number of registered sub-services has not exceeded.
	if len(ha.services) >= ha.maxServices {
		return errors.New(errors.KsiBufferOverflow).AppendMessage("Exceed maximum nof HA sub-services.")
	}

	// Apply the configuration listener callback.
	haCfgListener, err := ha.subSrvConfigListener()
	if err != nil {
		return err
	}
	if err := srv.SetConfigListener(haCfgListener); err != nil {
		return err
	}

	// Register the service in HA cache.
	ha.services = append(ha.services, srv)
	return nil
}

type (
	// Asynchronous return from a goroutine.
	asyncResponse struct {
		// Sub-service ID.
		id int
		// Sub-service manipulated request, e.g. updated request ID (if relevant).
		request *request
		// Sub-service response (in case asyncResponse.err == nil)
		response *response
		// In case something went wrong (e.g. API call return, or communication error).
		err error
	}

	// Asynchronous communication channel.
	asyncResponseChan struct {
		channel chan asyncResponse
		guard   sync.RWMutex
	}
)

func (arc *asyncResponseChan) close() {
	arc.guard.Lock()
	defer arc.guard.Unlock()

	if !arc.unsafeIsClosed() {
		close(arc.channel)
	}
}

func (arc *asyncResponseChan) isClosed() bool {
	arc.guard.RLock()
	defer arc.guard.RUnlock()

	return arc.unsafeIsClosed()
}

func (arc *asyncResponseChan) unsafeIsClosed() bool {
	select {
	case <-arc.channel:
		return true
	default:
		return false
	}
}

// Returns true if the response could be placed into the receiver channel, otherwise false.
func (arc *asyncResponseChan) message(r asyncResponse) bool {
	arc.guard.RLock()
	defer arc.guard.RUnlock()

	// Verify the channel is still open.
	if !arc.isClosed() {
		arc.channel <- r
		return true
	}
	return false
}

// send implements service interface.
func (ha *highAvailabilityService) send(req *request) (*response, error) {
	if ha == nil || req == nil {
		return nil, errors.New(errors.KsiInvalidArgumentError)
	}
	// Verify that sub-services are configured.
	if len(ha.services) == 0 {
		return nil, errors.New(errors.KsiInvalidStateError).
			AppendMessage("High availability service is not properly initialized.")
	}

	haContext, haCancel := context.WithCancel(context.Background())
	defer haCancel()
	haReq := *req
	haReq.context = func() context.Context { return haContext }

	// Asynchronous communication channel.
	respCh := &asyncResponseChan{
		channel: make(chan asyncResponse),
	}
	for i, srv := range ha.services {
		// Start a asynchronous service request.
		go func(id int, s *basicService, r *request, done *asyncResponseChan) {
			// Clone the request as some parts of the request container will be modified based on sub-service settings.
			// The cloned request will be returned to the back to the caller.
			reqCopy, err := r.clone()
			if err != nil {
				err = errors.KsiErr(err).AppendMessage(fmt.Sprintf("HA subservice[%d]: Failed to clone request.", id))
				if !done.message(asyncResponse{id, reqCopy, nil, err}) {
					log.Info(fmt.Sprintf("HA subservice[%d]: response channel is closed.", id))
					log.Info(err)
				}
				return
			}
			reqCopy.context = r.context

			resp, err := s.send(reqCopy)
			if err != nil {
				err = errors.KsiErr(err).AppendMessage(fmt.Sprintf("HA subservice[%d]: Failed to receive response.", id))
				if !done.message(asyncResponse{id, reqCopy, nil, err}) {
					log.Info(fmt.Sprintf("HA subservice[%d]: response channel is closed.", id))
					log.Info(err)
				}
				return
			}
			log.Debug(fmt.Sprintf("HA subservice[%d]: response received.", id))
			if !done.message(asyncResponse{id, reqCopy, resp, nil}) {
				log.Info(fmt.Sprintf("HA subservice[%d]: dropping response; channel is closed.", id))
			}
		}(i, srv, &haReq, respCh)
	}

	var (
		// Response counter.
		count int
		// Error cache.
		respErrors = make([]error, 0, len(ha.services))
	)
	// Handle async response.
	for {
		// Wait for the next response.
		var resp asyncResponse
		select {
		case <-req.context().Done():
			respCh.close()
			haCancel()
			return nil, errors.New(errors.KsiNetworkError).AppendMessage("Request was canceled.")
		case resp = <-respCh.channel:
			count++
			// continue
		}

		if resp.err != nil {
			log.Info("HA sub-service[", resp.id, "] response error: \n", resp.err)
			respErrors = append(respErrors, resp.err)
		}

		reqConf, err := resp.request.config()
		if err != nil {
			respCh.close()
			haCancel()
			return nil, errors.KsiErr(err).AppendMessage("Failed to extract request config component.")
		}

		switch {
		// Check if config has been explicitly requested. In that case wait for all sub-services to respond.
		case reqConf != nil:
			if resp.response != nil {
				if err := ha.handleConfig(resp.request, resp.response); err != nil {
					respCh.close()
					haCancel()
					return nil, err
				}
			}
			// Wait for all sub-services to respond.
			if count >= len(ha.services) {
				respCh.close()
				haCancel()

				// Check if all sub-services have returned an error.
				if len(respErrors) == len(ha.services) {
					// Just return the latest registered error.
					return nil, errors.KsiErr(respErrors[len(respErrors)-1]).
						AppendMessage("Latest HA errors from a sub-service.")
				}
				// Verify that response instance is present, will be missing in case of error.
				response := resp.response
				if response == nil {
					if response, err = newResponse(resp.request.respType()); err != nil {
						return nil, err
					}
				}
				// Return the response with updated configuration.
				return response, response.setConfig(ha.conf)
			}

		// Service response. Return first successful response.
		default:
			if resp.response != nil {
				respCh.close()
				haCancel()

				// In case the response contains server push configuration.
				if err := ha.handleConfig(resp.request, resp.response); err != nil {
					return nil, err
				}
				return resp.response, nil
			}
			// No valid response received.
			if count >= len(ha.services) {
				respCh.close()
				haCancel()

				msg := "No valid response received from HA sub services."
				if len(respErrors) != 0 {
					return nil, errors.KsiErr(respErrors[len(respErrors)-1]).
						AppendMessage(msg).AppendMessage("This is latest registered error.")
				}
				return nil, errors.New(errors.KsiInvalidStateError).AppendMessage(msg)
			}
		}
	}
}

func (ha *highAvailabilityService) handleConfig(req *request, resp *response) error {
	if ha == nil || req == nil || resp == nil {
		return errors.New(errors.KsiInvalidArgumentError)
	}

	respConf, err := resp.config()
	if err != nil {
		return err
	}

	if respConf != nil {
		if err := ha.conf.Consolidate(respConf, haConfigLimits, haConfigLogic); err != nil {
			return err
		}

		reqConf, err := req.config()
		if err != nil {
			return err
		}
		// Check if the config has been requested, or is it a server push configuration.
		if reqConf == nil && ha.confListener != nil {
			// Invoke the config listener callback.
			if err := ha.confListener(respConf); err != nil {
				return errors.KsiErr(err).AppendMessage("Config listener returned error.")
			}
			// Reset config to avoid double handling of the same data.
			return resp.setConfig(nil)
		}
	}

	return nil
}
