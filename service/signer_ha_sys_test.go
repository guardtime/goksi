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
	"sync"
	"testing"

	"github.com/guardtime/goksi/hash"
	"github.com/guardtime/goksi/log"
	"github.com/guardtime/goksi/pdu"
	"github.com/guardtime/goksi/signature"
	"github.com/guardtime/goksi/test"
	"github.com/guardtime/goksi/test/sysconf"
	"github.com/guardtime/goksi/test/utils"
)

const (
	testSigHaOptSch = iota
	testSigHaOptCfg
)

func TestSysHaSignerHTTP(t *testing.T) {

	logger, defFunc, err := test.InitLogger(t, testLogDir, log.DEBUG, t.Name())
	if err != nil {
		t.Fatal("Failed to initialize logger: ", err)
	}
	defer defFunc()

	cfg := utils.LoadConfigFile(t, testConfFile)

	haSignerRunner(t, logger, cfg.Schema.Http, cfg)
}

func TestSysHaSignerTCP(t *testing.T) {

	logger, defFunc, err := test.InitLogger(t, testLogDir, log.DEBUG, t.Name())
	if err != nil {
		t.Fatal("Failed to initialize logger: ", err)
	}
	defer defFunc()

	// Check if system test config is present and load it.
	cfg := utils.LoadConfigFile(t, testConfFile)

	haSignerRunner(t, logger, cfg.Schema.Tcp, cfg)
}

func haSignerRunner(t *testing.T, logger log.Logger, schema string, cfg *sysconf.Configuration) {
	// Apply logger.
	log.SetLogger(logger)

	test.Suite{
		{Func: testHaSignerSendAggrRequest},
		{Func: testHaSignerSignImprint},
		{Func: testHaSignerConfig},
		{Func: testHaSignerSendAggrRequestCanceledByContext},
	}.Runner(t, schema, cfg)
}

func testHaSignerSendAggrRequest(t *testing.T, opt ...interface{}) {
	var (
		testImprint = hash.Imprint{0x01,
			0xc4, 0xbb, 0xcb, 0x1f, 0xbe, 0xc9, 0x9d, 0x65, 0xbf, 0x59, 0xd8, 0x5c, 0x8c, 0xb6, 0x2e, 0xe2,
			0xdb, 0x96, 0x3f, 0x0f, 0xe1, 0x06, 0xf4, 0x83, 0xd9, 0xaf, 0xa7, 0x3b, 0xd4, 0xe3, 0x9a, 0x8a,
		}

		testSchema = opt[testSigHaOptSch].(string)
		testCfg    = opt[testSigHaOptCfg].(*sysconf.Configuration)
	)

	// Gather service options.
	var opts []Option
	for _, srvCfg := range testCfg.HighAvailability.Aggregator {
		opts = append(opts, OptHighAvailability(OptEndpoint(srvCfg.BuildURI(testSchema), srvCfg.User, srvCfg.Pass)))
	}

	srv, err := NewSigner(opts...)
	if err != nil {
		t.Fatal("Failed to create signer: ", err)
	}

	req, err := pdu.NewAggregationReq(testImprint)
	if err != nil {
		t.Fatal("Failed to create request: ", err)
	}

	resp, err := srv.Send(req)
	if err != nil {
		t.Fatal("Failed to receive response: ", err)
	}

	sig, err := signature.New(signature.BuildFromAggregationResp(resp, 0))
	if err != nil {
		t.Fatal("Failed to create ksi signature from aggregation response: ", err)
	}
	if sig == nil {
		t.Fatal("KSI signature must be returned.")
	}
	log.Debug(sig)
}

func testHaSignerSignImprint(t *testing.T, opt ...interface{}) {
	var (
		testImprint = hash.Imprint{0x01,
			0xc4, 0xbb, 0xcb, 0x1f, 0xbe, 0xc9, 0x9d, 0x65, 0xbf, 0x59, 0xd8, 0x5c, 0x8c, 0xb6, 0x2e, 0xe2,
			0xdb, 0x96, 0x3f, 0x0f, 0xe1, 0x06, 0xf4, 0x83, 0xd9, 0xaf, 0xa7, 0x3b, 0xd4, 0xe3, 0x9a, 0x8a,
		}

		testSchema = opt[testSigHaOptSch].(string)
		testCfg    = opt[testSigHaOptCfg].(*sysconf.Configuration)
	)

	// Gather service options.
	var opts []Option
	for _, srvCfg := range testCfg.HighAvailability.Aggregator {
		opts = append(opts, OptHighAvailability(OptEndpoint(srvCfg.BuildURI(testSchema), srvCfg.User, srvCfg.Pass)))
	}

	srv, err := NewSigner(opts...)
	if err != nil {
		t.Fatal("Failed to create signer: ", err)
	}

	sig, err := srv.Sign(testImprint)
	if err != nil {
		t.Fatal("Failed to receive response: ", err)
	}
	if sig == nil {
		t.Fatal("KSI signature must be returned.")
	}
	log.Debug(sig)
}

func testHaSignerConfig(t *testing.T, opt ...interface{}) {
	var (
		testSchema = opt[testSigHaOptSch].(string)
		testCfg    = opt[testSigHaOptCfg].(*sysconf.Configuration)
	)

	// Gather service options.
	var opts []Option
	for _, srvCfg := range testCfg.HighAvailability.Aggregator {
		opts = append(opts, OptHighAvailability(OptEndpoint(srvCfg.BuildURI(testSchema), srvCfg.User, srvCfg.Pass)))
	}

	srv, err := NewSigner(opts...)
	if err != nil {
		t.Fatal("Failed to create service: ", err)
	}

	config, err := srv.Config()
	if err != nil {
		t.Fatal("Failed to receive server configuration: ", err)
	}
	if config == nil {
		t.Fatal("Configuration has not been returned.")
	}
	log.Debug(config)
}

func testHaSignerSendAggrRequestCanceledByContext(t *testing.T, opt ...interface{}) {
	var (
		testSchema = opt[testSigHaOptSch].(string)
		testCfg    = opt[testSigHaOptCfg].(*sysconf.Configuration)
	)

	// Gather service options.
	var opts []Option
	for _, srvCfg := range testCfg.HighAvailability.Aggregator {
		opts = append(opts, OptHighAvailability(OptEndpoint(srvCfg.BuildURI(testSchema), srvCfg.User, srvCfg.Pass)))
	}

	srv, err := NewSigner(opts...)
	if err != nil {
		t.Fatal("Failed to create signer: ", err)
	}

	req, err := pdu.NewAggregationReq(hash.Default.ZeroImprint())
	if err != nil {
		t.Fatal("Failed to create request: ", err)
	}

	// Initialize request send worker.
	var (
		reqContext, reqCancel = context.WithCancel(context.Background())
		respErr               error
		resp                  *pdu.AggregatorResp
		wg                    sync.WaitGroup
	)
	wg.Add(1)
	go func() {
		resp, respErr = srv.Send(req.WithContext(reqContext))
		wg.Done()
	}()
	// Cancel the request.
	reqCancel()
	// Wait for the worker to complete.
	wg.Wait()
	// Verify return values.
	if respErr == nil {
		t.Fatal("Must return cancellation error.")
	}
	if resp != nil {
		t.Fatal("No response must be returned.")
	}
}
