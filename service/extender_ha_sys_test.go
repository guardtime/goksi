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
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/guardtime/goksi/log"
	"github.com/guardtime/goksi/pdu"
	"github.com/guardtime/goksi/publications"
	"github.com/guardtime/goksi/signature"
	"github.com/guardtime/goksi/test"
	"github.com/guardtime/goksi/test/sysconf"
	"github.com/guardtime/goksi/test/utils"
)

const (
	testExtHaOptSch = iota
	testExtHaOptCfg
	testExtHaOptPfh
)

func TestSysHaExtenderHTTP(t *testing.T) {

	logger, defFunc, err := test.InitLogger(t, testLogDir, log.DEBUG, t.Name())
	if err != nil {
		t.Fatal("Failed to initialize logger: ", err)
	}
	defer defFunc()

	// Check if system test config is present and load it.
	cfg := utils.LoadConfigFile(t, testConfFile)

	haExtenderRunner(t, logger, cfg.Schema.Http, cfg)
}

func TestSysHaExtenderTCP(t *testing.T) {

	logger, defFunc, err := test.InitLogger(t, testLogDir, log.DEBUG, t.Name())
	if err != nil {
		t.Fatal("Failed to initialize logger: ", err)
	}
	defer defFunc()
	// Apply logger.
	log.SetLogger(logger)

	// Check if system test config is present and load it.
	cfg := utils.LoadConfigFile(t, testConfFile)

	haExtenderRunner(t, logger, cfg.Schema.Tcp, cfg)
}

func haExtenderRunner(t *testing.T, logger log.Logger, schema string, cfg *sysconf.Configuration) {
	// Apply logger.
	log.SetLogger(logger)

	pfh, err := publications.NewFileHandler(
		publications.FileHandlerSetPublicationsURL(cfg.Pubfile.Url),
		publications.FileHandlerSetFileCertConstraints(cfg.Pubfile.Constraints()),
	)
	if err != nil {
		t.Fatal("Failed to initialize publications file handler: ", err)
	}

	test.Suite{
		{Func: testHaExtendToHead},
		{Func: testHaExtendToNearestPublication},
		{Func: testHaExtenderConfig},
		{Func: testHaExtenderSendCanceledByContext},
	}.Runner(t, schema, cfg, pfh)
}

func testHaExtendToHead(t *testing.T, opt ...interface{}) {
	// Test case resources.
	var (
		testSigFile = filepath.Join(testResourceSigDir, "ok-sig-2018-06-15.1.ksig")

		testSchema = opt[testExtHaOptSch].(string)
		testCfg    = opt[testExtHaOptCfg].(*sysconf.Configuration)
	)

	sig, err := signature.New(signature.BuildFromFile(testSigFile))
	if err != nil {
		t.Fatal("Failed to create ksi signature from file: ", err)
	}

	// Gather extender options.
	var opts []Option
	for _, srvCfg := range testCfg.HighAvailability.Extender {
		opts = append(opts, OptHighAvailability(OptEndpoint(srvCfg.BuildURI(testSchema), srvCfg.User, srvCfg.Pass)))
	}

	extender, err := NewExtender(opt[testExtHaOptPfh].(*publications.FileHandler), opts...)
	if err != nil {
		t.Fatal("Failed to create extender: ", err)
	}

	_, err = extender.Extend(sig, ExtendOptionToTime(time.Time{}))
	if err != nil {
		t.Fatal("Failed to receive response: ", err)
	}
}

func testHaExtendToNearestPublication(t *testing.T, opt ...interface{}) {
	// Test case resources.
	var (
		testSigFile = filepath.Join(testResourceSigDir, "ok-sig-2014-08-01.1.ksig")

		testSchema         = opt[testExtHaOptSch].(string)
		testPubFileHandler = opt[testExtHaOptPfh].(*publications.FileHandler)
		testCfg            = opt[testExtHaOptCfg].(*sysconf.Configuration)
	)

	sig, err := signature.New(signature.BuildFromFile(testSigFile))
	if err != nil {
		t.Fatal("Failed to create ksi signature from file: ", err)
	}

	// Gather extender options.
	var opts []Option
	for _, srvCfg := range testCfg.HighAvailability.Extender {
		opts = append(opts, OptHighAvailability(OptEndpoint(srvCfg.BuildURI(testSchema), srvCfg.User, srvCfg.Pass)))
	}

	extender, err := NewExtender(testPubFileHandler, opts...)
	if err != nil {
		t.Fatal("Failed to create signer: ", err)
	}

	extSig, err := extender.Extend(sig)
	if err != nil {
		t.Fatal("Failed to receive response: ", err)
	}

	extSigPubRec, err := extSig.Publication()
	if err != nil {
		t.Fatal("Failed to extract publication record: ", err)
	}
	extSigPubData, err := extSigPubRec.PublicationData()
	if err != nil {
		t.Fatal("Failed to extract publication response: ", err)
	}

	pubFile, err := testPubFileHandler.ReceiveFile()
	if err != nil {
		t.Fatal("Failed to get publications file: ", err)
	}

	pubRec, err := pubFile.PublicationRec(publications.PubRecSearchByPubData(extSigPubData))
	if err != nil {
		t.Fatal("Failed to find publication record: ", err)
	}
	if pubRec == nil {
		t.Fatal("There must be a matching publication record.")
	}
}

func testHaExtenderConfig(t *testing.T, opt ...interface{}) {
	// Test case resources.
	var (
		testSchema         = opt[testExtHaOptSch].(string)
		testPubFileHandler = opt[testExtHaOptPfh].(*publications.FileHandler)
		testCfg            = opt[testExtHaOptCfg].(*sysconf.Configuration)
	)

	// Gather extender options.
	var opts []Option
	for _, srvCfg := range testCfg.HighAvailability.Extender {
		opts = append(opts, OptHighAvailability(OptEndpoint(srvCfg.BuildURI(testSchema), srvCfg.User, srvCfg.Pass)))
	}

	extender, err := NewExtender(testPubFileHandler, opts...)
	if err != nil {
		t.Fatal("Failed to create service: ", err)
	}

	config, err := extender.Config()
	if err != nil {
		t.Fatal("Failed to receive server configuration: ", err)
	}
	if config == nil {
		t.Fatal("Configuration has not been returned.")
	}
	log.Debug(config)
}

func testHaExtenderSendCanceledByContext(t *testing.T, opt ...interface{}) {
	var (
		testSchema = opt[testExtHaOptSch].(string)
		testCfg    = opt[testExtHaOptCfg].(*sysconf.Configuration)

		testFrom = time.Unix(1398866256, 0)
		testTo   = time.Unix(1408060800, 0)
	)

	// Gather extender options.
	var opts []Option
	for _, srvCfg := range testCfg.HighAvailability.Extender {
		opts = append(opts, OptHighAvailability(OptEndpoint(srvCfg.BuildURI(testSchema), srvCfg.User, srvCfg.Pass)))
	}

	srv, err := NewExtender(opt[testExtHaOptPfh].(*publications.FileHandler), opts...)
	if err != nil {
		t.Fatal("Failed to create extender: ", err)
	}

	req, err := pdu.NewExtendingReq(testFrom, pdu.ExtReqSetPubTime(testTo))
	if err != nil {
		t.Fatal("Failed to create request: ", err)
	}

	// Initialize request send worker.
	var (
		reqContext, reqCancel = context.WithCancel(context.Background())
		respErr               error
		resp                  *pdu.ExtenderResp
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
