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

	"github.com/guardtime/goksi/errors"
	"github.com/guardtime/goksi/log"
	"github.com/guardtime/goksi/net"
	"github.com/guardtime/goksi/pdu"
	"github.com/guardtime/goksi/publications"
	"github.com/guardtime/goksi/signature"
	"github.com/guardtime/goksi/test"
	"github.com/guardtime/goksi/test/utils"
)

const (
	extTestOptNet = iota
	extTestOptPfh
)

func TestSysExtenderHTTP(t *testing.T) {

	logger, defFunc, err := test.InitLogger(t, testLogDir, log.DEBUG, t.Name())
	if err != nil {
		t.Fatal("Failed to initialize logger: ", err)
	}
	defer defFunc()
	// Apply logger.
	log.SetLogger(logger)

	// Check if system test config is present and load it.
	cfg := utils.LoadConfigFile(t, testConfFile)

	pfh, err := publications.NewFileHandler(
		publications.FileHandlerSetPublicationsURL(cfg.Pubfile.Url),
		publications.FileHandlerSetFileCertConstraints(cfg.Pubfile.Constraints()),
	)
	if err != nil {
		t.Fatal("Failed to initialize publications file handler: ", err)
	}

	nc, err := net.NewClient(cfg.Extender.BuildURI(cfg.Schema.Http), cfg.Extender.User, cfg.Extender.Pass)
	if err != nil {
		t.Fatal("Failed to initialize network client: ", err)
	}

	extenderSysTestSuite.Runner(t, nc, pfh)
}

func TestSysExtenderTCP(t *testing.T) {

	logger, defFunc, err := test.InitLogger(t, testLogDir, log.DEBUG, t.Name())
	if err != nil {
		t.Fatal("Failed to initialize logger: ", err)
	}
	defer defFunc()
	// Apply logger.
	log.SetLogger(logger)

	// Check if system test config is present and load it.
	cfg := utils.LoadConfigFile(t, testConfFile)

	pfh, err := publications.NewFileHandler(
		publications.FileHandlerSetPublicationsURL(cfg.Pubfile.Url),
		publications.FileHandlerSetFileCertConstraints(cfg.Pubfile.Constraints()),
	)
	if err != nil {
		t.Fatal("Failed to initialize publications file handler: ", err)
	}

	nc, err := net.NewClient(cfg.Extender.BuildURI(cfg.Schema.Tcp), cfg.Extender.User, cfg.Extender.Pass)
	if err != nil {
		t.Fatal("Failed to initialize network client: ", err)
	}

	extenderSysTestSuite.Runner(t, nc, pfh)
}

var extenderSysTestSuite = test.Suite{
	{Func: testExtendToTime},
	{Func: testGetConfig},
	{Func: testExtendToTimeBeforeSignature},
	{Func: testExtendToFuture},
	{Func: testExtendWithNotAccessiblePublicationsFile},
	{Func: testExtenderExtendToNearestPublication},
	{Func: testExtenderReceiveCalendar},
	{Func: testExtenderWithContextCancel},
}

func testExtendWithNotAccessiblePublicationsFile(t *testing.T, opt ...interface{}) {
	// Test case resources.
	var (
		testSigFile = filepath.Join(testResourceSigDir, "ok-sig-2018-06-15.1.ksig")
	)

	extender, err := NewExtender(nil,
		OptNetClient(opt[extTestOptNet].(net.Client)),
	)
	if err != nil {
		t.Fatal("Failed to create extender: ", err)
	}

	sig, err := signature.New(signature.BuildFromFile(testSigFile))
	if err != nil {
		t.Fatal("Failed to create ksi signature from file: ", err)
	}

	extSig, err := extender.Extend(sig)
	if err != nil {
		t.Fatal("Extensions should have failed: ", err)
	}

	if extSig == nil {
		t.Fatal("Signature should be extended to head if publications file is not provided.")
	}
}

func testGetConfig(t *testing.T, opt ...interface{}) {
	extender, err := NewExtender(opt[extTestOptPfh].(*publications.FileHandler),
		OptNetClient(opt[extTestOptNet].(net.Client)),
	)
	if err != nil {
		t.Fatal("Failed to create extender: ", err)
	}
	cfg, err := extender.Config()
	if err != nil {
		t.Fatal("Failed to get extender config: ", err)
	}

	if cfg == nil {
		t.Fatal("Extender config can not be nil")
	}

}

func testExtendToTimeBeforeSignature(t *testing.T, opt ...interface{}) {
	var (
		testSigFile = filepath.Join(testResourceSigDir, "ok-sig-2018-06-15.1.ksig")
	)

	extender, err := NewExtender(opt[extTestOptPfh].(*publications.FileHandler),
		OptNetClient(opt[extTestOptNet].(net.Client)),
	)
	if err != nil {
		t.Fatal("Failed to create extender: ", err)
	}

	sig, err := signature.New(signature.BuildFromFile(testSigFile))
	if err != nil {
		t.Fatal("Failed to create ksi signature from file: ", err)
	}

	sigTime, err := sig.SigningTime()
	if err != nil {
		t.Fatal("Failed to get signing time: ", err)
	}
	extToTime := sigTime.Unix() - int64(1000)

	extSig, err := extender.Extend(sig, ExtendOptionToTime(time.Unix(extToTime, int64(0))))
	if err == nil {
		t.Fatal("It should not be possible to extend to time before signing time: ", err)
	}
	if extSig != nil {
		t.Fatal("Signature should not be returned in case of error: ", err)
	}
}

func testExtendToFuture(t *testing.T, opt ...interface{}) {
	var (
		testSigFile = filepath.Join(testResourceSigDir, "ok-sig-2018-06-15.1.ksig")
	)

	extender, err := NewExtender(opt[extTestOptPfh].(*publications.FileHandler),
		OptNetClient(opt[extTestOptNet].(net.Client)),
	)
	if err != nil {
		t.Fatal("Failed to create extender: ", err)
	}

	sig, err := signature.New(signature.BuildFromFile(testSigFile))
	if err != nil {
		t.Fatal("Failed to create ksi signature from file: ", err)
	}

	extToTime := time.Now().Unix() + int64(1000000)

	extSig, err := extender.Extend(sig, ExtendOptionToTime(time.Unix(extToTime, int64(0))))
	if err == nil {
		t.Fatal("It should not be possible to extend to future time.")
	}

	if extSig != nil {
		t.Fatal("Signature should not be returned in case of error: ", err)
	}
}

func testExtendToTime(t *testing.T, opt ...interface{}) {
	var (
		testSigFile = filepath.Join(testResourceSigDir, "ok-sig-2018-06-15.1.ksig")
	)

	extender, err := NewExtender(opt[extTestOptPfh].(*publications.FileHandler),
		OptNetClient(opt[extTestOptNet].(net.Client)),
	)
	if err != nil {
		t.Fatal("Failed to create extender: ", err)
	}

	sig, err := signature.New(signature.BuildFromFile(testSigFile))
	if err != nil {
		t.Fatal("Failed to create ksi signature from file: ", err)
	}

	sigTime, err := sig.SigningTime()
	if err != nil {
		t.Fatal("Failed to get signing time: ", err)
	}
	extToTime := sigTime.Unix() + int64(10000)

	extSig, err := extender.Extend(sig, ExtendOptionToTime(time.Unix(extToTime, int64(0))))
	if err != nil {
		t.Fatal("Failed to receive response: ", err)
	}

	isExtended, err := extSig.IsExtended()
	if err != nil {
		t.Fatal("Unable to retrieve extended status: ", err)
	}
	if !isExtended {
		t.Fatal("Signature was not extended.")
	}
}

func testExtenderExtendToNearestPublication(t *testing.T, opt ...interface{}) {
	var (
		testSigFile             = filepath.Join(testResourceSigDir, "ok-sig-2014-08-01.1.ksig")
		publicationsFileHandler = opt[extTestOptPfh].(*publications.FileHandler)
	)

	extender, err := NewExtender(publicationsFileHandler,
		OptNetClient(opt[extTestOptNet].(net.Client)),
	)
	if err != nil {
		t.Fatal("Failed to create signer: ", err)
	}

	sig, err := signature.New(signature.BuildFromFile(testSigFile))
	if err != nil {
		t.Fatal("Failed to create ksi signature from file: ", err)
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

	pubFile, err := publicationsFileHandler.ReceiveFile()
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

func testExtenderReceiveCalendar(t *testing.T, opt ...interface{}) {
	var (
		testPubFileHandler = opt[extTestOptPfh].(*publications.FileHandler)
		testNecClient      = opt[extTestOptNet].(net.Client)
		testFrom           = time.Unix(1398866256, 0)
		testTo             = time.Unix(1408060800, 0)
	)

	extender, err := NewExtender(testPubFileHandler,
		OptNetClient(testNecClient),
	)
	if err != nil {
		t.Fatal("Failed to create signer: ", err)
	}

	resp, err := extender.ReceiveCalendar(testFrom, testTo)
	if err != nil {
		t.Fatal("Failed to receive extender response: ", err)
	}
	aggrTime, err := resp.AggregationTime()
	if err != nil {
		t.Fatal("Failed to extract aggregation time: ", err)

	}
	pubTime, err := resp.PublicationTime()
	if err != nil {
		t.Fatal("Failed to extract aggregation time: ", err)

	}

	if !testFrom.Equal(aggrTime) || !pubTime.Equal(pubTime) {
		t.Fatal("Calendar time mismatch.")
	}
}

func testExtenderWithContextCancel(t *testing.T, opt ...interface{}) {
	type (
		response struct {
			data interface{}
			err  error
		}
		worker func(*Extender, context.Context, *sync.WaitGroup, *response)
	)

	var (
		testPubFileHandler = opt[extTestOptPfh].(*publications.FileHandler)
		testNecClient      = opt[extTestOptNet].(net.Client)

		testFrom    = time.Unix(1398866256, 0)
		testTo      = time.Unix(1408060800, 0)
		testSigFile = filepath.Join(testResourceSigDir, "ok-sig-2014-08-01.1.ksig")

		workers = []worker{
			func(srv *Extender, reqContext context.Context, wg *sync.WaitGroup, res *response) {
				defer wg.Done()
				req, err := pdu.NewExtendingReq(testFrom, pdu.ExtReqSetPubTime(testTo))
				if err != nil {
					res.data = nil
					res.err = err
					return
				}

				resp, err := srv.Send(req.WithContext(reqContext))
				res.data = resp
				res.err = err
			},

			func(srv *Extender, reqContext context.Context, wg *sync.WaitGroup, res *response) {
				defer wg.Done()
				sig, err := signature.New(signature.BuildFromFile(testSigFile))
				if err != nil {
					res.data = nil
					res.err = err
					return
				}

				resp, err := srv.Extend(sig, ExtendOptionToTime(time.Time{}), ExtendOptionWithContext(reqContext))
				res.data = resp
				res.err = err
			},
		}
		replies = make([]response, len(workers))
		wg      sync.WaitGroup
	)

	srv, err := NewExtender(testPubFileHandler, OptNetClient(testNecClient))
	if err != nil {
		t.Fatal("Failed to create extender: ", err)
	}

	wg.Add(len(workers))
	for i, send := range workers {
		reqContext, reqCancel := context.WithCancel(context.Background())
		go send(srv, reqContext, &wg, &replies[i])
		// Cancel the request.
		reqCancel()
	}
	// Wait for the worker to complete.
	wg.Wait()

	for i, resp := range replies {
		// Verify return values.
		if resp.err == nil || errors.KsiErr(resp.err).Code() != errors.KsiNetworkError {
			t.Fatalf("[%d] Must return cancellation error.", i)
		}
		// Verify no data was returned.
		switch v := resp.data.(type) {
		case *pdu.ExtenderResp:
			if v != nil {
				t.Fatalf("[%d] No response must be returned.", i)
			}
		case *signature.Signature:
			if v != nil {
				t.Fatalf("[%d] No signature must be returned.", i)
			}
		default:
			t.Fatalf("[%d] Unexpected response type.", i)
		}
	}
}
