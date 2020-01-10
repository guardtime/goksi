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

	"github.com/guardtime/goksi/errors"
	"github.com/guardtime/goksi/hash"
	"github.com/guardtime/goksi/log"
	"github.com/guardtime/goksi/net"
	"github.com/guardtime/goksi/pdu"
	"github.com/guardtime/goksi/publications"
	"github.com/guardtime/goksi/signature"
	"github.com/guardtime/goksi/signature/verify/result"
	"github.com/guardtime/goksi/test"
	"github.com/guardtime/goksi/test/sysconf"
	"github.com/guardtime/goksi/test/utils"
)

func TestSysSignerHTTP(t *testing.T) {

	logger, defFunc, err := test.InitLogger(t, testLogDir, log.DEBUG, t.Name())
	if err != nil {
		t.Fatal("Failed to initialize logger: ", err)
	}
	defer defFunc()

	// Check if system test config is present and load it.
	cfg := utils.LoadConfigFile(t, testConfFile)

	signerRunner(t, logger, cfg.Schema.Http, cfg)
}

func TestSysSignerTCP(t *testing.T) {

	logger, defFunc, err := test.InitLogger(t, testLogDir, log.DEBUG, t.Name())
	if err != nil {
		t.Fatal("Failed to initialize logger: ", err)
	}
	defer defFunc()

	// Check if system test config is present and load it.
	cfg := utils.LoadConfigFile(t, testConfFile)

	signerRunner(t, logger, cfg.Schema.Tcp, cfg)
}

func signerRunner(t *testing.T, logger log.Logger, schema string, cfg *sysconf.Configuration) {
	// Apply logger.
	log.SetLogger(logger)

	// Create network client.
	nc, err := net.NewClient(cfg.Aggregator.BuildURI(schema), cfg.Aggregator.User, cfg.Aggregator.Pass)
	if err != nil {
		t.Fatal("Failed to initialize net client: ", err)
	}

	test.Suite{
		{Func: testSignerSendAggrRequest},
		{Func: testSignerSignImprint},
		{Func: testSignerSignWithInternalPolicyOption},
		{Func: testSignerSignWithOptionsKeyBasedPolicy},
		{Func: testSignerSendConfRequest},
		{Func: testSignerWithContextCancel},
	}.Runner(t, nc, cfg)
}

const (
	signerSysTestOptNet = iota
	signerSysTestOptCfg
)

func testSignerSendAggrRequest(t *testing.T, opt ...interface{}) {
	var (
		testImprint = hash.Imprint{0x01,
			0xc4, 0xbb, 0xcb, 0x1f, 0xbe, 0xc9, 0x9d, 0x65, 0xbf, 0x59, 0xd8, 0x5c, 0x8c, 0xb6, 0x2e, 0xe2,
			0xdb, 0x96, 0x3f, 0x0f, 0xe1, 0x06, 0xf4, 0x83, 0xd9, 0xaf, 0xa7, 0x3b, 0xd4, 0xe3, 0x9a, 0x8a,
		}
	)

	srv, err := NewSigner(OptNetClient(opt[signerSysTestOptNet].(net.Client)))
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

func testSignerSignImprint(t *testing.T, opt ...interface{}) {
	var (
		testImprint = hash.Imprint{0x01,
			0xc4, 0xbb, 0xcb, 0x1f, 0xbe, 0xc9, 0x9d, 0x65, 0xbf, 0x59, 0xd8, 0x5c, 0x8c, 0xb6, 0x2e, 0xe2,
			0xdb, 0x96, 0x3f, 0x0f, 0xe1, 0x06, 0xf4, 0x83, 0xd9, 0xaf, 0xa7, 0x3b, 0xd4, 0xe3, 0x9a, 0x8a,
		}
	)

	srv, err := NewSigner(OptNetClient(opt[signerSysTestOptNet].(net.Client)))
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

func testSignerSignWithInternalPolicyOption(t *testing.T, opt ...interface{}) {
	var (
		testImprint = hash.Imprint{0x01,
			0xc4, 0xbb, 0xcb, 0x1f, 0xbe, 0xc9, 0x9d, 0x65, 0xbf, 0x59, 0xd8, 0x5c, 0x8c, 0xb6, 0x2e, 0xe2,
			0xdb, 0x96, 0x3f, 0x0f, 0xe1, 0x06, 0xf4, 0x83, 0xd9, 0xaf, 0xa7, 0x3b, 0xd4, 0xe3, 0x9a, 0x8a,
		}
		testPolicy = signature.InternalVerificationPolicy
	)

	srv, err := NewSigner(OptNetClient(opt[signerSysTestOptNet].(net.Client)))
	if err != nil {
		t.Fatal("Failed to create signer: ", err)
	}

	// Sign without policy option.
	sigDef, err := srv.Sign(testImprint)
	if err != nil {
		t.Fatal("Failed to receive response: ", err)
	}
	if sigDef == nil {
		t.Fatal("KSI signature must be returned.")
	}
	sigDefVerRes, err := sigDef.VerificationResult()
	if err != nil {
		t.Fatal("Failed to get signature verification result: ", err)
	}
	if sigDefVerRes == nil {
		t.Fatal("Must return verification result.")
	}

	// Sign with policy option.
	sigPol, err := srv.Sign(testImprint, SignOptionVerificationPolicy(testPolicy))
	if err != nil {
		t.Fatal("Failed to receive response: ", err)
	}
	if sigPol == nil {
		t.Fatal("KSI signature must be returned.")
	}
	sigPolVerRes, err := sigPol.VerificationResult()
	if err != nil {
		t.Fatal("Failed to get signature verification result: ", err)
	}
	if sigPolVerRes == nil {
		t.Fatal("Must return verification result.")
	}

	// Verify the final rule name.
	if sigDefVerRes.FinalResult().RuleName() != sigPolVerRes.FinalResult().RuleName() {
		t.Fatal("Verification result final rule mismatch.")
	}
}

func testSignerSignWithOptionsKeyBasedPolicy(t *testing.T, opt ...interface{}) {
	var (
		testImprint = hash.Imprint{0x01,
			0xc4, 0xbb, 0xcb, 0x1f, 0xbe, 0xc9, 0x9d, 0x65, 0xbf, 0x59, 0xd8, 0x5c, 0x8c, 0xb6, 0x2e, 0xe2,
			0xdb, 0x96, 0x3f, 0x0f, 0xe1, 0x06, 0xf4, 0x83, 0xd9, 0xaf, 0xa7, 0x3b, 0xd4, 0xe3, 0x9a, 0x8a,
		}
		testPolicy       = signature.KeyBasedVerificationPolicy
		testCfgNetClient = opt[signerSysTestOptNet].(net.Client)
		testCfgPubFile   = opt[signerSysTestOptCfg].(*sysconf.Configuration).Pubfile
	)

	srv, err := NewSigner(OptNetClient(testCfgNetClient))
	if err != nil {
		t.Fatal("Failed to create signer: ", err)
	}

	pfh, err := publications.NewFileHandler(
		publications.FileHandlerSetPublicationsURL(testCfgPubFile.Url),
		publications.FileHandlerSetFileCertConstraints(testCfgPubFile.Constraints()),
	)
	if err != nil {
		t.Fatal("Failed to initialize publications file handler: ", err)
	}

	sig, err := srv.Sign(testImprint,
		SignOptionVerificationPolicy(testPolicy),
		SignOptionVerificationOptions(
			signature.VerCtxOptPublicationsFileHandler(pfh),
		),
	)
	if err != nil {
		t.Fatal("Failed to receive response: ", err)
	}
	if sig == nil {
		t.Fatal("KSI signature must be returned.")
	}
	sigVerRes, err := sig.VerificationResult()
	if err != nil {
		t.Fatal("Failed to get signature verification result: ", err)
	}
	if sigVerRes == nil {
		t.Fatal("Must return verification result.")
	}

	// Verify the signature via policy interface with same options.
	verCtx, err := signature.NewVerificationContext(sig,
		signature.VerCtxOptPublicationsFileHandler(pfh),
	)
	if err != nil {
		t.Fatal("Failed to create verification context: ", err)
	}
	res, err := testPolicy.Verify(verCtx)
	if err != nil {
		t.Fatal("Policy Verify returned error: ", err)
	}
	if res != result.OK {
		t.Fatal("Verification failed with result: ", res)
	}
	verRes, err := verCtx.Result()
	if err != nil {
		t.Fatal("Failed to get verification result: ", res)
	}

	// Compare verification results.
	sigResCode, err := sigVerRes.FinalResult().ResultCode()
	if err != nil {
		t.Fatal("Failed to get signature final result code: ", err)
	}
	verResCode, err := verRes.FinalResult().ResultCode()
	if err != nil {
		t.Fatal("Failed to get verification final result code: ", err)
	}
	if sigResCode != verResCode {
		t.Fatal("Verification result code mismatch.")
	}
	if sigVerRes.FinalResult().RuleName() != verRes.FinalResult().RuleName() {
		t.Fatal("Verification result final rule name mismatch.")
	}
}

func testSignerSendConfRequest(t *testing.T, opt ...interface{}) {

	srv, err := NewSigner(OptNetClient(opt[signerSysTestOptNet].(net.Client)))
	if err != nil {
		t.Fatal("Failed to create signer: ", err)
	}

	req, err := pdu.NewAggregatorConfigReq()
	if err != nil {
		t.Fatal("Failed to create request: ", err)
	}

	resp, err := srv.Send(req)
	if err != nil {
		t.Fatal("Failed to receive response: ", err)
	}

	cfgReps, err := resp.Config()
	if err != nil {
		t.Fatal("Failed to get config response: ", err)
	}
	if cfgReps == nil {
		t.Error("Missing config response")
	}
	log.Debug(cfgReps.String())

	sig, err := signature.New(signature.BuildFromAggregationResp(resp, 0))
	if err == nil {
		log.Debug(sig)
		t.Fatal("Aggregation response should have not been returned.")
	}
	if errors.KsiErr(err).Code() != errors.KsiInvalidArgumentError {
		t.Fatal("Error code mismatch: ", err)
	}
}

func testSignerWithContextCancel(t *testing.T, opt ...interface{}) {
	type (
		response struct {
			data interface{}
			err  error
		}
		worker func(*Signer, context.Context, *sync.WaitGroup, *response)
	)

	var (
		testNecClient = opt[signerSysTestOptNet].(net.Client)

		workers = []worker{
			func(srv *Signer, reqContext context.Context, wg *sync.WaitGroup, res *response) {
				defer wg.Done()
				req, err := pdu.NewAggregationReq(hash.Default.ZeroImprint())
				if err != nil {
					res.data = nil
					res.err = err
					return
				}

				resp, err := srv.Send(req.WithContext(reqContext))
				res.data = resp
				res.err = err
			},

			func(srv *Signer, reqContext context.Context, wg *sync.WaitGroup, res *response) {
				defer wg.Done()
				resp, err := srv.Sign(hash.Default.ZeroImprint(), SignOptionWithContext(reqContext))
				res.data = resp
				res.err = err
			},
		}
		replies = make([]response, len(workers))
		wg      sync.WaitGroup
	)

	srv, err := NewSigner(OptNetClient(testNecClient))
	if err != nil {
		t.Fatal("Failed to create signer: ", err)
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
		case *pdu.AggregatorResp:
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
