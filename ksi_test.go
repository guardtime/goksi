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

package ksi

import (
	"encoding/csv"
	"os"
	"path"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/guardtime/goksi/errors"
	"github.com/guardtime/goksi/hash"
	"github.com/guardtime/goksi/log"
	"github.com/guardtime/goksi/pdu"
	"github.com/guardtime/goksi/publications"
	"github.com/guardtime/goksi/service"
	"github.com/guardtime/goksi/signature"
	"github.com/guardtime/goksi/signature/verify/reserr"
	"github.com/guardtime/goksi/signature/verify/result"
	"github.com/guardtime/goksi/test"
	"github.com/guardtime/goksi/test/sysconf"
	"github.com/guardtime/goksi/test/utils"
	"github.com/guardtime/goksi/test/utils/mock"
)

const (
	csvComment = '#'
	csvComma   = ';'

	testUser = "anon"
	testPass = "anon"
)

type csvField byte

const (
	csvFieldSignatureURI csvField = iota
	csvFieldVerificationState
	csvFieldErrorCode
	csvFieldErrorMessage
	csvFieldInputHashLevel
	csvFieldAggrInputHash
	csvFieldCalInputHash
	csvFieldCalOutputHash
	csvFieldAggrTime
	csvFieldPubTime
	csvFieldPubString
	csvFieldExtendPerm
	csvFieldExtendResp
	csvFieldPubsFile
	csvFieldCertFile
)

type verifyStrategy byte

const (
	vsNotImplemented verifyStrategy = iota
	vsParseFailure
	vsPolicy
)

var (
	testRoot            = filepath.Join("test")
	confFile            = filepath.Join(testRoot, "systest.conf.json")
	logDir              = filepath.Join(testRoot, "out")
	resourceDir         = filepath.Join(testRoot, "resource")
	resourceTestPackDir = filepath.Join(resourceDir, "SignatureTestPack")
)

func TestSysPack(t *testing.T) {

	logger, defFunc, err := test.InitLogger(t, logDir, log.DEBUG, t.Name())
	if err != nil {
		t.Fatal("Failed to initialize logger: ", err)
	}
	defer defFunc()
	// Apply logger.
	log.SetLogger(logger)

	// Check if system test config is present and load it.
	cfg := utils.LoadConfigFile(t, confFile)

	test.Suite{
		{Func: validSignaturesTests},
		{Func: invalidSignaturesTests},
		{Func: policyVerificationTests},
		{Func: internalPolicySignaturesTests},
	}.Runner(t, cfg)
}

const (
	ksiSysTestOptCfg = iota
)

func validSignaturesTests(t *testing.T, opt ...interface{}) {
	testLoader(t, opt[ksiSysTestOptCfg].(*sysconf.Configuration),
		filepath.Join(resourceTestPackDir, "valid-signatures"), "signature-results.csv")
}

func invalidSignaturesTests(t *testing.T, opt ...interface{}) {
	testLoader(t, opt[ksiSysTestOptCfg].(*sysconf.Configuration),
		filepath.Join(resourceTestPackDir, "invalid-signatures"), "invalid-signature-results.csv")
}

func policyVerificationTests(t *testing.T, opt ...interface{}) {
	testLoader(t, opt[ksiSysTestOptCfg].(*sysconf.Configuration),
		filepath.Join(resourceTestPackDir, "policy-verification-signatures"), "policy-verification-results.csv")
}

func internalPolicySignaturesTests(t *testing.T, opt ...interface{}) {
	testLoader(t, opt[ksiSysTestOptCfg].(*sysconf.Configuration),
		filepath.Join(resourceTestPackDir, "internal-policy-signatures"), "internal-policy-results.csv")
}

func testLoader(t *testing.T, cfg *sysconf.Configuration, rootPath, csvFile string) {
	csvPath := path.Join(rootPath, csvFile)
	recs, err := loadRecords(csvPath)
	if err != nil {
		t.Fatal("Failed to load CSV records: ", err)
	}

	log.Debug("TestPack CSV file: ", csvPath)
	for _, rec := range recs {
		csvLine := strings.Join(rec, ";")
		t.Run(csvLine,
			func(t *testing.T) {
				log.Debug("Test CSV record: ", csvLine)
				testRunner(cfg, t, rootPath, rec)
			},
		)
	}
}

func loadRecords(p string) ([][]string, error) {
	f, err := os.Open(p)
	if err != nil {
		return nil, err
	}
	defer func() {
		if err := f.Close(); err != nil {
			log.Error("Failed to close file: ", err)
		}
	}()

	r := csv.NewReader(f)
	r.Comma = csvComma
	r.Comment = csvComment

	return r.ReadAll()
}

func testRunner(cfg *sysconf.Configuration, t *testing.T, root string, csvRec []string) {

	var (
		err error

		pfhOpts = []publications.FileHandlerSetting{
			publications.FileHandlerSetFileCertConstraints(cfg.Pubfile.Constraints()),
		}
		verOpts []signature.VerCtxOption

		verStrategy verifyStrategy
		verPolicy   signature.Policy
		verErr      = reserr.ErrNA
		verErrMgs   string
	)

	// Set verification state and policy.
	if len(csvRec[csvFieldVerificationState]) > 0 {
		switch csvRec[csvFieldVerificationState] {
		case "not-implemented":
			verStrategy = vsNotImplemented
		case "parsing":
			verStrategy = vsParseFailure
		default:
			switch csvRec[csvFieldVerificationState] {
			case "calendar":
				verPolicy = signature.CalendarBasedVerificationPolicy
			case "key":
				verPolicy = signature.KeyBasedVerificationPolicy
			case "userPublication":
				verPolicy = signature.UserProvidedPublicationBasedVerificationPolicy
			case "publicationsFile":
				verPolicy = signature.PublicationsFileBasedVerificationPolicy
			case "internal":
				verPolicy = signature.InternalVerificationPolicy
			default:
				t.Error("Skipping test case because of unknown verification state: ", csvRec[csvFieldVerificationState])
			}
			verStrategy = vsPolicy
		}
	}
	if verStrategy == vsNotImplemented {
		log.Debug("Skipping test.")
		t.Skip("Skipping test for 'not_implemented'")
		return
	}

	if len(csvRec[csvFieldCertFile]) > 0 {
		pfhOpts = append(pfhOpts, publications.FileHandlerSetTrustedCertificateFromFilePem(path.Join(root, csvRec[csvFieldCertFile])))
	}

	var pubsFile *publications.File
	if len(csvRec[csvFieldPubsFile]) > 0 {
		pubsFile, err = publications.NewFile(publications.FileFromFile(path.Join(root, csvRec[csvFieldPubsFile])))
		assert(t, err == nil, "Failed to load publications file: ", err)

		verOpts = append(verOpts, signature.VerCtxOptPublicationsFile(pubsFile))
	} else {
		pfhOpts = append(pfhOpts, publications.FileHandlerSetPublicationsURL(cfg.Pubfile.Url))
	}

	if len(csvRec[csvFieldAggrInputHash]) > 0 {
		verOpts = append(verOpts, signature.VerCtxOptDocumentHash(hash.Imprint(utils.StringToBin(csvRec[csvFieldAggrInputHash]))))
	}

	if len(csvRec[csvFieldInputHashLevel]) > 0 {
		tmp, err := strconv.ParseUint(csvRec[csvFieldInputHashLevel], 10, 64)
		assert(t, err == nil, "Failed to parse level value: ", err)
		assert(t, tmp < (0xff+1), "Input level is to large: ", tmp)

		verOpts = append(verOpts, signature.VerCtxOptInputHashLevel(byte(tmp)))
	}

	if len(csvRec[csvFieldPubString]) > 0 {
		tmp, err := pdu.NewPublicationData(pdu.PubDataFromString(csvRec[csvFieldPubString]))
		assert(t, err == nil, "Failed to parse publication string:", err)

		verOpts = append(verOpts, signature.VerCtxOptUserPublication(tmp))
	}

	pfh, err := publications.NewFileHandler(pfhOpts...)
	if err != nil {
		t.Fatal("Failed to initialize publications file handler: ", err)
	}
	verOpts = append(verOpts, signature.VerCtxOptPublicationsFileHandler(pfh))

	if pubsFile != nil {
		err = pfh.Verify(pubsFile)
		assert(t, err == nil, "Failed to verify publications file: ", err)
	}

	if len(csvRec[csvFieldExtendPerm]) > 0 && csvRec[csvFieldExtendPerm] == "true" {
		verOpts = append(verOpts, signature.VerCtxOptExtendingPermitted(true))
	}
	if len(csvRec[csvFieldExtendResp]) > 0 {
		client := mock.NewFileReaderClient(path.Join(root, csvRec[csvFieldExtendResp]), testUser, testPass)
		tmp, err := service.NewExtender(pfh, service.OptNetClient(client))
		assert(t, err == nil, "Failed setup extender: ", err)

		verOpts = append(verOpts, signature.VerCtxOptCalendarProvider(tmp))
	} else {
		tmp, err := service.NewExtender(pfh, service.OptEndpoint(cfg.Extender.BuildURI(cfg.Schema.Tcp), cfg.Extender.User, cfg.Extender.Pass))
		assert(t, err == nil, "Failed setup extender: ", err)

		verOpts = append(verOpts, signature.VerCtxOptCalendarProvider(tmp))
	}

	sig, err := signature.New(signature.BuildNoVerify(
		signature.BuildFromFile(path.Join(root, csvRec[csvFieldSignatureURI]))))
	if err != nil {
		assert(t, verStrategy == vsParseFailure, "Unexpected failure: ", err)
		assert(t, err.(*errors.KsiError).Code() == errors.KsiInvalidFormatError ||
			err.(*errors.KsiError).Code() == errors.KsiInvalidStateError,
			"Signature parsing did not fail with expected error: ", err.Error())
		log.Debug("Signature is expected to fail during parsing stage.")
		return
	}
	assert(t, verStrategy != vsParseFailure, "Signature must have failed during parse stage.")

	verCtx, err := signature.NewVerificationContext(sig, verOpts...)
	assert(t, err == nil, "Failed to create verification context: ", err)

	res, err := verPolicy.Verify(verCtx)
	assert(t, err == nil, "Failed to verify: ", err)

	// Verify test case expectations match the verification result.
	if len(csvRec[csvFieldErrorCode]) > 0 && csvRec[csvFieldErrorCode] != "OK" {
		verErr = reserr.CodeByName(csvRec[csvFieldErrorCode])
		verErrMgs = csvRec[csvFieldErrorMessage]
		assert(t, verErr != reserr.ErrNA, "Unknown error code: ", csvRec[csvFieldErrorCode])
	}
	if verErr != reserr.ErrNA {
		// Verification is expected to fail.
		assert(t, res != result.OK, "Signature verification should have failed.")
		// Test case has failed as expected. Verify fail result.
		verResult, err := verCtx.Result()
		assert(t, err == nil, "Failed to get verification result: ", err)
		resultErr, ok := verResult.Error().(*errors.KsiError)
		assert(t, ok, "Unknown verification result error:", resultErr)
		resultCode := reserr.Code(resultErr.ExtCode())
		assert(t, resultErr.Code() == errors.KsiVerificationFailure && resultCode == verErr, "Error code mismatch.")
		assert(t, verErr.Message() == verErrMgs, "Error message mismatch.")
	} else {
		// Verification is not expected to fail.
		assert(t, res == result.OK, "Signature verification should not fail. Result:", res)
	}

	if len(csvRec[csvFieldCalInputHash]) > 0 {
		hsh, err := sig.AggregationHashChainListAggregate(0)
		assert(t, err == nil, "Failed to aggregate hash chains: ", err)
		assert(t, hash.Equal(hsh, hash.Imprint(utils.StringToBin(csvRec[csvFieldCalInputHash]))), "Calendar input hash mismatch.")
	}

	if len(csvRec[csvFieldCalOutputHash]) > 0 {
		calChain, err := sig.CalendarChain()
		assert(t, err == nil, "Failed to get calendar hash chain:", err)

		hsh, err := calChain.Aggregate()
		assert(t, err == nil, "Failed to calendar hash chain: ", err)
		assert(t, hash.Equal(hsh, hash.Imprint(utils.StringToBin(csvRec[csvFieldCalOutputHash]))), "Calendar output hash mismatch.")
	}

	if len(csvRec[csvFieldAggrTime]) > 0 {
		tmp, err := strconv.ParseUint(csvRec[csvFieldAggrTime], 10, 64)
		assert(t, err == nil, "Failed to parse aggregation time:", err)

		sigTime, err := sig.SigningTime()
		assert(t, err == nil, "Failed to get signing time: ", err)
		assert(t, sigTime.Equal(time.Unix(int64(tmp), 0)), "Aggregation time mismatch.")
	}

	if len(csvRec[csvFieldPubTime]) > 0 {
		tmp, err := strconv.ParseUint(csvRec[csvFieldPubTime], 10, 64)
		assert(t, err == nil, "Failed to parse pub time:", err)

		calChain, err := sig.CalendarChain()
		assert(t, err == nil, "Failed to get calendar hash chain:", err)

		pubTime, err := calChain.PublicationTime()
		assert(t, err == nil, "Failed to get publication time: ", err)
		assert(t, pubTime.Equal(time.Unix(int64(tmp), 0)), "Aggregation time mismatch.")
	}
}

func assert(t *testing.T, cond bool, msgArgs ...interface{}) {
	if !cond {
		log.Debug(msgArgs...)
		t.Fatal(msgArgs...)
	}
}
