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

package signature

import (
	"path/filepath"
	"testing"
	"time"

	"github.com/guardtime/goksi/errors"
	"github.com/guardtime/goksi/log"
	"github.com/guardtime/goksi/pdu"
	"github.com/guardtime/goksi/publications"
	"github.com/guardtime/goksi/signature/verify"
	"github.com/guardtime/goksi/signature/verify/reserr"
	"github.com/guardtime/goksi/signature/verify/result"
	"github.com/guardtime/goksi/test"
	"github.com/guardtime/goksi/test/utils/mock"
)

func TestUnitRules(t *testing.T) {

	logger, defFunc, err := test.InitLogger(t, testLogDir, log.DEBUG, t.Name())
	if err != nil {
		t.Fatal("Failed to initialize logger: ", err)
	}
	defer defFunc()
	// Apply logger.
	log.SetLogger(logger)

	test.Suite{
		{Func: testRuleVerifier},
	}.Runner(t)
}

func testRuleVerifier(t *testing.T, _ ...interface{}) {
	type ruleTestCase struct {
		file    string
		result  result.Code
		err     bool
		verOpts []VerCtxOption
	}
	// Test case resources.

	var (
		testDocOkSig20140602 = []byte{0x01,
			0x11, 0xa7, 0x00, 0xb0, 0xc8, 0x06, 0x6c, 0x47, 0xec, 0xba, 0x05, 0xed, 0x37, 0xbc, 0x14, 0xdc,
			0xad, 0xb2, 0x38, 0x55, 0x2d, 0x86, 0xc6, 0x59, 0x34, 0x2d, 0x1d, 0x7e, 0x87, 0xb8, 0x77, 0x2d}
		testHashSha512 = []byte{0x05,
			0x41, 0x36, 0xe5, 0x46, 0x6a, 0x08, 0x2b, 0x35, 0x90, 0xad, 0x58, 0x87, 0x5a, 0xd2, 0xaf, 0x6a,
			0x7e, 0x56, 0x04, 0x69, 0x2b, 0x0d, 0x28, 0x1c, 0xad, 0x55, 0xbe, 0xba, 0x07, 0x3c, 0xb9, 0x95,
			0xf3, 0x3c, 0x6c, 0x4b, 0xf1, 0x56, 0x01, 0xa3, 0xae, 0x38, 0x7c, 0xc8, 0xde, 0x21, 0x7f, 0x55,
			0xd7, 0xe5, 0x93, 0x50, 0xcd, 0x9e, 0xaf, 0x96, 0x35, 0x9b, 0x30, 0xf3, 0x80, 0xa2, 0xd2, 0x23}
		testLevel               byte = 5
		testUsrPubOkSig20140801      = "AAAAAA-C2E7FB-GAPOFH-M5AADL-HSN6WE-3GI6I4-G7HMG5-6STP2H-6N762O-HGFZ75-N2GTCI-SKQUOW"
		testPubStr20180715           = "AAAAAA-C3JKHI-AAKZ7D-HQQZU2-AF2ZKN-ZNXY5B-LMWRIN-DI37WF-PETGGY-YWWEA7-3MRG3N-V4WO2F"
		testPubStr20180615           = "AAAAAA-C3EMAY-AANR4X-52H7U6-XSTKWP-IXMQMW-C6KJDS-SIRRVW-BSYVFV-ZXQGZD-SBF47F-6QIG64"

		testData = []struct {
			rule              Rule
			errCode           reserr.Code
			ignoreCalProvider bool
			cases             []ruleTestCase
		}{

			{DocumentHashPresenceRule{}, reserr.ErrNA, false, []ruleTestCase{
				{filepath.Join(testSigDir, "ok-sig-2014-06-2.ksig"), result.OK, false, []VerCtxOption{
					VerCtxOptDocumentHash(testDocOkSig20140602)}},
				{filepath.Join(testSigDir, "ok-sig-2014-06-2.ksig"), result.NA, false, nil},
			}},

			{DocumentHashAlgorithmVerificationRule{}, reserr.Gen04, false, []ruleTestCase{
				{filepath.Join(testSigDir, "ok-sig-2014-06-2.ksig"), result.OK, false, []VerCtxOption{
					VerCtxOptDocumentHash(testDocOkSig20140602)}},
				{filepath.Join(testSigDir, "ok-sig-2014-06-2.ksig"), result.NA, true, nil},
				{filepath.Join(testSigDir, "ok-sig-2014-06-2.ksig"), result.FAIL, false, []VerCtxOption{
					VerCtxOptDocumentHash(testHashSha512)}},
			}},

			{DocumentHashVerificationRule{}, reserr.Gen01, false, []ruleTestCase{
				{filepath.Join(testSigDir, "ok-sig-2014-06-2.ksig"), result.OK, false, []VerCtxOption{
					VerCtxOptDocumentHash(testDocOkSig20140602)}},
				{filepath.Join(testSigDir, "ok-sig-2014-06-2.ksig"), result.NA, true, nil},
				{filepath.Join(testSigDir, "ok-sig-2014-06-2.ksig"), result.FAIL, false, []VerCtxOption{
					VerCtxOptDocumentHash(testHashSha512)}},
			}},

			{InputHashLevelVerificationRule{}, reserr.Gen03, false, []ruleTestCase{
				{filepath.Join(testSigDir, "signature-with-rfc3161-record-ok.ksig"), result.OK, false, nil},
				{filepath.Join(testSigDir, "signature-with-rfc3161-record-ok.ksig"), result.FAIL, false, []VerCtxOption{
					VerCtxOptInputHashLevel(1)}},
				{filepath.Join(testSigDir, "signature-with-rfc3161-record-ok.ksig"), result.FAIL, false, []VerCtxOption{
					VerCtxOptInputHashLevel(0xff)}},
				{filepath.Join(testSigDir, "ok-sig-2017-04-21.1-input-hash-level-5.ksig"), result.OK, false, nil},
				{filepath.Join(testSigDir, "ok-sig-2017-04-21.1-input-hash-level-5.ksig"), result.OK, false, []VerCtxOption{
					VerCtxOptInputHashLevel(testLevel)}},
				{filepath.Join(testSigDir, "ok-sig-2017-04-21.1-input-hash-level-5.ksig"), result.OK, false, []VerCtxOption{
					VerCtxOptInputHashLevel(testLevel - 1)}},
				{filepath.Join(testSigDir, "ok-sig-2017-04-21.1-input-hash-level-5.ksig"), result.FAIL, false, []VerCtxOption{
					VerCtxOptInputHashLevel(testLevel + 1)}},
				{filepath.Join(testSigDir, "nok-sig-invalid-level-correction.ksig"), result.NA, true, nil},
			}},

			{InputHashAlgorithmVerificationRule{}, reserr.Int13, false, []ruleTestCase{
				{filepath.Join(testSigDir, "nok-sig-doc-hsh-sha1.ksig"), result.FAIL, false, nil},
				{filepath.Join(testSigDir, "rfc3161-sha1-as-input-hash-2017.ksig"), result.FAIL, false, nil},
				{filepath.Join(testSigDir, "ok-sig-2014-06-2.ksig"), result.OK, false, nil},
				{filepath.Join(testSigDir, "signature-with-rfc3161-record-ok.ksig"), result.OK, false, nil},
				{filepath.Join(testSigDir, "rfc3161-sha1-as-input-hash-2016-01.ksig"), result.OK, false, nil},
			}},

			{Rfc3161RecordPresenceRule{}, reserr.ErrNA, false, []ruleTestCase{
				{filepath.Join(testSigDir, "ok-sig-2014-06-2.ksig"), result.NA, false, nil},
				{filepath.Join(testSigDir, "signature-with-rfc3161-record-ok.ksig"), result.OK, false, nil},
			}},

			{Rfc3161RecordHashAlgorithmVerificationRule{}, reserr.Int14, false, []ruleTestCase{
				{filepath.Join(testSigDir, "signature-with-rfc3161-record-ok.ksig"), result.OK, false, nil},
				{filepath.Join(testSigDir, "rfc3161-sha1-in-sig-atr-2016-01.ksig"), result.OK, false, nil},
				{filepath.Join(testSigDir, "rfc3161-sha1-in-sig-atr-2017.ksig"), result.FAIL, false, nil},
				{filepath.Join(testSigDir, "rfc3161-sha1-in-tst-algo-2016-01.ksig"), result.OK, false, nil},
				{filepath.Join(testSigDir, "rfc3161-sha1-in-tst-algo-2017.ksig"), result.FAIL, false, nil},
			}},

			{Rfc3161RecordOutputHashAlgorithmVerificationRule{}, reserr.Int17, false, []ruleTestCase{
				{filepath.Join(testSigDir, "signature-with-rfc3161-record-ok.ksig"), result.OK, false, nil},
				{filepath.Join(testSigDir, "rfc3161-sha1-in-aggr-input.ksig"), result.FAIL, false, nil},
			}},

			{AggregationHashChainIndexContinuationVerificationRule{}, reserr.Int12, false, []ruleTestCase{
				{filepath.Join(testSigDir, "ok-sig-2014-08-01.1.ksig"), result.OK, false, nil},
				{filepath.Join(testSigDir, "signature-with-rfc3161-record-ok.ksig"), result.OK, false, nil},
				{filepath.Join(testSigDir, "signature-with-rfc3161-record-changed-index-count.ksig"), result.FAIL, false, nil},
				{filepath.Join(testSigDir, "signature-with-rfc3161-record-ok-changed-chain-index.ksig"), result.FAIL, false, nil},
				{filepath.Join(testSigDir, "signature-with-rfc3161-record-ok-changed-chain-index-and-aggr-time.ksig"), result.FAIL, false, nil},
				{filepath.Join(testSigDir, "nok-sig-2014-08-01.1.double-aggr-chain.ksig"), result.FAIL, false, nil},
				{filepath.Join(testSigDir, "nok-sig-2014-08-01.1.same-chain-index.ksig"), result.FAIL, false, nil},
				{filepath.Join(testSigDir, "nok-sig-2014-08-01.1.wrong-chain-index.ksig"), result.FAIL, false, nil},
			}},

			{AggregationChainMetaDataVerificationRule{}, reserr.Int11, false, []ruleTestCase{
				{filepath.Join(testSigDir, "ok-sig-metadata-with-padding.ksig"), result.OK, false, nil},
				{filepath.Join(testSigDir, "ok-sig-metadata-without-padding.ksig"), result.OK, false, nil},
				{filepath.Join(testSigDir, "ok-sig-2014-04-30.1.ksig"), result.OK, false, nil},
				{filepath.Join(testSigDir, "nok-sig-metadata-padding-not-tlv8.ksig"), result.FAIL, false, nil},
				{filepath.Join(testSigDir, "nok-sig-metadata-padding-flags-not-set.ksig"), result.FAIL, false, nil},
				{filepath.Join(testSigDir, "nok-sig-metadata-padding-value-not-01.ksig"), result.FAIL, false, nil},
				{filepath.Join(testSigDir, "nok-sig-metadata-padding-value-not-0101.ksig"), result.FAIL, false, nil},
				{filepath.Join(testSigDir, "nok-sig-metadata-padding-value-len.ksig"), result.FAIL, false, nil},
				{filepath.Join(testSigDir, "nok-sig-metadata-length-not-even.ksig"), result.FAIL, false, nil},
				{filepath.Join(testSigDir, "nok-sig-metadata-padding-missing.ksig"), result.FAIL, false, nil},
			}},

			{AggregationChainHashAlgorithmVerificationRule{}, reserr.Int15, false, []ruleTestCase{
				{filepath.Join(testSigDir, "ok-sig-2014-06-2.ksig"), result.OK, false, nil},
				{filepath.Join(testSigDir, "sha1-as-aggregation-algo-2016-01.ksig"), result.OK, false, nil},
				{filepath.Join(testSigDir, "sha1-as-aggregation-algo-2017.ksig"), result.FAIL, false, nil},
			}},

			{AggregationHashChainConsistencyVerificationRule{}, reserr.Int01, false, []ruleTestCase{
				{filepath.Join(testSigDir, "ok-sig-2014-04-30.1.ksig"), result.OK, false, nil},
				{filepath.Join(testSigDir, "signature-with-invalid-rfc3161-output-hash.ksig"), result.FAIL, false, nil},
				{filepath.Join(testSigDir, "bad-aggregation-chain.ksig"), result.FAIL, false, nil},
			}},

			{AggregationHashChainTimeConsistencyVerificationRule{}, reserr.Int02, false, []ruleTestCase{
				{filepath.Join(testSigDir, "ok-sig-2014-04-30.1.ksig"), result.OK, false, nil},
				{filepath.Join(testSigDir, "signature-with-rfc3161-record-ok.ksig"), result.OK, false, nil},
				{filepath.Join(testSigDir, "signature-inconsistent-aggregation-chain-time.ksig"), result.FAIL, false, nil},
				{filepath.Join(testSigDir, "signature-with-rfc3161-record-ok-changed-aggregation-time.ksig"), result.FAIL, false, nil},
				{filepath.Join(testSigDir, "signature-with-rfc3161-record-ok-changed-chain-index-and-aggr-time.ksig"), result.FAIL, false, nil},
			}},

			{AggregationHashChainIndexConsistencyVerificationRule{}, reserr.Int10, false, []ruleTestCase{
				{filepath.Join(testSigDir, "ok-sig-2014-08-01.1.ksig"), result.OK, false, nil},
				{filepath.Join(testSigDir, "signature-with-rfc3161-record-ok.ksig"), result.OK, false, nil},
				{filepath.Join(testSigDir, "chain-index-ok.ksig"), result.OK, false, nil},
				{filepath.Join(testSigDir, "chain-index-nok.ksig"), result.FAIL, false, nil},
				{filepath.Join(testSigDir, "chain-index-prefix.ksig"), result.FAIL, false, nil},
				{filepath.Join(testSigDir, "chain-index-prefixes.ksig"), result.FAIL, false, nil},
				{filepath.Join(testSigDir, "chain-index-suffix.ksig"), result.FAIL, false, nil},
			}},

			{CalendarHashChainPresenceRule{}, reserr.ErrNA, false, []ruleTestCase{
				{filepath.Join(testSigDir, "ok-sig-2014-04-30.1.ksig"), result.OK, false, nil},
				{filepath.Join(testSigDir, "ok-sig-2014-04-30.1-no-cal-hashchain.ksig"), result.NA, false, nil},
			}},

			{CalendarHashChainInputHashVerificationRule{}, reserr.Int03, false, []ruleTestCase{
				{filepath.Join(testSigDir, "ok-sig-2014-06-2.ksig"), result.OK, false, nil},
				{filepath.Join(testSigDir, "signature-with-invalid-calendar-hash-chain.ksig"), result.FAIL, false, nil},
				{filepath.Join(testSigDir, "ok-sig-2014-04-30.1-no-cal-hashchain.ksig"), result.NA, true, nil},
			}},

			{CalendarHashChainAggregationTimeVerificationRule{}, reserr.Int04, false, []ruleTestCase{
				{filepath.Join(testSigDir, "ok-sig-2014-06-2.ksig"), result.OK, false, nil},
				{filepath.Join(testSigDir, "signature-with-invalid-calendar-chain-aggregation-time.ksig"), result.FAIL, false, nil},
				{filepath.Join(testSigDir, "ok-sig-2014-04-30.1-no-cal-hashchain.ksig"), result.NA, true, nil},
			}},

			{CalendarHashChainRegistrationTimeVerificationRule{}, reserr.Int05, false, []ruleTestCase{
				{filepath.Join(testSigDir, "ok-sig-2014-06-2.ksig"), result.OK, false, nil},
				{filepath.Join(testSigDir, "signature-with-invalid-calendar-chain-aggregation-time.ksig"), result.FAIL, false, nil},
				{filepath.Join(testSigDir, "ok-sig-2014-04-30.1-no-cal-hashchain.ksig"), result.NA, true, nil},
			}},

			{CalendarChainHashAlgorithmObsoleteAtPubTimeVerificationRule{}, reserr.Int16, false, []ruleTestCase{
				{filepath.Join(testSigDir, "ok-sig-2014-06-2.ksig"), result.OK, false, nil},
				{filepath.Join(testSigDir, "nok-sig-calendar-chain-has-sha1-in-right-link.ksig"), result.OK, false, nil},
				{filepath.Join(testSigDir, "ok-sig-2014-04-30.1-no-cal-hashchain.ksig"), result.NA, true, nil},
			}},

			{PublicationRecordPresenceRule{}, reserr.ErrNA, false, []ruleTestCase{
				{filepath.Join(testSigDir, "ok-sig-2018-06-15.1-extended.ksig"), result.OK, false, nil},
				{filepath.Join(testSigDir, "ok-sig-2018-06-15.1.ksig"), result.NA, false, nil},
			}},

			{PublicationRecordPublicationTimeVerificationRule{}, reserr.Int07, false, []ruleTestCase{
				{filepath.Join(testSigDir, "ok-sig-2014-06-2-extended.ksig"), result.OK, false, nil},
				{filepath.Join(testSigDir, "signature-with-invalid-publication-record-publication-data-time.ksig"), result.FAIL, false, nil},
				{filepath.Join(testSigDir, "ok-sig-2014-06-2.ksig"), result.NA, true, nil},
			}},

			{PublicationRecordPublicationHashVerificationRule{}, reserr.Int09, false, []ruleTestCase{
				{filepath.Join(testSigDir, "ok-sig-2014-06-2-extended.ksig"), result.OK, false, nil},
				{filepath.Join(testSigDir, "signature-with-invalid-publication-record-publication-data-hash.ksig"), result.FAIL, false, nil},
				{filepath.Join(testSigDir, "ok-sig-2014-06-2.ksig"), result.NA, true, nil},
			}},

			{CalendarAuthRecordPresenceRule{}, reserr.ErrNA, false, []ruleTestCase{
				{filepath.Join(testSigDir, "ok-sig-2014-06-2.ksig"), result.OK, false, nil},
				{filepath.Join(testSigDir, "ok-sig-2014-06-2-extended.ksig"), result.NA, false, nil},
			}},

			{CalendarAuthenticationRecordAggregationTimeVerificationRule{}, reserr.Int06, false, []ruleTestCase{
				{filepath.Join(testSigDir, "ok-sig-2014-06-2.ksig"), result.OK, false, nil},
				{filepath.Join(testSigDir, "signature-with-invalid-calendar-authentication-record-time.ksig"), result.FAIL, false, nil},
				{filepath.Join(testSigDir, "ok-sig-2014-06-2-extended.ksig"), result.NA, true, nil},
			}},

			{CalendarAuthenticationRecordAggregationHashVerificationRule{}, reserr.Int08, false, []ruleTestCase{
				{filepath.Join(testSigDir, "ok-sig-2014-06-2.ksig"), result.OK, false, nil},
				{filepath.Join(testSigDir, "signature-with-invalid-calendar-authentication-record-hash.ksig"), result.FAIL, false, nil},
				{filepath.Join(testSigDir, "ok-sig-2014-06-2-extended.ksig"), result.NA, true, nil},
				{filepath.Join(testSigDir, "ok-sig-2014-04-30.1-no-cal-hashchain.ksig"), result.NA, true, nil},
			}},

			{UserProvidedPublicationExistenceRule{}, reserr.ErrNA, false, []ruleTestCase{
				{filepath.Join(testSigDir, "ok-sig-2014-08-01.1.ksig"), result.OK, false, []VerCtxOption{
					VerCtxOptUserPublication(pubDataFromString(t, testUsrPubOkSig20140801))}},
				{filepath.Join(testSigDir, "ok-sig-2014-08-01.1.ksig"), result.NA, false, nil},
			}},

			{UserProvidedPublicationTimeVerificationRule{}, reserr.ErrNA, false, []ruleTestCase{
				{filepath.Join(testSigDir, "ok-sig-2018-06-15.1-extended.ksig"), result.OK, false, []VerCtxOption{
					VerCtxOptUserPublication(pubDataFromString(t, testPubStr20180715))}},
				{filepath.Join(testSigDir, "ok-sig-2018-06-15.1-extended.ksig"), result.NA, false, []VerCtxOption{
					VerCtxOptUserPublication(pubDataFromString(t, testUsrPubOkSig20140801))}},
				{filepath.Join(testSigDir, "ok-sig-2018-06-15.1-extended.ksig"), result.NA, true, nil},
				{filepath.Join(testSigDir, "ok-sig-2014-08-01.1.ksig"), result.NA, true, nil},
				{filepath.Join(testSigDir, "ok-sig-2014-08-01.1.ksig"), result.NA, true, []VerCtxOption{
					VerCtxOptUserPublication(pubDataFromString(t, testUsrPubOkSig20140801))}},
			}},

			{UserProvidedPublicationHashVerificationRule{}, reserr.Pub04, false, []ruleTestCase{
				{filepath.Join(testSigDir, "ok-sig-2018-06-15.1-extended.ksig"), result.OK, false, []VerCtxOption{
					VerCtxOptUserPublication(pubDataFromString(t, testPubStr20180715))}},
				{filepath.Join(testSigDir, "ok-sig-2018-06-15.1-extended.ksig"), result.FAIL, false, []VerCtxOption{
					VerCtxOptUserPublication(pubDataFromString(t, testUsrPubOkSig20140801))}},
				{filepath.Join(testSigDir, "ok-sig-2018-06-15.1-extended.ksig"), result.NA, true, nil},
				{filepath.Join(testSigDir, "ok-sig-2014-08-01.1.ksig"), result.NA, true, nil},
				{filepath.Join(testSigDir, "ok-sig-2014-08-01.1.ksig"), result.NA, true, []VerCtxOption{
					VerCtxOptUserPublication(pubDataFromString(t, testUsrPubOkSig20140801))}},
			}},

			{SignatureCalendarHashAlgorithmDeprecatedAtPubTimeVerificationRule{}, reserr.Gen02, false, []ruleTestCase{
				{filepath.Join(testSigDir, "ok-sig-2014-06-2.ksig"), result.OK, false, nil},
				{filepath.Join(testSigDir, "signature-deprecated-algorithm-in-calendar-chain-right-link.ksig"), result.OK, false, nil},
				{filepath.Join(testSigDir, "signature-deprecated-algorithm-in-calendar-chain.ksig"), result.NA, false, nil},
				{filepath.Join(testSigDir, "ok-sig-2014-04-30.1-no-cal-hashchain.ksig"), result.NA, true, nil},
			}},

			{UserProvidedPublicationCreationTimeVerificationRule{}, reserr.Gen02, false, []ruleTestCase{
				{filepath.Join(testSigDir, "ok-sig-2018-06-15.1-extended.ksig"), result.OK, false, []VerCtxOption{
					VerCtxOptUserPublication(pubDataFromString(t, testPubStr20180715))}},
				{filepath.Join(testSigDir, "ok-sig-2014-08-01.1.ksig"), result.OK, false, []VerCtxOption{
					VerCtxOptUserPublication(pubDataFromString(t, testPubStr20180715))}},
				{filepath.Join(testSigDir, "ok-sig-2018-06-15.1-extended.ksig"), result.NA, false, []VerCtxOption{
					VerCtxOptUserPublication(pubDataFromString(t, testPubStr20180615))}},
				{filepath.Join(testSigDir, "ok-sig-2018-06-15.1-extended.ksig"), result.NA, true, nil},
			}},

			{ExtendingPermittedRule{}, reserr.Gen02, false, []ruleTestCase{
				{filepath.Join(testSigDir, "ok-sig-2014-04-30.1.ksig"), result.OK, false, []VerCtxOption{
					VerCtxOptExtendingPermitted(true)}},
				{filepath.Join(testSigDir, "ok-sig-2014-04-30.1.ksig"), result.NA, false, nil},
				{filepath.Join(testSigDir, "ok-sig-2014-04-30.1.ksig"), result.NA, false, []VerCtxOption{
					VerCtxOptExtendingPermitted(false)}},
			}},

			{UserProvidedPublicationExtendedCalendarHashAlgorithmDeprecatedAtPubTimeVerificationRule{}, reserr.Gen02, false, []ruleTestCase{
				{filepath.Join(testSigDir, "ok-sig-2018-06-15.1.ksig"), result.OK, false, []VerCtxOption{
					VerCtxOptUserPublication(pubDataFromString(t, testPubStr20180715)),
					VerCtxOptCalendarProvider(extenderFromFileReaderClient(t, "ok-sig-2018-06-15.1-extend_response.tlv"))}},
				{filepath.Join(testSigDir, "ok-sig-2018-06-15.1-extended.ksig"), result.OK, false, []VerCtxOption{
					VerCtxOptUserPublication(pubDataFromString(t, testPubStr20180715)),
					VerCtxOptCalendarProvider(extenderFromFileReaderClient(t, "ok-sig-2018-06-15.1-extend_response.tlv"))}},
				{filepath.Join(testSigDir, "ok-sig-2014-08-01.1.ksig"), result.OK, false, []VerCtxOption{
					VerCtxOptUserPublication(pubDataFromString(t, testPubStr20180715)),
					VerCtxOptCalendarProvider(extenderFromFileReaderClient(t, "ok-sig-2018-06-15.1-extend_response-sha1_right_link.tlv"))}},
				{filepath.Join(testSigDir, "ok-sig-2014-08-01.1.ksig"), result.NA, false, []VerCtxOption{
					VerCtxOptUserPublication(pubDataFromString(t, testPubStr20180715)),
					VerCtxOptCalendarProvider(extenderFromFileReaderClient(t, "ok-sig-2018-06-15.1-extend_response-sha1_left_link.tlv"))}},
			}},

			{UserProvidedPublicationHashMatchesExtendedResponseVerificationRule{}, reserr.Pub01, false, []ruleTestCase{
				{filepath.Join(testSigDir, "ok-sig-2018-06-15.1.ksig"), result.OK, false, []VerCtxOption{
					VerCtxOptUserPublication(pubDataFromString(t, testPubStr20180715)),
					VerCtxOptCalendarProvider(extenderFromFileReaderClient(t, "ok-sig-2018-06-15.1-extend_response.tlv"))}},
				{filepath.Join(testSigDir, "ok-sig-2018-06-15.1-extended.ksig"), result.OK, false, []VerCtxOption{
					VerCtxOptUserPublication(pubDataFromString(t, testPubStr20180715)),
					VerCtxOptCalendarProvider(extenderFromFileReaderClient(t, "ok-sig-2018-06-15.1-extend_response.tlv"))}},
				{filepath.Join(testSigDir, "ok-sig-2018-06-15.1.ksig"), result.NA, true, nil},
				{filepath.Join(testSigDir, "ok-sig-2018-06-15.1.ksig"), result.NA, true, []VerCtxOption{
					VerCtxOptUserPublication(pubDataFromString(t, testPubStr20180715))}},
				{filepath.Join(testSigDir, "ok-sig-2018-06-15.1-extended.ksig"), result.FAIL, false, []VerCtxOption{
					VerCtxOptUserPublication(pubDataFromString(t, testPubStr20180715)),
					VerCtxOptCalendarProvider(extenderFromFileReaderClient(t, "ok-sig-2014-04-30.1-extend_response.tlv"))}},
			}},

			{UserProvidedPublicationTimeMatchesExtendedResponseVerificationRule{}, reserr.Pub02, false, []ruleTestCase{
				{filepath.Join(testSigDir, "ok-sig-2018-06-15.1.ksig"), result.OK, false, []VerCtxOption{
					VerCtxOptUserPublication(pubDataFromString(t, testPubStr20180715)),
					VerCtxOptCalendarProvider(extenderFromFileReaderClient(t, "ok-sig-2018-06-15.1-extend_response.tlv"))}},
				{filepath.Join(testSigDir, "ok-sig-2018-06-15.1-extended.ksig"), result.OK, false, []VerCtxOption{
					VerCtxOptUserPublication(pubDataFromString(t, testPubStr20180715)),
					VerCtxOptCalendarProvider(extenderFromFileReaderClient(t, "ok-sig-2018-06-15.1-extend_response.tlv"))}},
				{filepath.Join(testSigDir, "ok-sig-2018-06-15.1.ksig"), result.NA, true, nil},
				{filepath.Join(testSigDir, "ok-sig-2018-06-15.1.ksig"), result.NA, true, []VerCtxOption{
					VerCtxOptUserPublication(pubDataFromString(t, testPubStr20180715))}},
				{filepath.Join(testSigDir, "ok-sig-2018-06-15.1-extended.ksig"), result.FAIL, false, []VerCtxOption{
					VerCtxOptUserPublication(pubDataFromString(t, testPubStr20180715)),
					VerCtxOptCalendarProvider(extenderFromFileReaderClient(t, "ok-sig-2014-04-30.1-extend_response.tlv"))}},
				{filepath.Join(testSigDir, "ok-sig-2018-06-15.1-extended.ksig"), result.NA, true, []VerCtxOption{
					VerCtxOptUserPublication(pubDataFromString(t, testPubStr20180715)),
					VerCtxOptCalendarProvider(extenderFromFileReaderClient(t, "ok-sig-2018-06-15.1-extend_response-missing_left_link.tlv"))}},
			}},

			{UserProvidedPublicationExtendedSignatureInputHashVerificationRule{}, reserr.Pub03, false, []ruleTestCase{
				{filepath.Join(testSigDir, "ok-sig-2018-06-15.1.ksig"), result.OK, false, []VerCtxOption{
					VerCtxOptUserPublication(pubDataFromString(t, testPubStr20180715)),
					VerCtxOptCalendarProvider(extenderFromFileReaderClient(t, "ok-sig-2018-06-15.1-extend_response.tlv"))}},
				{filepath.Join(testSigDir, "ok-sig-2018-06-15.1-extended.ksig"), result.OK, false, []VerCtxOption{
					VerCtxOptUserPublication(pubDataFromString(t, testPubStr20180715)),
					VerCtxOptCalendarProvider(extenderFromFileReaderClient(t, "ok-sig-2018-06-15.1-extend_response.tlv"))}},
				{filepath.Join(testSigDir, "ok-sig-2018-06-15.1.ksig"), result.NA, true, nil},
				{filepath.Join(testSigDir, "ok-sig-2018-06-15.1.ksig"), result.NA, true, []VerCtxOption{
					VerCtxOptUserPublication(pubDataFromString(t, testPubStr20180715))}},
				{filepath.Join(testSigDir, "ok-sig-2018-06-15.1-extended.ksig"), result.FAIL, false, []VerCtxOption{
					VerCtxOptUserPublication(pubDataFromString(t, testPubStr20180715)),
					VerCtxOptCalendarProvider(extenderFromFileReaderClient(t, "ok-sig-2014-04-30.1-extend_response.tlv"))}},
				{filepath.Join(testSigDir, "ok-sig-2018-06-15.1-extended.ksig"), result.OK, false, []VerCtxOption{
					VerCtxOptUserPublication(pubDataFromString(t, testPubStr20180715)),
					VerCtxOptCalendarProvider(extenderFromFileReaderClient(t, "ok-sig-2018-06-15.1-extend_response-missing_left_link.tlv"))}},
			}},

			{PublicationsFileContainsSignaturePublicationVerificationRule{}, reserr.ErrNA, false, []ruleTestCase{
				{filepath.Join(testSigDir, "ok-sig-2018-06-15.1-extended.ksig"), result.OK, false, []VerCtxOption{
					VerCtxOptPublicationsFile(pubFileFromPath(t, "ksi-publications.bin"))}},
				{filepath.Join(testSigDir, "ok-sig-2018-06-15.1-extended.ksig"), result.NA, false, []VerCtxOption{
					VerCtxOptPublicationsFile(pubFileFromPath(t, "ksi-publications_20180611.bin"))}},
				{filepath.Join(testSigDir, "ok-sig-2018-06-15.1.ksig"), result.NA, true, nil},
			}},
			{PublicationsFileContainsSignaturePublicationVerificationRule{}, reserr.Gen02, false, []ruleTestCase{
				{filepath.Join(testSigDir, "ok-sig-2018-06-15.1-extended.ksig"), result.NA, false, nil},
			}},

			{PublicationsFileSignaturePublicationHashVerificationRule{}, reserr.Pub05, false, []ruleTestCase{
				{filepath.Join(testSigDir, "ok-sig-2018-06-15.1-extended.ksig"), result.OK, false, []VerCtxOption{
					VerCtxOptPublicationsFile(pubFileFromPath(t, "ksi-publications.bin"))}},
				{filepath.Join(testSigDir, "ok-sig-2018-06-15.1-extended.ksig"), result.FAIL, false, []VerCtxOption{
					VerCtxOptPublicationsFile(pubFileFromPath(t, "ksi-publications_20180611.bin"))}},
				{filepath.Join(testSigDir, "ok-sig-2018-06-15.1.ksig"), result.NA, true, nil},
			}},

			{PublicationsFileContainsSuitablePublicationVerificationRule{}, reserr.Gen02, false, []ruleTestCase{
				{filepath.Join(testSigDir, "ok-sig-2018-06-15.1.ksig"), result.OK, false, []VerCtxOption{
					VerCtxOptPublicationsFile(pubFileFromPath(t, "ksi-publications.bin"))}},
				{filepath.Join(testSigDir, "ok-sig-2018-06-15.1-extended.ksig"), result.OK, false, []VerCtxOption{
					VerCtxOptPublicationsFile(pubFileFromPath(t, "ksi-publications.bin"))}},
				{filepath.Join(testSigDir, "ok-sig-2018-06-15.1-extended.ksig"), result.NA, false, []VerCtxOption{
					VerCtxOptPublicationsFile(pubFileFromPath(t, "ksi-publications_20180611.bin"))}},
				{filepath.Join(testSigDir, "ok-sig-2018-06-15.1.ksig"), result.NA, false, nil},
			}},

			{PubFileExtendedCalendarHashAlgorithmDeprecatedAtPubTimeVerificationRule{}, reserr.Gen02, false, []ruleTestCase{
				{filepath.Join(testSigDir, "ok-sig-2018-06-15.1.ksig"), result.OK, false, []VerCtxOption{
					VerCtxOptPublicationsFile(pubFileFromPath(t, "ksi-publications.bin")),
					VerCtxOptCalendarProvider(extenderFromFileReaderClient(t, "ok-sig-2018-06-15.1-extend_response.tlv"))}},
				{filepath.Join(testSigDir, "ok-sig-2018-06-15.1-extended.ksig"), result.OK, false, []VerCtxOption{
					VerCtxOptPublicationsFile(pubFileFromPath(t, "ksi-publications.bin")),
					VerCtxOptCalendarProvider(extenderFromFileReaderClient(t, "ok-sig-2018-06-15.1-extend_response.tlv"))}},
				{filepath.Join(testSigDir, "ok-sig-2014-08-01.1.ksig"), result.OK, false, []VerCtxOption{
					VerCtxOptPublicationsFile(pubFileFromPath(t, "ksi-publications.bin")),
					VerCtxOptCalendarProvider(extenderFromFileReaderClient(t, "ok-sig-2018-06-15.1-extend_response-sha1_right_link.tlv"))}},
				{filepath.Join(testSigDir, "ok-sig-2014-08-01.1.ksig"), result.NA, false, []VerCtxOption{
					VerCtxOptPublicationsFile(pubFileFromPath(t, "ksi-publications.bin")),
					VerCtxOptCalendarProvider(extenderFromFileReaderClient(t, "ok-sig-2018-06-15.1-extend_response-sha1_left_link.tlv"))}},
				{filepath.Join(testSigDir, "ok-sig-2018-06-15.1-extended.ksig"), result.NA, true, []VerCtxOption{
					VerCtxOptPublicationsFile(pubFileFromPath(t, "ksi-publications_20180611.bin"))}},
			}},

			{PublicationsFilePublicationHashMatchesExtenderResponseVerificationRule{}, reserr.Pub01, false, []ruleTestCase{
				{filepath.Join(testSigDir, "ok-sig-2018-06-15.1.ksig"), result.OK, false, []VerCtxOption{
					VerCtxOptPublicationsFile(pubFileFromPath(t, "ksi-publications.bin")),
					VerCtxOptCalendarProvider(extenderFromFileReaderClient(t, "ok-sig-2018-06-15.1-extend_response.tlv"))}},
				{filepath.Join(testSigDir, "ok-sig-2018-06-15.1-extended.ksig"), result.OK, false, []VerCtxOption{
					VerCtxOptPublicationsFile(pubFileFromPath(t, "ksi-publications.bin")),
					VerCtxOptCalendarProvider(extenderFromFileReaderClient(t, "ok-sig-2018-06-15.1-extend_response.tlv"))}},
				{filepath.Join(testSigDir, "ok-sig-2018-06-15.1.ksig"), result.NA, true, []VerCtxOption{
					VerCtxOptPublicationsFile(pubFileFromPath(t, "ksi-publications.bin"))}},
				{filepath.Join(testSigDir, "ok-sig-2018-06-15.1-extended.ksig"), result.NA, true, []VerCtxOption{
					VerCtxOptPublicationsFile(pubFileFromPath(t, "ksi-publications_20180611.bin")),
					VerCtxOptCalendarProvider(extenderFromFileReaderClient(t, "ok-sig-2014-04-30.1-extend_response.tlv"))}},
			}},
			{PublicationsFilePublicationHashMatchesExtenderResponseVerificationRule{}, reserr.Gen02, false, []ruleTestCase{
				{filepath.Join(testSigDir, "ok-sig-2018-06-15.1.ksig"), result.NA, false, nil},
				{filepath.Join(testSigDir, "ok-sig-2018-06-15.1.ksig"), result.NA, false, []VerCtxOption{
					VerCtxOptCalendarProvider(extenderFromFileReaderClient(t, "ok-sig-2018-06-15.1-extend_response.tlv"))}},
			}},

			{PublicationsFilePublicationTimeMatchesExtendedResponseVerificationRule{}, reserr.Pub02, false, []ruleTestCase{
				{filepath.Join(testSigDir, "ok-sig-2018-06-15.1.ksig"), result.OK, false, []VerCtxOption{
					VerCtxOptPublicationsFile(pubFileFromPath(t, "ksi-publications.bin")),
					VerCtxOptCalendarProvider(extenderFromFileReaderClient(t, "ok-sig-2018-06-15.1-extend_response.tlv"))}},
				{filepath.Join(testSigDir, "ok-sig-2018-06-15.1-extended.ksig"), result.OK, false, []VerCtxOption{
					VerCtxOptPublicationsFile(pubFileFromPath(t, "ksi-publications.bin")),
					VerCtxOptCalendarProvider(extenderFromFileReaderClient(t, "ok-sig-2018-06-15.1-extend_response.tlv"))}},
				{filepath.Join(testSigDir, "ok-sig-2018-06-15.1.ksig"), result.NA, true, []VerCtxOption{
					VerCtxOptPublicationsFile(pubFileFromPath(t, "ksi-publications.bin"))}},
				{filepath.Join(testSigDir, "ok-sig-2018-06-15.1-extended.ksig"), result.NA, true, []VerCtxOption{
					VerCtxOptPublicationsFile(pubFileFromPath(t, "ksi-publications_20180611.bin")),
					VerCtxOptCalendarProvider(extenderFromFileReaderClient(t, "ok-sig-2014-04-30.1-extend_response.tlv"))}},
			}},
			{PublicationsFilePublicationTimeMatchesExtendedResponseVerificationRule{}, reserr.Gen02, false, []ruleTestCase{
				{filepath.Join(testSigDir, "ok-sig-2018-06-15.1.ksig"), result.NA, false, nil},
				{filepath.Join(testSigDir, "ok-sig-2018-06-15.1.ksig"), result.NA, false, []VerCtxOption{
					VerCtxOptCalendarProvider(extenderFromFileReaderClient(t, "ok-sig-2018-06-15.1-extend_response.tlv"))}},
			}},

			{PublicationsFileExtendedSignatureInputHashVerificationRule{}, reserr.Pub03, false, []ruleTestCase{
				{filepath.Join(testSigDir, "ok-sig-2018-06-15.1.ksig"), result.OK, false, []VerCtxOption{
					VerCtxOptPublicationsFile(pubFileFromPath(t, "ksi-publications.bin")),
					VerCtxOptCalendarProvider(extenderFromFileReaderClient(t, "ok-sig-2018-06-15.1-extend_response.tlv"))}},
				{filepath.Join(testSigDir, "ok-sig-2018-06-15.1-extended.ksig"), result.OK, false, []VerCtxOption{
					VerCtxOptPublicationsFile(pubFileFromPath(t, "ksi-publications.bin")),
					VerCtxOptCalendarProvider(extenderFromFileReaderClient(t, "ok-sig-2018-06-15.1-extend_response.tlv"))}},
				{filepath.Join(testSigDir, "ok-sig-2018-06-15.1.ksig"), result.NA, true, nil},
				{filepath.Join(testSigDir, "ok-sig-2018-06-15.1.ksig"), result.NA, true, []VerCtxOption{
					VerCtxOptPublicationsFile(pubFileFromPath(t, "ksi-publications.bin"))}},
				{filepath.Join(testSigDir, "ok-sig-2018-06-15.1-extended.ksig"), result.FAIL, false, []VerCtxOption{
					VerCtxOptPublicationsFile(pubFileFromPath(t, "ksi-publications.bin")),
					VerCtxOptCalendarProvider(extenderFromFileReaderClient(t, "ok-sig-2014-04-30.1-extend_response.tlv"))}},
				{filepath.Join(testSigDir, "ok-sig-2018-06-15.1-extended.ksig"), result.OK, false, []VerCtxOption{
					VerCtxOptPublicationsFile(pubFileFromPath(t, "ksi-publications.bin")),
					VerCtxOptCalendarProvider(extenderFromFileReaderClient(t, "ok-sig-2018-06-15.1-extend_response-missing_left_link.tlv"))}},
				{filepath.Join(testSigDir, "ok-sig-2018-06-15.1-extended.ksig"), result.FAIL, false, []VerCtxOption{
					VerCtxOptPublicationsFile(pubFileFromPath(t, "ksi-publications.bin")),
					VerCtxOptCalendarProvider(extenderFromFileReaderClient(t, "ok-sig-2014-04-30.1-extend_response.tlv"))}},
				{filepath.Join(testSigDir, "ok-sig-2018-06-15.1.ksig"), result.NA, true, []VerCtxOption{
					VerCtxOptPublicationsFile(pubFileFromPath(t, "ksi-publications_20180611.bin"))}},
			}},

			{CalendarHashChainExistenceRule{}, reserr.Gen02, false, []ruleTestCase{
				{filepath.Join(testSigDir, "ok-sig-2014-04-30.1.ksig"), result.OK, false, nil},
				{filepath.Join(testSigDir, "ok-sig-2014-04-30.1-no-cal-hashchain.ksig"), result.NA, false, nil},
			}},

			{CalendarHashChainAlgorithmDeprecatedRule{}, reserr.Gen02, false, []ruleTestCase{
				{filepath.Join(testSigDir, "ok-sig-2014-06-2.ksig"), result.OK, false, nil},
				{filepath.Join(testSigDir, "signature-deprecated-algorithm-in-calendar-chain-right-link.ksig"), result.OK, false, nil},
				{filepath.Join(testSigDir, "signature-deprecated-algorithm-in-calendar-chain.ksig"), result.NA, false, nil},
				{filepath.Join(testSigDir, "ok-sig-2014-04-30.1-no-cal-hashchain.ksig"), result.NA, true, nil},
			}},

			{CalendarAuthenticationRecordExistenceRule{}, reserr.Gen02, false, []ruleTestCase{
				{filepath.Join(testSigDir, "ok-sig-2014-06-2.ksig"), result.OK, false, nil},
				{filepath.Join(testSigDir, "ok-sig-2014-06-2-extended.ksig"), result.NA, false, nil},
			}},

			{CertificateExistenceRule{}, reserr.Gen02, false, []ruleTestCase{
				{filepath.Join(testSigDir, "ok-sig-2018-06-15.1.ksig"), result.OK, false, []VerCtxOption{
					VerCtxOptPublicationsFile(pubFileFromPath(t, "ksi-publications.bin"))}},
				{filepath.Join(testSigDir, "ok-sig-2018-06-15.1.ksig"), result.NA, false, []VerCtxOption{
					VerCtxOptPublicationsFile(pubFileFromPath(t, "publications-nocerts.bin"))}},
				{filepath.Join(testSigDir, "ok-sig-2018-06-15.1.ksig"), result.NA, false, nil},
			}},

			{CertificateValidityRule{}, reserr.Key03, false, []ruleTestCase{
				{filepath.Join(testSigDir, "ok-sig-2014-04-30.1.ksig"), result.OK, false, []VerCtxOption{
					VerCtxOptPublicationsFile(pubFileFromPath(t, "ksi-publications.bin"))}},
				{filepath.Join(testSigDir, "nok-sig-2017-08-23.1.invalid-cert-timespan.ksig"), result.FAIL, false, []VerCtxOption{
					VerCtxOptPublicationsFile(pubFileFromPath(t, "ksi-publications.invalid-cert.validity.bin"))}},
				{filepath.Join(testSigDir, "ok-sig-2018-06-15.1-extended.ksig"), result.NA, true, nil},
				{filepath.Join(testSigDir, "ok-sig-2014-04-30.1.ksig"), result.OK, false, []VerCtxOption{
					VerCtxOptPublicationsFile(pubFileFromPath(t, "ksi-publications_20180611.bin"))}},
			}},
			{CertificateValidityRule{}, reserr.Gen02, false, []ruleTestCase{
				{filepath.Join(testSigDir, "ok-sig-2014-04-30.1.ksig"), result.NA, false, nil},
			}},

			{CalendarAuthenticationRecordSignatureVerificationRule{}, reserr.Key02, false, []ruleTestCase{
				{filepath.Join(testSigDir, "ok-sig-2018-06-15.1.ksig"), result.OK, false, []VerCtxOption{
					VerCtxOptPublicationsFile(pubFileFromPath(t, "ksi-publications.bin"))}},
				{filepath.Join(testSigDir, "signature-cal-auth-wrong-signing-value.ksig"), result.FAIL, false, []VerCtxOption{
					VerCtxOptPublicationsFile(pubFileFromPath(t, "ksi-publications.bin"))}},
				{filepath.Join(testSigDir, "ok-sig-2018-06-15.1-extended.ksig"), result.NA, true, []VerCtxOption{
					VerCtxOptPublicationsFile(pubFileFromPath(t, "ksi-publications.bin"))}},
				{filepath.Join(testSigDir, "ok-sig-2018-06-15.1.ksig"), result.NA, true, []VerCtxOption{
					VerCtxOptPublicationsFile(pubFileFromPath(t, "publications-nocerts.bin"))}},
			}},
			{CalendarAuthenticationRecordSignatureVerificationRule{}, reserr.Gen02, false, []ruleTestCase{
				{filepath.Join(testSigDir, "ok-sig-2018-06-15.1.ksig"), result.NA, false, nil},
			}},

			{ExtendedSignatureCalendarChainInputHashVerificationRule{}, reserr.Cal02, false, []ruleTestCase{
				{filepath.Join(testSigDir, "ok-sig-2018-06-15.1-extended.ksig"), result.OK, false, []VerCtxOption{
					VerCtxOptCalendarProvider(extenderFromFileReaderClient(t, "ok-sig-2018-06-15.1-extend_response.tlv"))}},
				{filepath.Join(testSigDir, "ok-sig-2014-04-30.1-no-cal-hashchain.ksig"), result.OK, false, []VerCtxOption{
					VerCtxOptCalendarProvider(extenderFromFileReaderClient(t, "ok-sig-2014-04-30.1-extend_response.tlv"))}},
				{filepath.Join(testSigDir, "ok-sig-2018-06-15.1.ksig"), result.OK, false, []VerCtxOption{
					VerCtxOptCalendarProvider(extenderFromFileReaderClient(t, "ok-sig-2018-06-15.1-extend_response.tlv"))}},
				{filepath.Join(testSigDir, "ok-sig-2018-06-15.1.ksig"), result.FAIL, false, []VerCtxOption{
					VerCtxOptCalendarProvider(extenderFromFileReaderClient(t, "ok-sig-2014-04-30.1-extend_response.tlv"))}},
				{filepath.Join(testSigDir, "ok-sig-2018-06-15.1.ksig"), result.NA, true, nil},
			}},

			{ExtendedSignatureCalendarChainAggregationTimeVerificationRule{}, reserr.Cal03, false, []ruleTestCase{
				{filepath.Join(testSigDir, "ok-sig-2018-06-15.1-extended.ksig"), result.OK, false, []VerCtxOption{
					VerCtxOptCalendarProvider(extenderFromFileReaderClient(t, "ok-sig-2018-06-15.1-extend_response.tlv"))}},
				{filepath.Join(testSigDir, "ok-sig-2014-04-30.1-no-cal-hashchain.ksig"), result.OK, false, []VerCtxOption{
					VerCtxOptCalendarProvider(extenderFromFileReaderClient(t, "ok-sig-2014-04-30.1-extend_response.tlv"))}},
				{filepath.Join(testSigDir, "ok-sig-2018-06-15.1.ksig"), result.OK, false, []VerCtxOption{
					VerCtxOptCalendarProvider(extenderFromFileReaderClient(t, "ok-sig-2018-06-15.1-extend_response.tlv"))}},
				{filepath.Join(testSigDir, "ok-sig-2018-06-15.1.ksig"), result.FAIL, false, []VerCtxOption{
					VerCtxOptCalendarProvider(extenderFromFileReaderClient(t, "ok-sig-2014-04-30.1-extend_response.tlv"))}},
				{filepath.Join(testSigDir, "ok-sig-2018-06-15.1.ksig"), result.NA, true, nil},
			}},

			{ExtendedSignatureCalendarChainRootHashVerificationRule{}, reserr.Cal01, false, []ruleTestCase{
				{filepath.Join(testSigDir, "ok-sig-2018-06-15.1-extended.ksig"), result.OK, false, []VerCtxOption{
					VerCtxOptCalendarProvider(extenderFromFileReaderClient(t, "ok-sig-2018-06-15.1-extend_response.tlv"))}},
				{filepath.Join(testSigDir, "ok-sig-2014-04-30.1-no-cal-hashchain.ksig"), result.NA, true, []VerCtxOption{
					VerCtxOptCalendarProvider(extenderFromFileReaderClient(t, "ok-sig-2014-04-30.1-extend_response.tlv"))}},
				{filepath.Join(testSigDir, "ok-sig-2018-06-15.1.ksig"), result.NA, true, nil},
				{filepath.Join(testSigDir, "ok-sig-2018-06-15.1-extended.ksig"), result.FAIL, false, []VerCtxOption{
					VerCtxOptCalendarProvider(extenderFromFileReaderClient(t, "ok-sig-2014-04-30.1-extend_response.tlv"))}},
			}},

			{ExtendedSignatureCalendarHashChainRightLinksMatchesVerificationRule{}, reserr.Cal04, false, []ruleTestCase{
				{filepath.Join(testSigDir, "ok-sig-2018-06-15.1-extended.ksig"), result.OK, false, []VerCtxOption{
					VerCtxOptCalendarProvider(extenderFromFileReaderClient(t, "ok-sig-2018-06-15.1-extend_response.tlv"))}},
				{filepath.Join(testSigDir, "ok-sig-2014-04-30.1-no-cal-hashchain.ksig"), result.NA, true, []VerCtxOption{
					VerCtxOptCalendarProvider(extenderFromFileReaderClient(t, "ok-sig-2014-04-30.1-extend_response.tlv"))}},
				{filepath.Join(testSigDir, "ok-sig-2018-06-15.1.ksig"), result.OK, false, []VerCtxOption{
					VerCtxOptCalendarProvider(extenderFromFileReaderClient(t, "ok-sig-2018-06-15.1-extend_response.tlv"))}},
				{filepath.Join(testSigDir, "ok-sig-2018-06-15.1.ksig"), result.FAIL, false, []VerCtxOption{
					VerCtxOptCalendarProvider(extenderFromFileReaderClient(t, "ok-sig-2014-04-30.1-extend_response.tlv"))}},
				{filepath.Join(testSigDir, "ok-sig-2018-06-15.1.ksig"), result.NA, true, nil},
			}},
			{UserProvidedPublicationExtendToPublication{}, reserr.Gen02, true, []ruleTestCase{
				{filepath.Join(testSigDir, "ok-sig-2018-06-15.1.ksig"), result.NA, true, []VerCtxOption{
					VerCtxOptCalendarProvider(extenderFromFileReaderClient(t, "ok-sig-2018-06-15.1-extend_response.tlv"))}},
				{filepath.Join(testSigDir, "ok-sig-2018-06-15.1.ksig"), result.OK, false, []VerCtxOption{
					VerCtxOptUserPublication(pubDataFromString(t, testPubStr20180715)),
					VerCtxOptCalendarProvider(extenderFromFileReaderClient(t, "ok-sig-2018-06-15.1-extend_response.tlv"))}},
				{filepath.Join(testSigDir, "ok-sig-2018-06-15.1-extended.ksig"), result.OK, false, []VerCtxOption{
					VerCtxOptUserPublication(pubDataFromString(t, testPubStr20180715)),
					VerCtxOptCalendarProvider(extenderFromFileReaderClient(t, "ok-sig-2018-06-15.1-extend_response.tlv"))}},
				{filepath.Join(testSigDir, "ok-sig-2018-06-15.1.ksig"), result.NA, false, []VerCtxOption{
					VerCtxOptUserPublication(pubDataFromString(t, testPubStr20180715)),
					VerCtxOptCalendarProvider(extenderFromFileReaderClient(t, "ok_extender_error_response_101.tlv"))}},
				{filepath.Join(testSigDir, "ok-sig-2018-06-15.1.ksig"), result.NA, false, []VerCtxOption{
					VerCtxOptUserPublication(pubDataFromString(t, testPubStr20180715)),
					VerCtxOptCalendarProvider(extenderFromFileReaderClient(t, "ok_extender_error_response_102.tlv"))}},
				{filepath.Join(testSigDir, "ok-sig-2018-06-15.1.ksig"), result.NA, false, []VerCtxOption{
					VerCtxOptUserPublication(pubDataFromString(t, testPubStr20180715)),
					VerCtxOptCalendarProvider(extenderFromFileReaderClient(t, "ok_extender_error_response_103.tlv"))}},
				{filepath.Join(testSigDir, "ok-sig-2018-06-15.1.ksig"), result.NA, false, []VerCtxOption{
					VerCtxOptUserPublication(pubDataFromString(t, testPubStr20180715)),
					VerCtxOptCalendarProvider(extenderFromFileReaderClient(t, "ok_extender_error_response_104.tlv"))}},
				{filepath.Join(testSigDir, "ok-sig-2018-06-15.1.ksig"), result.NA, false, []VerCtxOption{
					VerCtxOptUserPublication(pubDataFromString(t, testPubStr20180715)),
					VerCtxOptCalendarProvider(extenderFromFileReaderClient(t, "ok_extender_error_response_105.tlv"))}},
				{filepath.Join(testSigDir, "ok-sig-2018-06-15.1.ksig"), result.NA, false, []VerCtxOption{
					VerCtxOptUserPublication(pubDataFromString(t, testPubStr20180715)),
					VerCtxOptCalendarProvider(extenderFromFileReaderClient(t, "ok_extender_error_response_106.tlv"))}},
				{filepath.Join(testSigDir, "ok-sig-2018-06-15.1.ksig"), result.NA, false, []VerCtxOption{
					VerCtxOptUserPublication(pubDataFromString(t, testPubStr20180715)),
					VerCtxOptCalendarProvider(extenderFromFileReaderClient(t, "ok_extender_error_response_107.tlv"))}},
				{filepath.Join(testSigDir, "ok-sig-2018-06-15.1.ksig"), result.NA, false, []VerCtxOption{
					VerCtxOptUserPublication(pubDataFromString(t, testPubStr20180715)),
					VerCtxOptCalendarProvider(extenderFromFileReaderClient(t, "ok_extender_error_response_200.tlv"))}},
				{filepath.Join(testSigDir, "ok-sig-2018-06-15.1.ksig"), result.NA, false, []VerCtxOption{
					VerCtxOptUserPublication(pubDataFromString(t, testPubStr20180715)),
					VerCtxOptCalendarProvider(extenderFromFileReaderClient(t, "ok_extender_error_response_201.tlv"))}},
				{filepath.Join(testSigDir, "ok-sig-2018-06-15.1.ksig"), result.NA, false, []VerCtxOption{
					VerCtxOptUserPublication(pubDataFromString(t, testPubStr20180715)),
					VerCtxOptCalendarProvider(extenderFromFileReaderClient(t, "ok_extender_error_response_202.tlv"))}},
				{filepath.Join(testSigDir, "ok-sig-2018-06-15.1.ksig"), result.NA, false, []VerCtxOption{
					VerCtxOptUserPublication(pubDataFromString(t, testPubStr20180715)),
					VerCtxOptCalendarProvider(extenderFromFileReaderClient(t, "ok_extender_error_response_300.tlv"))}},
				{filepath.Join(testSigDir, "ok-sig-2018-06-15.1.ksig"), result.NA, false, []VerCtxOption{
					VerCtxOptUserPublication(pubDataFromString(t, testPubStr20180715)),
					VerCtxOptCalendarProvider(extenderFromFileReaderClient(t, "ok_extender_error_response_301.tlv"))}},
			}},

			{PublicationsFileExtendToPublication{}, reserr.Gen02, true, []ruleTestCase{
				{filepath.Join(testSigDir, "ok-sig-2018-06-15.1.ksig"), result.NA, false, []VerCtxOption{
					VerCtxOptCalendarProvider(extenderFromFileReaderClient(t, "ok-sig-2018-06-15.1-extend_response.tlv"))}},
				{filepath.Join(testSigDir, "ok-sig-2018-06-15.1.ksig"), result.OK, false, []VerCtxOption{
					VerCtxOptPublicationsFile(pubFileFromPath(t, "ksi-publications.bin")),
					VerCtxOptCalendarProvider(extenderFromFileReaderClient(t, "ok-sig-2018-06-15.1-extend_response.tlv"))}},
				{filepath.Join(testSigDir, "ok-sig-2018-06-15.1-extended.ksig"), result.OK, false, []VerCtxOption{
					VerCtxOptPublicationsFile(pubFileFromPath(t, "ksi-publications.bin")),
					VerCtxOptCalendarProvider(extenderFromFileReaderClient(t, "ok-sig-2018-06-15.1-extend_response.tlv"))}},
				{filepath.Join(testSigDir, "ok-sig-2018-06-15.1.ksig"), result.NA, false, []VerCtxOption{
					VerCtxOptPublicationsFile(pubFileFromPath(t, "ksi-publications.bin")),
					VerCtxOptCalendarProvider(extenderFromFileReaderClient(t, "ok_extender_error_response_101.tlv"))}},
				{filepath.Join(testSigDir, "ok-sig-2018-06-15.1.ksig"), result.NA, false, []VerCtxOption{
					VerCtxOptPublicationsFile(pubFileFromPath(t, "ksi-publications.bin")),
					VerCtxOptCalendarProvider(extenderFromFileReaderClient(t, "ok_extender_error_response_102.tlv"))}},
				{filepath.Join(testSigDir, "ok-sig-2018-06-15.1.ksig"), result.NA, false, []VerCtxOption{
					VerCtxOptPublicationsFile(pubFileFromPath(t, "ksi-publications.bin")),
					VerCtxOptCalendarProvider(extenderFromFileReaderClient(t, "ok_extender_error_response_103.tlv"))}},
				{filepath.Join(testSigDir, "ok-sig-2018-06-15.1.ksig"), result.NA, false, []VerCtxOption{
					VerCtxOptPublicationsFile(pubFileFromPath(t, "ksi-publications.bin")),
					VerCtxOptCalendarProvider(extenderFromFileReaderClient(t, "ok_extender_error_response_104.tlv"))}},
				{filepath.Join(testSigDir, "ok-sig-2018-06-15.1.ksig"), result.NA, false, []VerCtxOption{
					VerCtxOptPublicationsFile(pubFileFromPath(t, "ksi-publications.bin")),
					VerCtxOptCalendarProvider(extenderFromFileReaderClient(t, "ok_extender_error_response_105.tlv"))}},
				{filepath.Join(testSigDir, "ok-sig-2018-06-15.1.ksig"), result.NA, false, []VerCtxOption{
					VerCtxOptPublicationsFile(pubFileFromPath(t, "ksi-publications.bin")),
					VerCtxOptCalendarProvider(extenderFromFileReaderClient(t, "ok_extender_error_response_106.tlv"))}},
				{filepath.Join(testSigDir, "ok-sig-2018-06-15.1.ksig"), result.NA, false, []VerCtxOption{
					VerCtxOptPublicationsFile(pubFileFromPath(t, "ksi-publications.bin")),
					VerCtxOptCalendarProvider(extenderFromFileReaderClient(t, "ok_extender_error_response_107.tlv"))}},
				{filepath.Join(testSigDir, "ok-sig-2018-06-15.1.ksig"), result.NA, false, []VerCtxOption{
					VerCtxOptPublicationsFile(pubFileFromPath(t, "ksi-publications.bin")),
					VerCtxOptCalendarProvider(extenderFromFileReaderClient(t, "ok_extender_error_response_200.tlv"))}},
				{filepath.Join(testSigDir, "ok-sig-2018-06-15.1.ksig"), result.NA, false, []VerCtxOption{
					VerCtxOptPublicationsFile(pubFileFromPath(t, "ksi-publications.bin")),
					VerCtxOptCalendarProvider(extenderFromFileReaderClient(t, "ok_extender_error_response_201.tlv"))}},
				{filepath.Join(testSigDir, "ok-sig-2018-06-15.1.ksig"), result.NA, false, []VerCtxOption{
					VerCtxOptPublicationsFile(pubFileFromPath(t, "ksi-publications.bin")),
					VerCtxOptCalendarProvider(extenderFromFileReaderClient(t, "ok_extender_error_response_202.tlv"))}},
				{filepath.Join(testSigDir, "ok-sig-2018-06-15.1.ksig"), result.NA, false, []VerCtxOption{
					VerCtxOptPublicationsFile(pubFileFromPath(t, "ksi-publications.bin")),
					VerCtxOptCalendarProvider(extenderFromFileReaderClient(t, "ok_extender_error_response_300.tlv"))}},
				{filepath.Join(testSigDir, "ok-sig-2018-06-15.1.ksig"), result.NA, false, []VerCtxOption{
					VerCtxOptPublicationsFile(pubFileFromPath(t, "ksi-publications.bin")),
					VerCtxOptCalendarProvider(extenderFromFileReaderClient(t, "ok_extender_error_response_301.tlv"))}},
			}},

			{ExtendSignatureCalendarChainInputHashToHead{}, reserr.Gen02, true, []ruleTestCase{
				{filepath.Join(testSigDir, "ok-sig-2018-06-15.1.ksig"), result.OK, false, []VerCtxOption{
					VerCtxOptCalendarProvider(extenderFromFileReaderClient(t, "ok-sig-2018-06-15.1-extend_response.tlv"))}},
				{filepath.Join(testSigDir, "ok-sig-2018-06-15.1-extended.ksig"), result.OK, false, []VerCtxOption{
					VerCtxOptCalendarProvider(extenderFromFileReaderClient(t, "ok-sig-2018-06-15.1-extend_response.tlv"))}},
				{filepath.Join(testSigDir, "ok-sig-2018-06-15.1.ksig"), result.NA, false, []VerCtxOption{
					VerCtxOptCalendarProvider(extenderFromFileReaderClient(t, "ok_extender_error_response_101.tlv"))}},
				{filepath.Join(testSigDir, "ok-sig-2018-06-15.1.ksig"), result.NA, false, []VerCtxOption{
					VerCtxOptCalendarProvider(extenderFromFileReaderClient(t, "ok_extender_error_response_102.tlv"))}},
				{filepath.Join(testSigDir, "ok-sig-2018-06-15.1.ksig"), result.NA, false, []VerCtxOption{
					VerCtxOptCalendarProvider(extenderFromFileReaderClient(t, "ok_extender_error_response_103.tlv"))}},
				{filepath.Join(testSigDir, "ok-sig-2018-06-15.1.ksig"), result.NA, false, []VerCtxOption{
					VerCtxOptCalendarProvider(extenderFromFileReaderClient(t, "ok_extender_error_response_104.tlv"))}},
				{filepath.Join(testSigDir, "ok-sig-2018-06-15.1.ksig"), result.NA, false, []VerCtxOption{
					VerCtxOptCalendarProvider(extenderFromFileReaderClient(t, "ok_extender_error_response_105.tlv"))}},
				{filepath.Join(testSigDir, "ok-sig-2018-06-15.1.ksig"), result.NA, false, []VerCtxOption{
					VerCtxOptCalendarProvider(extenderFromFileReaderClient(t, "ok_extender_error_response_106.tlv"))}},
				{filepath.Join(testSigDir, "ok-sig-2018-06-15.1.ksig"), result.NA, false, []VerCtxOption{
					VerCtxOptCalendarProvider(extenderFromFileReaderClient(t, "ok_extender_error_response_107.tlv"))}},
				{filepath.Join(testSigDir, "ok-sig-2018-06-15.1.ksig"), result.NA, false, []VerCtxOption{
					VerCtxOptCalendarProvider(extenderFromFileReaderClient(t, "ok_extender_error_response_200.tlv"))}},
				{filepath.Join(testSigDir, "ok-sig-2018-06-15.1.ksig"), result.NA, false, []VerCtxOption{
					VerCtxOptCalendarProvider(extenderFromFileReaderClient(t, "ok_extender_error_response_201.tlv"))}},
				{filepath.Join(testSigDir, "ok-sig-2018-06-15.1.ksig"), result.NA, false, []VerCtxOption{
					VerCtxOptCalendarProvider(extenderFromFileReaderClient(t, "ok_extender_error_response_202.tlv"))}},
				{filepath.Join(testSigDir, "ok-sig-2018-06-15.1.ksig"), result.NA, false, []VerCtxOption{
					VerCtxOptCalendarProvider(extenderFromFileReaderClient(t, "ok_extender_error_response_300.tlv"))}},
				{filepath.Join(testSigDir, "ok-sig-2018-06-15.1.ksig"), result.NA, false, []VerCtxOption{
					VerCtxOptCalendarProvider(extenderFromFileReaderClient(t, "ok_extender_error_response_301.tlv"))}},
			}},

			{ExtendSignatureCalendarChainInputHashToSamePubTime{}, reserr.Gen02, true, []ruleTestCase{
				{filepath.Join(testSigDir, "ok-sig-2018-06-15.1.ksig"), result.OK, false, []VerCtxOption{
					VerCtxOptCalendarProvider(extenderFromFileReaderClient(t, "ok-sig-2018-06-15.1-extend_response.tlv"))}},
				{filepath.Join(testSigDir, "ok-sig-2018-06-15.1-extended.ksig"), result.OK, false, []VerCtxOption{
					VerCtxOptCalendarProvider(extenderFromFileReaderClient(t, "ok-sig-2018-06-15.1-extend_response.tlv"))}},
				{filepath.Join(testSigDir, "ok-sig-2018-06-15.1.ksig"), result.NA, false, []VerCtxOption{
					VerCtxOptCalendarProvider(extenderFromFileReaderClient(t, "ok_extender_error_response_101.tlv"))}},
				{filepath.Join(testSigDir, "ok-sig-2018-06-15.1.ksig"), result.NA, false, []VerCtxOption{
					VerCtxOptCalendarProvider(extenderFromFileReaderClient(t, "ok_extender_error_response_102.tlv"))}},
				{filepath.Join(testSigDir, "ok-sig-2018-06-15.1.ksig"), result.NA, false, []VerCtxOption{
					VerCtxOptCalendarProvider(extenderFromFileReaderClient(t, "ok_extender_error_response_103.tlv"))}},
				{filepath.Join(testSigDir, "ok-sig-2018-06-15.1.ksig"), result.NA, false, []VerCtxOption{
					VerCtxOptCalendarProvider(extenderFromFileReaderClient(t, "ok_extender_error_response_104.tlv"))}},
				{filepath.Join(testSigDir, "ok-sig-2018-06-15.1.ksig"), result.NA, false, []VerCtxOption{
					VerCtxOptCalendarProvider(extenderFromFileReaderClient(t, "ok_extender_error_response_105.tlv"))}},
				{filepath.Join(testSigDir, "ok-sig-2018-06-15.1.ksig"), result.NA, false, []VerCtxOption{
					VerCtxOptCalendarProvider(extenderFromFileReaderClient(t, "ok_extender_error_response_106.tlv"))}},
				{filepath.Join(testSigDir, "ok-sig-2018-06-15.1.ksig"), result.NA, false, []VerCtxOption{
					VerCtxOptCalendarProvider(extenderFromFileReaderClient(t, "ok_extender_error_response_107.tlv"))}},
				{filepath.Join(testSigDir, "ok-sig-2018-06-15.1.ksig"), result.NA, false, []VerCtxOption{
					VerCtxOptCalendarProvider(extenderFromFileReaderClient(t, "ok_extender_error_response_200.tlv"))}},
				{filepath.Join(testSigDir, "ok-sig-2018-06-15.1.ksig"), result.NA, false, []VerCtxOption{
					VerCtxOptCalendarProvider(extenderFromFileReaderClient(t, "ok_extender_error_response_201.tlv"))}},
				{filepath.Join(testSigDir, "ok-sig-2018-06-15.1.ksig"), result.NA, false, []VerCtxOption{
					VerCtxOptCalendarProvider(extenderFromFileReaderClient(t, "ok_extender_error_response_202.tlv"))}},
				{filepath.Join(testSigDir, "ok-sig-2018-06-15.1.ksig"), result.NA, false, []VerCtxOption{
					VerCtxOptCalendarProvider(extenderFromFileReaderClient(t, "ok_extender_error_response_300.tlv"))}},
				{filepath.Join(testSigDir, "ok-sig-2018-06-15.1.ksig"), result.NA, false, []VerCtxOption{
					VerCtxOptCalendarProvider(extenderFromFileReaderClient(t, "ok_extender_error_response_301.tlv"))}},
			}},
		}
	)

	for _, rt := range testData {
		for i, tc := range rt.cases {

			log.Debug("START: ", rt.rule, " ::  [", i, "]", tc)

			sig, err := New(BuildNoVerify(BuildFromFile(tc.file)))
			if err != nil {
				t.Error("Failed to create ksi signature: ", err)
				continue
			}
			verCtx, err := NewVerificationContext(sig, tc.verOpts...)
			if err != nil {
				t.Error("Failed to create verification context: ", err)
				continue
			}

			// Buffer the calendar hash chain in case the provider is set.
			if !rt.ignoreCalProvider && verCtx.calProvider != nil {
				// Use dummy time, as the response is static.
				if err := verCtx.receiveCalendar(time.Time{}); err != nil {
					t.Error(rt.rule, "failed to buffer calendar: [", i, "]", tc, ".\nError:", err)
				}
			}

			// Just verify that the rule fails with invalid argument error.
			res, err := rt.rule.Verify(nil)
			if err == nil || errors.KsiErr(err).Code() != errors.KsiInvalidArgumentError {
				t.Error(rt.rule, "must fail with KsiInvalidArgumentError.")
			}
			if res.resCode != result.NA {
				t.Error(rt.rule, "must fail with NA.")
			}

			res, err = rt.rule.Verify(verCtx)
			if err != nil {
				// Verify if the test case should fail.
				if !tc.err {
					t.Error(rt.rule, "failed with: [", i, "]", tc, ".\nError:", err)
					continue
				}
			} else if tc.err {
				// Test case should have failed.
				t.Error(rt.rule, "expected to fail with: [", i, "]", tc)
			}
			if res.resCode != tc.result {
				t.Error(rt.rule, "result mismatch with: [", i, "]", tc)
			}
		}
	}
}

func pubDataFromString(t *testing.T, pubstr string) *pdu.PublicationData {
	t.Helper()

	pubData, err := pdu.NewPublicationData(pdu.PubDataFromString(pubstr))
	if err != nil {
		t.Fatal("Failed to parse publication string: ", err)
	}
	return pubData
}

func pubFileFromPath(t *testing.T, path string) *publications.File {
	t.Helper()

	pubFile, err := publications.NewFile(publications.FileFromFile(filepath.Join(testPubDir, path)))
	if err != nil {
		t.Fatal("Unable to parse publications file:", err)
	}
	return pubFile
}

func extenderFromFileReaderClient(t *testing.T, path string) verify.CalendarProvider {
	t.Helper()

	return &mockCalendarProvider{
		client: mock.NewFileReaderClient(filepath.Join(testTlvDir, path), "anon", "anon"),
	}
}
