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

package publications

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/guardtime/goksi/errors"
	"github.com/guardtime/goksi/log"
	"github.com/guardtime/goksi/pdu"
	"github.com/guardtime/goksi/test"
	"github.com/guardtime/goksi/tlv"
)

var (
	testRoot            = filepath.Join("..", "test")
	testLogDir          = filepath.Join(testRoot, "out")
	testResourceDir     = filepath.Join(testRoot, "resource")
	testResourcePubDir  = filepath.Join(testResourceDir, "publications")
	testResourceCertDir = filepath.Join(testResourceDir, "certificate")
	testResourceTlvDir  = filepath.Join(testResourceDir, "tlv")
)

func TestUnitFile(t *testing.T) {
	logger, defFunc, err := test.InitLogger(t, testLogDir, log.DEBUG, t.Name())
	if err != nil {
		t.Fatal("Failed to initialize logger: ", err)
	}
	defer defFunc()
	// Apply logger.
	log.SetLogger(logger)

	pfh, err := NewFileHandler(
		FileHandlerSetFileCertConstraint(OidEmail, "publications@guardtime.com"),
	)
	if err != nil {
		t.Fatal("Failed to initialize publications file handler: ", err)
	}

	test.Suite{
		{Func: testNewPubFileFromFile},
		{Func: testNewPubFileFromReader},
		{Func: testInvalidPubFileWithoutSignature},
		{Func: testInvalidPubFileWithInvalidSignature},
		{Func: testOkSignatureWithoutEnoughVerificationInformation},
		{Func: testNokPubfileWithUnknownCriticalElement},
		{Func: testPubfileWithNonDefaultCertificate},
		{Func: testPubfileWithLongCertificate},
		{Func: testPubfileWithEmbeddedIntermediateCertificates},
		{Func: testVerifyNilFileHandler},
		{Func: testVerifyNilFile},
		{Func: testVerifyNotInitializedFile},
		{Func: testVerifyInvalidFile},
		{Func: testPubfileWithEmbeddedIntermediateCertificatesRootCertIsNotTrustedButIsIncluded},
		{Func: testNokPubfileExpiredCertificate},
		{Func: testOkPubfileInvalidConstraints},
		{Func: testPubFileSearchPubRecByPubString},
		{Func: testPubFileSearchPubRecByPubData},
		{Func: testPubFileSearchPubRecByTime},
		{Func: testPubFileSearchPubRecLatest},
		{Func: testPubFileSearchPubRecNearest},
		{Func: testPubFileSearchPubRecFileNoRecs},
		{Func: testGetPublicationRecFromNilFile},
		{Func: testGetPublicationRecWithNilSearchCriteria},
		{Func: testGetPublicationRecWithSearchCriteriaReturnsError},
		{Func: testPubRecSearchByPubStringNilFile},
		{Func: testPubRecSearchByPubStringInvalidSearchString},
		{Func: testPubRecSearchByPubStringNoResult},
		{Func: testPubRecSearchByPubDataNilFile},
		{Func: testPubRecSearchByPubDataNilData},
		{Func: testPubRecSearchByTimeNilFile},
		{Func: testPubRecSearchLatestNilFile},
		{Func: testPubRecSearchNearestNilInput},
		{Func: testPubFileHandlerTTLOptions},
		{Func: testNewFileHandlerNilSettings},
		{Func: testNewFileHandlerNoSettings},
		{Func: testNewFileHandlerEmptySettingsList},
		{Func: testFileHandlerUseSystemCertStoreNilFileHandler},
		{Func: testFileHandlerUseSystemCertStoreOk},
		{Func: testFileHandlerSetTrustedCertificateDirNilFileHandler},
		{Func: testFileHandlerSetTrustedCertificateDirEmptyPath},
		{Func: testFileHandlerSetTrustedCertificateDirNotExistingPath},
		{Func: testFileHandlerSetTrustedCertificateDirNoCertFile},
		{Func: testFileHandlerSetTrustedCertificateNilFileHandler},
		{Func: testFileHandlerSetTrustedCertificateNilCertificate},
		{Func: testFileHandlerSetTrustedCertificateFromFilePemNilFileHandler},
		{Func: testFileHandlerSetTrustedCertificateFromFilePemEmptyPemFileName},
		{Func: testFileHandlerSetTrustedCertificateFromFilePemNotExistingPemFile},
		{Func: testFileHandlerSetPublicationsURLNilFileHandler},
		{Func: testFileHandlerSetFileCertConstraintNilFileHandler},
		{Func: testFileHandlerSetFileCertConstraintInvalidOid},
		{Func: testFileHandlerSetFileCertConstraintsNilFileHandler},
		{Func: testFileHandlerSetFileCertConstraintsEmptyConstraintList},
		{Func: testFileHandlerSetFileNilFileHandler},
		{Func: testFileHandlerSetFileNilFile},
		{Func: testFileHandlerSetFileTTLNilFileHandler},
		{Func: testFileHandlerSetFileTTLSetZeroDuration},
		{Func: testFileHandlerSetFileTTLSetMaxDuration},
		{Func: testFileHandlerSetFileTTLSetMinDuration},
		{Func: testFileHandlerSetFileTTLSetNegativeDuration},
		{Func: testReceiveFileNilFileHandler},
		{Func: testReceiveFileUriAndFileNil},
		{Func: testFileTtlNilFileHandler},
		{Func: testFileTtlOk},
		{Func: testPubFileCertificate},
		{Func: testPubFileCertificateIdNotPresent},
		{Func: testGetCertificateFromNilFile},
		{Func: testGetCertificateWithNilId},
		{Func: testGetCertificateWithNoId},
		{Func: testGetCertificateFromNotInitializedPubFile},
		{Func: testPubFileVerifyRecord},
		{Func: testVerifyNilPubRecord},
		{Func: testVerifyNilRecord},
		{Func: testVerifyNotInitializedRecord},
		{Func: testNewFileWithNilBuilder},
		{Func: testFileFromFileWithNoFilePath},
		{Func: testFileFromFileWithNilFile},
		{Func: testFileFromFileWithNotExistingFile},
		{Func: testFileFromBytesWithNilBytes},
		{Func: testFileFromBytesWithEmptyByte},
		{Func: testFileFromBytesWithNilFile},
		{Func: testFileFromBytesWithInvalidHeaderBytes},
		{Func: testFileFromBytesWithInvalidHeaderBytes2},
		{Func: testFileFromBytesOnlyHeader},
		{Func: testFileFromBytesWithInvalidFileBytes2},
		{Func: testFileFromReaderWithNilReader},
		{Func: testFileFromReaderWithNilFile},
		{Func: testFileFromUrlWithEmptyUrl},
		{Func: testFileFromUrlWithNilFile},
		{Func: testFileFromUrlWithInvalidUrlFormat},
		{Func: testFileFromUrlWithInvalidUrl},
		{Func: testCertificateToStringWitInvalidInput},
		{Func: testCertToString},
		{Func: testCertChainToStringWithNilInput},
		{Func: testCertChainToStringWithEmptyListInput},
		{Func: testOneCertInChainToString},
		{Func: testMultipleCertInChainToString},
		{Func: testNewPubFileWithNilOption},
		{Func: testNewPubFileFromPartialBinarySlice},
	}.Runner(t, pfh)
}

const (
	pfUTestOptPfh = iota
)

func testNewPubFileWithNilOption(t *testing.T, _ ...interface{}) {
	_, err := NewFileHandler(
		nil,
	)
	if err == nil {
		t.Fatal("Calling NewFileHandler with nil option should have been failed!")
	}

	if ec := errors.KsiErr(err).Code(); ec != errors.KsiInvalidArgumentError {
		t.Fatalf("Invalid error code: expecting %v, but got %v.", errors.KsiInvalidArgumentError, ec)
	}
}

func testNewPubFileFromFile(t *testing.T, _ ...interface{}) {
	var (
		testPubFile = filepath.Join(testResourcePubDir, "publications.bin")
		testCrtFile = filepath.Join(testResourceCertDir, "mock.crt")
	)

	pfh, err := NewFileHandler(
		FileHandlerSetTrustedCertificateFromFilePem(testCrtFile),
		FileHandlerSetFileCertConstraint(OidEmail, "publications@guardtime.com"),
	)
	if err != nil {
		t.Fatal("Failed to initialize publications file handler: ", err)
	}

	pubFile, err := NewFile(FileFromFile(testPubFile))
	if err != nil {
		t.Fatal("Failed to create publications file: ", err)
	}

	if pubFile == nil {
		t.Fatal("No file returned.")
	}

	err = pfh.Verify(pubFile)
	if err != nil {
		t.Fatal("Failed to verify publications file: ", err)
	}
}

func testNewPubFileFromReader(t *testing.T, _ ...interface{}) {
	var (
		testPubFile = filepath.Join(testResourcePubDir, "publications.bin")
		testCrtFile = filepath.Join(testResourceCertDir, "mock.crt")
	)

	pfh, err := NewFileHandler(
		FileHandlerSetTrustedCertificateFromFilePem(testCrtFile),
		FileHandlerSetFileCertConstraint(OidEmail, "publications@guardtime.com"),
	)
	if err != nil {
		t.Fatal("Failed to initialize publications file handler: ", err)
	}

	r, err := os.Open(testPubFile)
	if err != nil {
		t.Fatal("Failed to get publications file reader: ", err)
	}

	defer r.Close()

	pubFile, err := NewFile(FileFromReader(r))
	if err != nil {
		t.Fatal("Failed to create publications file: ", err)
	}

	if pubFile == nil {
		t.Fatal("No file returned.")
	}

	err = pfh.Verify(pubFile)
	if err != nil {
		t.Fatal("Failed to verify publications file: ", err)
	}
}

// This test was added as in some point of time goksi used to panic.
func testNewPubFileFromPartialBinarySlice(t *testing.T, _ ...interface{}) {
	var (
		testPubFile = filepath.Join(testResourcePubDir, "publications.bin")
	)

	r, err := os.Open(testPubFile)
	if err != nil {
		t.Fatal("Failed to get publications file reader: ", err)
	}

	defer r.Close()

	raw, err := ioutil.ReadAll(r)
	if err != nil {
		t.Fatal("Failed to read publications file: ", err)
	}

	_, err = NewFile(FileFromBytes(raw[:len(raw)-2]))
	if err == nil {
		t.Fatal("This call should have been failed!")
	}
}

func testInvalidPubFileWithoutSignature(t *testing.T, opt ...interface{}) {
	assertInvalidPubfile(t, opt[pfUTestOptPfh].(*FileHandler), "nok-publications-no-signature.bin", "TLV [700.704] (File.signature) count should be C1, but is 0.", "", "")
}

func testInvalidPubFileWithInvalidSignature(t *testing.T, opt ...interface{}) {
	assertInvalidPubfile(t, opt[pfUTestOptPfh].(*FileHandler), "nok-publications-wrong-signature.bin", "", "Unable to parse publications file PKCS7 signature.", "")
}

func testOkSignatureWithoutEnoughVerificationInformation(t *testing.T, opt ...interface{}) {
	assertInvalidPubfile(t, opt[pfUTestOptPfh].(*FileHandler), "ok-pub-one-record-1.bin", "", "Unable to verify PKCS7 signatures signing certificate.", "x509: certificate signed by unknown authority")
}

func testNokPubfileWithUnknownCriticalElement(t *testing.T, opt ...interface{}) {
	assertInvalidPubfile(t, opt[pfUTestOptPfh].(*FileHandler), "nok-publications-new-critical-element-in-publication-record.bin", "TLV (700.703.1) template not found for a mandatory TLV.", "", "")
}

func assertInvalidPubfile(t *testing.T, pfh *FileHandler, fname, parseError, verifyError, extError string) {
	var (
		testPubFile = filepath.Join(testResourcePubDir, fname)
	)

	if parseError != "" && verifyError != "" {
		t.Fatal("Invalid test! You cant have both parsing and verification error at the same time!")
	}

	pubFile, err := NewFile(FileFromFile(testPubFile))
	if parseError == "" {
		if err != nil {
			t.Fatal("Unable to parse publications file.!")
		}
	} else {
		if err == nil {
			t.Fatalf("This call should have failed with message '%s'.", parseError)
		}

		if pubFile != nil {
			t.Fatal("Publications file parsing failure must return nil.")
		}

		msg := errors.KsiErr(err).Message()[0]
		if msg != parseError {
			t.Fatalf("\nExpecting error: '%s'\nBut got error:   '%s'\n", parseError, msg)
		}

		return
	}

	if verifyError != "" {
		err := pfh.Verify(pubFile)

		msg := errors.KsiErr(err).Message()[0]
		if msg != verifyError {
			t.Error(err)
			t.Fatalf("\nExpecting error: '%s'\nBut got error:   '%s'\n", verifyError, msg)
		}

		if extError != "" {
			msg = errors.KsiErr(err).ExtError().Error()
			if msg != extError {
				t.Fatalf("\nExpecting error: '%s'\nBut got error:   '%s'\n", extError, msg)
			}
		}
	} else {
		t.Fatalf("Invalid test - verifyError must have value!")
	}
}

func testPubfileWithNonDefaultCertificate(t *testing.T, _ ...interface{}) {
	var (
		testPubFile  = filepath.Join(testResourcePubDir, "ok-pub-one-record-1.bin")
		testCertFile = filepath.Join(testResourceCertDir, "ok-test.crt")
	)

	pubFile, err := NewFile(FileFromFile(testPubFile))
	if err != nil {
		t.Fatal("Failed to create publications file: ", err)
	}

	pfh, err := NewFileHandler(
		FileHandlerSetTrustedCertificateFromFilePem(testCertFile),
		FileHandlerSetFileCertConstraint(OidEmail, "test@test.com"),
	)
	if err != nil {
		t.Fatal("Failed to initialize publications file handler: ", err)
	}

	err = pfh.Verify(pubFile)
	if err != nil {
		t.Fatal("Failed to verify publications file: ", err)
	}
}

func testPubfileWithLongCertificate(t *testing.T, _ ...interface{}) {
	var (
		testPubFile = filepath.Join(testResourcePubDir, "ok-pubfile-no-intermediate-certs.bin")
		ca1File     = filepath.Join(testResourceCertDir, "ok-cert-ca-1.pem.crt")
		ca2File     = filepath.Join(testResourceCertDir, "ok-cert-ca-2.pem.crt")
	)

	pubFile, err := NewFile(FileFromFile(testPubFile))
	if err != nil {
		t.Fatal("Failed to create publications file: ", err)
	}

	pfh, err := NewFileHandler(
		FileHandlerSetFileCertConstraint(OidEmail, "pub-test@test.com"),
		FileHandlerSetTrustedCertificateFromFilePem(ca1File),
		FileHandlerSetTrustedCertificateFromFilePem(ca2File),
	)
	if err != nil {
		t.Fatal("Failed to initialize publications file handler: ", err)
	}

	err = pfh.Verify(pubFile)
	if err != nil {
		t.Fatal("Failed to verify publications file: ", err)
	}
}

func testPubfileWithEmbeddedIntermediateCertificatesRootCertIsNotTrustedButIsIncluded(t *testing.T, opt ...interface{}) {
	// Signature contains all certificates needed for verification. As the embedded root certificate is not
	// trusted, verification MUST fail!
	assertInvalidPubfile(t, opt[pfUTestOptPfh].(*FileHandler), "ok-pubfile-intermediate-certs-embedded.bin", "", "Unable to verify PKCS7 signatures signing certificate.", "x509: certificate signed by unknown authority")
}

func testPubfileWithEmbeddedIntermediateCertificates(t *testing.T, _ ...interface{}) {
	var (
		testPubFile = filepath.Join(testResourcePubDir, "ok-pubfile-intermediate-certs-embedded.bin")
		ca1File     = filepath.Join(testResourceCertDir, "ok-cert-ca-1.pem.crt")
	)

	pubFile, err := NewFile(FileFromFile(testPubFile))
	if err != nil {
		t.Fatal("Failed to create publications file: ", err)
	}

	pfh, err := NewFileHandler(
		FileHandlerSetFileCertConstraint(OidEmail, "pub-test@test.com"),
		FileHandlerSetTrustedCertificateFromFilePem(ca1File),
	)
	if err != nil {
		t.Fatal("Failed to initialize publications file handler: ", err)
	}

	err = pfh.Verify(pubFile)
	if err != nil {
		t.Fatal("Failed to verify publications file: ", err)
	}
}

func testVerifyNilFileHandler(t *testing.T, _ ...interface{}) {
	var (
		fileHandler *FileHandler
		file        File
	)

	err := fileHandler.Verify(&file)
	if err == nil {
		t.Fatal("Should not be possible to verify with nil file handler.")
	}
}

func testVerifyNilFile(t *testing.T, _ ...interface{}) {
	var fileHandler FileHandler

	err := fileHandler.Verify(nil)
	if err == nil {
		t.Fatal("Should not be possible to verify nil file.")
	}
}

func testVerifyNotInitializedFile(t *testing.T, _ ...interface{}) {
	var (
		fileHandler FileHandler
		file        File
	)

	err := fileHandler.Verify(&file)
	if err == nil {
		t.Fatal("Should not be possible to verify with nil file handler.")
	}
}

func testVerifyInvalidFile(t *testing.T, _ ...interface{}) {
	var (
		file        File
		fileHandler FileHandler
	)
	tlv, err := tlv.NewTlv(tlv.ConstructEmpty(0x12, false, false))
	if err != nil {
		t.Fatal("Failed to create tlv element.")
	}
	file.rawTlv = tlv

	err = fileHandler.Verify(&file)
	if err == nil {
		t.Fatal("Should not be possible to verify file with no signature.")
	}
	if err.(*errors.KsiError).Code() != errors.KsiPublicationsFileNotSignedWithPki {
		t.Fatal("Unexpected error: ", err)
	}
}

func testNokPubfileExpiredCertificate(t *testing.T, _ ...interface{}) {
	var (
		testPubFile = "publications-with-bad-certificates.bin"
		ca1File     = filepath.Join(testResourceCertDir, "ok-cert-ca-1.pem.crt")
		ca2File     = filepath.Join(testResourceCertDir, "ok-cert-ca-2.pem.crt")
	)

	pfh, err := NewFileHandler(
		FileHandlerSetFileCertConstraint(OidEmail, "pub-test@test.com"),
		FileHandlerSetTrustedCertificateFromFilePem(ca1File),
		FileHandlerSetTrustedCertificateFromFilePem(ca2File),
	)
	if err != nil {
		t.Fatal("Failed to initialize publications file handler: ", err)
	}

	assertInvalidPubfile(t, pfh, testPubFile, "", "Unable to verify PKCS7 signatures signing certificate.", "x509: certificate has expired or is not yet valid")
}

func testOkPubfileInvalidConstraints(t *testing.T, _ ...interface{}) {
	var (
		testPubFile = "ok-pub-one-record-1.bin"
		cert        = filepath.Join(testResourceCertDir, "ok-test.crt")
	)

	pfh, err := NewFileHandler(
		FileHandlerSetFileCertConstraint(OidEmail, "pub-test@test.com"),
		FileHandlerSetTrustedCertificateFromFilePem(cert),
	)
	if err != nil {
		t.Fatal("Failed to initialize publications file handler: ", err)
	}

	assertInvalidPubfile(t, pfh, testPubFile, "", "Certificate constraints mismatch for 1.2.840.113549.1.9.1.", "")
}

func testPubFileSearchPubRecByPubString(t *testing.T, _ ...interface{}) {
	var (
		testPubFile = filepath.Join(testResourcePubDir, "ksi-publications_20180611.bin")

		testData = []struct {
			pubString string
			present   bool
		}{
			// Publication Code for 15 August 2018
			{"AAAAAA-C3ONWQ-AANO2I-UDF2Y3-YUANDE-FA4WDB-JMECT3-ZURJ6C-ZB4GSD-YUKTC7-PFGWY4-NZLPQP", false},
			// Publication Code for 15 July 2018
			{"AAAAAA-C3JKHI-AAKZ7D-HQQZU2-AF2ZKN-ZNXY5B-LMWRIN-DI37WF-PETGGY-YWWEA7-3MRG3N-V4WO2F", false},
			// Publication Code for 15 June 2018
			{"AAAAAA-C3EMAY-AANR4X-52H7U6-XSTKWP-IXMQMW-C6KJDS-SIRRVW-BSYVFV-ZXQGZD-SBF47F-6QIG64", false},
			// Publication Code for 15 May 2018
			{"AAAAAA-C27IRQ-AANPAD-VII3R3-DQDZ65-YQTRIC-5JHP2V-RUFUNA-NBQAXZ-FBLJRG-KXQGBG-T5PFE4", true},
			// Publication Code for 15 April 2018
			{"AAAAAA-C22KLA-AAKHJG-3HLWBQ-I5ZCTG-FRGFP5-UEEV2A-IKP2W3-VPZ6SB-EE6M5X-FBLT34-UAFNGG", true},
		}
	)

	pubFile, err := NewFile(FileFromFile(testPubFile))
	if err != nil {
		t.Fatal("Failed to create publications file: ", err)
	}

	for _, d := range testData {
		pubRec, err := pubFile.PublicationRec(PubRecSearchByPubString(d.pubString))
		if err != nil {
			t.Fatal("Failed to search for publication record: ", err)
		}
		if d.present {
			if pubRec == nil {
				t.Error("Pub record must be present in pub file.")
			}
		} else {
			if pubRec != nil {
				t.Error("Pub record is not present in pub file.")
			}
		}
	}
}

func testPubFileSearchPubRecByPubData(t *testing.T, _ ...interface{}) {
	var (
		testPubFile = filepath.Join(testResourcePubDir, "ksi-publications_20180611.bin")

		testData = []struct {
			pubString string
			present   bool
		}{
			// Publication Code for 15 August 2018
			{"AAAAAA-C3ONWQ-AANO2I-UDF2Y3-YUANDE-FA4WDB-JMECT3-ZURJ6C-ZB4GSD-YUKTC7-PFGWY4-NZLPQP", false},
			// Publication Code for 15 July 2018
			{"AAAAAA-C3JKHI-AAKZ7D-HQQZU2-AF2ZKN-ZNXY5B-LMWRIN-DI37WF-PETGGY-YWWEA7-3MRG3N-V4WO2F", false},
			// Publication Code for 15 June 2018
			{"AAAAAA-C3EMAY-AANR4X-52H7U6-XSTKWP-IXMQMW-C6KJDS-SIRRVW-BSYVFV-ZXQGZD-SBF47F-6QIG64", false},
			// Publication Code for 15 May 2018
			{"AAAAAA-C27IRQ-AANPAD-VII3R3-DQDZ65-YQTRIC-5JHP2V-RUFUNA-NBQAXZ-FBLJRG-KXQGBG-T5PFE4", true},
			// Publication Code for 15 April 2018
			{"AAAAAA-C22KLA-AAKHJG-3HLWBQ-I5ZCTG-FRGFP5-UEEV2A-IKP2W3-VPZ6SB-EE6M5X-FBLT34-UAFNGG", true},
		}
	)

	pubFile, err := NewFile(FileFromFile(testPubFile))
	if err != nil {
		t.Fatal("Failed to create publications file: ", err)
	}

	for _, d := range testData {
		pubData, err := pdu.NewPublicationData(pdu.PubDataFromString(d.pubString))
		if err != nil {
			t.Fatal("Failed to create pub data: ", err)
		}

		pubRec, err := pubFile.PublicationRec(PubRecSearchByPubData(pubData))
		if err != nil {
			t.Fatal("Failed to search for publication record: ", err)
		}
		if d.present {
			if pubRec == nil {
				t.Error("Pub record must be present in pub file.")
			}
		} else {
			if pubRec != nil {
				t.Error("Pub record is not present in pub file.")
			}
		}
	}
}

func testPubFileSearchPubRecByTime(t *testing.T, _ ...interface{}) {
	var (
		testPubFile = filepath.Join(testResourcePubDir, "ksi-publications_20180611.bin")
		testData    = []struct {
			pubTime time.Time
			present bool
		}{
			// Publication time for 15 August 2018
			{time.Unix(1534291200, 0), false},
			// Publication time for 15 July 2018
			{time.Unix(1531612800, 0), false},
			// Publication time for 15 June 2018
			{time.Unix(1529020800, 0), false},
			// Publication time for 15 May 2018
			{time.Unix(1526342400, 0), true},
			// Publication time for 15 April 2018
			{time.Unix(1523750400, 0), true},
		}
	)

	pubFile, err := NewFile(FileFromFile(testPubFile))
	if err != nil {
		t.Fatal("Failed to create publications file: ", err)
	}

	for _, d := range testData {
		pubRec, err := pubFile.PublicationRec(PubRecSearchByTime(d.pubTime))
		if err != nil {
			t.Fatal("Failed to search for publication record: ", err)
		}
		if d.present {
			if pubRec == nil {
				t.Error("Pub record must be present in pub file.")
			}
		} else {
			if pubRec != nil {
				t.Error("Pub record is not present in pub file.")
			}
		}
	}
}

func testPubFileSearchPubRecLatest(t *testing.T, _ ...interface{}) {
	var (
		testPubFile = filepath.Join(testResourcePubDir, "ksi-publications_20180611.bin")
		testData    = []struct {
			tm      time.Time
			pubTime time.Time
			present bool
		}{
			// Time before Publication time for 15 August 2018
			{time.Unix(1534291200-1, 0), time.Unix(1534291200, 0), false},
			// Time before Publication time for 15 July 2018
			{time.Unix(1531612800-1, 0), time.Unix(1531612800, 0), false},
			// Time before Publication time for 15 June 2018
			{time.Unix(1529020800-1, 0), time.Unix(1529020800, 0), false},
			// Time before Publication time for 15 May 2018
			{time.Unix(1526342400-1, 0), time.Unix(1526342400, 0), true},
			// Time before Publication time for 15 April 2018
			{time.Unix(1523750400-1, 0), time.Unix(1526342400, 0), true},
			// Time ater Publication time for 15 April 2018
			{time.Unix(1523750400+1, 0), time.Unix(1526342400, 0), true},
		}
	)

	pubFile, err := NewFile(FileFromFile(testPubFile))
	if err != nil {
		t.Fatal("Failed to create publications file: ", err)
	}

	for _, d := range testData {
		pubRec, err := pubFile.PublicationRec(PubRecSearchLatest(d.tm))
		if err != nil {
			t.Fatal("Failed to search for publication record: ", err)
		}
		if d.present {
			if pubRec == nil {
				t.Error("Pub record must be present in pub file.")
			}

			pubData, err := pubRec.PublicationData()
			if err != nil {
				t.Fatal("Failed to get publication data: ", err)
			}

			pubTime, err := pubData.PublicationTime()
			if err != nil {
				t.Fatal("Failed to get publication time: ", err)
			}

			if !d.pubTime.Equal(pubTime) {
				t.Error("Pub time mismatch: ", d.pubTime, " vs ", pubTime)
			}
		} else {
			if pubRec != nil {
				t.Error("Pub record is not present in pub file.")
			}
		}
	}
}

func testPubFileSearchPubRecNearest(t *testing.T, _ ...interface{}) {
	var (
		testPubFile = filepath.Join(testResourcePubDir, "ksi-publications_20180611.bin")
		testData    = []struct {
			tm      time.Time
			pubTime time.Time
			present bool
		}{
			// Time before Publication time for 15 August 2018
			{time.Unix(1534291200-1, 0), time.Unix(1534291200, 0), false},
			// Time before Publication time for 15 July 2018
			{time.Unix(1531612800-1, 0), time.Unix(1531612800, 0), false},
			// Time before Publication time for 15 June 2018
			{time.Unix(1529020800-1, 0), time.Unix(1529020800, 0), false},
			// Time before Publication time for 15 May 2018
			{time.Unix(1526342400-1, 0), time.Unix(1526342400, 0), true},
			// Time before Publication time for 15 April 2018
			{time.Unix(1523750400-1, 0), time.Unix(1523750400, 0), true},
			// Time ater Publication time for 15 April 2018
			{time.Unix(1523750400+1, 0), time.Unix(1526342400, 0), true},
		}
	)

	pubFile, err := NewFile(FileFromFile(testPubFile))
	if err != nil {
		t.Fatal("Failed to create publications file: ", err)
	}

	for _, d := range testData {
		pubRec, err := pubFile.PublicationRec(PubRecSearchNearest(d.tm))
		if err != nil {
			t.Fatal("Failed to search for publication record: ", err)
		}
		if d.present {
			if pubRec == nil {
				t.Error("Pub record must be present in pub file.")
			}

			pubData, err := pubRec.PublicationData()
			if err != nil {
				t.Fatal("Failed to get publication data: ", err)
			}

			pubTime, err := pubData.PublicationTime()
			if err != nil {
				t.Fatal("Failed to get publication time: ", err)
			}

			if !d.pubTime.Equal(pubTime) {
				t.Error("Pub time mismatch: ", d.pubTime, " vs ", pubTime)
			}
		} else {
			if pubRec != nil {
				t.Error("Pub record is not present in pub file.")
			}
		}
	}
}

func testPubFileSearchPubRecFileNoRecs(t *testing.T, _ ...interface{}) {
	var (
		testPubFile = filepath.Join(testResourcePubDir, "ksi-publications.no-pub-recs.bin")

		// Publication for 15 April 2018
		testPubTime   = time.Unix(1523750400, 0)
		testPubString = "AAAAAA-C22KLA-AAKHJG-3HLWBQ-I5ZCTG-FRGFP5-UEEV2A-IKP2W3-VPZ6SB-EE6M5X-FBLT34-UAFNGG"
	)

	pubFile, err := NewFile(FileFromFile(testPubFile))
	if err != nil {
		t.Fatal("Failed to create publications file: ", err)
	}

	pubRec, err := pubFile.PublicationRec(PubRecSearchByPubString(testPubString))
	if err != nil {
		t.Error("Must not fail: ", err)
	}
	if pubRec != nil {
		t.Error("Record should not be returned.")
	}

	pd, err := pdu.NewPublicationData(pdu.PubDataFromString(testPubString))
	if err != nil {
		t.Fatal("Failed to create pub data: ", err)
	}
	pubRec, err = pubFile.PublicationRec(PubRecSearchByPubData(pd))
	if err != nil {
		t.Error("Must not fail: ", err)
	}
	if pubRec != nil {
		t.Error("Record should not be returned.")
	}

	pubRec, err = pubFile.PublicationRec(PubRecSearchByTime(testPubTime))
	if err != nil {
		t.Error("Must not fail: ", err)
	}
	if pubRec != nil {
		t.Error("Record should not be returned.")
	}

	pubRec, err = pubFile.PublicationRec(PubRecSearchLatest(testPubTime))
	if err != nil {
		t.Error("Must not fail: ", err)
	}
	if pubRec != nil {
		t.Error("Record should not be returned.")
	}

	pubRec, err = pubFile.PublicationRec(PubRecSearchNearest(testPubTime))
	if err != nil {
		t.Error("Must not fail: ", err)
	}
	if pubRec != nil {
		t.Error("Record should not be returned.")
	}

}

func testGetPublicationRecFromNilFile(t *testing.T, _ ...interface{}) {
	var (
		pubFile *File
		search  PubRecSearchBy
	)
	_, err := pubFile.PublicationRec(search)
	if err == nil {
		t.Fatal("Should not be possible to get publication record from nil publication file.")
	}
}

func testGetPublicationRecWithNilSearchCriteria(t *testing.T, _ ...interface{}) {
	var pubFile File
	_, err := pubFile.PublicationRec(nil)
	if err == nil {
		t.Fatal("Should not be possible to get publication record with nil search criteria.")
	}
}

func testGetPublicationRecWithSearchCriteriaReturnsError(t *testing.T, _ ...interface{}) {
	var pubFile File
	_, err := pubFile.PublicationRec(PubRecSearchByPubString(""))
	if err == nil {
		t.Fatal("Should not be possible to get publication record if search criteria returns error.")
	}
}

func testPubRecSearchByPubStringNilFile(t *testing.T, _ ...interface{}) {
	var pubFile *File
	search := PubRecSearchByPubString("pub.string")
	_, err := search(pubFile)
	if err == nil {
		t.Fatal("Should not be possible to search from nil file.")
	}
}

func testPubRecSearchByPubStringInvalidSearchString(t *testing.T, _ ...interface{}) {
	var pubFile File
	search := PubRecSearchByPubString("")
	_, err := search(&pubFile)
	if err == nil {
		t.Fatal("Should not be possible to search with empty string.")
	}
}

func testPubRecSearchByPubStringNoResult(t *testing.T, _ ...interface{}) {
	var (
		testPubFile = filepath.Join(testResourcePubDir, "ksi-publications.no-pub-recs.bin")
	)
	search := PubRecSearchByPubString("no result for this search string")
	pubFile, err := NewFile(FileFromFile(testPubFile))
	if err != nil {
		t.Fatal("Failed to create publications file: ", err)
	}
	val, err := search(pubFile)
	if err == nil || val != -1 {
		t.Fatal("Should not get any results if publication string does not yield results.")
	}
}

func testPubRecSearchByPubDataNilFile(t *testing.T, _ ...interface{}) {
	var (
		pubFile *File
		pubData pdu.PublicationData
	)
	search := PubRecSearchByPubData(&pubData)
	_, err := search(pubFile)
	if err == nil {
		t.Fatal("Should not be possible to search from nil file.")
	}
}

func testPubRecSearchByPubDataNilData(t *testing.T, _ ...interface{}) {
	var pubFile File
	search := PubRecSearchByPubData(nil)
	_, err := search(&pubFile)
	if err == nil {
		t.Fatal("Should not be possible to search with empty publication data.")
	}
}

func testPubRecSearchByTimeNilFile(t *testing.T, _ ...interface{}) {
	var pubFile *File
	search := PubRecSearchByTime(time.Time{})
	_, err := search(pubFile)
	if err == nil {
		t.Fatal("Should not be possible to search from nil file.")
	}
}

func testPubRecSearchLatestNilFile(t *testing.T, _ ...interface{}) {
	var pubFile *File
	search := PubRecSearchLatest(time.Time{})
	_, err := search(pubFile)
	if err == nil {
		t.Fatal("Should not be possible to search from nil file.")
	}
}

func testPubRecSearchNearestNilInput(t *testing.T, _ ...interface{}) {
	var pubFile *File
	search := PubRecSearchNearest(time.Time{})
	_, err := search(pubFile)
	if err == nil {
		t.Fatal("Should not be possible to search from nil file.")
	}
}

func testPubFileHandlerTTLOptions(t *testing.T, _ ...interface{}) {

	var (
		testPubFile     = filepath.Join(testResourcePubDir, "ksi-publications.bin")
		testTTLDuration = 10 * time.Second
	)

	pubFile, err := NewFile(FileFromFile(testPubFile))
	if err != nil {
		t.Fatal("Failed to initialize publications file: ", err)
	}

	pubFileHandler, err := NewFileHandler(
		FileHandlerSetFile(pubFile),
		FileHandlerSetFileCertConstraint(OidEmail, "publications@guardtime.com"),
		FileHandlerSetFileTTL(testTTLDuration),
	)
	if err != nil {
		t.Fatal("Failed to initialize publications file handler: ", err)
	}

	hTTL, _ := pubFileHandler.FileTTL()
	if hTTL != testTTLDuration {
		t.Error("TTL mismatch.")
	}

	rcvFile, err := pubFileHandler.ReceiveFile()
	if err != nil {
		t.Fatal("File receiver failed: ", err)
	}

	if rcvFile != pubFile {
		t.Error("Returned file mismatch.")
	}
}

func testNewFileHandlerNilSettings(t *testing.T, _ ...interface{}) {
	_, err := NewFileHandler(nil)
	if err == nil {
		t.Fatal("Should not be possible to crate publications file handler with nil pointer setting.")
	}
}

func testNewFileHandlerNoSettings(t *testing.T, _ ...interface{}) {
	_, err := NewFileHandler()
	if err != nil {
		t.Fatal("Failed to create new publications file handler with no settings.")
	}
}

func testNewFileHandlerEmptySettingsList(t *testing.T, _ ...interface{}) {
	var settings []FileHandlerSetting
	_, err := NewFileHandler(settings...)
	if err != nil {
		t.Fatal("Failed to create new publications file handler with empty settings list.")
	}
}

func testFileHandlerUseSystemCertStoreNilFileHandler(t *testing.T, _ ...interface{}) {
	handler := FileHandlerUseSystemCertStore()
	err := handler(nil)
	if err == nil {
		t.Fatal("FileHandlerUseSystemCertStore with nil FilHandler input should fail.")
	}
}

func testFileHandlerUseSystemCertStoreOk(t *testing.T, _ ...interface{}) {
	if runtime.GOOS != "windows" {
		var fHandler fileHandler
		handler := FileHandlerUseSystemCertStore()
		err := handler(&fHandler)
		if err != nil {
			t.Fatal("Failed to use FileHandlerUseSystemCertStore: ", err)
		}
	}
}

func testFileHandlerSetTrustedCertificateDirNilFileHandler(t *testing.T, _ ...interface{}) {
	handler := FileHandlerSetTrustedCertificateDir("path.to.cert")
	err := handler(nil)
	if err == nil {
		t.Fatal("FileHandlerSetTrustedCertificateDir with nil FilHandler input should fail.")
	}
}

func testFileHandlerSetTrustedCertificateDirEmptyPath(t *testing.T, _ ...interface{}) {
	var fHandler fileHandler
	handler := FileHandlerSetTrustedCertificateDir("")
	err := handler(&fHandler)
	if err == nil {
		t.Fatal("FileHandlerSetTrustedCertificateDir with empty path should fail.")
	}
}

func testFileHandlerSetTrustedCertificateDirNotExistingPath(t *testing.T, _ ...interface{}) {
	var fHandler fileHandler
	handler := FileHandlerSetTrustedCertificateDir("path.to.cert")
	err := handler(&fHandler)
	if err == nil {
		t.Fatal("FileHandlerSetTrustedCertificateDir with not existing path should fail.")
	}
}

func testFileHandlerSetTrustedCertificateDirNoCertFile(t *testing.T, _ ...interface{}) {
	var fHandler fileHandler
	workingdir, err := os.Getwd()
	if err != nil {
		t.Fatal("Failed to get current working dir.")
	}
	handler := FileHandlerSetTrustedCertificateDir(workingdir)
	err = handler(&fHandler)
	if err != nil {
		t.Fatal("FileHandlerSetTrustedCertificateDir with no cert files in given path should not fail.")
	}
}

func testFileHandlerSetTrustedCertificateNilFileHandler(t *testing.T, _ ...interface{}) {
	var cert *x509.Certificate
	handler := FileHandlerSetTrustedCertificate(cert)
	err := handler(nil)
	if err == nil {
		t.Fatal("FileHandlerSetTrustedCertificate with nil file handler should fail.")
	}
}

func testFileHandlerSetTrustedCertificateNilCertificate(t *testing.T, _ ...interface{}) {
	var fHandler fileHandler
	handler := FileHandlerSetTrustedCertificate(nil)
	err := handler(&fHandler)
	if err == nil {
		t.Fatal("FileHandlerSetTrustedCertificate with nil certificate should fail.")
	}
}

func testFileHandlerSetTrustedCertificateFromFilePemNilFileHandler(t *testing.T, _ ...interface{}) {
	handler := FileHandlerSetTrustedCertificateFromFilePem("cert.file.pem")
	err := handler(nil)
	if err == nil {
		t.Fatal("FileHandlerSetTrustedCertificateFromFilePem with nil file handler should fail.")
	}
}

func testFileHandlerSetTrustedCertificateFromFilePemEmptyPemFileName(t *testing.T, _ ...interface{}) {
	var fHandler fileHandler
	handler := FileHandlerSetTrustedCertificateFromFilePem("")
	err := handler(&fHandler)
	if err == nil {
		t.Fatal("FileHandlerSetTrustedCertificateFromFilePem with empty certificate file name should fail.")
	}
}

func testFileHandlerSetTrustedCertificateFromFilePemNotExistingPemFile(t *testing.T, _ ...interface{}) {
	var fHandler fileHandler
	handler := FileHandlerSetTrustedCertificateFromFilePem("some.kind.of.pem.file")
	err := handler(&fHandler)
	if err == nil {
		t.Fatal("FileHandlerSetTrustedCertificateFromFilePem with not existing file should fail.")
	}
}

func testFileHandlerSetPublicationsURLNilFileHandler(t *testing.T, _ ...interface{}) {
	handler := FileHandlerSetPublicationsURL("http://some.url.kind.of.url.com")
	err := handler(nil)
	if err == nil {
		t.Fatal("FileHandlerSetPublicationsURL with nil file handler should fail.")
	}
}

func testFileHandlerSetFileCertConstraintNilFileHandler(t *testing.T, _ ...interface{}) {
	handler := FileHandlerSetFileCertConstraint(OidCommonName, "some.oid.value")
	err := handler(nil)
	if err == nil {
		t.Fatal("FileHandlerSetFileCertConstraint with nil file handler should fail.")
	}
}

func testFileHandlerSetFileCertConstraintInvalidOid(t *testing.T, _ ...interface{}) {
	var oid OID
	handler := FileHandlerSetFileCertConstraint(oid, "")
	err := handler(nil)
	if err == nil {
		t.Fatal("FileHandlerSetFileCertConstraint with nil file handler should fail.")
	}
}

func testFileHandlerSetFileCertConstraintsNilFileHandler(t *testing.T, _ ...interface{}) {
	cnst := []pkix.AttributeTypeAndValue{{asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 1}, "publications@guardtime.com"}}
	if len(cnst) == 0 {
		t.Fatal("Constraint was not created.")
	}
	handler := FileHandlerSetFileCertConstraints(cnst)
	err := handler(nil)
	if err == nil {
		t.Fatal("FileHandlerSetFileCertConstraints with nil file handler should fail.")
	}
}

func testFileHandlerSetFileCertConstraintsEmptyConstraintList(t *testing.T, _ ...interface{}) {
	var cnst []pkix.AttributeTypeAndValue
	handler := FileHandlerSetFileCertConstraints(cnst)
	err := handler(nil)
	if err == nil {
		t.Fatal("FileHandlerSetFileCertConstraints with nil file handler should fail.")
	}
}

func testFileHandlerSetFileNilFileHandler(t *testing.T, _ ...interface{}) {
	var file File
	handler := FileHandlerSetFile(&file)
	err := handler(nil)
	if err == nil {
		t.Fatal("FileHandlerSetFile with nil file handler should fail.")
	}
}

func testFileHandlerSetFileNilFile(t *testing.T, _ ...interface{}) {
	var fHandler fileHandler
	handler := FileHandlerSetFile(nil)
	err := handler(&fHandler)
	if err == nil {
		t.Fatal("FileHandlerSetFile with nil file should fail.")
	}
}

func testFileHandlerSetFileTTLNilFileHandler(t *testing.T, _ ...interface{}) {
	handler := FileHandlerSetFileTTL(0)
	err := handler(nil)
	if err == nil {
		t.Fatal("FileHandlerSetFileTTL with nil file handler should fail.")
	}
}

func testFileHandlerSetFileTTLSetZeroDuration(t *testing.T, _ ...interface{}) {
	var fHandler fileHandler
	handler := FileHandlerSetFileTTL(0)
	err := handler(&fHandler)
	if err != nil {
		t.Fatal("FileHandlerSetFileTTL with zero duration should be OK.")
	}
}

func testFileHandlerSetFileTTLSetMaxDuration(t *testing.T, _ ...interface{}) {
	var fHandler fileHandler
	duration := time.Duration(1<<63 - 1)
	handler := FileHandlerSetFileTTL(duration)
	err := handler(&fHandler)
	if err != nil {
		t.Fatal("FileHandlerSetFileTTL with max duration should be OK.")
	}
}

func testFileHandlerSetFileTTLSetMinDuration(t *testing.T, _ ...interface{}) {
	var fHandler fileHandler
	duration := time.Duration(-1 << 63)
	handler := FileHandlerSetFileTTL(duration)
	err := handler(&fHandler)
	if err == nil {
		t.Fatal("FileHandlerSetFileTTL with negative duration should fail.")
	}
}

func testFileHandlerSetFileTTLSetNegativeDuration(t *testing.T, _ ...interface{}) {
	var fHandler fileHandler
	duration := time.Duration(-1)
	handler := FileHandlerSetFileTTL(duration)
	err := handler(&fHandler)
	if err == nil {
		t.Fatal("FileHandlerSetFileTTL with negative duration should fail.")
	}
}

func testReceiveFileNilFileHandler(t *testing.T, _ ...interface{}) {
	var handler *FileHandler
	_, err := handler.ReceiveFile()
	if err == nil {
		t.Fatal("Should not be possible to receive file with nil file handler.")
	}
}

func testReceiveFileUriAndFileNil(t *testing.T, _ ...interface{}) {
	handler, err := NewFileHandler(FileHandlerSetFileCertConstraint(OidEmail, "its@not.working"))
	if err != nil {
		t.Fatal("Failed to create publications file handler.")
	}
	_, err = handler.ReceiveFile()
	if err == nil {
		t.Fatal("Should not be possible to receive file with nil file or empty file uri.")
	}
}

func testFileTtlNilFileHandler(t *testing.T, _ ...interface{}) {
	var handler *FileHandler
	_, err := handler.FileTTL()
	if err == nil {
		t.Fatal("Should not be possible to get file TTL from nil file handler.")
	}
}

func testFileTtlOk(t *testing.T, _ ...interface{}) {
	handler, err := NewFileHandler(FileHandlerSetFileTTL(123456))
	if err != nil {
		t.Fatal("Failed to create publications file handler.")
	}
	val, err := handler.FileTTL()
	if err != nil {
		t.Fatal("Failed to get file TTL from file handler.")
	}
	if val != 123456 {
		t.Fatal("Expected TTl value 123456 but got ", val)
	}
}

func testPubFileCertificate(t *testing.T, _ ...interface{}) {

	var (
		testPubFile  = filepath.Join(testResourcePubDir, "ksi-publications.bin")
		testAggrResp = filepath.Join(testResourceTlvDir, "ok-sig-2014-07-01.1-aggr_response.tlv")
	)

	raw, err := ioutil.ReadFile(testAggrResp)
	if err != nil {
		t.Fatal("Failed to read tlv file: ", err)
	}

	resp := &pdu.AggregatorResp{}
	if err := resp.Decode(raw); err != nil {
		t.Fatal("Failed to decode tlv: ", err)
	}
	aggrResp, err := resp.AggregationResp()
	if err != nil {
		t.Fatal("Failed to extract aggregation response: ", err)
	}
	calAuthRec, err := aggrResp.CalendarAuthRec()
	if err != nil {
		t.Fatal("Failed to extract authentication record: ", err)
	}
	sigData, err := calAuthRec.SignatureData()
	if err != nil {
		t.Fatal("Failed to extract signature data: ", err)
	}
	certId, err := sigData.CertID()
	if err != nil {
		t.Fatal("Failed to extract certificate id: ", err)
	}

	pubFile, err := NewFile(FileFromFile(testPubFile))
	if err != nil {
		t.Fatal("Failed to create publications file: ", err)
	}
	certRec, err := pubFile.Certificate(certId)
	if err != nil {
		t.Fatal("Failed to extract certificate record: ", err)
	}
	if certRec == nil {
		t.Fatal("Must return valid certificate record.")
	}
}

func testPubFileCertificateIdNotPresent(t *testing.T, _ ...interface{}) {

	var (
		testPubFile = filepath.Join(testResourcePubDir, "ksi-publications.bin")
	)

	pubFile, err := NewFile(FileFromFile(testPubFile))
	if err != nil {
		t.Fatal("Failed to create publications file: ", err)
	}

	certRec, err := pubFile.Certificate([]byte{0})
	if err != nil {
		t.Fatal("Failed to extract certificate record: ", err)
	}
	if certRec != nil {
		t.Fatal("Must not return a certificate record.")
	}
}

func testGetCertificateFromNilFile(t *testing.T, _ ...interface{}) {
	var pubFile *File
	_, err := pubFile.Certificate([]byte{0})
	if err == nil {
		t.Fatal("Should not be possible to get certificate from nil file.")
	}
}

func testGetCertificateWithNilId(t *testing.T, _ ...interface{}) {
	var pubFile File
	_, err := pubFile.Certificate(nil)
	if err == nil {
		t.Fatal("Should not be possible to get certificate with nil ID.")
	}
}

func testGetCertificateWithNoId(t *testing.T, _ ...interface{}) {
	var pubFile File
	_, err := pubFile.Certificate([]byte{})
	if err == nil {
		t.Fatal("Should not be possible to get certificate with no ID.")
	}
}

func testGetCertificateFromNotInitializedPubFile(t *testing.T, _ ...interface{}) {
	var pubFile File
	val, err := pubFile.Certificate([]byte{0})
	if err != nil || val != nil {
		t.Fatal("Should get nil value and error, but got: ", val, err)
	}
}

func testPubFileVerifyRecord(t *testing.T, _ ...interface{}) {
	var (
		testPubFile  = filepath.Join(testResourcePubDir, "ksi-publications.bin")
		testAggrResp = filepath.Join(testResourceTlvDir, "ok-sig-2014-07-01.1-aggr_response.tlv")
	)

	raw, err := ioutil.ReadFile(testAggrResp)
	if err != nil {
		t.Fatal("Failed to read tlv file: ", err)
	}

	resp := &pdu.AggregatorResp{}
	if err := resp.Decode(raw); err != nil {
		t.Fatal("Failed to decode tlv: ", err)
	}
	aggrResp, err := resp.AggregationResp()
	if err != nil {
		t.Fatal("Failed to extract aggregation response: ", err)
	}
	calAuthRec, err := aggrResp.CalendarAuthRec()
	if err != nil {
		t.Fatal("Failed to extract authentication record: ", err)
	}

	pubFile, err := NewFile(FileFromFile(testPubFile))
	if err != nil {
		t.Fatal("Failed to create publications file: ", err)
	}
	if err := pubFile.VerifyRecord(calAuthRec); err != nil {
		t.Fatal("Failed to extract certificate record: ", err)
	}
}

func testVerifyNilPubRecord(t *testing.T, _ ...interface{}) {
	var (
		pubFile *File
		calAuth pdu.CalendarAuthRec
	)
	err := pubFile.VerifyRecord(&calAuth)
	if err == nil {
		t.Fatal("Should not be possible to verify nil publications file.")
	}
}

func testVerifyNilRecord(t *testing.T, _ ...interface{}) {
	var (
		pubFile File
	)
	err := pubFile.VerifyRecord(nil)
	if err == nil {
		t.Fatal("Should not be possible to verify nil record.")
	}
}

func testVerifyNotInitializedRecord(t *testing.T, _ ...interface{}) {
	var (
		pubFile File
		calAuth pdu.CalendarAuthRec
	)
	err := pubFile.VerifyRecord(&calAuth)
	if err == nil {
		t.Fatal("Should not be possible to verify nil record.")
	}
}

func testNewFileWithNilBuilder(t *testing.T, _ ...interface{}) {
	_, err := NewFile(nil)
	if err == nil {
		t.Fatal("Should not be possible to build publications file with nil builder.")
	}
}

func testFileFromFileWithNoFilePath(t *testing.T, _ ...interface{}) {
	tmp := &file{}
	bldr := FileFromFile("")
	err := bldr(tmp)
	if err == nil {
		t.Fatal("Should not be possible to create file with no file path.")
	}
}

func testFileFromFileWithNilFile(t *testing.T, _ ...interface{}) {
	bldr := FileFromFile("Some.kind.of.file")
	err := bldr(nil)
	if err == nil {
		t.Fatal("Should not be possible to create file with no base file.")
	}
}

func testFileFromFileWithNotExistingFile(t *testing.T, _ ...interface{}) {
	tmp := &file{}
	bldr := FileFromFile("Some.kind.of.file")
	err := bldr(tmp)
	if err == nil {
		t.Fatal("Should not be possible to create file with not existing file.")
	}
}

func testFileFromBytesWithNilBytes(t *testing.T, _ ...interface{}) {
	tmp := &file{}
	bldr := FileFromBytes(nil)
	err := bldr(tmp)
	if err == nil {
		t.Fatal("Should not be possible to create file with nil input bytes.")
	}
}

func testFileFromBytesWithEmptyByte(t *testing.T, _ ...interface{}) {
	tmp := &file{}
	bldr := FileFromBytes([]byte{})
	err := bldr(tmp)
	if err == nil {
		t.Fatal("Should not be possible to create file with no bytes.")
	}
}

func testFileFromBytesWithNilFile(t *testing.T, _ ...interface{}) {
	bldr := FileFromBytes([]byte{0x12, 0x14})
	err := bldr(nil)
	if err == nil {
		t.Fatal("Should not be possible to create file with no base file.")
	}
}

func testFileFromBytesWithInvalidHeaderBytes(t *testing.T, _ ...interface{}) {
	tmp := &file{}
	bldr := FileFromBytes([]byte{0x12, 0x14})
	err := bldr(tmp)
	if err == nil {
		t.Fatal("Should not be possible to create file with no base file.")
	}
}

func testFileFromBytesWithInvalidHeaderBytes2(t *testing.T, _ ...interface{}) {
	tmp := &file{}
	bldr := FileFromBytes([]byte{0x12, 0x14, 0x14, 0x14, 0x14, 0x14, 0x14, 0x14, 0x14, 0x14, 0x14, 0x14, 0x14, 0x14, 0x14, 0x14, 0x14, 0x14})
	err := bldr(tmp)
	if err == nil {
		t.Fatal("Should not be possible to create file with invalid publications file header bytes.")
	}
}

func testFileFromBytesOnlyHeader(t *testing.T, _ ...interface{}) {
	tmp := &file{}
	bldr := FileFromBytes([]byte(pubFileHeaderID))
	err := bldr(tmp)
	if err == nil {
		t.Fatal("Should not be possible to create file from just header.")
	}
	if errors.KsiErr(err).Code() != errors.KsiInvalidFormatError {
		t.Fatal("Unexpected error returned: ", err)
	}
}

func testFileFromBytesWithInvalidFileBytes2(t *testing.T, _ ...interface{}) {
	tmp := &file{}
	pubBytes := []byte("KSIPUBLF")
	dataBytes := []byte{0x14, 0x14, 0x14, 0x14, 0x14, 0x14, 0x14, 0x14, 0x14}
	pubBytes = append(pubBytes, dataBytes...)
	bldr := FileFromBytes(pubBytes)
	err := bldr(tmp)
	if err == nil {
		t.Fatal("Should not be possible to create file with invalid publications file bytes.")
	}
}

func testFileFromReaderWithNilReader(t *testing.T, _ ...interface{}) {
	tmp := &file{}
	bldr := FileFromReader(nil)
	err := bldr(tmp)
	if err == nil {
		t.Fatal("Should not be possible to create file with nil reader.")
	}
}

func testFileFromReaderWithNilFile(t *testing.T, _ ...interface{}) {
	var testPubFile = filepath.Join(testResourcePubDir, "publications.bin")
	reader, err := os.Open(testPubFile)
	if err != nil {
		t.Fatal("Failed to get publications file reader: ", err)
	}

	bldr := FileFromReader(reader)
	err = bldr(nil)
	if err == nil {
		t.Fatal("Should not be possible to create file with nil reader.")
	}
}

func testFileFromUrlWithEmptyUrl(t *testing.T, _ ...interface{}) {
	tmp := &file{}
	bldr := FileFromURL("")
	err := bldr(tmp)
	if err == nil {
		t.Fatal("Should not be possible to create file with nil reader.")
	}
}

func testFileFromUrlWithNilFile(t *testing.T, _ ...interface{}) {
	bldr := FileFromURL("some.url.kind.of.url")
	err := bldr(nil)
	if err == nil {
		t.Fatal("Should not be possible to create file with nil reader.")
	}
}

func testFileFromUrlWithInvalidUrlFormat(t *testing.T, _ ...interface{}) {
	tmp := &file{}
	bldr := FileFromURL("some.url.kind.of.url")
	err := bldr(tmp)
	if err == nil {
		t.Fatal("Should not be possible to create file with invalid url format.")
	}
}

func testFileFromUrlWithInvalidUrl(t *testing.T, _ ...interface{}) {
	tmp := &file{}
	bldr := FileFromURL("http://some.url.kind.of.url")
	err := bldr(tmp)
	if err == nil {
		t.Fatal("Should not be possible to create file with invalid url.")
	}
}

func testCertificateToStringWitInvalidInput(t *testing.T, _ ...interface{}) {
	certString := CertificateToString(nil)
	if certString != "nil" {
		t.Fatal("Unexpected nil certificate string: ", certString)
	}
}

func testCertToString(t *testing.T, _ ...interface{}) {
	certs, _, err := getX509Certificates(1)
	if err != nil {
		t.Fatal("Failed to get certificate: ", err)
	}
	certString := CertificateToString(certs[0])

	var subString = "PKI Certificate"
	if !strings.Contains(certString, subString) {
		t.Fatal(fmt.Sprintf("Did not find expected substring (%s) from certificate string: (%s)", subString, certString))
	}
	subString = "Issued to:"
	if !strings.Contains(certString, subString) {
		t.Fatal(fmt.Sprintf("Did not find expected substring (%s) from certificate string: (%s)", subString, certString))
	}
	subString = "Issued by:"
	if !strings.Contains(certString, subString) {
		t.Fatal(fmt.Sprintf("Did not find expected substring (%s) from certificate string: (%s)", subString, certString))
	}
	subString = "Valid from:"
	if !strings.Contains(certString, subString) {
		t.Fatal(fmt.Sprintf("Did not find expected substring (%s) from certificate string: (%s)", subString, certString))
	}
	subString = "Serial Number:"
	if !strings.Contains(certString, subString) {
		t.Fatal(fmt.Sprintf("Did not find expected substring (%s) from certificate string: (%s)", subString, certString))
	}
}

func testCertChainToStringWithNilInput(t *testing.T, _ ...interface{}) {
	certChainString := CertChainToString(nil)
	if certChainString != "nil" {
		t.Fatal("Unexpected certificate chain string with nil chain: ", certChainString)
	}
}

func testCertChainToStringWithEmptyListInput(t *testing.T, _ ...interface{}) {
	var certChain []*x509.Certificate
	certChainString := CertChainToString(certChain)
	if certChainString != "nil" {
		t.Fatal("Unexpected certificate chain string with empty list: ", certChainString)
	}
}

func testOneCertInChainToString(t *testing.T, _ ...interface{}) {
	certs, _, err := getX509Certificates(1)
	if err != nil {
		t.Fatal("Failed to get certificate: ", err)
	}
	certChainString := CertChainToString(certs)
	if !strings.Contains(certChainString, "Certificate(0)") {
		t.Fatal(fmt.Sprintf("Did not find expected substring (%s) from certificate.String: (%s)", "Certificate(0)", certChainString))
	}
	if strings.Contains(certChainString, "Certificate(1)") {
		t.Fatal(fmt.Sprintf("Found unexpected substring (%s) from certificate.String: (%s)", "Certificate(0)", certChainString))
	}
}

func testMultipleCertInChainToString(t *testing.T, _ ...interface{}) {
	certs, count, err := getX509Certificates(2)
	if err != nil {
		t.Fatal("Failed to get certificates: ", err)
	}
	if count != 2 {
		t.Fatal("Failed to get 2 certificates from publications file.")
	}
	certChainString := CertChainToString(certs)
	if !strings.Contains(certChainString, "Certificate(0)") {
		t.Fatal(fmt.Sprintf("Did not find expected substring (%s) from certificate chain (%s): ", "Certificate(0)", certChainString))
	}
	if !strings.Contains(certChainString, "Certificate(1)") {
		t.Fatal(fmt.Sprintf("Did not find expected substring (%s) from certificate chain (%s): ", "Certificate(1)", certChainString))
	}
	if strings.Contains(certChainString, "Certificate(2)") {
		t.Fatal(fmt.Sprintf("Found unexpected substring (%s) from certificate chain (%s) : ", "Certificate(2)", certChainString))
	}
}

func getX509Certificates(limit int) ([]*x509.Certificate, int, error) {
	var (
		certChain   []*x509.Certificate
		testPubFile = filepath.Join(testResourcePubDir, "publications.bin")
		cert        *x509.Certificate
		count       int
	)
	reader, err := os.Open(testPubFile)
	if err != nil {
		return nil, 0, err
	}

	file, err := NewFile(FileFromReader(reader))
	if err != nil {
		return nil, 0, err
	}
	certs := file.certRecs
	if certs == nil {
		return nil, 0, errors.New(errors.KsiInvalidArgumentError).AppendMessage("No certificates in publications file.")
	}
	for _, rec := range *certs {
		if rec == nil {
			return nil, 0, errors.New(errors.KsiInvalidArgumentError).AppendMessage("Certificates record is nil.")
		}
		certBytes, err := rec.Cert()
		if err != nil {
			return nil, 0, err
		}

		cert, err = x509.ParseCertificate(certBytes)
		if err != nil {
			return nil, 0, err
		}
		certChain = append(certChain, cert)
		count += 1
		if count >= limit {
			break
		}
	}
	return certChain, count, nil
}
