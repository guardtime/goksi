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

package blocksigner

import (
	"path/filepath"
	"testing"

	"github.com/guardtime/goksi/hash"
	"github.com/guardtime/goksi/log"
	"github.com/guardtime/goksi/pdu"
	"github.com/guardtime/goksi/service"
	"github.com/guardtime/goksi/test"
	"github.com/guardtime/goksi/test/utils"
	"github.com/guardtime/goksi/test/utils/mock"
	"github.com/guardtime/goksi/treebuilder"
)

var (
	testRoot           = filepath.Join("..", "test")
	testLogDir         = filepath.Join(testRoot, "out")
	testResourceDir    = filepath.Join(testRoot, "resource")
	testResourceTlvDir = filepath.Join(testResourceDir, "tlv")
	testConfFile       = filepath.Join(testRoot, "systest.conf.json")
)

func TestUnitBlocksigner(t *testing.T) {
	logger, defFunc, err := test.InitLogger(t, testLogDir, log.DEBUG, t.Name())
	if err != nil {
		t.Fatal("Failed to initialize logger: ", err)
	}
	defer defFunc()
	// Apply logger.
	log.SetLogger(logger)

	test.Suite{
		{Func: testNewBlocksignerWithNilSigner},
		{Func: testNewBlocksignerWithNoOptions},
		{Func: testNewBlocksignerWithEmptyOptionsList},
		{Func: testSignWithNilSigningService},
		{Func: testSignWithNilReceiver},
		{Func: testSignEmptyBlockSigner},
		{Func: testGetSignatureFromNilBlocksigner},
		{Func: testGetSignatureFromNotSignedTree},
		{Func: testBlocksignerWithMetadata},
		{Func: testBlocksignerMaskingWithPrevRecFirstBlock},
		{Func: testBlocksignerMaskingWithPrevRecFirstBlockAndMetadata},
	}.Runner(t)
}

func testNewBlocksignerWithNilSigner(t *testing.T, _ ...interface{}) {
	_, err := New(nil)
	if err == nil {
		t.Fatal("Should not be possible to create blocksigner with no signing service.")
	}
}

func testNewBlocksignerWithNoOptions(t *testing.T, _ ...interface{}) {
	var testAggrResp = filepath.Join(testResourceTlvDir, "test_meta_data_response.tlv")
	srv, err := service.NewSigner(service.OptNetClient(mock.NewFileReaderClient(testAggrResp, "anon", "anon")))
	if err != nil {
		t.Fatal("Failed to create signer: ", err)
	}

	if _, err = New(srv, nil); err == nil {
		t.Fatal("Should not be possible to create blocksigner with nil pointer options.")
	}
}

func testNewBlocksignerWithEmptyOptionsList(t *testing.T, _ ...interface{}) {
	var (
		testAggrResp = filepath.Join(testResourceTlvDir, "test_meta_data_response.tlv")
		opts         treebuilder.TreeOpt
	)
	srv, err := service.NewSigner(service.OptNetClient(mock.NewFileReaderClient(testAggrResp, "anon", "anon")))
	if err != nil {
		t.Fatal("Failed to create signer: ", err)
	}

	if _, err = New(srv, opts); err == nil {
		t.Fatal("Should be possible to create blocksigner with empty options list.")
	}
}

func testSignWithNilSigningService(t *testing.T, _ ...interface{}) {
	var blockSigner Blocksigner

	if _, err := blockSigner.Sign(); err == nil {
		t.Fatal("Should not be possible to sign with nil signer.")
	}
}

func testSignWithNilReceiver(t *testing.T, _ ...interface{}) {
	var blockSigner *Blocksigner

	if _, err := blockSigner.Sign(); err == nil {
		t.Fatal("Should not be possible to sign with nil block signer.")
	}
}

func testSignEmptyBlockSigner(t *testing.T, _ ...interface{}) {
	var (
		testAggrResp = filepath.Join(testResourceTlvDir, "test_meta_data_response.tlv")
	)
	srv, err := service.NewSigner(service.OptNetClient(mock.NewFileReaderClient(testAggrResp, "anon", "anon")))
	if err != nil {
		t.Fatal("Failed to create signer: ", err)
	}

	blockSigner, err := New(srv)
	if err != nil {
		t.Fatal("Failed to create block signer.")
	}

	if _, err = blockSigner.Sign(); err == nil {
		t.Fatal("Should not be possible to sign empty block signer.")
	}
}

func testGetSignatureFromNilBlocksigner(t *testing.T, _ ...interface{}) {
	var blockSigner *Blocksigner
	if _, _, err := blockSigner.Signatures(); err == nil {
		t.Fatal("Should not be possible to get signatures from nil block signer.")
	}
}

func testGetSignatureFromNotSignedTree(t *testing.T, _ ...interface{}) {
	var (
		testAggrResp = filepath.Join(testResourceTlvDir, "test_meta_data_response.tlv")
	)
	srv, err := service.NewSigner(service.OptNetClient(mock.NewFileReaderClient(testAggrResp, "anon", "anon")))
	if err != nil {
		t.Fatal("Failed to create signer: ", err)
	}

	blockSigner, err := New(srv)
	if err != nil {
		t.Fatal("Failed to create block signer.")
	}

	if _, _, err = blockSigner.Signatures(); err == nil {
		t.Fatal("Should not be possible to get signatures from not signed block signer.")
	}
}

func testBlocksignerWithMetadata(t *testing.T, _ ...interface{}) {

	var (
		testAggrResp = filepath.Join(testResourceTlvDir, "test_meta_data_response.tlv")
		testData     = "LAPTOP"
		testClientId = []string{"Alice", "Bob", "Claire"}
		testAlgo     = hash.SHA2_256
	)

	hsr, err := testAlgo.New()
	if err != nil {
		t.Fatal("Failed to create data hasher: ", err)
	}
	if _, err = hsr.Write([]byte(testData)); err != nil {
		t.Fatal("Failed to write to hasher: ", err)
	}
	dataHsh, err := hsr.Imprint()
	if err != nil {
		t.Fatal("Failed to extract imprint: ", err)
	}

	srv, err := service.NewSigner(service.OptNetClient(mock.NewFileReaderClient(testAggrResp, "anon", "anon")))
	if err != nil {
		t.Fatal("Failed to create signer: ", err)
	}
	block, err := New(srv, treebuilder.TreeOptAlgorithm(testAlgo))
	if err != nil {
		t.Fatal("Failed to create block signer: ", err)
	}
	for _, cid := range testClientId {
		md, err := pdu.NewMetaData(cid)
		if err != nil {
			t.Fatal("Failed to create metadata: ", err)
		}
		err = block.AddNode(dataHsh,
			treebuilder.InputHashOptionMetadata(md),
			treebuilder.InputHashOptionUserContext(cid),
		)
		if err != nil {
			t.Fatal("Failed to add leaf to block: ", err)
		}
	}

	rootSig, err := block.Sign()
	if err != nil {
		t.Fatal("Failed to sign the block: ", err)
	}
	if rootSig == nil {
		t.Error("Root signature must be returned.")
	}

	rootHsh, _, err := block.Aggregate()
	if err != nil {
		t.Fatal("Failed to close tree: ", err)
	}
	rootDoc, err := rootSig.DocumentHash()
	if err != nil {
		t.Fatal("Failed to extract root signature document hash: ", err)
	}
	if !hash.Equal(rootHsh, rootDoc) {
		t.Fatal("Root hash mismatch.")
	}

	sigs, ctxs, err := block.Signatures()
	if err != nil {
		t.Fatal("Failed to extract block leaf signatures: ", err)
	}
	if len(sigs) != len(ctxs) {
		t.Fatal("Data count mismatch.")
	}
	if len(testClientId) != len(sigs) {
		t.Fatal("Signature count mismatch.")
	}
}

func testBlocksignerMaskingWithPrevRecFirstBlock(t *testing.T, _ ...interface{}) {

	var (
		testAggrResp = filepath.Join(testResourceTlvDir, "test_masking_response.tlv")
		testHash     = utils.StringToBin("01004313f53502a18fe4a31ae0197ab09d4597042942a3a54e846fa01ff5479fa2")
		testIV       = []byte{0x01, 0x02, 0xff, 0xfe, 0xaa, 0xa9, 0xf1, 0x55, 0x23, 0x51, 0xa1}
		testRecCount = 101
		testAlgo     = hash.SHA2_256
	)

	srv, err := service.NewSigner(service.OptNetClient(mock.NewFileReaderClient(testAggrResp, "anon", "anon")))
	if err != nil {
		t.Fatal("Failed to create signer: ", err)
	}
	block, err := New(srv,
		treebuilder.TreeOptAlgorithm(testAlgo),
		treebuilder.TreeOptMaskingWithPreviousLeaf(testIV, testAlgo.ZeroImprint()),
	)
	if err != nil {
		t.Fatal("Failed to create block signer: ", err)
	}
	for i := 0; i < testRecCount; i++ {
		if err := block.AddNode(testHash); err != nil {
			t.Fatal("Failed to add leaf to block: ", err)
		}
	}

	rootSig, err := block.Sign()
	if err != nil {
		t.Fatal("Failed to sign the block: ", err)
	}
	if rootSig == nil {
		t.Error("Root signature must be returned.")
	}

	sigs, ctxs, err := block.Signatures()
	if err != nil {
		t.Fatal("Failed to extract block leaf signatures: ", err)
	}
	if len(sigs) != len(ctxs) {
		t.Fatal("Data count mismatch.")
	}
	if testRecCount != len(sigs) {
		t.Fatal("Signature count mismatch.")
	}
}

func testBlocksignerMaskingWithPrevRecFirstBlockAndMetadata(t *testing.T, _ ...interface{}) {

	var (
		testAggrResp = filepath.Join(testResourceTlvDir, "test_meta_data_masking.tlv")
		testHash     = utils.StringToBin("01004313f53502a18fe4a31ae0197ab09d4597042942a3a54e846fa01ff5479fa2")
		testIV       = []byte{0x01, 0x02, 0xff, 0xfe, 0xaa, 0xa9, 0xf1, 0x55, 0x23, 0x51, 0xa1}
		testRecCount = 10
		testAlgo     = hash.SHA2_256
	)

	srv, err := service.NewSigner(service.OptNetClient(mock.NewFileReaderClient(testAggrResp, "anon", "anon")))
	if err != nil {
		t.Fatal("Failed to create signer: ", err)
	}
	block, err := New(srv,
		treebuilder.TreeOptAlgorithm(testAlgo),
		treebuilder.TreeOptMaskingWithPreviousLeaf(testIV, testAlgo.ZeroImprint()),
	)
	if err != nil {
		t.Fatal("Failed to create block signer: ", err)
	}

	md, err := pdu.NewMetaData("Anon")
	if err != nil {
		t.Fatal("Failed to create metadata: ", err)
	}
	for i := 0; i < testRecCount; i++ {
		if err := block.AddNode(testHash, treebuilder.InputHashOptionMetadata(md)); err != nil {
			t.Fatal("Failed to add leaf to block: ", err)
		}
	}

	rootSig, err := block.Sign()
	if err != nil {
		t.Fatal("Failed to sign the block: ", err)
	}
	if rootSig == nil {
		t.Error("Root signature must be returned.")
	}

	sigs, ctxs, err := block.Signatures()
	if err != nil {
		t.Fatal("Failed to extract block leaf signatures: ", err)
	}
	if len(sigs) != len(ctxs) {
		t.Fatal("Data count mismatch.")
	}
	if testRecCount != len(sigs) {
		t.Fatal("Signature count mismatch.")
	}
}
