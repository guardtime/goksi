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
	"testing"

	"github.com/guardtime/goksi/hash"
	"github.com/guardtime/goksi/log"
	"github.com/guardtime/goksi/net"
	"github.com/guardtime/goksi/pdu"
	"github.com/guardtime/goksi/service"
	"github.com/guardtime/goksi/test"
	"github.com/guardtime/goksi/test/sysconf"
	"github.com/guardtime/goksi/test/utils"
	"github.com/guardtime/goksi/treebuilder"
)

func TestSysBlocksignerTcp(t *testing.T) {

	logger, defFunc, err := test.InitLogger(t, testLogDir, log.DEBUG, t.Name())
	if err != nil {
		t.Fatal("Failed to initialize logger: ", err)
	}
	defer defFunc()

	// Check if system test config is present and load it.
	cfg := utils.LoadConfigFile(t, testConfFile)

	blocksignerTestRunner(t, logger, cfg.Schema.Tcp, cfg)
}

func TestSysBlocksignerHttp(t *testing.T) {

	logger, defFunc, err := test.InitLogger(t, testLogDir, log.DEBUG, t.Name())
	if err != nil {
		t.Fatal("Failed to initialize logger: ", err)
	}
	defer defFunc()

	// Check if system test config is present and load it.
	cfg := utils.LoadConfigFile(t, testConfFile)

	blocksignerTestRunner(t, logger, cfg.Schema.Http, cfg)
}

func blocksignerTestRunner(t *testing.T, logger log.Logger, schema string, cfg *sysconf.Configuration) {
	// Apply logger.
	log.SetLogger(logger)

	// Create ksi Context.
	nc, err := net.NewClient(cfg.Aggregator.BuildURI(schema), cfg.Aggregator.User, cfg.Aggregator.Pass)
	if err != nil {
		t.Fatal("Failed to initialize network client: ", err)
	}

	test.Suite{
		{Func: testBlocksignerWithNoValidSigningService},
		{Func: testBlocksignerAddDocumentHash},
		{Func: testBlocksignerAddDocumentHashWithMasking},
		{Func: testBlocksignerAddDocumentHashAndMetaWithMasking},
		{Func: testBlocksignerAddDocumentHashWithLevel},
	}.Runner(t, nc, cfg)
}

const (
	bsSysTestOptNet = iota
	bsSysTestOptCfg
)

func testBlocksignerWithNoValidSigningService(t *testing.T, opt ...interface{}) {
	var (
		testHash     = utils.StringToBin("01004313f53502a18fe4a31ae0197ab09d4597042942a3a54e846fa01ff5479fa2")
		testRecCount = 10
		cfg          = opt[bsSysTestOptCfg].(*sysconf.Configuration)
	)

	networkClient, err := net.NewClient(cfg.Extender.BuildURI(cfg.Schema.Http), cfg.Extender.User, cfg.Extender.Pass)
	if err != nil {
		t.Fatal("Failed to create new signing client: ", err)
	}

	signer, err := service.NewSigner(service.OptNetClient(networkClient))
	if err != nil {
		t.Fatal("Failed to create signer: ", err)
	}
	block, err := New(signer)
	if err != nil {
		t.Fatal("Failed to create block signer: ", err)
	}
	for i := 0; i < testRecCount; i++ {
		if err := block.AddNode(testHash); err != nil {
			t.Fatal("Failed to add leaf to block: ", err)
		}
	}

	if _, err = block.Sign(); err == nil {
		t.Fatal("Should not be possible to sign with non valid signings service.")
	}
}

func testBlocksignerAddDocumentHash(t *testing.T, opt ...interface{}) {

	var (
		testHash     = utils.StringToBin("01004313f53502a18fe4a31ae0197ab09d4597042942a3a54e846fa01ff5479fa2")
		testRecCount = 10
	)

	signer, err := service.NewSigner(service.OptNetClient(opt[bsSysTestOptNet].(net.Client)))
	if err != nil {
		t.Fatal("Failed to create signer: ", err)
	}
	block, err := New(signer)
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

func testBlocksignerAddDocumentHashWithMasking(t *testing.T, opt ...interface{}) {

	var (
		testHash     = utils.StringToBin("01004313f53502a18fe4a31ae0197ab09d4597042942a3a54e846fa01ff5479fa2")
		testIV       = []byte{0x01, 0x02, 0xff, 0xfe, 0xaa, 0xa9, 0xf1, 0x55, 0x23, 0x51, 0xa1}
		testRecCount = 10
	)

	signer, err := service.NewSigner(service.OptNetClient(opt[bsSysTestOptNet].(net.Client)))
	if err != nil {
		t.Fatal("Failed to create signer: ", err)
	}
	block, err := New(signer,
		treebuilder.TreeOptMaskingWithPreviousLeaf(testIV, hash.Default.ZeroImprint()),
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

func testBlocksignerAddDocumentHashAndMetaWithMasking(t *testing.T, opt ...interface{}) {

	var (
		testHash = utils.StringToBin("01004313f53502a18fe4a31ae0197ab09d4597042942a3a54e846fa01ff5479fa2")
		testIV   = []byte{0x01, 0x02, 0xff, 0xfe, 0xaa, 0xa9, 0xf1, 0x55, 0x23, 0x51, 0xa1}
		names    = []string{"Oliver", "Olivia", "Amelia", "Jack", "Jessica", "Charlie", "Sarah"}
	)

	signer, err := service.NewSigner(service.OptNetClient(opt[bsSysTestOptNet].(net.Client)))
	if err != nil {
		t.Fatal("Failed to create signer: ", err)
	}
	block, err := New(signer,
		treebuilder.TreeOptMaskingWithPreviousLeaf(testIV, hash.Default.ZeroImprint()),
	)
	if err != nil {
		t.Fatal("Failed to create block signer: ", err)
	}
	for i, user := range names {
		md, err := pdu.NewMetaData(user, pdu.MetaDataSequenceNr(uint64(i)))
		if err != nil {
			t.Fatal("Failed to create metadata: ", err)
		}

		err = block.AddNode(testHash,
			treebuilder.InputHashOptionMetadata(md),
			treebuilder.InputHashOptionUserContext(user),
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

	sigs, ctxs, err := block.Signatures()
	if err != nil {
		t.Fatal("Failed to extract block leaf signatures: ", err)
	}
	if len(sigs) != len(ctxs) {
		t.Fatal("Data count mismatch.")
	}
	if len(names) != len(sigs) {
		t.Fatal("Signature count mismatch.")
	}

	for i, sig := range sigs {
		ids, err := sig.AggregationHashChainIdentity()
		if err != nil {
			t.Fatal("Failed to extract signature aggregation hash chain identity: ", err)
		}

		user, err := ids[0].ClientID()
		if err != nil {
			t.Fatal("Failed to extract client id: ", err)
		}
		seqnr, err := ids[0].SequenceNr()
		if err != nil {
			t.Fatal("Failed to extract sequence number: ", err)
		}

		if user != names[i] || seqnr != uint64(i) {
			t.Fatal("Identity values mismatch")
		}
	}
}

func testBlocksignerAddDocumentHashWithLevel(t *testing.T, opt ...interface{}) {

	var (
		testHash = []string{
			"019d5238eb20876f7570441bd01fdc2fbea45ba2c37ed708d909cd90eb4544fd46",
			"013b810aa5efffa207621656e60566016ff6e604bc5ddd8ee896f4b3e31d66b12b",
			"012df8a263c33af0aa1b0c9443570323a870f13c96eecbe749c35d069697b54e96",
		}
	)

	signer, err := service.NewSigner(service.OptNetClient(opt[bsSysTestOptNet].(net.Client)))
	if err != nil {
		t.Fatal("Failed to create signer: ", err)
	}
	block, err := New(signer)
	if err != nil {
		t.Fatal("Failed to create block signer: ", err)
	}
	for i, h := range testHash {
		if err := block.AddNode(utils.StringToBin(h), treebuilder.InputHashOptionLevel(byte(i))); err != nil {
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
}
