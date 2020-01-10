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

package treebuilder

import (
	"testing"

	"github.com/guardtime/goksi/log"
	"github.com/guardtime/goksi/net"
	"github.com/guardtime/goksi/service"
	"github.com/guardtime/goksi/signature"
	"github.com/guardtime/goksi/test"
	"github.com/guardtime/goksi/test/sysconf"
	"github.com/guardtime/goksi/test/utils"
)

func TestSysTreeBuilderTcp(t *testing.T) {

	logger, defFunc, err := test.InitLogger(t, testLogDir, log.DEBUG, t.Name())
	if err != nil {
		t.Fatal("Failed to initialize logger: ", err)
	}
	defer defFunc()

	// Check if system test config is present and load it.
	cfg := utils.LoadConfigFile(t, testConfFile)

	treeBuilderTestRunner(t, logger, cfg.Schema.Tcp, cfg)
}

func TestSysTreeBuilderHttp(t *testing.T) {

	logger, defFunc, err := test.InitLogger(t, testLogDir, log.DEBUG, t.Name())
	if err != nil {
		t.Fatal("Failed to initialize logger: ", err)
	}
	defer defFunc()

	// Check if system test config is present and load it.
	cfg := utils.LoadConfigFile(t, testConfFile)

	treeBuilderTestRunner(t, logger, cfg.Schema.Http, cfg)
}

func treeBuilderTestRunner(t *testing.T, logger log.Logger, schema string, cfg *sysconf.Configuration) {
	// Apply logger.
	log.SetLogger(logger)

	// Create ksi Context.
	nc, err := net.NewClient(cfg.Aggregator.BuildURI(schema), cfg.Aggregator.User, cfg.Aggregator.Pass)
	if err != nil {
		t.Fatal("Failed to initialize network client: ", err)
	}

	test.Suite{
		{Func: testTreeBuilderCreateSignatures},
	}.Runner(t, nc)
}

const (
	tbSysTestOptNet = iota
)

func testTreeBuilderCreateSignatures(t *testing.T, opt ...interface{}) {

	tree, err := New()
	if err != nil {
		t.Fatal("Failed to create tree builder: ", err)
	}

	resource := []struct {
		h string
		l byte
	}{
		{"0109A9FE430803D8984273324CF462E40A875D483DE6DD0D86BC6DFF4D27C9D853", 0},
		{"01BEC84E1F95F729F4482338E781341B1615F5B0A882231AE6C0FAEF7D0E6121D5", 0},
		{"01C734EEFE09B6B717B0BA6997CA634ADB93E2F227BEB785BBB8B4472651084509", 0},
		{"01B0CF0A7E6E0420D27CDFA11BDFAC4AA9BC777AE4D6C0211816BCB91DE7C920AD", 0},
		{"01BB95E9B09E7F6BC95533D805739E26510A05F9788A86C7F81BA8F81E0E6C43DA", 0},
		{"017943B1F4521425E11B461A76B9F46B08980FFD04CD080497D55A8C063E6DCDF7", 0},
		{"0123C4ADE3B64A45694088FD427399D3C2EC120BB0D5DF8C5212B1562F8D821902", 0},
		{"01A360BBAE9A0215196449971E57EB91B6C9B39725408324BE325D40C254353FBF", 0},
		{"010347A3E6C16B743473CECD6CAAD813464F8B8BD03829F649DD2FD3BA60D02ECD", 0},
		{"0178C63034846B2C6E67218FBD9F583330442A99D7165492FA5732024F27FE7FFA", 0},
		{"010579A776558FE48456A30E56B9BF58E595FF7D4DF049275C0D0ED5B361E91382", 0},
	}

	for i, d := range resource {
		if err := tree.AddNode(utils.StringToBin(d.h),
			InputHashOptionLevel(d.l), InputHashOptionUserContext(d.h)); err != nil {
			t.Fatal("Failed to add tree node: ", err)
		}

		p, err := tree.Count()
		if err != nil {
			t.Fatal("Failed to get tree count: ", err)
		}

		if i != p-1 {
			t.Error("Position mismatch.")
		}
	}

	signer, err := service.NewSigner(service.OptNetClient(opt[tbSysTestOptNet].(net.Client)))
	if err != nil {
		t.Fatal("Failed create signer: ", err)
	}

	rootHsh, rootLvl, err := tree.Aggregate()
	if err != nil {
		t.Fatal("Failed to close tree: ", err)
	}
	rootSig, err := signer.Sign(rootHsh, service.SignOptionLevel(rootLvl))
	if err != nil {
		t.Fatal("Failed to receive response: ", err)
	}

	leafs, err := tree.Leafs()
	if err != nil {
		t.Fatal("Failed to get tree leafs: ", err)
	}
	for _, l := range leafs {
		usrCtx, err := l.UserCtx()
		if err != nil {
			t.Fatal("Failed to get leaf user context: ", err)
		}
		if _, ok := usrCtx.(string); !ok {
			t.Fatal("Wrong user context returner: ", usrCtx)
		}

		aggrChain, err := l.AggregationChain()
		if err != nil {
			t.Fatal("Failed to get leaf aggregation hash chain: ", err)
		}

		_, err = signature.New(signature.BuildWithAggrChain(rootSig, aggrChain))
		if err != nil {
			t.Fatal("Failed to build signature: ", err)
		}
	}
}
