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

/*
var (
	testRoot     = filepath.Join("..", "..", "test")
	testConfFile = filepath.Join(testRoot, "systest.conf.json")
	testLogDir   = filepath.Join(testRoot, "out")
	//testResourceDir = filepath.Join(testRoot, "resource")
	//testSignatureDir = filepath.Join(testResourceDir, "signature")
)

func TestHaHTTP(t *testing.T) {

	logger, defFunc, err := test.InitLogger(t, testLogDir, log.DEBUG, t.Name())
	if err != nil {
		t.Fatal("Failed to initialize logger: ", err)
	}
	defer defFunc()

	cfg, err := sysconf.New(testConfFile)
	if err != nil {
		t.Fatal("Failed to load configuration: ", err)
	}

	haTestRunner(t, logger, cfg, cfg.Schema.Http)
}

func TestHaTCP(t *testing.T) {

	logger, defFunc, err := test.InitLogger(t, testLogDir, log.DEBUG, t.Name())
	if err != nil {
		t.Fatal("Failed to initialize logger: ", err)
	}
	defer defFunc()

	cfg, err := sysconf.New(testConfFile)
	if err != nil {
		t.Fatal("Failed to load configuration: ", err)
	}

	haTestRunner(t, logger, cfg, cfg.Schema.Tcp)
}

func haTestRunner(t *testing.T, logger log.Interface, cfg *sysconf.Configuration, schema string) {
	// Apply logger.
	log.SetLogger(logger)

	test.Suite{
		{"haSigner", haSigner},
		//{"haSignerConfigRcv", haSignerConfigRcv},
		{"haExtender", haExtender},
		//{"haExtenderConfigRcv", haExtenderConfigRcv},
	}.Runner(t, schema, cfg)

}

const (
	haTestOptSchema = iota
	haTestOptConf
)

func haSigner(t *testing.T, opt ...interface{}) {
	var (
		testSchema = opt[haTestOptSchema].(string)
		testCfg    = opt[haTestOptConf].(*sysconf.Configuration)

		testImprint = hash.Imprint{0x01,
			0xc4, 0xbb, 0xcb, 0x1f, 0xbe, 0xc9, 0x9d, 0x65,
			0xbf, 0x59, 0xd8, 0x5c, 0x8c, 0xb6, 0x2e, 0xe2,
			0xdb, 0x96, 0x3f, 0x0f, 0xe1, 0x06, 0xf4, 0x83,
			0xd9, 0xaf, 0xa7, 0x3b, 0xd4, 0xe3, 0x9a, 0x8a,
		}
	)

	ha, err := New()
	if err != nil {
		t.Fatal("Failed to create HA service: ", err)
	}

	for _, srv := range testCfg.highAvailabilityService.Aggregator {
		client, err := net.NewClient(srv.BuildURI(testSchema), srv.User, srv.Pass)
		if err != nil {
			t.Fatal("Failed create network client: ", err)
		}

		sigSrv, err := service.NewService(service.OptNetClient(client))
		if err != nil {
			t.Fatal("Failed create service: ", err)
		}

		if err := ha.addSubService(sigSrv); err != nil {
			t.Fatal("Failed to add HA sub-service: ", err)
		}
	}

	aggrReq, err := pdu.NewAggregationReq(testImprint)
	if err != nil {
		t.Fatal("Failed to create aggregation request: ", err)
	}
	req, err := service.newRequest(service.AggregatorRequest(aggrReq))
	if err != nil {
		t.Fatal("Fails to add signer to service request: ", err)
	}

	resp, err := ha.Send(req)
	if err != nil {
		t.Fatal("Failed to receive response: ", err)
	}

	aggrResp, err := resp.aggregatorResp()
	if err != nil {
		t.Fatal("Failed to get aggregator response: ", err)
	}
	if aggrResp == nil {
		t.Fatal("No response returned.")
	}
}
*/

/*
func haSignerConfigRcv(t *testing.T, opt ...interface{}) {
	var (
		testSchema = opt[haTestOptSchema].(string)
		testCfg    = opt[haTestOptConf].(*sysconf.Configuration)
	)

	ha, err := NewHighAvailabilityService()
	if err != nil {
		t.Fatal("Failed to create HA signer: ", err)
	}

	for _, srv := range testCfg.highAvailabilityService.Aggregator {
		client, err := net.NewClient(srv.BuildURI(testSchema), srv.User, srv.Pass)
		if err != nil {
			t.Fatal("Failed create network client: ", err)
		}

		signer, err := NewSigner(ServiceOptNetClient(client))
		if err != nil {
			t.Fatal("Failed create signer: ", err)
		}

		if err := ha.addSubService(signer); err != nil {
			t.Fatal("Fails to add signer to HA service: ", err)
		}

	}

	cfg, err := ha.ConfigRcv()
	if err != nil {
		t.Fatal("Failed to receive response: ", err)
	}
	if cfg == nil {
		t.Fatal(fmt.Sprintf("Expected response type mismatch."))
	}
}
*/

/*
func haExtender(t *testing.T, opt ...interface{}) {
	var (
		testSchema   = opt[haTestOptSchema].(string)
		testCfg      = opt[haTestOptConf].(*sysconf.Configuration)
		testFromTime = time.Unix(1529020000, 0)
		testToTime   = time.Unix(1529020800, 0) // Publication time for 15 June 2018
	)

	ha, err := New()
	if err != nil {
		t.Fatal("Failed to create HA service: ", err)
	}

	for _, srv := range testCfg.highAvailabilityService.Extender {
		extSrv, err := service.NewService(service.OptEndpoint(srv.BuildURI(testSchema), srv.User, srv.Pass))
		if err != nil {
			t.Fatal("Failed create service: ", err)
		}

		if err := ha.addSubService(extSrv); err != nil {
			t.Fatal("Failed to add HA sub-service: ", err)
		}
	}

	extReq, err := pdu.NewExtendingReq(testFromTime,
		pdu.ExtReqSetPubTime(testToTime),
	)
	if err != nil {
		t.Fatal("Failed to create request: ", err)
	}
	req, err := service.newRequest(service.extenderRequest(extReq))
	if err != nil {
		t.Fatal("Fails to add signer to service request: ", err)
	}

	resp, err := ha.Send(req)
	if err != nil {
		t.Fatal("Failed to receive response: ", err)
	}

	extResp, err := resp.extenderResp()
	if err != nil {
		t.Fatal("Failed to get aggregator response: ", err)
	}
	if extResp == nil {
		t.Fatal("No response returned.")
	}
}
*/
/*
func haExtenderConfigRcv(t *testing.T, opt ...interface{}) {
	var (
		testSchema = opt[haTestOptSchema].(string)
		testCfg    = opt[haTestOptConf].(*sysconf.Configuration)
	)

	ha, err := NewHighAvailabilityService()
	if err != nil {
		t.Fatal("Failed to create HA signer: ", err)
	}

	pfh, err := NewPublicationsFileHandler()
	if err != nil {
		t.Fatal("Failed to initialize publications file handler: ", err)
	}

	for _, srv := range testCfg.highAvailabilityService.Extender {
		client, err := net.NewClient(srv.BuildURI(testSchema), srv.User, srv.Pass)
		if err != nil {
			t.Fatal("Failed create network client: ", err)
		}

		extender, err := NewExtender(pfh,
			ServiceOptNetClient(client))
		if err != nil {
			t.Fatal("Failed create signer: ", err)
		}

		if err := ha.addSubService(extender); err != nil {
			t.Fatal("Failes to add signer to HA service: ", err)
		}

	}

	cfg, err := ha.ConfigRcv()
	if err != nil {
		t.Fatal("Failed to receive response: ", err)
	}
	if cfg == nil {
		t.Fatal(fmt.Sprintf("Expected response type mismatch."))
	}
}
*/
