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

package pdu

import (
	"testing"

	"github.com/guardtime/goksi/hash"
	"github.com/guardtime/goksi/log"
	"github.com/guardtime/goksi/test"
)

func TestUnitConfig(t *testing.T) {
	logger, defFunc, err := test.InitLogger(t, testLogDir, log.DEBUG, t.Name())
	if err != nil {
		t.Fatal("Failed to initialize logger: ", err)
	}
	defer defFunc()
	// Apply logger.
	log.SetLogger(logger)

	test.Suite{
		{Func: testConfigFunctionsWithNilReceiver},
		{Func: testConfigFunctionsWithEmptyConfig},

		{Func: testConfigConsolidateMaxLevelLimits},
		{Func: testConfigConsolidateMaxLevelStrategyKeepLargest},
		{Func: testConfigConsolidateMaxLevelStrategyKeepSmallest},

		{Func: testConfigConsolidateAggrAlgoValueStrategyApplyNew},
		{Func: testConfigConsolidateAggrAlgoValueStrategyKeepCustom},

		{Func: testConfigConsolidateAggrPeriodLimits},
		{Func: testConfigConsolidateAggrPeriodStrategyKeepLargest},
		{Func: testConfigConsolidateAggrPeriodStrategyKeepSmallest},

		{Func: testConfigConsolidateMaxReqLimits},
		{Func: testConfigConsolidateMaxReqStrategyKeepLargest},
		{Func: testConfigConsolidateMaxReqStrategyKeepSmallest},

		{Func: testConfigConsolidateParentUriValueStrategyAppend},
		{Func: testConfigConsolidateParentUriValueStrategyApplyNew},

		{Func: testConfigConsolidateCalFirstLimits},
		{Func: testConfigConsolidateCalFirstStrategyKeepEarliest},
		{Func: testConfigConsolidateCalFirstStrategyKeepLatest},
		{Func: testConfigConsolidateCalLastLimits},
	}.Runner(t)
}

func testConfigFunctionsWithNilReceiver(t *testing.T, _ ...interface{}) {
	var (
		conf *Config
	)

	if _, err := conf.AggrAlgo(); err == nil {
		t.Fatal("Must fail with nil receiver.")
	}
	if _, err := conf.AggrPeriod(); err == nil {
		t.Fatal("Must fail with nil receiver.")
	}
	if _, err := conf.CalFirst(); err == nil {
		t.Fatal("Must fail with nil receiver.")
	}
	if _, err := conf.CalLast(); err == nil {
		t.Fatal("Must fail with nil receiver.")
	}
	if err := conf.Consolidate(&Config{}, ConfigLimits{}, ConfigConsStrategy{}); err == nil {
		t.Fatal("Must fail with nil receiver.")
	}
	if _, err := conf.MaxLevel(); err == nil {
		t.Fatal("Must fail with nil receiver.")
	}
	if _, err := conf.MaxReq(); err == nil {
		t.Fatal("Must fail with nil receiver.")
	}
	if _, err := conf.ParentURI(); err == nil {
		t.Fatal("Must fail with nil receiver.")
	}
	if conf.String() != "" {
		t.Fatal("Must fail with nil receiver.")
	}
}

func testConfigFunctionsWithEmptyConfig(t *testing.T, _ ...interface{}) {
	var (
		conf Config

		defaultMaxLevel   byte
		defaultAggrAlgo   = hash.Default
		defaultAggrPeriod uint64
		defaultMaxReq     uint64
		defaultParentURI  []string
		defaultCalFirst   uint64
		defaultCalLast    uint64
	)

	if v, err := conf.AggrAlgo(); err != nil {
		t.Fatal("Must not fail with empty receiver:", err)
	} else if v != defaultAggrAlgo {
		t.Fatal("Default value mismatch: expected=", defaultAggrAlgo, " actual=", v)
	}
	if v, err := conf.AggrPeriod(); err != nil {
		t.Fatal("Must not fail with empty receiver:", err)
	} else if v != defaultAggrPeriod {
		t.Fatal("Default value mismatch: expected=", defaultAggrPeriod, " actual=", v)
	}
	if v, err := conf.CalFirst(); err != nil {
		t.Fatal("Must not fail with empty receiver:", err)
	} else if v != defaultCalFirst {
		t.Fatal("Default value mismatch: expected=", defaultCalFirst, " actual=", v)
	}
	if v, err := conf.CalLast(); err != nil {
		t.Fatal("Must not fail with empty receiver:", err)
	} else if v != defaultCalLast {
		t.Fatal("Default value mismatch: expected=", defaultCalLast, " actual=", v)
	}
	if v, err := conf.MaxLevel(); err != nil {
		t.Fatal("Must not fail with empty receiver:", err)
	} else if v != defaultMaxLevel {
		t.Fatal("Default value mismatch: expected=", defaultMaxLevel, " actual=", v)
	}
	if v, err := conf.MaxReq(); err != nil {
		t.Fatal("Must not fail with empty receiver:", err)
	} else if v != defaultMaxReq {
		t.Fatal("Default value mismatch: expected=", defaultMaxReq, " actual=", v)
	}
	if v, err := conf.ParentURI(); err != nil {
		t.Fatal("Must not fail with empty receiver:", err)
	} else if len(v) != len(defaultParentURI) {
		t.Fatal("Default value mismatch: expected=", len(defaultParentURI), " actual=", len(v))
	}
	if conf.String() == "" {
		t.Fatal("Must fail with nil receiver.")
	}

	if err := conf.Consolidate(&Config{}, ConfigLimits{}, ConfigConsStrategy{}); err != nil {
		t.Fatal("Must not fail with empty receiver:", err)
	} else if conf.aggrAlgo != nil ||
		conf.aggrPeriod != nil ||
		conf.calFirst != nil ||
		conf.calLast != nil ||
		conf.maxLevel != nil ||
		conf.maxReq != nil ||
		conf.parentURI != nil {
		t.Fatal("Expected empty config. Actual=", conf)
	}
}

func testConfigConsolidateMaxLevelLimits(t *testing.T, _ ...interface{}) {
	var (
		testConf   Config
		testLimits = ConfigLimits{
			MaxLevelLow:  10,
			MaxLevelHigh: 20,
		}

		valLow  = testLimits.MaxLevelLow - 1
		valHigh = testLimits.MaxLevelHigh + 1
		valMid  = (testLimits.MaxLevelLow + testLimits.MaxLevelHigh) / 2

		confValueLow  = Config{maxLevel: newUint64(valLow)}
		confValueHigh = Config{maxLevel: newUint64(valHigh)}
		confValueMid  = Config{maxLevel: newUint64(valMid)}
	)

	if err := testConf.Consolidate(&confValueLow, testLimits, ConfigConsStrategy{}); err != nil {
		t.Fatal("Consolidation must not fail:", err)
	}
	if testConf.maxLevel != nil {
		t.Fatal("Out of range value should have not been applied.")
	}

	if err := testConf.Consolidate(&confValueHigh, testLimits, ConfigConsStrategy{}); err != nil {
		t.Fatal("Consolidation must not fail:", err)
	}
	if testConf.maxLevel != nil {
		t.Fatal("Out of range value should have not been applied.")
	}

	if err := testConf.Consolidate(&confValueMid, testLimits, ConfigConsStrategy{}); err != nil {
		t.Fatal("Consolidation must not fail:", err)
	}
	if testConf.maxLevel == nil || *testConf.maxLevel != valMid {
		t.Fatal("In range value should have been applied.")
	}
}

func testConfigConsolidateMaxLevelStrategyKeepLargest(t *testing.T, _ ...interface{}) {
	var (
		testConf   Config
		testLimits = ConfigLimits{
			MaxLevelLow:  10,
			MaxLevelHigh: 20,
		}
		testStrategy = ConfigConsStrategy{MaxLevelKeepLargest: true}

		maxLevelLow  = testLimits.MaxLevelHigh + 1
		maxLevelHigh = testLimits.MaxLevelHigh - 1
		maxLevelMid  = (testLimits.MaxLevelLow + testLimits.MaxLevelHigh) / 2

		confMaxLevelLow  = Config{maxLevel: newUint64(maxLevelLow)}
		confMaxLevelHigh = Config{maxLevel: newUint64(maxLevelHigh)}
		confMaxLevelMid  = Config{maxLevel: newUint64(maxLevelMid)}
	)

	if err := testConf.Consolidate(&confMaxLevelMid, testLimits, testStrategy); err != nil {
		t.Fatal("Consolidation must not fail:", err)
	}
	if testConf.maxLevel == nil || *testConf.maxLevel != maxLevelMid {
		t.Fatal("Expected value mismatch.")
	}

	if err := testConf.Consolidate(&confMaxLevelLow, testLimits, testStrategy); err != nil {
		t.Fatal("Consolidation must not fail:", err)
	}
	if testConf.maxLevel == nil || *testConf.maxLevel != maxLevelMid {
		t.Fatal("Expected value mismatch.")
	}

	if err := testConf.Consolidate(&confMaxLevelHigh, testLimits, testStrategy); err != nil {
		t.Fatal("Consolidation must not fail:", err)
	}
	if testConf.maxLevel == nil || *testConf.maxLevel != maxLevelHigh {
		t.Fatal("Expected value mismatch.")
	}
}

func testConfigConsolidateMaxLevelStrategyKeepSmallest(t *testing.T, _ ...interface{}) {
	var (
		testConf   Config
		testLimits = ConfigLimits{
			MaxLevelLow:  10,
			MaxLevelHigh: 20,
		}
		testStrategy = ConfigConsStrategy{MaxLevelKeepLargest: false}

		maxLevelLow  = testLimits.MaxLevelLow + 1
		maxLevelHigh = testLimits.MaxLevelHigh - 1
		maxLevelMid  = (testLimits.MaxLevelLow + testLimits.MaxLevelHigh) / 2

		confMaxLevelLow  = Config{maxLevel: newUint64(maxLevelLow)}
		confMaxLevelHigh = Config{maxLevel: newUint64(maxLevelHigh)}
		confMaxLevelMid  = Config{maxLevel: newUint64(maxLevelMid)}
	)

	if err := testConf.Consolidate(&confMaxLevelMid, testLimits, testStrategy); err != nil {
		t.Fatal("Consolidation must not fail:", err)
	}
	if testConf.maxLevel == nil || *testConf.maxLevel != maxLevelMid {
		t.Fatal("Expected value mismatch.")
	}

	if err := testConf.Consolidate(&confMaxLevelLow, testLimits, testStrategy); err != nil {
		t.Fatal("Consolidation must not fail:", err)
	}
	if testConf.maxLevel == nil || *testConf.maxLevel != maxLevelLow {
		t.Fatal("Expected value mismatch.")
	}

	if err := testConf.Consolidate(&confMaxLevelHigh, testLimits, testStrategy); err != nil {
		t.Fatal("Consolidation must not fail:", err)
	}
	if testConf.maxLevel == nil || *testConf.maxLevel != maxLevelLow {
		t.Fatal("Expected value mismatch.")
	}
}

func testConfigConsolidateAggrAlgoValueStrategyApplyNew(t *testing.T, _ ...interface{}) {
	var (
		testConf     Config
		testLimits   = ConfigLimits{}
		testStrategy = ConfigConsStrategy{AggrAlgorithm: hash.SHA_NA}

		confAggrAlgoDefault = Config{aggrAlgo: newUint64(uint64(hash.Default))}
		confAggrAlgoSHA1    = Config{aggrAlgo: newUint64(uint64(hash.SHA1))}
	)

	if err := testConf.Consolidate(&confAggrAlgoDefault, testLimits, testStrategy); err != nil {
		t.Fatal("Consolidation must not fail:", err)
	}
	if testConf.aggrAlgo == nil || *testConf.aggrAlgo != uint64(hash.Default) {
		t.Fatal("Expected value mismatch.")
	}

	if err := testConf.Consolidate(&confAggrAlgoSHA1, testLimits, testStrategy); err != nil {
		t.Fatal("Consolidation must not fail:", err)
	}
	if testConf.aggrAlgo == nil || *testConf.aggrAlgo != uint64(hash.Default) {
		t.Fatal("Expected value mismatch.")
	}
}

func testConfigConsolidateAggrAlgoValueStrategyKeepCustom(t *testing.T, _ ...interface{}) {
	var (
		testConf     Config
		testLimits   = ConfigLimits{}
		testStrategy = ConfigConsStrategy{AggrAlgorithm: hash.SM3}

		confAggrAlgoDefault = Config{aggrAlgo: newUint64(uint64(hash.Default))}
		confAggrAlgoSHA1    = Config{aggrAlgo: newUint64(uint64(hash.SHA1))}
	)

	if err := testConf.Consolidate(&confAggrAlgoDefault, testLimits, testStrategy); err != nil {
		t.Fatal("Consolidation must not fail:", err)
	}
	if testConf.aggrAlgo == nil || *testConf.aggrAlgo != uint64(testStrategy.AggrAlgorithm) {
		t.Fatal("Expected value mismatch.")
	}

	if err := testConf.Consolidate(&confAggrAlgoSHA1, testLimits, testStrategy); err != nil {
		t.Fatal("Consolidation must not fail:", err)
	}
	if testConf.aggrAlgo == nil || *testConf.aggrAlgo != uint64(testStrategy.AggrAlgorithm) {
		t.Fatal("Expected value mismatch.")
	}
}

func testConfigConsolidateAggrPeriodLimits(t *testing.T, _ ...interface{}) {
	var (
		testConf   Config
		testLimits = ConfigLimits{
			AggrPeriodLow:  10,
			AggrPeriodHigh: 20,
		}

		valLow  = testLimits.AggrPeriodLow - 1
		valHigh = testLimits.AggrPeriodHigh + 1
		valMid  = (testLimits.AggrPeriodLow + testLimits.AggrPeriodHigh) / 2

		confValueLow  = Config{aggrPeriod: newUint64(valLow)}
		confValueHigh = Config{aggrPeriod: newUint64(valHigh)}
		confValueMid  = Config{aggrPeriod: newUint64(valMid)}
	)

	if err := testConf.Consolidate(&confValueLow, testLimits, ConfigConsStrategy{}); err != nil {
		t.Fatal("Consolidation must not fail:", err)
	}
	if testConf.aggrPeriod != nil {
		t.Fatal("Out of range value should have not been applied.")
	}

	if err := testConf.Consolidate(&confValueHigh, testLimits, ConfigConsStrategy{}); err != nil {
		t.Fatal("Consolidation must not fail:", err)
	}
	if testConf.aggrPeriod != nil {
		t.Fatal("Out of range value should have not been applied.")
	}

	if err := testConf.Consolidate(&confValueMid, testLimits, ConfigConsStrategy{}); err != nil {
		t.Fatal("Consolidation must not fail:", err)
	}
	if testConf.aggrPeriod == nil || *testConf.aggrPeriod != valMid {
		t.Fatal("In range value should have been applied.")
	}
}

func testConfigConsolidateAggrPeriodStrategyKeepLargest(t *testing.T, _ ...interface{}) {
	var (
		testConf   Config
		testLimits = ConfigLimits{
			AggrPeriodLow:  10,
			AggrPeriodHigh: 20,
		}
		testStrategy = ConfigConsStrategy{AggrPeriodKeepLargest: true}

		valLow  = testLimits.AggrPeriodLow + 1
		valHigh = testLimits.AggrPeriodHigh - 1
		valMid  = (testLimits.AggrPeriodLow + testLimits.AggrPeriodHigh) / 2

		confValueLow  = Config{aggrPeriod: newUint64(valLow)}
		confValueHigh = Config{aggrPeriod: newUint64(valHigh)}
		confValueMid  = Config{aggrPeriod: newUint64(valMid)}
	)

	if err := testConf.Consolidate(&confValueMid, testLimits, testStrategy); err != nil {
		t.Fatal("Consolidation must not fail:", err)
	}
	if testConf.aggrPeriod == nil || *testConf.aggrPeriod != valMid {
		t.Fatal("Expected value mismatch.")
	}

	if err := testConf.Consolidate(&confValueLow, testLimits, testStrategy); err != nil {
		t.Fatal("Consolidation must not fail:", err)
	}
	if testConf.aggrPeriod == nil || *testConf.aggrPeriod != valMid {
		t.Fatal("Expected value mismatch.")
	}

	if err := testConf.Consolidate(&confValueHigh, testLimits, testStrategy); err != nil {
		t.Fatal("Consolidation must not fail:", err)
	}
	if testConf.aggrPeriod == nil || *testConf.aggrPeriod != valHigh {
		t.Fatal("Expected value mismatch.")
	}
}

func testConfigConsolidateAggrPeriodStrategyKeepSmallest(t *testing.T, _ ...interface{}) {
	var (
		testConf   Config
		testLimits = ConfigLimits{
			AggrPeriodLow:  10,
			AggrPeriodHigh: 20,
		}
		testStrategy = ConfigConsStrategy{AggrPeriodKeepLargest: false}

		valLow  = testLimits.AggrPeriodLow + 1
		valHigh = testLimits.AggrPeriodHigh - 1
		valMid  = (testLimits.AggrPeriodLow + testLimits.AggrPeriodHigh) / 2

		confValueLow  = Config{aggrPeriod: newUint64(valLow)}
		confValueHigh = Config{aggrPeriod: newUint64(valHigh)}
		confValueMid  = Config{aggrPeriod: newUint64(valMid)}
	)

	if err := testConf.Consolidate(&confValueMid, testLimits, testStrategy); err != nil {
		t.Fatal("Consolidation must not fail:", err)
	}
	if testConf.aggrPeriod == nil || *testConf.aggrPeriod != valMid {
		t.Fatal("Expected value mismatch.")
	}

	if err := testConf.Consolidate(&confValueLow, testLimits, testStrategy); err != nil {
		t.Fatal("Consolidation must not fail:", err)
	}
	if testConf.aggrPeriod == nil || *testConf.aggrPeriod != valLow {
		t.Fatal("Expected value mismatch.")
	}

	if err := testConf.Consolidate(&confValueHigh, testLimits, testStrategy); err != nil {
		t.Fatal("Consolidation must not fail:", err)
	}
	if testConf.aggrPeriod == nil || *testConf.aggrPeriod != valLow {
		t.Fatal("Expected value mismatch.")
	}
}

func testConfigConsolidateMaxReqLimits(t *testing.T, _ ...interface{}) {
	var (
		testConf   Config
		testLimits = ConfigLimits{
			MaxReqLow:  10,
			MaxReqHigh: 20,
		}

		valLow  = testLimits.MaxReqLow - 1
		valHigh = testLimits.MaxReqHigh + 1
		valMid  = (testLimits.MaxReqLow + testLimits.MaxReqHigh) / 2

		confValueLow  = Config{maxReq: newUint64(valLow)}
		confValueHigh = Config{maxReq: newUint64(valHigh)}
		confValueMid  = Config{maxReq: newUint64(valMid)}
	)

	if err := testConf.Consolidate(&confValueLow, testLimits, ConfigConsStrategy{}); err != nil {
		t.Fatal("Consolidation must not fail:", err)
	}
	if testConf.maxReq != nil {
		t.Fatal("Out of range value should have not been applied.")
	}

	if err := testConf.Consolidate(&confValueHigh, testLimits, ConfigConsStrategy{}); err != nil {
		t.Fatal("Consolidation must not fail:", err)
	}
	if testConf.maxReq != nil {
		t.Fatal("Out of range value should have not been applied.")
	}

	if err := testConf.Consolidate(&confValueMid, testLimits, ConfigConsStrategy{}); err != nil {
		t.Fatal("Consolidation must not fail:", err)
	}
	if testConf.maxReq == nil || *testConf.maxReq != valMid {
		t.Fatal("In range value should have been applied.")
	}
}

func testConfigConsolidateMaxReqStrategyKeepLargest(t *testing.T, _ ...interface{}) {
	var (
		testConf   Config
		testLimits = ConfigLimits{
			MaxReqLow:  10,
			MaxReqHigh: 20,
		}
		testStrategy = ConfigConsStrategy{MaxRequestsKeepLargest: true}

		valLow  = testLimits.MaxReqLow + 1
		valHigh = testLimits.MaxReqHigh - 1
		valMid  = (testLimits.MaxReqLow + testLimits.MaxReqHigh) / 2

		confValueLow  = Config{maxReq: newUint64(valLow)}
		confValueHigh = Config{maxReq: newUint64(valHigh)}
		confValueMid  = Config{maxReq: newUint64(valMid)}
	)

	if err := testConf.Consolidate(&confValueMid, testLimits, testStrategy); err != nil {
		t.Fatal("Consolidation must not fail:", err)
	}
	if testConf.maxReq == nil || *testConf.maxReq != valMid {
		t.Fatal("Expected value mismatch.")
	}

	if err := testConf.Consolidate(&confValueLow, testLimits, testStrategy); err != nil {
		t.Fatal("Consolidation must not fail:", err)
	}
	if testConf.maxReq == nil || *testConf.maxReq != valMid {
		t.Fatal("Expected value mismatch.")
	}

	if err := testConf.Consolidate(&confValueHigh, testLimits, testStrategy); err != nil {
		t.Fatal("Consolidation must not fail:", err)
	}
	if testConf.maxReq == nil || *testConf.maxReq != valHigh {
		t.Fatal("Expected value mismatch.")
	}
}

func testConfigConsolidateMaxReqStrategyKeepSmallest(t *testing.T, _ ...interface{}) {
	var (
		testConf   Config
		testLimits = ConfigLimits{
			MaxReqLow:  10,
			MaxReqHigh: 20,
		}
		testStrategy = ConfigConsStrategy{MaxRequestsKeepLargest: false}

		valLow  = testLimits.MaxReqLow + 1
		valHigh = testLimits.MaxReqHigh - 1
		valMid  = (testLimits.MaxReqLow + testLimits.MaxReqHigh) / 2

		confValueLow  = Config{maxReq: newUint64(valLow)}
		confValueHigh = Config{maxReq: newUint64(valHigh)}
		confValueMid  = Config{maxReq: newUint64(valMid)}
	)

	if err := testConf.Consolidate(&confValueMid, testLimits, testStrategy); err != nil {
		t.Fatal("Consolidation must not fail:", err)
	}
	if testConf.maxReq == nil || *testConf.maxReq != valMid {
		t.Fatal("Expected value mismatch.")
	}

	if err := testConf.Consolidate(&confValueLow, testLimits, testStrategy); err != nil {
		t.Fatal("Consolidation must not fail:", err)
	}
	if testConf.maxReq == nil || *testConf.maxReq != valLow {
		t.Fatal("Expected value mismatch.")
	}

	if err := testConf.Consolidate(&confValueHigh, testLimits, testStrategy); err != nil {
		t.Fatal("Consolidation must not fail:", err)
	}
	if testConf.maxReq == nil || *testConf.maxReq != valLow {
		t.Fatal("Expected value mismatch.")
	}
}

func testConfigConsolidateParentUriValueStrategyAppend(t *testing.T, _ ...interface{}) {
	var (
		testConf     Config
		testLimits   = ConfigLimits{}
		testStrategy = ConfigConsStrategy{ParentUriAppend: true}

		confWithParentUriList1 = Config{parentURI: &([]string{"some.uri.11", "some.uri.12", "some.uri.13"})}
		confWithParentUriList2 = Config{parentURI: &([]string{"some.uri.21", "some.uri.22"})}
	)

	if err := testConf.Consolidate(&confWithParentUriList1, testLimits, testStrategy); err != nil {
		t.Fatal("Consolidation must not fail:", err)
	}
	if testConf.parentURI == nil || len(*testConf.parentURI) != len(*confWithParentUriList1.parentURI) {
		t.Fatal("Expected value mismatch.")
	}
	if err := testConf.Consolidate(&confWithParentUriList1, testLimits, testStrategy); err != nil {
		t.Fatal("Consolidation must not fail:", err)
	}
	if testConf.parentURI == nil || len(*testConf.parentURI) != len(*confWithParentUriList1.parentURI) {
		t.Fatal("Expected value mismatch.")
	}

	if err := testConf.Consolidate(&confWithParentUriList2, testLimits, testStrategy); err != nil {
		t.Fatal("Consolidation must not fail:", err)
	}
	if testConf.parentURI == nil ||
		(len(*testConf.parentURI) != len(*confWithParentUriList1.parentURI)+len(*confWithParentUriList2.parentURI)) {
		t.Fatal("Expected value mismatch.")
	}
	if err := testConf.Consolidate(&confWithParentUriList1, testLimits, testStrategy); err != nil {
		t.Fatal("Consolidation must not fail:", err)
	}
	if testConf.parentURI == nil ||
		(len(*testConf.parentURI) != len(*confWithParentUriList1.parentURI)+len(*confWithParentUriList2.parentURI)) {
		t.Fatal("Expected value mismatch.")
	}
}

func testConfigConsolidateParentUriValueStrategyApplyNew(t *testing.T, _ ...interface{}) {
	var (
		testConf     Config
		testLimits   = ConfigLimits{}
		testStrategy = ConfigConsStrategy{ParentUriAppend: false}

		confWithParentUriList1 = Config{parentURI: &([]string{"some.uri.11", "some.uri.12", "some.uri.13"})}
		confWithParentUriList2 = Config{parentURI: &([]string{"some.uri.21", "some.uri.22"})}
	)

	if err := testConf.Consolidate(&confWithParentUriList1, testLimits, testStrategy); err != nil {
		t.Fatal("Consolidation must not fail:", err)
	}
	if testConf.parentURI == nil || len(*testConf.parentURI) != len(*confWithParentUriList1.parentURI) {
		t.Fatal("Expected value mismatch.")
	}

	if err := testConf.Consolidate(&confWithParentUriList2, testLimits, testStrategy); err != nil {
		t.Fatal("Consolidation must not fail:", err)
	}
	if testConf.parentURI == nil || len(*testConf.parentURI) != len(*confWithParentUriList2.parentURI) {
		t.Fatal("Expected value mismatch.")
	}
}

func testConfigConsolidateCalFirstLimits(t *testing.T, _ ...interface{}) {
	var (
		testConf   Config
		testLimits = ConfigLimits{
			CalFirstLow: 10,
		}

		valLow  = testLimits.CalFirstLow - 1
		valHigh = testLimits.CalFirstLow + 1

		confValueLow  = Config{calFirst: newUint64(valLow)}
		confValueHigh = Config{calFirst: newUint64(valHigh)}
	)

	if err := testConf.Consolidate(&confValueLow, testLimits, ConfigConsStrategy{}); err != nil {
		t.Fatal("Consolidation must not fail:", err)
	}
	if testConf.calFirst != nil {
		t.Fatal("Out of range value should have not been applied.")
	}

	if err := testConf.Consolidate(&confValueHigh, testLimits, ConfigConsStrategy{}); err != nil {
		t.Fatal("Consolidation must not fail:", err)
	}
	if testConf.calFirst == nil || *testConf.calFirst != valHigh {
		t.Fatal("In range value should have been applied.")
	}
}

func testConfigConsolidateCalFirstStrategyKeepEarliest(t *testing.T, _ ...interface{}) {
	var (
		testConf   Config
		testLimits = ConfigLimits{
			CalFirstLow: 10,
		}
		testStrategy = ConfigConsStrategy{CalFirstKeepEarliest: true}

		valLow  = testLimits.CalFirstLow + 1
		valHigh = testLimits.CalFirstLow + 10
		valMid  = (valLow + valHigh) / 2

		confValueLow  = Config{calFirst: newUint64(valLow)}
		confValueHigh = Config{calFirst: newUint64(valHigh)}
		confValueMid  = Config{calFirst: newUint64(valMid)}
	)

	if err := testConf.Consolidate(&confValueMid, testLimits, testStrategy); err != nil {
		t.Fatal("Consolidation must not fail:", err)
	}
	if testConf.calFirst == nil || *testConf.calFirst != valMid {
		t.Fatal("Expected value mismatch.")
	}

	if err := testConf.Consolidate(&confValueLow, testLimits, testStrategy); err != nil {
		t.Fatal("Consolidation must not fail:", err)
	}
	if testConf.calFirst == nil || *testConf.calFirst != valLow {
		t.Fatal("Expected value mismatch.")
	}

	if err := testConf.Consolidate(&confValueHigh, testLimits, testStrategy); err != nil {
		t.Fatal("Consolidation must not fail:", err)
	}
	if testConf.calFirst == nil || *testConf.calFirst != valLow {
		t.Fatal("Expected value mismatch.")
	}
}

func testConfigConsolidateCalFirstStrategyKeepLatest(t *testing.T, _ ...interface{}) {
	var (
		testConf   Config
		testLimits = ConfigLimits{
			CalFirstLow: 10,
		}
		testStrategy = ConfigConsStrategy{CalFirstKeepEarliest: false}

		valLow  = testLimits.CalFirstLow + 1
		valHigh = testLimits.CalFirstLow + 10
		valMid  = (valLow + valHigh) / 2

		confValueLow  = Config{calFirst: newUint64(valLow)}
		confValueHigh = Config{calFirst: newUint64(valHigh)}
		confValueMid  = Config{calFirst: newUint64(valMid)}
	)

	if err := testConf.Consolidate(&confValueMid, testLimits, testStrategy); err != nil {
		t.Fatal("Consolidation must not fail:", err)
	}
	if testConf.calFirst == nil || *testConf.calFirst != valMid {
		t.Fatal("Expected value mismatch.")
	}

	if err := testConf.Consolidate(&confValueLow, testLimits, testStrategy); err != nil {
		t.Fatal("Consolidation must not fail:", err)
	}
	if testConf.calFirst == nil || *testConf.calFirst != valMid {
		t.Fatal("Expected value mismatch.")
	}

	if err := testConf.Consolidate(&confValueHigh, testLimits, testStrategy); err != nil {
		t.Fatal("Consolidation must not fail:", err)
	}
	if testConf.calFirst == nil || *testConf.calFirst != valHigh {
		t.Fatal("Expected value mismatch.")
	}
}

func testConfigConsolidateCalLastLimits(t *testing.T, _ ...interface{}) {
	var (
		testConf   = Config{calFirst: newUint64(100)}
		testLimits = ConfigLimits{
			CalFirstLow: 10,
		}

		valLow  = *testConf.calFirst - 1
		valHigh = *testConf.calFirst + 1

		confValueLow  = Config{calLast: newUint64(valLow)}
		confValueHigh = Config{calLast: newUint64(valHigh)}
	)

	if err := testConf.Consolidate(&confValueLow, testLimits, ConfigConsStrategy{}); err != nil {
		t.Fatal("Consolidation must not fail:", err)
	}
	if testConf.calLast != nil {
		t.Fatal("Out of range value should have not been applied.")
	}

	if err := testConf.Consolidate(&confValueHigh, testLimits, ConfigConsStrategy{}); err != nil {
		t.Fatal("Consolidation must not fail:", err)
	}
	if testConf.calLast == nil || *testConf.calLast != valHigh {
		t.Fatal("Higher value should have been applied.")
	}
}
