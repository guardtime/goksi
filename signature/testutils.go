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
	"github.com/guardtime/goksi/hash"
	"github.com/guardtime/goksi/log"
	"github.com/guardtime/goksi/net"
	"github.com/guardtime/goksi/pdu"
	"github.com/guardtime/goksi/signature/verify/reserr"
	"github.com/guardtime/goksi/signature/verify/result"
)

var (
	testRoot        = filepath.Join("..", "test")
	testLogDir      = filepath.Join(testRoot, "out")
	testResourceDir = filepath.Join(testRoot, "resource")
	testSigDir      = filepath.Join(testResourceDir, "signature")
	testPubDir      = filepath.Join(testResourceDir, "publications")
	testTlvDir      = filepath.Join(testResourceDir, "tlv")
	testCrtDir      = filepath.Join(testResourceDir, "certificate")
)

func verificationResultMatch(t *testing.T, res *RuleResult,
	expResCode result.Code, expErrCode reserr.Code, expRuleName string) {
	t.Helper()

	resCode, _ := res.ResultCode()
	if expResCode != resCode {
		t.Fatal("Verification result code mismatch.")
	}
	resError, _ := res.ErrorCode()
	if resError != reserr.ErrNA && expErrCode != resError {
		t.Fatal("Verification result error mismatch.")
	}
	if expRuleName != res.RuleName() {
		t.Fatal("Verification rule mismatch.")
	}
}

type mockCalendarProvider struct {
	client net.Client
}

// Receive implements verify.(CalendarProvider) interface.
func (p *mockCalendarProvider) ReceiveCalendar(from, to time.Time) (*pdu.CalendarChain, error) {
	log.Debug("Using mock calendar provider.")
	log.Debug("Expecting calendar: ")
	log.Debug("  from ", from.Unix(), " (", from, ")")
	log.Debug("  to   ", to.Unix(), " (", to, ")")

	if p == nil {
		return nil, errors.New(errors.KsiInvalidArgumentError)
	}

	raw, err := p.client.Receive(nil, nil)
	if err != nil {
		return nil, err
	}
	resp := pdu.ExtenderResp{}
	if err := resp.Decode(raw); err != nil {
		return nil, err
	}
	if err := resp.Verify(hash.Default, p.client.Key()); err != nil {
		return nil, err
	}

	extResp, err := resp.ExtendingResp()
	if err != nil {
		return nil, err
	}

	return extResp.CalendarChain()
}
