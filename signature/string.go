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
	"strconv"
	"strings"
)

// String implements fmt.(Stringer) interface.
func (s *Signature) String() string {
	var b strings.Builder

	b.WriteString("KSI Signature:\n")
	if s == nil {
		return "(null)\n"
	}

	b.WriteString("Document hash: ")
	if imprint, err := s.DocumentHash(); err == nil {
		b.WriteString(imprint.String())
		b.WriteString("\n")
	} else {
		b.WriteString("N/A\n")
	}

	b.WriteString("Signing time: ")
	if time, err := s.SigningTime(); err == nil {
		b.WriteString("(")
		b.WriteString(strconv.FormatInt(time.Unix(), 10))
		b.WriteString(") ")
		b.WriteString(time.String())
		b.WriteString("\n")
	} else {
		b.WriteString("N/A\n")
	}

	if id, err := s.AggregationHashChainIdentity(); err == nil {
		b.WriteString(id.String())
	}

	b.WriteString("Trust anchor: ")
	if s.calAuthRec != nil {
		b.WriteString("'Calendar Authentication Record'.")
	} else if s.publication != nil {
		b.WriteString("'Publication Record'.")
	} else if s.calChain != nil {
		b.WriteString("'Calendar Blockchain'.")
	} else {
		b.WriteString("N/A.")
	}
	b.WriteString("\n")

	b.WriteString("-------------------------------------------\n")
	if s.aggrChainList != nil {
		for i, chain := range *s.aggrChainList {
			b.WriteString(strconv.FormatInt(int64(i), 10))
			b.WriteString(". Aggregation hash chain:\n")
			b.WriteString(chain.String())
			b.WriteString("\n")
		}
	} else {
		b.WriteString("Aggregation hash chain: N/A\n")
	}

	b.WriteString("-------------------------------------------\n")
	if s.calChain != nil {
		b.WriteString("Calendar hash chain:\n")
		b.WriteString(s.calChain.String())
		b.WriteString("\n")
	}
	return b.String()
}
