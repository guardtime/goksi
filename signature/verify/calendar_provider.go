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

package verify

import (
	"time"

	"github.com/guardtime/goksi/pdu"
)

// CalendarProvider is used to deliver calendar hash chains from the server to the client.
type CalendarProvider interface {
	// ReceiveCalendar returns a new calendar where from specifies the time of the aggregation round from which the
	// calendar hash chain should start, and parameter to is the time of the calendar root hash value to which the
	// aggregation hash value should be connected by the calendar hash chain.
	ReceiveCalendar(from, to time.Time) (*pdu.CalendarChain, error)
}
