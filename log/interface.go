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

package log

// Logger is the logger interface.
type Logger interface {
	// LogDebug for debug priority logging. Events generated to aid in debugging,
	// application flow and detailed service troubleshooting.
	Debug(v ...interface{})
	// LogInfo for info priority logging. Events that have no effect on service,
	// but can aid in performance, status and statistics monitoring.
	Info(v ...interface{})
	// LogNotice for info priority logging. Changes in state that do not necessarily
	// cause service degradation.
	Notice(v ...interface{})
	// LogWarning for warning priority logging. Changes in state that affects the service
	// degradation.
	Warning(v ...interface{})
	// LogError for error priority logging. Unrecoverable fatal errors only - gasp of
	// death - code cannot continue and will terminate.
	Error(v ...interface{})
}
