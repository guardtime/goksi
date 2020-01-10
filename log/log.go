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

// Package log implements a logger interface that is used for logging KSI functionality.
//
// In order to enable logging a logger must be registered fist by invoking SetLogger() with an Interface implementation.
// Logging can be disabled by calling SetLogger(nil).
//
// Package provides also an basic logging implementation Logger, that generates lines of formatted output to an io.Writer.
package log

var logger Logger

// SetLogger initialize a global logger.
// In order to disable logging set the parameter l to nil.
func SetLogger(l Logger) {
	logger = l
}

// Debug for debug level logging. Events generated to aid in debugging,
// application flow and detailed service troubleshooting.
func Debug(v ...interface{}) {
	if logger == nil {
		return
	}
	logger.Debug(v...)
}

// Info for info level logging. Events that have no effect on service,
// but can aid in performance, status and statistics monitoring.
func Info(v ...interface{}) {
	if logger == nil {
		return
	}
	logger.Info(v...)
}

// Notice for info level logging. Changes in state that do not necessarily
// cause service degradation.
func Notice(v ...interface{}) {
	if logger == nil {
		return
	}
	logger.Notice(v...)
}

// Warning for warning level logging. Changes in state that affects the
// service degradation.
func Warning(v ...interface{}) {
	if logger == nil {
		return
	}
	logger.Warning(v...)
}

// Error for error level logging. Unrecoverable fatal errors only - gasp of
// death - code cannot continue and will terminate.
func Error(v ...interface{}) {
	if logger == nil {
		return
	}
	logger.Error(v...)
}
