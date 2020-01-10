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
	"fmt"
	"strings"

	"github.com/guardtime/goksi/errors"
	"github.com/guardtime/goksi/hash"
	"github.com/guardtime/goksi/log"
)

// MaxLevel returns maximum level value that the nodes in the client's aggregation tree are allowed to have.
// Applicable for aggregation service only.
func (c *Config) MaxLevel() (byte, error) {
	if c == nil {
		return 0, errors.New(errors.KsiInvalidArgumentError)
	}
	if c.maxLevel == nil {
		return 0, nil
	}
	if *c.maxLevel > 0xff {
		return 0, errors.New(errors.KsiInvalidFormatError).AppendMessage("Max level exceed 0xff.")
	}
	return byte(*c.maxLevel), nil
}

// AggrAlgo returns identifier of the hash function that the client is recommended to use in its aggregation trees.
// Applicable for aggregation service only.
func (c *Config) AggrAlgo() (hash.Algorithm, error) {
	if c == nil {
		return hash.SHA_NA, errors.New(errors.KsiInvalidArgumentError)
	}
	if c.aggrAlgo == nil {
		return hash.Default, nil
	}
	return hash.Algorithm(*c.aggrAlgo), nil
}

// AggrPeriod returns recommended duration of client's aggregation round in milliseconds.
// Applicable for aggregation service only.
func (c *Config) AggrPeriod() (uint64, error) {
	if c == nil {
		return 0, errors.New(errors.KsiInvalidArgumentError)
	}
	if c.aggrPeriod == nil {
		return 0, nil
	}
	return *c.aggrPeriod, nil
}

// MaxReq returns maximum number of requests the client is allowed to send within the recommended duration.
// Applicable for aggregation and extending services.
func (c *Config) MaxReq() (uint64, error) {
	if c == nil {
		return 0, errors.New(errors.KsiInvalidArgumentError)
	}
	if c.maxReq == nil {
		return 0, nil
	}
	return *c.maxReq, nil
}

// ParentURI returns parent server URI list. Typically, these are all members of one cluster.
// Applicable for aggregation and extending services.
func (c *Config) ParentURI() ([]string, error) {
	if c == nil {
		return nil, errors.New(errors.KsiInvalidArgumentError)
	}
	if c.parentURI == nil {
		return nil, nil
	}
	return *c.parentURI, nil
}

// CalFirst returns aggregation time of the oldest calendar record the extender has.
// Applicable for extending service only.
func (c *Config) CalFirst() (uint64, error) {
	if c == nil {
		return 0, errors.New(errors.KsiInvalidArgumentError)
	}
	if c.calFirst == nil {
		return 0, nil
	}
	return *c.calFirst, nil
}

// CalLast returns aggregation time of the newest calendar record the extender has.
// Applicable for extending service only.
func (c *Config) CalLast() (uint64, error) {
	if c == nil {
		return 0, errors.New(errors.KsiInvalidArgumentError)
	}
	if c.calLast == nil {
		return 0, nil
	}
	return *c.calLast, nil
}

// String implements fmt.(Stringer) interface.
func (c *Config) String() string {
	if c == nil {
		return ""
	}
	var b strings.Builder
	b.WriteString("Config:\n")
	if c.maxLevel != nil {
		b.WriteString(fmt.Sprintf("  Maximum level: %d\n", *c.maxLevel))
	}
	if c.aggrAlgo != nil {
		b.WriteString("  Aggregation hash algorithm: ")
		b.WriteString(hash.Algorithm(*c.aggrAlgo).String())
		b.WriteString("\n")
	}
	if c.aggrPeriod != nil {
		b.WriteString(fmt.Sprintf("  Aggregation period: %d\n", *c.aggrPeriod))
	}
	if c.maxReq != nil {
		b.WriteString(fmt.Sprintf("  Maximum requests: %d\n", *c.maxReq))
	}
	if c.calFirst != nil {
		b.WriteString(fmt.Sprintf("  Calendar first time: %d\n", *c.calFirst))
	}
	if c.calLast != nil {
		b.WriteString(fmt.Sprintf("  Calendar last time: %d\n", *c.calLast))
	}
	if c.parentURI != nil {
		b.WriteString("  Parent URI:\n")
		for i, uri := range *c.parentURI {
			b.WriteString(fmt.Sprintf("  %d: %s\n", i, uri))
		}
	}
	return b.String()
}

// ConfigLimits is used for configuration consolidation.
// See (Config).Consolidate().
type ConfigLimits struct {
	// MaxLevelLow limits the lower bound of the maximum level value.
	MaxLevelLow uint64
	// MaxLevelHigh limits the upper bound of the maximum level value.
	MaxLevelHigh uint64

	// AggrPeriodLow limits the lower bound of the recommended duration of aggregation round.
	AggrPeriodLow uint64
	// AggrPeriodHigh limits the upper bound of the recommended duration of aggregation round.
	AggrPeriodHigh uint64

	// MaxReqLow limits the lower bound of the maximum number of requests within of the recommended duration.
	MaxReqLow uint64
	// MaxReqHigh limits the upper bound of the maximum number of requests within of the recommended duration.
	MaxReqHigh uint64

	// CalFirstLow limits the aggregation time of the oldest calendar record to be accepted.
	// Note that the aggregation time of the newest calendar record can not be limited, thus all values
	// greater than CalFirstLow will be accepted.
	CalFirstLow uint64
}

// ConfigConsStrategy is the logic upon which configuration values are consolidated.
// See (Config).Consolidate().
type ConfigConsStrategy struct {
	// MaxLevelKeepLargest: if set, the largest value is preserved.
	MaxLevelKeepLargest bool
	// AggrAlgorithm: if set to hash.SHA_NA, the latest valid value is preserved. Otherwise the applied algorithm will
	// override the value from 'cfg'.
	// Note that the applied algorithm is not verified, only the new algorithm from 'cfg' is verified (see (Algorithm).Trusted()).
	AggrAlgorithm hash.Algorithm
	// AggrPeriodKeepLargest: if set, the largest value is preserved.
	AggrPeriodKeepLargest bool
	// MaxRequestsKeepLargest: if set, the largest value is preserved.
	MaxRequestsKeepLargest bool
	// ParentUriAppend: if set, URIs from the new 'cfg' will be appended to the already present list. Otherwise only
	// latest will be preserved.
	// Note that only unique entries are kept.
	ParentUriAppend bool
	// CalFirstKeepEarliest: if set, the earliest value is preserved.
	// Note that the aggregation time of the newest calendar record can not be limited, thus all values
	// greater than CalFirstLow will be accepted. For the same reason calendar last time is not limited and the latest value
	// is preserved (values before calendar first time are discarded).
	CalFirstKeepEarliest bool
}

// Consolidate merges the provided configuration cfg into the receiver configuration based on the provided limits and
// strategy.
func (c *Config) Consolidate(cfg *Config, limits ConfigLimits, logic ConfigConsStrategy) error {
	if c == nil || cfg == nil {
		return errors.New(errors.KsiInvalidArgumentError)
	}

	if cfg.maxLevel != nil {
		if *cfg.maxLevel < limits.MaxLevelLow || *cfg.maxLevel > limits.MaxLevelHigh {
			log.Info("The max level value is not in the valid range: ", *cfg.maxLevel)
		} else if c.maxLevel == nil ||
			(logic.MaxLevelKeepLargest && *c.maxLevel < *cfg.maxLevel) ||
			(!logic.MaxLevelKeepLargest && *c.maxLevel > *cfg.maxLevel) {
			c.maxLevel = cfg.maxLevel

		}
	}

	if cfg.aggrAlgo != nil {
		if logic.AggrAlgorithm == hash.SHA_NA {
			alg := hash.Algorithm(*cfg.aggrAlgo)
			if !alg.Trusted() {
				log.Info("The aggregation algorithm is not trusted: ", alg)
			} else {
				c.aggrAlgo = cfg.aggrAlgo
			}
		} else {
			c.aggrAlgo = newUint64(uint64(logic.AggrAlgorithm))
		}
	}

	if cfg.aggrPeriod != nil {
		if *cfg.aggrPeriod < limits.AggrPeriodLow || *cfg.aggrPeriod > limits.AggrPeriodHigh {
			log.Info("The aggregation period value is not in the valid range: ", *cfg.aggrPeriod)
		} else if c.aggrPeriod == nil ||
			(logic.AggrPeriodKeepLargest && *c.aggrPeriod < *cfg.aggrPeriod) ||
			(!logic.AggrPeriodKeepLargest && *c.aggrPeriod > *cfg.aggrPeriod) {
			c.aggrPeriod = cfg.aggrPeriod

		}
	}

	if cfg.maxReq != nil {
		if *cfg.maxReq < limits.MaxReqLow || *cfg.maxReq > limits.MaxReqHigh {
			log.Info("The max requests count is not in the valid range: ", *cfg.maxReq)
		} else if c.maxReq == nil ||
			(logic.MaxRequestsKeepLargest && *c.maxReq < *cfg.maxReq) ||
			(!logic.MaxRequestsKeepLargest && *c.maxReq > *cfg.maxReq) {
			c.maxReq = cfg.maxReq
		}
	}

	if cfg.parentURI != nil {
		var (
			uriMap = map[string]bool{}
			uris   = []string{}
		)
		// Handle the available URIs first.
		if c.parentURI != nil && logic.ParentUriAppend {
			for _, uri := range *c.parentURI {
				if _, ok := uriMap[uri]; !ok {
					uriMap[uri] = true
					uris = append(uris, uri)
				}
			}
		}
		// Add new URIs.
		for _, uri := range *cfg.parentURI {
			if _, ok := uriMap[uri]; !ok {
				uriMap[uri] = true
				uris = append(uris, uri)
			}
		}
		c.parentURI = &uris
	}

	if cfg.calFirst != nil {
		if *cfg.calFirst < limits.CalFirstLow {
			log.Info("The calendar first time is not in the valid range: ", *cfg.calFirst)
		} else if c.calFirst == nil ||
			(!logic.CalFirstKeepEarliest && *c.calFirst < *cfg.calFirst) ||
			(logic.CalFirstKeepEarliest && *c.calFirst > *cfg.calFirst) {
			c.calFirst = cfg.calFirst
		}
	}

	if cfg.calLast != nil {
		if (*cfg.calLast < limits.CalFirstLow) || (c.calFirst != nil && *c.calFirst > *cfg.calLast) {
			log.Info("The calendar last time is not in the valid range: ", *cfg.calLast)
		} else if c.calLast == nil || *c.calLast < *cfg.calLast {
			c.calLast = cfg.calLast
		}
	}

	return nil
}
