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
	"encoding/hex"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/guardtime/goksi/errors"
	"github.com/guardtime/goksi/hash"
)

// AggregationTime returns aggregation chain aggregation time.
// If time is not present, an error is returned.
func (c *AggregationChain) AggregationTime() (time.Time, error) {
	if c == nil {
		return time.Time{}, errors.New(errors.KsiInvalidArgumentError)
	}
	if c.aggrTime == nil {
		return time.Time{}, errors.New(errors.KsiInvalidStateError).
			AppendMessage("Inconsistent aggregation hash chain.").
			AppendMessage("Missing aggregation time.")
	}
	return time.Unix(int64(*c.aggrTime), 0), nil
}

// setAggregationTime is aggregation chain time setter.
func (c *AggregationChain) setAggregationTime(t time.Time) error {
	if c == nil || t.IsZero() {
		return errors.New(errors.KsiInvalidArgumentError)
	}
	c.aggrTime = newUint64(uint64(t.Unix()))
	return nil
}

// ChainIndex returns aggregation chain index.
// If chain index is not present, an error is returned.
func (c *AggregationChain) ChainIndex() ([]uint64, error) {
	if c == nil || c.chainIndex == nil {
		return nil, errors.New(errors.KsiInvalidArgumentError)
	}

	return *c.chainIndex, nil
}

// prependChainIndex adds a new index to the front of the aggregation chain index.
func (c *AggregationChain) prependChainIndex(i []uint64) error {
	if c == nil || i == nil {
		return errors.New(errors.KsiInvalidArgumentError)
	}
	tmp := append([]uint64(nil), i...)
	*c.chainIndex = append(tmp, *c.chainIndex...)
	return nil
}

// InputData returns aggregation chain input data.
// If data is not present, nil is returned.
func (c *AggregationChain) InputData() ([]byte, error) {
	if c == nil {
		return nil, errors.New(errors.KsiInvalidArgumentError)
	}
	if c.inputData == nil {
		return nil, nil
	}
	return *c.inputData, nil
}

// InputHash returns aggregation chain input hash.
// If hash is not present, an error is returned.
func (c *AggregationChain) InputHash() (hash.Imprint, error) {
	if c == nil {
		return nil, errors.New(errors.KsiInvalidArgumentError)
	}
	if c.inputHash == nil {
		return nil, errors.New(errors.KsiInvalidStateError).
			AppendMessage("Inconsistent aggregation hash chain.").
			AppendMessage("Missing input hash.")
	}
	return *c.inputHash, nil
}

// AggregationAlgo returns aggregation chain aggregation algorithm.
// If algorithm is not present, an error is returned.
func (c *AggregationChain) AggregationAlgo() (hash.Algorithm, error) {
	if c == nil || c.aggrAlgo == nil {
		return hash.SHA_NA, errors.New(errors.KsiInvalidArgumentError)
	}
	return hash.Algorithm(*c.aggrAlgo), nil
}

// ChainLinks returns aggregation chain links.
// If links are not present, an error is returned.
func (c *AggregationChain) ChainLinks() ([]*ChainLink, error) {
	if c == nil || c.chainLinks == nil {
		return nil, errors.New(errors.KsiInvalidArgumentError)
	}
	return *c.chainLinks, nil
}

// CalculateShape represents the shape of the aggregation chain as a bit-field. The bits represent the path
// from the root of the tree to the location of a hash value as a sequence of moves from a parent node in the
// tree to either the left or right child (bit values 0 and 1, respectively). Each bit sequence starts with a
// 1-bit to make sure no left most 0-bits are lost.
func (c *AggregationChain) CalculateShape() (uint64, error) {
	if c == nil || c.chainLinks == nil || len(*c.chainLinks) == 0 {
		return 0, errors.New(errors.KsiInvalidArgumentError)
	}

	// Left pad the value with 1.
	var tmp uint64 = 1

	i := len(*c.chainLinks)
	if i > ( /*size of(uint64)*/ 8<<3)+1 {
		return 0, errors.New(errors.KsiInvalidFormatError)
	}

	for ; i > 0; i-- {
		link := (*c.chainLinks)[i-1]

		tmp <<= 1
		if link.isLeft {
			tmp |= 1
		}
	}
	return tmp, nil
}

// String implements the Stringer interface.
// Returns an empty string in case of an error.
func (c *AggregationChain) String() string {
	if c == nil {
		return ""
	}

	var b strings.Builder
	b.WriteString("Aggregation time: (")
	if c.aggrTime != nil {
		b.WriteString(strconv.FormatUint(*c.aggrTime, 10))
	}
	b.WriteString(") ")
	if c.aggrTime != nil {
		b.WriteString(time.Unix(int64(*c.aggrTime), 0).String())
	}
	b.WriteString("\n")
	if c.chainIndex != nil {
		b.WriteString(fmt.Sprintf("Chain index     : %02x\n", *c.chainIndex))
	}
	if c.inputData != nil {
		b.WriteString("Input data      : ")
		b.WriteString(hex.EncodeToString(*c.inputData))
		b.WriteString("\n")
	}
	b.WriteString("Input hash      : ")
	if c.inputHash != nil {
		b.WriteString(hash.Imprint(*c.inputHash).String())
	}
	b.WriteString("\n")
	b.WriteString("Aggr. algorithm : ")
	if c.aggrAlgo != nil {
		b.WriteString(hash.Algorithm(*c.aggrAlgo).String())
	}
	b.WriteString("\n")
	if c.chainLinks != nil {
		b.WriteString(ChainLinkList(*c.chainLinks).String())
	}
	return b.String()
}

// Aggregate aggregates the aggregation hash chain. The 'startLevel' parameter is the level of the first chain link.
// Returns the resulting root hash and aggregation chain height.
func (c *AggregationChain) Aggregate(startLevel byte) (hash.Imprint, byte, error) {
	if c == nil {
		return nil, 0, errors.New(errors.KsiInvalidArgumentError)
	}
	if c.chainLinks == nil || c.aggrAlgo == nil || c.inputHash == nil {
		return nil, 0, errors.New(errors.KsiInvalidStateError).
			AppendMessage("Inconsistent aggregation chain.").
			AppendMessage("Missing mandatory aggregation chain elements.")
	}

	hsh, lvl, err := ChainLinkList(*c.chainLinks).aggregateChain(false, hash.Algorithm(*c.aggrAlgo), *c.inputHash, startLevel)
	if err != nil {
		return nil, 0, errors.KsiErr(err).AppendMessage("Failed to calculate aggregation hash chain root hash.")
	}
	return hsh, lvl, nil
}

// Identity returns aggregation hash chain identity. The returned list consists of individual hash chain link identities.
// The identities in the list are ordered - the higher-link identity is before lower-link identity.
func (c *AggregationChain) Identity() (HashChainLinkIdentityList, error) {
	if c == nil {
		return nil, errors.New(errors.KsiInvalidArgumentError)
	}
	if c.chainLinks == nil {
		return nil, errors.New(errors.KsiInvalidStateError).
			AppendMessage("Inconsistent aggregation chain.").
			AppendMessage("Missing aggregation chain links.")
	}

	idList := make(HashChainLinkIdentityList, 0, len(*c.chainLinks))
	for _, link := range *c.chainLinks {
		id, err := link.Identity()
		if err != nil {
			return nil, err
		}
		if id != nil {
			idList = append(idList, id)
		}
	}
	return idList, nil
}

// AggregationChainList is alias type for []*AggregationChain.
type AggregationChainList []*AggregationChain

// Len implements sort.(Interface).
func (l AggregationChainList) Len() int { return len(l) }

// Less implements sort.(Interface).
func (l AggregationChainList) Less(i, j int) bool {
	c := l.Len()
	if c == 0 || i >= c || j >= c {
		return false
	}

	return len(*l[i].chainIndex) > len(*l[j].chainIndex)
}

// Swap implements sort.(Interface).
func (l AggregationChainList) Swap(i, j int) {
	c := l.Len()
	if c == 0 || i >= c || j >= c {
		return
	}

	l[i], l[j] = l[j], l[i]
}

// Aggregate aggregates the aggregation hash chain list and returns the result root hash.
// The aggregation result is the input hash of the calendar hash chain (CalendarChain).
// Note that the aggregation chain must be sequential, meaning that the root hash of previous aggregation chain must
// match the input hash of the following aggregation chain, otherwise an error is returned.
func (l AggregationChainList) Aggregate(lvl byte) (hash.Imprint, error) {
	if len(l) == 0 {
		return nil, errors.New(errors.KsiInvalidArgumentError)
	}

	var (
		hsh hash.Imprint
		err error
	)
	// Aggregate all the aggregation hash chains.
	for _, chain := range l {
		if chain.inputHash == nil {
			return nil, errors.New(errors.KsiInvalidStateError).
				AppendMessage("Inconsistent aggregation chain.").
				AppendMessage("Missing input hash.")
		}
		if hsh != nil && !hash.Equal(hsh, *chain.inputHash) {
			return nil, errors.New(errors.KsiInvalidFormatError).AppendMessage("Hash values mismatch.")
		}

		if hsh, lvl, err = chain.Aggregate(lvl); err != nil {
			return nil, err
		}
	}
	return hsh, nil
}

// Identity returns a list of the identities present in all aggregation hash chains.
func (l AggregationChainList) Identity() (HashChainLinkIdentityList, error) {
	if len(l) == 0 {
		return nil, errors.New(errors.KsiInvalidArgumentError)
	}

	var idList HashChainLinkIdentityList
	for _, aggrChain := range l {
		aggrID, err := aggrChain.Identity()
		if err != nil {
			return nil, err
		}

		if aggrID != nil {
			idList = append(idList, aggrID...)
		}
	}
	return idList, nil
}
