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
	"strconv"
	"strings"
	"time"

	"github.com/guardtime/goksi/errors"
	"github.com/guardtime/goksi/hash"
	"github.com/guardtime/goksi/log"
)

// PublicationTime returns calendar hash chain publication time.
// If not present, an error is returned.
func (c *CalendarChain) PublicationTime() (time.Time, error) {
	if c == nil || c.pubTime == nil {
		return time.Time{}, errors.New(errors.KsiInvalidArgumentError)
	}
	return time.Unix(int64(*c.pubTime), 0), nil
}

// AggregationTime returns calendar hash chain aggregation time, or 0 if not present (see (time.(Time).IsZero())).
func (c *CalendarChain) AggregationTime() (time.Time, error) {
	if c == nil {
		return time.Time{}, errors.New(errors.KsiInvalidArgumentError)
	}
	if c.aggrTime == nil {
		return time.Time{}, nil
	}
	return time.Unix(int64(*c.aggrTime), 0), nil
}

// InputHash returns calendar hash chain input hash.
// If not present, an error is returned.
func (c *CalendarChain) InputHash() (hash.Imprint, error) {
	if c == nil || c.inputHash == nil {
		return nil, errors.New(errors.KsiInvalidArgumentError)
	}
	return *c.inputHash, nil
}

// ChainLinks returns calendar hash chain links.
// If not present, an error is returned.
func (c *CalendarChain) ChainLinks() ([]*ChainLink, error) {
	if c == nil || c.chainLinks == nil {
		return nil, errors.New(errors.KsiInvalidArgumentError)
	}
	return *c.chainLinks, nil
}

// String implements fmt.(Stringer) interface.
func (c *CalendarChain) String() string {
	if c == nil {
		return ""
	}
	var b strings.Builder
	b.WriteString("Aggregation time: (")
	b.WriteString(strconv.FormatUint(*c.aggrTime, 10))
	b.WriteString(") ")
	b.WriteString(time.Unix(int64(*c.aggrTime), 0).String())
	b.WriteString("\n")
	if c.pubTime != nil {
		b.WriteString("Publication time: (")
		b.WriteString(strconv.FormatUint(*c.pubTime, 10))
		b.WriteString(") ")
		b.WriteString(time.Unix(int64(*c.pubTime), 0).String())
		b.WriteString("\n")
	}
	b.WriteString("Input hash      : ")
	if c.inputHash != nil {
		b.WriteString(hash.Imprint(*c.inputHash).String())
	}
	b.WriteString("\n")
	if c.chainLinks != nil {
		b.WriteString(ChainLinkList(*c.chainLinks).String())
	}
	return b.String()

}

// Aggregate aggregates the calendar hash chain.
// Returns the resulting root hash.
func (c *CalendarChain) Aggregate() (hash.Imprint, error) {
	if c == nil || c.chainLinks == nil || c.inputHash == nil {
		return nil, errors.New(errors.KsiInvalidArgumentError)
	}

	hsh, _, err := ChainLinkList(*c.chainLinks).aggregateChain(true, hash.SHA_NA, *c.inputHash, 0xff)
	if err != nil {
		return nil, errors.KsiErr(err).AppendMessage("Failed to calculate calendar hash chain root hash.")
	}
	return hsh, nil
}

// CalculateAggregationTime returns aggregation time calculated based on the shape of the calendar hash chain.
func (c *CalendarChain) CalculateAggregationTime() (time.Time, error) {
	if c == nil || c.chainLinks == nil || c.pubTime == nil {
		return time.Unix(0, 0), errors.New(errors.KsiInvalidArgumentError)
	}

	// Since the calendar tree is built in a deterministic manner, the shape of the tree for any moment can be
	// reconstructed from the number of leaf nodes in the tree at that moment, which is one more than the number of
	// seconds from 1970-01-01T00:00:00Z to that moment.
	// Therefore, given the time when the calendar tree was created and a hash chain extracted from it, we can
	// compute the time value corresponding to the leaf node belonging to the hash chain.
	// The algorithm for doing this relies on two facts regarding the calendar tree:
	// 	a. The left sub-tree of a node is always a perfect binary tree.
	// 	b. When the right sub-tree of a node contains M leaves, it has the same structure that an entire calendar tree
	// 	built on M leaves would have.
	// These two properties follow immediately from the way the calendar tree is constructed.
	// Let P be the publication time (the time when the calendar tree was created) and S be the "shape" of the calendar
	// hash chain, i.e. S is a sequence of "left" and "right" indicators that denote the left and right links, starting
	// from the root of the tree (the last link of the chain). The algorithm get_time(P, S) that computes the
	// UTC time t (in seconds from 1970-01-01T00:00:00Z) just traverses the calendar hash chain from top to bottom and
	// sums up the number of leaves of each sub-tree associated with a right link in the chain (which indicates that the
	// sub-tree is to the left from the chain, or in the past compared to the time corresponding to the leaf).
	var (
		// Result accumulator.
		t int64
		// Temporary variable.
		r = int64(*c.pubTime)
	)
	// Traverse the list from the end to the beginning.
	for i := len(*c.chainLinks) - 1; i >= 0; i-- {
		if r <= 0 {
			return time.Unix(0, 0), errors.New(errors.KsiInvalidFormatError)
		}

		if (*c.chainLinks)[i].isLeft {
			r = highBit(r) - 1
		} else {
			t += highBit(r)
			r -= highBit(r)
		}
	}

	if r != 0 {
		return time.Unix(0, 0), errors.New(errors.KsiInvalidFormatError)
	}
	return time.Unix(int64(t), 0), nil
}

// highBit returns the value of the highest 1-bit in the binary representation of r.
// For example, high_bit(3)=high_bit(2)=2, high_bit(7)=high_bit(4)=4. One may also define high_bit(r) as the highest
// integral power of 2 less than or equal to r, or as 2^floor(log2(r)), where log2 denotes binary logarithm and floor
// the greatest integer function.
func highBit(r int64) int64 {
	r |= (r >> 1)
	r |= (r >> 2)
	r |= (r >> 4)
	r |= (r >> 8)
	r |= (r >> 16)
	r |= (r >> 32)
	return r - (r >> 1)
}

// VerifyCompatibility checks if the two calendar hash chains are compatible with each other.
// The function performs the following checks:
//  - The input hashes match.
//  - The aggregation times match. Note that the publication times may differ.
//  - The right links from both calendar hash chains are pairwise equal.
// The publication time from the two aggregation hash chains and also the left-links from both of the chains can differ.
func (c *CalendarChain) VerifyCompatibility(with *CalendarChain) error {
	if c == nil || with == nil {
		return errors.New(errors.KsiInvalidArgumentError)
	}

	// Verify aggregation time compatibility.
	// Make sure the aggregation times are the same. Note that the publication times must not be equal.
	if !(c.aggrTime != nil && with.aggrTime != nil && *c.aggrTime == *with.aggrTime) {
		msg := "Incompatible calendar hash chain - aggregation times mismatch."
		log.Info(msg)
		return errors.New(errors.KsiIncompatibleHashChain).AppendMessage(msg)
	}

	// Verify input hash compatibility.
	// Make sure the input hashes are equal.
	if !(c.inputHash != nil && with.inputHash != nil && hash.Equal(*c.inputHash, *with.inputHash)) {
		msg := "Incompatible calendar hash chain - input hashes mismatch."
		log.Info(msg)
		return errors.New(errors.KsiIncompatibleHashChain).AppendMessage(msg)
	}

	return c.RightLinkMatch(with)
}

func (l ChainLinkList) nextRightLink(from int) (*ChainLink, int) {
	var i int
	for i = from; i < len(l); i++ {
		link := l[i]

		if link.isLeft {
			continue
		}
		return link, i
	}
	return nil, i
}

// RightLinkMatch verifies that the right links are pairwise equal.
func (c *CalendarChain) RightLinkMatch(l *CalendarChain) error {
	if l == nil || c == nil {
		return errors.New(errors.KsiInvalidArgumentError)
	}
	if l.chainLinks == nil || c.chainLinks == nil {
		return errors.New(errors.KsiInvalidStateError).AppendMessage("Missing calendar hash chain.")
	}

	var (
		li    int
		ri    int
		lLink *ChainLink
		rLink *ChainLink
	)

	for {
		lLink, li = ChainLinkList(*l.chainLinks).nextRightLink(li)
		rLink, ri = ChainLinkList(*c.chainLinks).nextRightLink(ri)

		if lLink == nil && rLink == nil {
			return nil
		}
		if lLink == nil || rLink == nil {
			msg := "Different number of right links in calendar hash chain."
			log.Info(msg)
			return errors.New(errors.KsiIncompatibleHashChain).AppendMessage(msg)
		}

		if !hash.Equal(*lLink.siblingHash, *rLink.siblingHash) {
			msg := "Different sibling hashes in right links in calendar hash chains."
			log.Info(msg)
			return errors.New(errors.KsiIncompatibleHashChain).AppendMessage(msg)
		}
		li++
		ri++
	}
}
