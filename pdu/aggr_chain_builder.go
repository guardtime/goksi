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
	"time"

	"github.com/guardtime/goksi/errors"
	"github.com/guardtime/goksi/hash"
)

type (
	// AggregationChainBuilder provides the ability for constructing aggregation chains.
	AggregationChainBuilder struct {
		aggrChain *AggregationChain
	}
	aggregationChainBuilder struct {
		obj AggregationChainBuilder
	}

	// AggrChainInit is initializer for AggregationChainBuilder.
	AggrChainInit func(*aggregationChainBuilder) error
)

// BuildFromAggregationChain will initialize AggregationChainBuilder with specified AggregationChain.
// Builder operations will not affect original input aggregation hash chain.
func BuildFromAggregationChain(aggrChain *AggregationChain) AggrChainInit {
	return func(a *aggregationChainBuilder) error {
		if aggrChain == nil {
			return errors.New(errors.KsiInvalidArgumentError)
		}
		if a == nil {
			return errors.New(errors.KsiInvalidArgumentError).
				AppendMessage("Missing aggregation hash chain builder object.")
		}

		clone, err := clonePDU(aggrChain)
		if err != nil {
			return err
		}

		a.obj.aggrChain = clone.(*AggregationChain)

		return nil
	}
}

// BuildFromImprint will initialize AggregationChainBuilder with aggregation hash algorithm and input hash.
func BuildFromImprint(aggrAlgo hash.Algorithm, inputHash hash.Imprint) AggrChainInit {
	return func(a *aggregationChainBuilder) error {
		if !aggrAlgo.Registered() || !inputHash.IsValid() {
			return errors.New(errors.KsiInvalidArgumentError)
		}
		if a == nil {
			return errors.New(errors.KsiInvalidArgumentError).
				AppendMessage("Missing aggregation hash chain builder object.")
		}

		a.obj.aggrChain = &AggregationChain{
			aggrAlgo:   newUint64(uint64(aggrAlgo)),
			inputHash:  newImprint(inputHash),
			chainLinks: new([]*ChainLink),
		}

		return nil
	}
}

// NewAggregationChainBuilder returns a new builder instance. Use the init option for setting the builder initial state.
func NewAggregationChainBuilder(init AggrChainInit) (*AggregationChainBuilder, error) {
	if init == nil {
		return nil, errors.New(errors.KsiInvalidArgumentError)
	}
	tmp := aggregationChainBuilder{}

	// Initialize aggregation chain builder.
	if err := init(&tmp); err != nil {
		return nil, errors.KsiErr(err).AppendMessage("Unable to initialize AggregationChainBuilder.")
	}

	return &tmp.obj, nil
}

// AdjustLevelCorrection applies newly calculated level correction value to the aggregation chain first chain link.
// The calculation of the new level correction value is performed based on the provided calculation strategy calc.
func (b *AggregationChainBuilder) AdjustLevelCorrection(calc LevelCalculator, lvl byte) error {
	if b == nil || calc == nil {
		return errors.New(errors.KsiInvalidArgumentError)
	}
	if b.aggrChain == nil {
		return errors.New(errors.KsiInvalidStateError)
	}
	if b.aggrChain.chainLinks == nil || (*b.aggrChain.chainLinks)[0] == nil {
		return errors.New(errors.KsiInvalidStateError).
			AppendMessage("Inconsistent aggregation chain.").
			AppendMessage("Missing aggregation hash chain links.")
	}
	if lvl == 0 {
		// Nothing to calculate.
		return nil
	}

	// Get the first chain link and its level correction value.
	link := (*b.aggrChain.chainLinks)[0]
	// Level correction is optional. If not present, it is null.
	var curLvl byte
	if link.levelCorr != nil {
		curLvl = byte(*link.levelCorr)
	}
	newLvl, err := calc(curLvl, lvl)
	if err != nil {
		return err
	}

	link.levelCorr = nil
	if newLvl != 0 {
		link.levelCorr = newUint64(uint64(newLvl))
	}

	return nil
}

// LevelCalculator is aggregation chain level correction calculation strategy.
type LevelCalculator func(byte, byte) (byte, error)

// LevelAdd is aggregation chain level correction calculation strategy for summing provided values.
// The sum of the value must not exceed maximum tree level.
func LevelAdd(l, r byte) (byte, error) {
	t := uint16(l) + uint16(r)
	if t > 0xff {
		return 0, errors.New(errors.KsiBufferOverflow).AppendMessage("Maximum tree level exceeded.")
	}
	return byte(t), nil
}

// LevelSubtract is aggregation chain level correction calculation strategy for subtracting the value r from l.
// Value l must be greater than r, otherwise an error is returned.
func LevelSubtract(l, r byte) (byte, error) {
	if l < r {
		return 0, errors.New(errors.KsiInvalidFormatError)
	}

	t := l - r
	return t, nil
}

// SetAggregationTime is setter for aggregation chain time.
func (b *AggregationChainBuilder) SetAggregationTime(t time.Time) error {
	if b == nil || t.IsZero() {
		return errors.New(errors.KsiInvalidArgumentError)
	}
	if b.aggrChain == nil {
		return errors.New(errors.KsiInvalidStateError)
	}

	return b.aggrChain.setAggregationTime(t)
}

// PrependChainIndex adds a new index to the front of the aggregation chain index.
func (b *AggregationChainBuilder) PrependChainIndex(i []uint64) error {
	if b == nil || i == nil {
		return errors.New(errors.KsiInvalidArgumentError)
	}
	if b.aggrChain == nil {
		return errors.New(errors.KsiInvalidStateError)
	}

	return b.aggrChain.prependChainIndex(i)
}

// AddChainLink appends a new chain link.
// The sibling data can be applied via functional setters (see LinkSiblingMetaData, LinkSiblingHash)
func (b *AggregationChainBuilder) AddChainLink(isLeft bool, lvlCorrection byte, siblingData LinkSiblingDataSetter) error {
	if b == nil || siblingData == nil {
		return errors.New(errors.KsiInvalidArgumentError)
	}
	if b.aggrChain == nil {
		return errors.New(errors.KsiInvalidStateError)
	}

	link := chainLink{obj: ChainLink{
		isLeft:     isLeft,
		isCalendar: false,
	}}
	if lvlCorrection != 0 {
		link.obj.levelCorr = newUint64(uint64(lvlCorrection))
	}
	if err := siblingData(&link); err != nil {
		return err
	}
	*b.aggrChain.chainLinks = append(*b.aggrChain.chainLinks, &link.obj)
	return nil
}

// LinkSiblingDataSetter is functional value setter for the chain link value.
type LinkSiblingDataSetter func(*chainLink) error
type chainLink struct {
	obj ChainLink
}

// LinkSiblingMetaData is sibling metadata setter.
func LinkSiblingMetaData(md *MetaData) LinkSiblingDataSetter {
	return func(l *chainLink) error {
		if md == nil {
			return errors.New(errors.KsiInvalidArgumentError)
		}
		if l == nil {
			return errors.New(errors.KsiInvalidArgumentError).AppendMessage("Missing chain link base object.")
		}

		l.obj.metadata = md
		return nil
	}
}

// LinkSiblingHash is sibling hash setter.
func LinkSiblingHash(hsh hash.Imprint) LinkSiblingDataSetter {
	return func(l *chainLink) error {
		if hsh == nil {
			return errors.New(errors.KsiInvalidArgumentError)
		}
		if l == nil {
			return errors.New(errors.KsiInvalidArgumentError).AppendMessage("Missing chain link base object.")
		}
		l.obj.siblingHash = &hsh
		return nil
	}
}

// Build constructs and returns the resulting aggregation hash chain.
// The receiver's internal state is reset after this method returns AggregationChain.
func (b *AggregationChainBuilder) Build() (*AggregationChain, error) {
	if b == nil {
		return nil, errors.New(errors.KsiInvalidArgumentError)
	}
	if b.aggrChain == nil {
		return nil, errors.New(errors.KsiInvalidStateError)
	}
	if len(*b.aggrChain.chainLinks) == 0 {
		return nil, errors.New(errors.KsiInvalidFormatError).AppendMessage("Missing aggregation chain links.")
	}

	// Set aggregation time.
	if b.aggrChain.aggrTime == nil {
		b.aggrChain.aggrTime = newUint64(uint64(time.Now().Unix()))
	}

	// Calculate the chain index or if it's provided, verify it.
	index, err := b.aggrChain.CalculateShape()
	if err != nil {
		return nil, err
	}
	if b.aggrChain.chainIndex == nil || len(*b.aggrChain.chainIndex) == 0 {
		b.aggrChain.chainIndex = new([]uint64)
		*b.aggrChain.chainIndex = append(*b.aggrChain.chainIndex, index)
	} else {
		if index != (*b.aggrChain.chainIndex)[len(*b.aggrChain.chainIndex)-1] {
			return nil, errors.New(errors.KsiInvalidFormatError).
				AppendMessage("Aggregation hash chain calculate shape does not match with its chain index.")
		}
	}

	tmp := b.aggrChain
	// Invalidate the internal aggregation chain.
	b.aggrChain = nil
	return tmp, nil
}
