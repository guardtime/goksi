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

// Package blocksigner implements signing of locally aggregated trees built by treebuilder to create multiple
// signatures with a single signing request. Depending on the configuration of treebuilder (see treebuilder.Tree)
// it is possible to perform 'plain' aggregation or more advanced block-based aggrgeation.
//
// Block-based aggregation main enhancements when compared to 'plain' local aggregation is that the blocks are
// inter-linked together to form a long term immutable chain and blinding masks are added to ensure the confidentiality
// when proof for a given record is extracted.
//
// Local aggregation is based on Merkle tree data structure. Having built and signed such a tree, the hash chain from any
// leaf (record) to the root can be extracted and presented as a proof that the leaf (record) participated in the
// computation that yielded the signed root hash value.
package blocksigner

import (
	"fmt"

	"github.com/guardtime/goksi/errors"
	"github.com/guardtime/goksi/hash"
	"github.com/guardtime/goksi/log"
	"github.com/guardtime/goksi/pdu"
	"github.com/guardtime/goksi/service"
	"github.com/guardtime/goksi/signature"
	"github.com/guardtime/goksi/treebuilder"
)

// Blocksigner is extension to treebuilder (see treebuilder.Tree) providing signing functionality.
type Blocksigner struct {
	treebuilder.Tree

	signer        *service.Signer      // Signer to be used for signing tree root hash.
	rootSignature *signature.Signature // KSI signature of the block root hash.
}

// New returns an initialized Blocksigner instance.
// It is mandatory to provide signer. Treebuilder is configured to permit tree with maximum height,
// and the aggregation is performed with default hash algorithm. To change or add options, see (treebuilder.TreeOpt).
func New(signer *service.Signer, options ...treebuilder.TreeOpt) (*Blocksigner, error) {
	if signer == nil {
		return nil, errors.New(errors.KsiInvalidArgumentError)
	}

	tree, err := treebuilder.New(append([]treebuilder.TreeOpt{
		// Apply default Tree values.
		treebuilder.TreeOptAlgorithm(hash.Default),
		treebuilder.TreeOptMaxLevel(pdu.TreeMaxLevel)},
		// Apply user provided Tree options.
		options...,
	)...)
	if err != nil {
		return nil, errors.KsiErr(err).AppendMessage("Failed to apply tree options.")
	}

	tmp := &Blocksigner{
		signer: signer,
		Tree:   *tree,
	}
	return tmp, nil
}

// Sign finalizes and aggregates the underling tree and performs the signing of the
// calculated root hash value. It returns the root signature for the constructed block.
// After signing no more leafs can be added to the tree.
//
// For extracting individual record signature (Blocksigner).Signatures().
func (b *Blocksigner) Sign() (*signature.Signature, error) {
	if b == nil || b.signer == nil {
		return nil, errors.New(errors.KsiInvalidArgumentError)
	}

	// Create block root signature.
	rootHsh, rootLvl, err := b.Aggregate()
	if err != nil {
		return nil, err
	}

	log.Debug(fmt.Sprintf("Tree root level=%d hash=%s", rootLvl, rootHsh))
	b.rootSignature, err = b.signer.Sign(rootHsh, service.SignOptionLevel(rootLvl))
	if err != nil {
		return nil, err
	}
	return b.rootSignature, nil
}

// Signatures returns KSI signatures and the context (see treebuilder.InputHashOptionUserContext)
// associated with the record in the same order they have been added (see treebuilder.(Tree).AddNode())
// into the locally aggregated tree.
//
// Note that the block has to be signed first (see (Blocksigner).Sign()).
func (b *Blocksigner) Signatures() ([]*signature.Signature, []interface{}, error) {
	if b == nil || b.rootSignature == nil {
		return nil, nil, errors.New(errors.KsiInvalidArgumentError)
	}

	// Generate leaf signatures.
	leafs, err := b.Leafs()
	if err != nil {
		return nil, nil, err
	}
	var (
		sigBuf = make([]*signature.Signature, 0, len(leafs))
		ctxBuf = make([]interface{}, 0, len(leafs))
	)
	for _, l := range leafs {
		aggrChain, err := l.AggregationChain()
		if err != nil {
			return nil, nil, err
		}

		// Adjust level correction.
		lvl, err := l.Level()
		if err != nil {
			return nil, nil, err
		}
		if lvl != 0 {
			acb, err := pdu.NewAggregationChainBuilder(pdu.BuildFromAggregationChain(aggrChain))
			if err != nil {
				return nil, nil, err
			}
			if err := acb.AdjustLevelCorrection(pdu.LevelAdd, lvl); err != nil {
				return nil, nil, errors.KsiErr(err).AppendMessage("Failed to adjust level correction.")
			}
			ac, err := acb.Build()
			if err != nil {
				return nil, nil, err
			}
			aggrChain = ac
		}

		leafSig, err := signature.New(signature.BuildWithAggrChain(b.rootSignature, aggrChain))
		if err != nil {
			return nil, nil, err
		}
		userCtx, err := l.UserCtx()
		if err != nil {
			return nil, nil, err
		}

		sigBuf = append(sigBuf, leafSig)
		ctxBuf = append(ctxBuf, userCtx)
	}
	return sigBuf, ctxBuf, nil
}
