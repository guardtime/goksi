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

// Package treebuilder implements functions for local aggregation.
//
// A locally aggregated tree can be used to create multiple signatures with a single signing request (see Blocksigner).
//
//
// Blinding masks
//
// The hash chain extracted from the Merkle tree for one leaf (record) contains hash values of other nodes (including
// neighboring record). A strong hash function can't be directly reversed to learn the input value (for instance the
// neighboring record) from which the hash value in the chain was created. However, a typical log record may contain
// insufficient entropy to make that argument - an attacker who knows the pattern of the input could exhaustively test
// all possible variants to find the one that yields the hash value actually in the chain and thus learn the contents
// of the record. To prevent this kind of informed brute-force attack, a blinding mask with sufficient entropy could be
// added to each record before aggregating the hash values.
//
// Following three record masking options are supported:
//
// - No masking (default).
//
// - Blinding mask is computed by the concatenation of previous record hash and initialization vector (IV).
//
// - Blinding mask is computed by the concatenation of 1-based record index in the block and IV.
//
//
// No Masking
//
// Since masking adds some overhead and may not be needed in all use cases, it is possible to skip masking. In this case
// the hashes of the actual records are directly aggregated into the Merkle tree. This is the default behavior.
//
//
// Masking with previous record hash and IV
//
// With this masking option leaf node of the previous record is concatenated with IV to compute the blinding mask.
// The advantage of such masking is that it also provides inter-linking of blocks. The disadvantage is that building
// of a block can only start when the previous block is complete. To enable masking with previous record hash and IV,
// option TreeOptMaskingWithPreviousLeaf must be used.
//
//
// Masking with index and IV
//
// With this masking option 1-based record index is concatenated with IV to compute the blinding mask. The advantage is
// that records can be processed in parallel and building of the block can start before the previous block has been
// finished. To enable masking with IV and index, option TreeOptMaskingWithIndex must be used.
package treebuilder

import (
	"encoding/binary"
	"fmt"
	"math"
	"time"

	"github.com/guardtime/goksi/errors"
	"github.com/guardtime/goksi/hash"
	"github.com/guardtime/goksi/log"
	"github.com/guardtime/goksi/pdu"
	"github.com/guardtime/goksi/treebuilder/listener"
)

type (
	// Tree is Merkle tree builder object.
	Tree struct {
		// Aggregation algorithm identifier used to compute the output hash values of the link structures.
		algorithm hash.Algorithm
		// Maximum level of the root hash.
		maxLevel byte
		leafs    []*TreeNode

		aggrRoot *TreeNode
		aggrTime time.Time

		initLeaf  hash.Imprint     // The first leaf to be used for masking with previous record hash and IV. This should be the last leaf of previous block, or a zero hash for the very first block.
		lastLeaf  hash.Imprint     // The last leaf value added to the tree. Used for masking with previous record hash and IV.
		iv        []byte           // A random seed (an 'initialization vector').
		leafCount uint64           // Added leaf counter. Used for masking with index and IV.
		hsr       *hash.DataHasher // Internal hasher for blinding mask computation.
		cache     [pdu.TreeMaxLevel]*TreeNode

		recordListener    listener.RecordHashListener
		metadataListener  listener.MetadataListener
		aggregateListener listener.AggregateHashListener
	}

	// TreeNode is the leaf and internal node of the Merkle tree.
	TreeNode struct {
		// Reference to the owning tree builder instance.
		tree *Tree

		// Tree leaf (initial) value.
		leafValue interface{}
		// User data associated with the first level tree leaf.
		userCtx interface{}

		// Current node value.
		hshValue []byte
		// Current node level.
		level byte

		// References to the connected nodes.
		parent *TreeNode
		lChild *TreeNode
		rChild *TreeNode
	}
)

const (
	defaultMaxLevel = pdu.TreeMaxLevel
)

// New returns a new tree builder instance for local aggregation.
// Use options parameter for additional configuration. By default, aggregation algorithm is set to hash.Default,
// maximum tree height is set to 0xff, and masking is disabled.
func New(options ...TreeOpt) (*Tree, error) {
	tmp := tree{obj: Tree{
		algorithm: hash.Default,
		maxLevel:  defaultMaxLevel,
	}}

	for _, setter := range options {
		if err := tmp.setOption(setter); err != nil {
			return nil, err
		}
	}

	return &tmp.obj, nil
}

func (t *tree) setOption(opt TreeOpt) error {
	if t == nil {
		return errors.New(errors.KsiInvalidArgumentError)
	}
	if opt == nil {
		return errors.New(errors.KsiInvalidArgumentError).AppendMessage("Provided option is nil.")
	}

	if err := opt(t); err != nil {
		return errors.KsiErr(err).AppendMessage("Unable to apply tree option.")
	}
	return nil
}

type (
	// TreeOpt is the configuration option for the tree builder.
	// See TreeOptAggregateListener, TreeOptAlgorithm,
	// TreeOptMaskingWithIndex, TreeOptMaskingWithPreviousLeaf, TreeOptMaxLevel,
	// TreeOptMetadataListener and TreeOptRecordListener.
	TreeOpt func(*tree) error
	tree    struct {
		obj Tree
	}
)

// TreeOptAlgorithm is the aggregation algorithm identifier used to compute the output hash values of the link structures.
func TreeOptAlgorithm(alg hash.Algorithm) TreeOpt {
	return func(t *tree) error {
		if t == nil {
			return errors.New(errors.KsiInvalidArgumentError).AppendMessage("Missing tree builder.")
		}
		if !alg.Trusted() || !alg.Registered() {
			return errors.New(errors.KsiInvalidArgumentError).AppendMessage("Invalid hash algorithm.")
		}

		log.Debug("Setting hash algorithm to: ", alg)
		t.obj.algorithm = alg
		return nil
	}
}

// TreeOptMaxLevel is the tree maximum level setter.
// Note that the value is 0-based.
func TreeOptMaxLevel(lvl byte) TreeOpt {
	return func(t *tree) error {
		if t == nil {
			return errors.New(errors.KsiInvalidArgumentError).AppendMessage("Missing tree builder.")
		}
		t.obj.maxLevel = lvl
		log.Debug("Setting max level to : ", t.obj.maxLevel)
		return nil
	}
}

// TreeOptMaskingWithPreviousLeaf enables masking and provides the value of IV and previous block
// last leaf. The value of IV should be about as long as the outputs of the hash function and kept with the same
// confidentiality as the data itself. Blinding mask is computed by the concatenation of previous record hash and IV.
//
// In order to increase the entropy of the nodes. A blinding mask with sufficient entropy is applied to each record
// before aggregating the hash value. The advantage of such masking is that it also provides inter-linking of blocks.
// The disadvantage is that building of a block can only start when the previous block is complete.
//
// Note that for the very first record (the first record of the first block), a zero hash value must be used (see
// hash.(Algorithm).ZeroImprint()).
func TreeOptMaskingWithPreviousLeaf(iv []byte, leaf hash.Imprint) TreeOpt {
	return func(t *tree) error {
		if t == nil {
			return errors.New(errors.KsiInvalidArgumentError).AppendMessage("Missing tree builder.")
		}
		if !leaf.IsValid() {
			return errors.New(errors.KsiInvalidArgumentError).AppendMessage("Invalid last leaf imprint.")
		}
		if len(iv) == 0 {
			return errors.New(errors.KsiInvalidArgumentError).AppendMessage("Missing IV.")
		}
		log.Debug("Block inter-linking previous leaf: ", leaf)

		t.obj.initLeaf = leaf
		t.obj.lastLeaf = leaf
		t.obj.iv = iv

		return nil
	}
}

// TreeOptMaskingWithIndex enables masking and provides the blinding mask IV (a random seed).
// The value should be about as long as the outputs of the hash function and kept with the same confidentiality as
// the data itself.
func TreeOptMaskingWithIndex(iv []byte) TreeOpt {
	return func(t *tree) error {
		if t == nil {
			return errors.New(errors.KsiInvalidArgumentError).AppendMessage("Missing tree builder.")
		}
		if len(iv) == 0 {
			return errors.New(errors.KsiInvalidArgumentError).AppendMessage("Missing IV.")
		}
		log.Debug(fmt.Sprintf("Masking initialization vector: %x", iv))
		t.obj.iv = iv
		return nil
	}
}

// TreeOptRecordListener allows to add leaf node listener to the tree builder. The listener will be notified on every
// newly added node to the tree (see (Tree).AddNode()).
// The listener is invoked in the same order as the values are added to the tree.
func TreeOptRecordListener(l listener.RecordHashListener) TreeOpt {
	return func(t *tree) error {
		if t == nil {
			return errors.New(errors.KsiInvalidArgumentError).AppendMessage("Missing tree builder.")
		}
		if l == nil {
			return errors.New(errors.KsiInvalidArgumentError).AppendMessage("Missing record listener.")
		}
		t.obj.recordListener = l
		return nil
	}
}

// TreeOptMetadataListener allows to add leaf node metadata listener to the tree builder. The listener will be notified
// on every newly added metadata to the tree (see (Tree).AddNode())
// The listener is invoked in the same order as the values are added to the tree.
func TreeOptMetadataListener(l listener.MetadataListener) TreeOpt {
	return func(t *tree) error {
		if t == nil {
			return errors.New(errors.KsiInvalidArgumentError).AppendMessage("Missing tree builder.")
		}
		if l == nil {
			return errors.New(errors.KsiInvalidArgumentError).AppendMessage("Missing metadata listener.")
		}
		t.obj.metadataListener = l
		return nil
	}
}

// TreeOptAggregateListener allows to add an intermediate aggregate hash value listener to the tree builder. The listener
// will be notified when ever a new hash value is computed internally.
// The listener is invoked in the same order as the values are added to the tree.
func TreeOptAggregateListener(l listener.AggregateHashListener) TreeOpt {
	return func(t *tree) error {
		if t == nil {
			return errors.New(errors.KsiInvalidArgumentError).AppendMessage("Missing tree builder.")
		}
		if l == nil {
			return errors.New(errors.KsiInvalidArgumentError).AppendMessage("Missing aggregate listener.")
		}
		t.obj.aggregateListener = l
		return nil
	}
}

func (t *Tree) notifyRecordListener(node *TreeNode) error {
	if t == nil || node == nil {
		return errors.New(errors.KsiInvalidArgumentError)
	}
	if t.recordListener == nil {
		return nil
	}

	if err := t.recordListener.TreeRecordHash(node.hshValue, node.level); err != nil {
		return errors.KsiErr(err).AppendMessage("Tree record hash value notifier failed.")
	}
	return nil
}

func (t *Tree) notifyMetadataListener(node *TreeNode) error {
	if t == nil || node == nil {
		return errors.New(errors.KsiInvalidArgumentError)
	}
	if t.metadataListener == nil {
		return nil
	}

	if err := t.metadataListener.TreeMetadata(node.hshValue); err != nil {
		return errors.KsiErr(err).AppendMessage("Tree metadata record notifier failed.")
	}
	return nil
}

func (t *Tree) notifyAggregateListener(node *TreeNode) error {
	if t == nil || node == nil {
		return errors.New(errors.KsiInvalidArgumentError)
	}
	if t.aggregateListener == nil {
		return nil
	}

	if err := t.aggregateListener.TreeAggregateHash(node.hshValue, node.level); err != nil {
		return errors.KsiErr(err).AppendMessage("Tree intermediate aggregate hash notifier failed.")
	}
	return nil
}

// AddNode adds a new leaf to the tree. Use the options parameter for adding additional parameters.
//
// Note that if adding a leaf would make the level of the root hash greater than the tree maximum level,
// errors.KsiBufferOverflow error is returned.
func (t *Tree) AddNode(inputHash hash.Imprint, options ...InputHashOption) error {
	if t == nil || len(inputHash) == 0 {
		return errors.New(errors.KsiInvalidArgumentError)
	}

	if t.aggrRoot != nil {
		log.Error("Trying to add new leaf to a closed tree.")
		return errors.New(errors.KsiInvalidStateError).AppendMessage("Tree is closed.")
	}

	// Handle input options.
	opts := inputHashOptions{tree: t}
	for _, setter := range options {
		if setter == nil {
			return errors.New(errors.KsiInvalidArgumentError).AppendMessage("Provided option is nil.")
		}
		if err := setter(&opts); err != nil {
			return errors.KsiErr(err).AppendMessage("Unable to apply input hash option.")
		}
	}

	// Verify that there is spare space for adding extra data to the tree.
	height, err := t.expectedHeight(opts.level, opts.meta.val != nil)
	if err != nil {
		return errors.KsiErr(err).AppendMessage("Unable to add node to the tree.")
	}
	if height > t.maxLevel {
		return errors.New(errors.KsiBufferOverflow).AppendMessage("Tree max level overflow.")
	}

	xi := &TreeNode{
		tree:      t,
		hshValue:  append([]byte(nil), inputHash...),
		level:     opts.level,
		leafValue: inputHash,
		userCtx:   opts.userCtx,
	}
	t.leafs = append(t.leafs, xi)
	if err := t.notifyRecordListener(xi); err != nil {
		return err
	}

	// In case additional metadata is provided, make a sub-tree.
	if opts.meta.val != nil {
		mdi := TreeNode{
			tree:      t,
			hshValue:  opts.meta.bin,
			leafValue: opts.meta.val,
		}
		if err := t.notifyMetadataListener(&mdi); err != nil {
			return err
		}
		if xi, err = t.joinNodes(xi, &mdi); err != nil {
			return errors.KsiErr(err).AppendMessage("Failed to aggregate nodes.")
		}
	}

	if t.useBlindingMask() {
		mask, err := t.calculateBlindingMask()
		if err != nil {
			return errors.KsiErr(err).AppendMessage("Failed to calculate blinding mask.")
		}
		if mask == nil {
			return errors.New(errors.KsiInvalidFormatError).AppendMessage("Inconsistent blinding mask.")
		}
		log.Debug(fmt.Sprintf("Blinding mask for node[%d]: %s", t.leafCount, mask))

		mi := &TreeNode{
			tree:      t,
			hshValue:  append([]byte(nil), mask...),
			leafValue: mask,
		}
		if xi, err = t.joinNodes(mi, xi); err != nil {
			return errors.KsiErr(err).AppendMessage("Failed to aggregate nodes.")
		}
	}

	if err = t.insertNode(xi, 0); err != nil {
		return err
	}
	t.lastLeaf = hash.Imprint(xi.hshValue)
	log.Debug(fmt.Sprintf("Lash leaf at %d: %s", t.leafCount, t.lastLeaf))
	t.leafCount++

	return nil
}

type inputHashOptions struct {
	tree  *Tree
	level byte
	meta  struct {
		bin []byte
		val interface{}
	}
	userCtx interface{}
}

// InputHashOption is the configuration option for (Tree).AddNode.
// See InputHashOptionLevel, InputHashOptionMetadata and InputHashOptionUserContext.
type InputHashOption func(o *inputHashOptions) error

// InputHashOptionLevel provides the ability for setting input hash level.
func InputHashOptionLevel(level byte) InputHashOption {
	return func(o *inputHashOptions) error {
		if o == nil {
			return errors.New(errors.KsiInvalidArgumentError).AppendMessage("Missing options object.")
		}

		if o.tree.useBlindingMask() && level != 0 {
			return errors.New(errors.KsiInvalidStateError).
				AppendMessage("Level can not be used in combination with blinding mask.")
		}
		o.level = level
		return nil
	}
}

// InputHashOptionMetadata provides the ability for setting metadata.
//
// The metadata parameter can be used for providing additional metadata that will be joined with the input hash to a
// sub-tree which in result is added to the main tree. In consequence, adding metadata affect the tree height (level of
// the root hash).
// Currently supported data types are hash.(Imprint) and pdu.(*MetaData).
//
// Note that aggregation chain can only be retrieved for inputHash.
func InputHashOptionMetadata(metadata interface{}) InputHashOption {
	return func(o *inputHashOptions) error {
		if metadata == nil {
			return errors.New(errors.KsiInvalidArgumentError)
		}
		if o == nil {
			return errors.New(errors.KsiInvalidArgumentError).AppendMessage("Missing options object.")
		}

		// Verify the type and if the interface contains a valid value.
		switch value := metadata.(type) {
		case hash.Imprint:
			if value != nil {
				if !value.IsValid() {
					return errors.New(errors.KsiInvalidFormatError).
						AppendMessage("Invalid imprint.").
						AppendMessage("Unable to create metadata leaf.")
				}
				o.meta.bin = append([]byte(nil), value...)
				o.meta.val = value
			}
		case *pdu.MetaData:
			if value != nil {
				vTlv, err := value.EncodeToTlv()
				if err != nil {
					return errors.KsiErr(err).AppendMessage("Unable to create metadata leaf.")
				}
				o.meta.bin = append([]byte(nil), vTlv.Value()...)
				o.meta.val = value
			}
		default:
			return errors.New(errors.KsiInvalidFormatError).
				AppendMessage(fmt.Sprintf("Unsupported metadata type: %T", value))
		}
		return nil
	}
}

// InputHashOptionUserContext provides the ability for setting user context.
//
// The userCtx parameter can be used for setting user private data that can be associated with the input data in later
// aggregation hash chain extraction (see (TreeNode).UserCtx()).
//
// Note that the context data is not linked into the resulting tree in any way.
func InputHashOptionUserContext(userCtx interface{}) InputHashOption {
	return func(o *inputHashOptions) error {
		if userCtx == nil {
			return errors.New(errors.KsiInvalidArgumentError)
		}
		if o == nil {
			return errors.New(errors.KsiInvalidArgumentError).AppendMessage("Missing options object.")
		}
		o.userCtx = userCtx
		return nil
	}
}

func (t *Tree) expectedHeight(inputLevel byte, hasMeta bool) (byte, error) {
	if t == nil {
		return 0, errors.New(errors.KsiInvalidArgumentError)
	}

	// Calculate expected height for the new node.
	nodeExpectedHeight := int(inputLevel)
	if hasMeta {
		nodeExpectedHeight++
	}
	if t.useBlindingMask() {
		nodeExpectedHeight++
	}
	// Verify the expected height does not exceed tree limits.
	if nodeExpectedHeight > int(t.maxLevel) {
		return 0, errors.New(errors.KsiBufferOverflow).
			AppendMessage(fmt.Sprintf("Tree height exceeding the max level '%d'.", t.maxLevel))

	}

	// Calculate expected tree height.
	treeHeight := byte(nodeExpectedHeight)
	for i := 0; i < int(math.Log2(float64(len(t.leafs))))+1; i++ {
		if t.cache[i] == nil {
			continue
		}
		treeHeight = max(treeHeight, t.cache[i].level)
		if treeHeight >= t.maxLevel {
			return 0, errors.New(errors.KsiBufferOverflow).
				AppendMessage(fmt.Sprintf("Tree height exceeding the max level '%d'.", t.maxLevel))
		}
		treeHeight++
	}

	return treeHeight, nil
}

// Count returns leaf count (metadata and masking values are not counted).
func (t *Tree) Count() (int, error) {
	if t == nil {
		return 0, errors.New(errors.KsiInvalidArgumentError)
	}

	return len(t.leafs), nil
}

func (t *Tree) useBlindingMask() bool {
	return t.iv != nil
}

func (t *Tree) resetHasher() error {
	if t == nil {
		return errors.New(errors.KsiInvalidArgumentError)
	}

	if t.hsr == nil {
		hsr, err := t.algorithm.New()
		if err != nil {
			return nil
		}
		t.hsr = hsr
	}
	t.hsr.Reset()
	return nil
}

func (t *Tree) calculateBlindingMask() (hash.Imprint, error) {
	if t == nil || t.iv == nil {
		return nil, errors.New(errors.KsiInvalidArgumentError)
	}

	var (
		mask hash.Imprint
		err  error
	)
	if err := t.resetHasher(); err != nil {
		return nil, err
	}

	// When masking with previous record hash and IV, the blinding mask is computed as m[i] = hash(x[i-1] || IV ),
	// where x[i-1] is the hash value from the leaf node of the previous record.
	//
	// When masking with index and IV, the blinding mask is computed as m[i] = hash(i || IV), where i is the index of
	// the record in a block.
	if t.initLeaf != nil {
		if _, err = t.hsr.Write(t.lastLeaf); err != nil {
			return nil, err
		}
	} else {
		idxBuf := make([]byte, binary.MaxVarintLen64)
		n := binary.PutUvarint(idxBuf, t.leafCount+1)
		if _, err = t.hsr.Write(idxBuf[:n]); err != nil {
			return nil, err
		}
	}
	if _, err = t.hsr.Write(t.iv); err != nil {
		return nil, err
	}

	if mask, err = t.hsr.Imprint(); err != nil {
		return nil, err
	}
	return mask, nil
}

func (t *Tree) insertNode(n *TreeNode, at int) error {
	if t == nil || n == nil {
		return errors.New(errors.KsiInvalidArgumentError)
	}

	if t.cache[at] != nil {
		tmp, err := t.joinNodes(t.cache[at], n)
		if err != nil {
			return errors.KsiErr(err).AppendMessage("Failed to aggregate nodes.")
		}

		t.cache[at] = nil
		return t.insertNode(tmp, at+1)
	}
	t.cache[at] = n

	return nil
}

func (t *Tree) joinNodes(l, r *TreeNode) (*TreeNode, error) {
	if t == nil || l == nil || r == nil {
		return nil, errors.New(errors.KsiInvalidArgumentError)
	}

	lvl := max(l.level, r.level)
	if lvl == t.maxLevel {
		return nil, errors.New(errors.KsiBufferOverflow).
			AppendMessage(fmt.Sprintf("Tree height exceeding the max level '%d'.", t.maxLevel))
	}
	lvl++

	if err := t.resetHasher(); err != nil {
		return nil, err
	}
	if _, err := t.hsr.Write(l.hshValue); err != nil {
		return nil, err
	}
	if _, err := t.hsr.Write(r.hshValue); err != nil {
		return nil, err
	}
	if _, err := t.hsr.Write([]byte{lvl}); err != nil {
		return nil, err
	}

	hsh, err := t.hsr.Imprint()
	if err != nil {
		return nil, err
	}

	tmp := &TreeNode{
		tree:     t,
		hshValue: hsh,
		level:    lvl,
		lChild:   l,
		rChild:   r,
	}
	if err := t.notifyAggregateListener(tmp); err != nil {
		return nil, err
	}

	l.parent = tmp
	r.parent = tmp

	return tmp, nil
}

func max(l, r byte) byte {
	if l > r {
		return l
	}
	return r
}

// Aggregate aggregates currently added leafs (current state of the tree builder) and returns the root hash value and
// tree height.
//
// The method also finalizes the tree builder instance, meaning that no leafs can be added after invocation of
// this function. Sequential invocation of this function will return the buffered root hash and its level.
func (t *Tree) Aggregate() (hash.Imprint, byte, error) {
	if t == nil {
		return nil, 0, errors.New(errors.KsiInvalidArgumentError)
	}
	if len(t.leafs) == 0 {
		return nil, 0, errors.New(errors.KsiInvalidStateError).AppendMessage("Tree is empty.")
	}

	if t.aggrRoot == nil {
		var root *TreeNode
		var err error
		for i := 0; i < (int(math.Log2(float64(len(t.leafs)))) + 1); i++ {
			if t.cache[i] == nil {
				continue
			}

			if root == nil {
				root = t.cache[i]
			} else {
				root, err = t.joinNodes(t.cache[i], root)
				if err != nil {
					return nil, 0, errors.KsiErr(err).AppendMessage("Failed to aggregate nodes.")
				}
			}
		}
		t.aggrRoot = root
		t.aggrTime = time.Now()
	}
	return t.aggrRoot.hshValue, t.aggrRoot.level, nil
}

// LastLeaf returns last leaf added to the underling Merkle tree.
//
// When using inter-linking of the blocks, the last leaf node of the previous block is used for setting up every
// next block (see TreeOptMaskingWithPreviousLeaf).
//
// Note that when blinding mask is used, the returned hash value does not match with the last added node hash
// value but instead is the result of concatenation and hashing of input data with blinding mask
// (see TreeOptMaskingWithPreviousLeaf and TreeOptMaskingWithIndex).
func (t *Tree) LastLeaf() (hash.Imprint, error) {
	if t == nil {
		return nil, errors.New(errors.KsiInvalidArgumentError)
	}
	return t.lastLeaf, nil
}

// Leafs returns the added leafs in the same order they have been set.
// Only applicable for a finalized tree (see (Tree).Aggregate())
func (t *Tree) Leafs() ([]*TreeNode, error) {
	if t == nil {
		return nil, errors.New(errors.KsiInvalidArgumentError)
	}
	// Only return for a finalized tree.
	if t.aggrRoot == nil {
		return nil, errors.New(errors.KsiInvalidStateError).AppendMessage("The tree has not been finalized.")
	}
	return t.leafs, nil
}

// Level returns the aggregation level for the receiver tree node (leaf).
func (n *TreeNode) Level() (byte, error) {
	if n == nil {
		return 0, errors.New(errors.KsiInvalidArgumentError)
	}
	return n.level, nil
}

// AggregationChain returns the aggregation chain for the receiver tree node (leaf).
// Only applicable for a finalized tree (see (Tree).Aggregate())
func (n *TreeNode) AggregationChain() (*pdu.AggregationChain, error) {
	if n == nil || n.tree == nil {
		return nil, errors.New(errors.KsiInvalidArgumentError)
	}
	// Only return for a finalized tree.
	if n.tree.aggrRoot == nil {
		return nil, errors.New(errors.KsiInvalidStateError).AppendMessage("The tree has not been finalized.")
	}

	aggrChainBuilder, err := pdu.NewAggregationChainBuilder(pdu.BuildFromImprint(n.tree.algorithm, n.hshValue))
	if err != nil {
		return nil, err
	}

	// Retrieve chain links.
	node := n
	for node != nil {
		// Append link in case it is not the root node.
		if node.parent != nil {
			levelCorr := node.parent.level - node.level - 1
			isLeft := node == node.parent.lChild

			/* Determine the side of the sibling. */
			var sibling *TreeNode
			if isLeft {
				sibling = node.parent.rChild
			} else {
				sibling = node.parent.lChild
			}

			/* Check if this is a tree leaf. */
			if sibling.leafValue != nil {
				switch value := sibling.leafValue.(type) {
				case hash.Imprint:
					log.Debug("sibling.leafValue.(type) -> hash.Imprint : ", value)
					if err := aggrChainBuilder.AddChainLink(isLeft, levelCorr, pdu.LinkSiblingHash(value)); err != nil {
						return nil, err
					}
				case *pdu.MetaData:
					log.Debug("sibling.leafValue.(type) -> *MetaData : ", value)
					if err := aggrChainBuilder.AddChainLink(isLeft, levelCorr, pdu.LinkSiblingMetaData(value)); err != nil {
						return nil, err
					}
				default:
					return nil, errors.New(errors.KsiInvalidFormatError).
						AppendMessage(fmt.Sprintf("Unsupported leaf value type: %T", value))
				}
			} else {
				if err := aggrChainBuilder.AddChainLink(isLeft, levelCorr, pdu.LinkSiblingHash(sibling.hshValue)); err != nil {
					return nil, err
				}
			}
		}
		node = node.parent
	}

	return aggrChainBuilder.Build()
}

// UserCtx returns the user context private pointer associated with the the input data which receiver tree node (leaf)
// represents. See (Tree).AddNode(.., userCtx)
func (n *TreeNode) UserCtx() (interface{}, error) {
	if n == nil {
		return nil, errors.New(errors.KsiInvalidArgumentError)
	}
	return n.userCtx, nil
}
