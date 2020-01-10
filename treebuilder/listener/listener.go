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

// Package listener defines the tree builder aggregation process listeners.
//
// The use of the defined listener interfaces provides the ability for runtime tree serialization.
//
// In combination with block signer (see blocksigner package) also the tree root signature can be acquired and
// serialized along with the tree hashes without the need to store KSI signatures for every added record.
package listener

import "github.com/guardtime/goksi/hash"

// RecordHashListener is notified whenever a new document hash is added to a tree (see (Tree).AddNode()).
type RecordHashListener interface {
	TreeRecordHash(imprint hash.Imprint, level byte) error
}

// MetadataListener is notified whenever a metadata record is added to a tree (see (Tree).AddNode()).
type MetadataListener interface {
	TreeMetadata(metaTlv []byte) error
}

// AggregateHashListener is notified whenever an intermediate aggregate hash value is computed and added to a tree.
type AggregateHashListener interface {
	TreeAggregateHash(imprint hash.Imprint, level byte) error
}
