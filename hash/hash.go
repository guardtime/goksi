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

// Package hash implements the hash functions identifiers (see Algorithm) and hash computation functions.
//
// The result of a hash computation is returned in a form of an 'imprint' (see Imprint). An imprint represents a
// hash value and consists of a one-octet hash function identifier (see Algorithm) concatenated with the hash
// value itself.
//
// In order to use a hash functions for cryptographic computation, the functions must be registered. Some functions
// are registered by default (see Registered()), others need to be registered prior to their use (see RegisterHash()).
package hash

import (
	"crypto"
	"fmt"
	"hash"
	"strings"

	// Indirectly import packages from std library.
	// Additional packages can be imported by the user.
	_ "crypto/sha1"
	_ "crypto/sha256"
	_ "crypto/sha512"

	"github.com/guardtime/goksi/errors"
)

// Algorithm is the hash functions identifier.
type Algorithm int

const (
	// SHA1 is SHA-1 algorithm. Deprecated as of 01.07.2016.
	SHA1 Algorithm = 0x00

	// SHA2_256 is SHA-256 algorithm.
	SHA2_256 Algorithm = 0x01
	// RIPEMD160 is RIPEMD-160 algorithm.
	// In order to use the algorithm for hash computation, "golang.org/x/crypto/ripemd160" needs to be imported indirectly.
	RIPEMD160 Algorithm = 0x02
	// SHA2_384 is SHA-384 algorithm.
	SHA2_384 Algorithm = 0x04
	// SHA2_512 is SHA-512 algorithm.
	SHA2_512 Algorithm = 0x05

	// SHA3_224 is SHA3-244 algorithm.
	// In order to use SHA3 hash algorithm, the "golang.org/x/crypto/sha3" package needs to be imported indirectly and
	// the algorithm registered (see RegisterHash()).
	SHA3_224 Algorithm = 0x07
	// SHA3_256 is SHA3-256 algorithm.
	// In order to use SHA3 hash algorithm, the "golang.org/x/crypto/sha3" package needs to be imported indirectly and
	// the algorithm registered (see RegisterHash()).
	SHA3_256 Algorithm = 0x08
	// SHA3_384 is SHA3-384 algorithm.
	// In order to use SHA3 hash algorithm, the "golang.org/x/crypto/sha3" package needs to be imported indirectly and
	// the algorithm registered (see RegisterHash()).
	SHA3_384 Algorithm = 0x09
	// SHA3_512 is SHA3-512 algorithm.
	// In order to use SHA3 hash algorithm, the "golang.org/x/crypto/sha3" package needs to be imported indirectly and
	// the algorithm registered (see RegisterHash()).
	SHA3_512 Algorithm = 0x0a

	// SM3 algorithm.
	// In order to use SM3 hash algorithm, the implementation needs to be registered (see RegisterHash()).
	SM3 Algorithm = 0x0b

	// SHA_NA defines an invalid algorithm.
	SHA_NA Algorithm = 0x100
)

// Default is the recommended algorithm ID for hash computation.
const Default = SHA2_256

type hashFuncInfo struct {
	// Algorithm ID as defined in the crypto package.
	cryptoId crypto.Hash
	// User registered hasher constructor.
	newHash func() hash.Hash
	// Digest bit count.
	size int
	// Algorithm function underlying block size.
	blockSize int
	// The time the function has been marked as deprecated.
	deprecatedFrom int64
	// The time the function has been marked as obsolete.
	obsoleteFrom int64
	// Accepted names for this hash algorithm.
	names []string
}

var hashInfoMap = map[Algorithm]hashFuncInfo{
	SHA1:      {crypto.SHA1, nil, 160, 512, 1467331200, 0, []string{"SHA-1", "SHA1", ""}},
	SHA2_256:  {crypto.SHA256, nil, 256, 512, 0, 0, []string{"SHA-256", "SHA2-256", "SHA-2", "SHA2", "SHA256", "DEFAULT", ""}},
	RIPEMD160: {crypto.RIPEMD160, nil, 160, 512, 0, 0, []string{"RIPEMD-160", "RIPEMD160", ""}},
	SHA2_384:  {crypto.SHA384, nil, 384, 1024, 0, 0, []string{"SHA-384", "SHA384", "SHA2-384", ""}},
	SHA2_512:  {crypto.SHA512, nil, 512, 1024, 0, 0, []string{"SHA-512", "SHA512", "SHA2-512", ""}},
	SHA3_224:  {crypto.SHA3_224, nil, 224, 1152, 0, 0, []string{"SHA3-224", ""}},
	SHA3_256:  {crypto.SHA3_256, nil, 256, 1088, 0, 0, []string{"SHA3-256", ""}},
	SHA3_384:  {crypto.SHA3_384, nil, 384, 832, 0, 0, []string{"SHA3-384", ""}},
	SHA3_512:  {crypto.SHA3_512, nil, 512, 576, 0, 0, []string{"SHA3-512"}},
	SM3:       {0, nil, 256, 512, 0, 0, []string{"SM-3", "SM3", ""}},
}

func init() {
	if crypto.SHA1.Available() {
		RegisterHash(SHA1, crypto.SHA1.New)
	}

	if crypto.SHA256.Available() {
		RegisterHash(SHA2_256, crypto.SHA256.New)
	}
	if crypto.SHA384.Available() {
		RegisterHash(SHA2_384, crypto.SHA384.New)
	}
	if crypto.SHA512.Available() {
		RegisterHash(SHA2_512, crypto.SHA512.New)
	}

	// In order to be registered, "golang.org/x/crypto/ripemd160" needs to be imported indirectly by the user.
	if crypto.RIPEMD160.Available() {
		RegisterHash(RIPEMD160, crypto.RIPEMD160.New)
	}

	// Do not register SHA3 algorithm automatically (keep in sync with other KSI libraries).
	/*
		// In order to be registered, "golang.org/x/crypto/sha3" needs to be imported indirectly by the user.
		if crypto.SHA3_224.Available() {
			RegisterHash(SHA3_224, crypto.SHA3_224.New)
		}
		if crypto.SHA3_256.Available() {
			RegisterHash(SHA3_256, crypto.SHA3_256.New)
		}
		if crypto.SHA3_384.Available() {
			RegisterHash(SHA3_384, crypto.SHA3_384.New)
		}
		if crypto.SHA3_512.Available() {
			RegisterHash(SHA3_512, crypto.SHA3_512.New)
		}
	*/
}

// RegisterHash registers a function that returns a new instance of the given
// hash function. This is intended to be called from the init function in
// packages that implement hash functions.
func RegisterHash(h Algorithm, f func() hash.Hash) {
	if info, ok := hashInfoMap[h]; ok {
		info.newHash = f
		hashInfoMap[h] = info
		return
	}
	panic(fmt.Sprintf("RegisterHash() unknown hash function: %d.", h))
}

// Trusted is used to check if the given hash algorithm is trusted. If the algorithm has been marked
// as deprecated or obsolete, it will return false (otherwise true is returned). It is not checked if
// the deprecated and/or obsolete dates have passed but operation is impossible as soon as one of the
// dates is set. The intention is to make the change apparent right after upgrading the library rather
// than wait and possibly break normal operations in an apparently arbitrary moment.
func (a Algorithm) Trusted() bool {
	if info, ok := hashInfoMap[a]; ok {
		return info.obsoleteFrom == 0 && info.deprecatedFrom == 0
	}
	return false
}

// Defined reports whether the given hash function is defined by the library.
func (a Algorithm) Defined() bool {
	_, ok := hashInfoMap[a]
	return ok
}

// Registered checks whether the given hash algorithm is supported,
// meaning the hash value can be calculated using the API.
func (a Algorithm) Registered() bool {
	if info, ok := hashInfoMap[a]; ok {
		return info.newHash != nil
	}
	return false
}

// String returns a string representation of the given hash algorithm.
// Returns empty string in case of unknown algorithm.
func (a Algorithm) String() string {
	if info, ok := hashInfoMap[a]; ok {
		return info.names[0]
	}
	return ""
}

// ByName returns the hash function specified by the case insensitive string parameter name.
//
// To verify the correctness of the returned value, (Algorithm).Defined() or (Algorithm).Trusted() function must be used.
// The valid inputs are:
//  - "default" for the configured default hash algorithm or one of the following:
//  - "sha-1", "sha1",
//  - "sha-256", "sha2-256", "sha-2", "sha2", "sha256",
//  - "ripemd-160", "ripemd160",
//  - "sha-384", "sha384", "sha2-384",
//  - "sha-512", "sha512", "sha2-512",
//  - "sha3-224", "sha3-256", "sha3-384", "sha3-512",
//  - "sm-3", "sm3".
// The SHA-2 family names do not require the infix "2" as opposed to the SHA-3 family where the infix "3" is mandatory.
// This means "sha-256" is unambiguously the 256-bit version of SHA-2.
//
// Returns hash function, or KsiUnknownHashAlgorithm error in case of unrecognized name.
func ByName(name string) (Algorithm, error) {
	for algo, info := range hashInfoMap {
		for _, v := range info.names {
			if strings.EqualFold(v, name) {
				return algo, nil
			}
		}
	}
	return SHA_NA, errors.New(errors.KsiUnknownHashAlgorithm).
		AppendMessage(fmt.Sprintf("Unknown hash algorithm: %s.", name))
}

// DeprecatedFrom reports time the hash function has been marked as deprecated.
// Returns hash algorithm deprecate time as a Unix time, the number of seconds elapsed since January 1, 1970 UTC (1970-01-01T00:00:00Z),
// or 0 if not set. Returns an error if unknown.
func (a Algorithm) DeprecatedFrom() (int64, error) {
	if info, ok := hashInfoMap[a]; ok {
		return info.deprecatedFrom, nil
	}
	return 0, errors.New(errors.KsiUnknownHashAlgorithm).
		AppendMessage(fmt.Sprintf("Unknown hash algorithm: %d.", a))
}

// ObsoleteFrom reports time the hash function has been marked as obsolete.
// Returns hash algorithm obsolete time as a Unix time, the number of seconds elapsed since January 1, 1970 UTC (1970-01-01T00:00:00Z),
// or 0 if not set. Returns an error if unknown.
func (a Algorithm) ObsoleteFrom() (int64, error) {
	if info, ok := hashInfoMap[a]; ok {
		return info.obsoleteFrom, nil
	}
	return 0, errors.New(errors.KsiUnknownHashAlgorithm).
		AppendMessage(fmt.Sprintf("Unknown hash algorithm: %d.", a))
}

// FunctionStatus describes the hash function state at a certain time.
//
// Algorithm functions are being deprecated for which it has become evident that collisions have been found and are affordable.
// A deprecation date D (based on when the collisions become affordable) will be assigned to the deprecated function.
// In case the time of the signature can be trusted (e.g. it is extended to a publication before D, or does not have the
// deprecated hash function in its calendar chain), the signature remains valid as long as its time is before D.
//
// Similarly, when 2nd pre-image resistance is broken, the function is marked as obsolete since date F. When the 2nd pre-image
// resistance is broken, verification of the signature will always fail by default if such function is used somewhere in the
// signature.
type FunctionStatus byte

const (
	// Unknown state.
	Unknown = FunctionStatus(iota)
	// Normal function can be used for all hashing purposes with no restrictions.
	Normal
	// Deprecated (since date) - the function has been deprecated since the given date due to the loss of collision resistance.
	Deprecated
	// Obsolete (since date) - the function is obsolete since the given date due to loss of 2nd pre-image resistance.
	Obsolete
)

// StatusAt checks the status of the hash function at a given time.
// Returns Deprecated if the hash algorithm was deprecated at the given time;
// Obsolete if the hash algorithm was obsolete at the given time; or an error.
func (a Algorithm) StatusAt(at int64) FunctionStatus {
	if info, ok := hashInfoMap[a]; ok {
		if info.obsoleteFrom != 0 && info.obsoleteFrom <= at {
			return Obsolete
		}
		if info.deprecatedFrom != 0 && info.deprecatedFrom <= at {
			return Deprecated
		}
		return Normal
	}
	return Unknown
}

// HashFunc returns the underling hash function.
func (a Algorithm) HashFunc() (hash.Hash, error) {
	if info, ok := hashInfoMap[a]; ok {
		if info.newHash == nil {
			return nil, errors.New(errors.KsiInvalidStateError).
				AppendMessage(fmt.Sprintf("Hash algorithm is not initialized: %s.", a.String()))
		}
		return info.newHash(), nil
	}
	return nil, errors.New(errors.KsiUnknownHashAlgorithm).
		AppendMessage(fmt.Sprintf("Hash algorithm is not supported: %d.", a))
}

// Size returns the resulting digest length in bytes.
// In case of an error, a negative value is returned.
func (a Algorithm) Size() int {
	if info, ok := hashInfoMap[a]; ok {
		return info.size >> 3
	}
	return -1
}

// BlockSize returns the size of the data block the underlying hash algorithm operates upon in bytes.
// In case of an error, a negative value is returned.
func (a Algorithm) BlockSize() int {
	if info, ok := hashInfoMap[a]; ok {
		return info.blockSize >> 3
	}
	return -1
}

// ZeroImprint returns a zero imprint for the given algorithm.
func (a Algorithm) ZeroImprint() Imprint {
	if !a.Defined() {
		return nil
	}
	tmp := make(Imprint, 1+a.Size())
	tmp[0] = byte(a)
	return tmp
}

// ListSupported returns a slice of supported hash functions.
func ListSupported() []Algorithm {
	var tmp []Algorithm
	for algo := range hashInfoMap {
		if algo.Registered() {
			tmp = append(tmp, algo)
		}
	}
	return tmp
}

// ListDefined returns a slice of available hash functions.
func ListDefined() []Algorithm {
	var tmp []Algorithm
	for algo := range hashInfoMap {
		tmp = append(tmp, algo)
	}
	return tmp
}
