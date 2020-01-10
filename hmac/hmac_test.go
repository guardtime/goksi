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

package hmac

import (
	stdhash "hash"
	"testing"

	"github.com/guardtime/goksi/errors"
	"github.com/guardtime/goksi/hash"
	"github.com/guardtime/goksi/test/utils"
)

var (
	testKey               = "secret"
	testMessage           = "correct horse battery staple"
	sha256testMessageHMAC = utils.StringToBin("01f24bedb4e103c9bf78b312b570af224ceb090e0bcda18c2c106943269259cfed")
	sha256testEmptyHMAC   = utils.StringToBin("01f9e66e179b6747ae54108f82f8ade8b3c25d76fd30afde6c395822c530196169")
)

func TestUnitHmac(t *testing.T) {
	hsr, err := New(hash.SHA2_256, []byte(testKey))
	if err != nil {
		t.Fatalf("Failed to initialize HMAC hash function: %s.", err)
	}

	if _, err := hsr.Write([]byte(testMessage)); err != nil {
		t.Fatalf("Failed to write to hasher: %s.", err)
	}
	tmp, err := hsr.Imprint()
	if err != nil {
		t.Fatalf("Failed to extract imprint: %s.", err)
	}

	if !hash.Equal(tmp, sha256testMessageHMAC) {
		t.Fatal("HMAC mismatch")
	}
}

func TestUnitReset(t *testing.T) {
	hsr, err := New(hash.SHA2_256, []byte(testKey))
	if err != nil {
		t.Fatalf("Failed to initialize HMAC hash function: %s.", err)
	}

	if _, err := hsr.Write([]byte(testMessage)); err != nil {
		t.Fatalf("Failed to write to hasher: %s.", err)
	}

	hsr.Reset()

	if _, err := hsr.Write([]byte(testMessage)); err != nil {
		t.Fatalf("Failed to write to hasher: %s.", err)
	}

	tmp, err := hsr.Imprint()
	if err != nil {
		t.Fatalf("Failed to extract imprint: %s.", err)
	}

	if !hash.Equal(tmp, sha256testMessageHMAC) {
		t.Fatal("HMAC mismatch")
	}
}

func TestUnitEmptyHmac(t *testing.T) {
	hsr, err := New(hash.SHA2_256, []byte(testKey))
	if err != nil {
		t.Fatalf("Failed to initialize HMAC hash function: %s.", err)
	}

	tmp, err := hsr.Imprint()
	if err != nil {
		t.Fatalf("Failed to extract imprint: %s.", err)
	}

	if !hash.Equal(tmp, sha256testEmptyHMAC) {
		t.Fatal("HMAC mismatch")
	}
}

func TestUnitUnregisteredAlgorithm(t *testing.T) {
	_, err := New(hash.SM3, []byte(testKey))
	if err == nil {
		t.Fatalf("Must fail with unregistered algorithm.")
	}
}

func TestUnitAlgorithmHashFuncNil(t *testing.T) {
	hash.RegisterHash(hash.SM3,
		func() stdhash.Hash {
			return nil
		},
	)

	_, err := New(hash.SM3, []byte(testKey))
	if err == nil {
		t.Fatalf("Must fail with unregistered algorithm.")
	}
}

func TestUnitAlgorithmHashFuncError(t *testing.T) {
	hash.RegisterHash(hash.SM3,
		func() stdhash.Hash {
			return nil
		},
	)

	_, err := New(hash.SM3, []byte(testKey))
	if err == nil {
		t.Fatalf("Must fail with unregistered algorithm.")
	}
}

func TestGetImprintFromNilHmacHasher(t *testing.T) {
	var hasher *Hasher
	_, err := hasher.Imprint()
	if err == nil {
		t.Fatal("Should not be possible to get imprint from nil hmac hasher.")
	}
}

func TestGetImprintFromNotInitializedHmacHasher(t *testing.T) {
	var hasher Hasher
	_, err := hasher.Imprint()
	if err == nil {
		t.Fatal("Should not be possible to get imprint from not initialized hmac hasher.")
	}
}

func TestWriteToNilHmacHasher(t *testing.T) {
	var hasher *Hasher
	written, err := hasher.Write([]byte{0x12, 0x11, 0x44})
	if err == nil || written != -1 {
		t.Fatal("Should not be possible to write to nil hmac hasher.")
	}
}

func TestWriteToNotInitializedHmacHasher(t *testing.T) {
	var hasher Hasher
	written, err := hasher.Write([]byte{0x12, 0x11, 0x44})
	if err == nil || written != -1 {
		t.Fatal("Should not be possible to write to not initialized hmac hasher.")
	}
}

func TestGetSizeFromNilHmacHasher(t *testing.T) {
	var hasher *Hasher
	val := hasher.Size()
	if val != 0 {
		t.Fatal("Nil hmac hasher size must be 0.")
	}
}

func TestGetSizeFromNotInitializedHmacHasher(t *testing.T) {
	var hasher Hasher
	val := hasher.Size()
	if val != 0 {
		t.Fatal("Not initialized hmac hasher size must be 0.")
	}
}

func TestGetSizeFromHmacHasher(t *testing.T) {
	hasher, err := New(hash.SHA2_256, []byte{0x45, 0x46, 0x47, 0x48})
	if err != nil {
		t.Fatal("Failed to create hmac hasher: ", err)
	}
	val := hasher.Size()
	if val == 0 {
		t.Fatal("Nil hmac hasher size must be 0.")
	}
}

func TestGetBlockSizeFromNilHmacHasher(t *testing.T) {
	var hasher *Hasher
	val := hasher.BlockSize()
	if val != 0 {
		t.Fatal("Nil hmac hasher block size must be 0.")
	}
}

func TestGetBlockSizeFromNotInitializedHmacHasher(t *testing.T) {
	var hasher Hasher
	val := hasher.BlockSize()
	if val != 0 {
		t.Fatal("Not initialized hmac hasher blocksize must be 0.")
	}
}

func TestGetBlockSizeFromHmacHasher(t *testing.T) {
	hasher, err := New(hash.SHA2_256, []byte{0x45, 0x46, 0x47, 0x48})
	if err != nil {
		t.Fatal("Failed to create hmac hasher: ", err)
	}
	val := hasher.BlockSize()
	if val == 1024 {
		t.Fatal("Unexpected blocksize: ", val)
	}
}

func TestResetNilHmacHasher(t *testing.T) {
	var hasher *Hasher
	hasher.Reset()
}

func TestResetNotInitializedHmacHasher(t *testing.T) {
	var hasher Hasher
	hasher.Reset()
}

func TestUnitWorkWithUninitialized(t *testing.T) {
	hasher := &Hasher{}
	x := []byte{0x01}

	assertUninitialzedError := func(t *testing.T, err error) {
		if err == nil {
			t.Fatal("Previous call should have been failed.")
		}

		if ec := errors.KsiErr(err).Code(); ec != errors.KsiInvalidArgumentError {
			t.Fatalf("Invalid error code: expecting %v, but got %v.", errors.KsiInvalidArgumentError, ec)
		}
	}

	_, err := hasher.Write(x)
	assertUninitialzedError(t, err)

	_, err = hasher.Imprint()
	assertUninitialzedError(t, err)

	/* Following calls must not panic. */
	hasher.Reset()

	if s := hasher.BlockSize(); s != 0 {
		t.Fatalf("BlockSize for not initialized HMAC hasher must be 0, but is %v!", s)
	}

	if s := hasher.Size(); s != 0 {
		t.Fatalf("BlockSize for not initialized HMAC hasher must be 0, but is %v!", s)
	}
}
