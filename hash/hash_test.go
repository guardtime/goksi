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

package hash

import (
	"crypto"
	"strings"
	"testing"
	"time"

	"github.com/guardtime/goksi/errors"
	"github.com/guardtime/goksi/test/utils"
)

func verifyHashFuncID(t *testing.T, hshFunc Algorithm, expected byte) {
	if hshFunc != Algorithm(expected) {
		t.Errorf("Wrong KSI algo id: %d (isDefined: %d).", hshFunc, expected)
	}
}

func TestUnitHashFuncId(t *testing.T) {
	verifyHashFuncID(t, SHA1, 0x00)
	verifyHashFuncID(t, SHA2_256, 0x01)
	verifyHashFuncID(t, RIPEMD160, 0x02)
	verifyHashFuncID(t, SHA2_384, 0x04)
	verifyHashFuncID(t, SHA2_512, 0x05)
	verifyHashFuncID(t, SHA3_224, 0x07)
	verifyHashFuncID(t, SHA3_256, 0x08)
	verifyHashFuncID(t, SHA3_384, 0x09)
	verifyHashFuncID(t, SHA3_512, 0x0a)
	verifyHashFuncID(t, SM3, 0x0b)
}

func TestUnitHasherCreateError(t *testing.T) {
	if _, err := SM3.New(); err == nil {
		t.Fatalf("Must return error. SM3 is not supported by API.")
	}
}

func TestWriteToNilDataHasher(t *testing.T) {
	var hasher *DataHasher
	written, err := hasher.Write([]byte{0x32})
	if err == nil || written != -1 {
		t.Fatal("Should not be possible to write to nil data hasher.")
	}
}

func TestWriteToNotInitializedDataHasher(t *testing.T) {
	var hasher DataHasher
	written, err := hasher.Write([]byte{0x32})
	if err == nil || written != -1 {
		t.Fatal("Should not be possible to write to not initialized data hasher.")
	}
}

func TestGetImprintFromNilDataHasher(t *testing.T) {
	var hasher *DataHasher
	_, err := hasher.Imprint()
	if err == nil {
		t.Fatal("Should not be possible to get imprint from nil data hasher.")
	}
}

func TestGetImprintFromNotInitializedDataHasher(t *testing.T) {
	var hasher DataHasher
	_, err := hasher.Imprint()
	if err == nil {
		t.Fatal("Should not be possible to get imprint from nil data hasher.")
	}
}

func TestResetNilDataHasher(t *testing.T) {
	var hasher *DataHasher
	hasher.Reset()
}

func TestResetNotInitializedDataHasher(t *testing.T) {
	var hasher DataHasher
	hasher.Reset()
}

func TestGetSizeFromNilDataHasher(t *testing.T) {
	var hasher *DataHasher
	if !(hasher.Size() < 0) {
		t.Fatal("Unexpected hasher size from nil data hasher.")
	}
}

func TestGetSizeFromNotInitializedDataHasher(t *testing.T) {
	var hasher DataHasher
	if !(hasher.Size() < 0) {
		t.Fatal("Unexpected hasher size from not initialized data hasher.")
	}
}

func TestGetSizeFromOkDatahasher(t *testing.T) {
	hasher, err := SHA2_256.New()
	if err != nil {
		t.Fatal("Failed to create data hasher: ", err)
	}
	size := hasher.Size()
	if size != SHA2_256.Size() {
		t.Fatal("Empty data hasher should have size of 32, but was: ", size)
	}
}

func TestGetBlockSizeFromNilDataHasher(t *testing.T) {
	var hasher *DataHasher
	if !(hasher.BlockSize() < 0) {
		t.Fatal("Unexpected hasher block size from nil data hasher.")
	}
}

func TestGetBlockSizeFromNotInitializedDataHasher(t *testing.T) {
	var hasher DataHasher
	if !(hasher.BlockSize() < 0) {
		t.Fatal("Unexpected hasher block size from not initialized data hasher.")
	}
}

func TestGetBlockSizeFromOkDatahasher(t *testing.T) {
	hasher, err := SHA2_256.New()
	if err != nil {
		t.Fatal("Failed to create data hasher: ", err)
	}
	size := hasher.BlockSize()
	if size != SHA2_256.BlockSize() {
		t.Fatal("Empty data hasher should have block size of 1024, but was: ", size)
	}
}

func TestUnitDefaultAlgorithm(t *testing.T) {
	hshFunc, err := ByName("default")
	if err != nil {
		t.Fatalf("Failed to get default algo: %s.", err)
	}

	if hshFunc != Default {
		t.Fatalf("Wrong hash function: %s.", hshFunc)
	}
}

func verifyHash(t *testing.T, alg Algorithm, in string, res string) {
	hsr, err := alg.New()
	if err != nil {
		t.Fatal("Failed to extract new hash function: ", err)
	}

	if _, err := hsr.Write([]byte(in)); err != nil {
		t.Fatalf("Failed to write to hasher: %s.", err)
	}
	tmp, err := hsr.Imprint()
	if err != nil {
		t.Fatalf("Failed to extract imprint: %s.", err)
	}
	verifyHashFuncID(t, alg, tmp[0])

	if !Equal(tmp[1:], utils.StringToBin(res)) {
		t.Fatalf("Unexpected result for id: %s.", alg)
	}
}

var (
	testAlgorithmData = []struct {
		isDefined    bool
		isRegistered bool
		isTrusted    bool
		algo         Algorithm
		name         string
	}{
		{true, true, false, SHA1, "SHA-1"},
		{true, true, true, SHA2_256, "SHA-256"},
		{true, false, true, RIPEMD160, "RIPEMD-160"},
		{true, true, true, SHA2_384, "SHA-384"},
		{true, true, true, SHA2_512, "SHA-512"},
		{true, false, true, SHA3_224, "SHA3-224"},
		{true, false, true, SHA3_256, "SHA3-256"},
		{true, false, true, SHA3_384, "SHA3-384"},
		{true, false, true, SHA3_512, "SHA3-512"},
		{true, false, true, SM3, "SM-3"},

		{false, false, false, -1, ""},
		{false, false, false, SHA_NA, ""},
	}
)

func TestUnitAlgorithm_Defined(t *testing.T) {
	for i, td := range testAlgorithmData {
		if td.algo.Defined() {
			if !td.isDefined {
				t.Errorf("[%d] Algorithm is not defined: %d", i, int(td.algo))
			}
		} else {
			if td.isDefined {
				t.Errorf("[%d] Algorithm defined: %d", i, int(td.algo))
			}
		}
	}
}

func TestUnitAlgorithm_Registered(t *testing.T) {
	for i, td := range testAlgorithmData {
		if td.algo.Registered() {
			if !td.isRegistered {
				t.Errorf("[%d] Algorithm is not registered: %d", i, int(td.algo))
			}
		} else {
			if td.isRegistered {
				t.Errorf("[%d] Algorithm registered: %d", i, int(td.algo))
			}
		}
	}
}

func TestUnitAlgorithm_Trusted(t *testing.T) {
	for i, td := range testAlgorithmData {
		if td.algo.Trusted() {
			if !td.isTrusted {
				t.Errorf("[%d] Algorithm is not trusted: %d", i, int(td.algo))
			}
		} else {
			if td.isTrusted {
				t.Errorf("[%d] Algorithm trusted: %d", i, int(td.algo))
			}
		}
	}
}

func TestUnitAlgorithm_String(t *testing.T) {
	for i, td := range testAlgorithmData {
		name := td.algo.String()

		if name != td.name {
			t.Errorf("[%d] Algorithm string mismatch: '%s' vs '%s'", i, name, td.name)
		}
	}
}

func TestUnitAlgorithm_ByName(t *testing.T) {
	for i, td := range testAlgorithmData {
		if td.name != "" {
			algo, err := ByName(td.name)
			if err != nil {
				t.Fatalf("[%d] Algorithm name mismatch:\n%s", i, err)
			}
			if algo != td.algo {
				t.Errorf("[%d] Algorithm mismatch: %d vs %d", i, int(algo), int(td.algo))
			}
		}
	}

	algo, err := ByName("SHA-xxx")
	if err == nil {
		t.Error("Must return error.")
	}
	if algo != SHA_NA {
		t.Error("Invalid algorithm mast be returned")
	}
}

func TestUnitHasher(t *testing.T) {
	const input = "Once I was blind but now I C!"

	verifyHash(t, SHA1, input, "17feaf7afb41e469c907170915eab91aa9114c05")
	verifyHash(t, SHA2_256, input, "4d151c05f29a9757ff252ff1000fdcd28f88caaa52c020bc7d25e683890e7335")
	verifyHash(t, SHA2_384, input, "4495385793894ac9a2cc1b2d8760da3ce50d14a193b19166417d503d853ad3588689e5a6b0e65675367394a207cac264")
	verifyHash(t, SHA2_512, input, "2dcee3bebeeec061751c7e2c886fddb069502c3c71e1f70272d77a64c092e51b6a262d208939cc557de7650da347b08f643d515ff8009a7342454e73247761dd")
	// verifyHash(t, RIPEMD160, input, "404a79f20439e1d82492ed73ad413b6d95d643a6")
	// verifyHash(t, SHA3_224, input, "a6baf12a64284ac71f9cf63cb7cb60391b3cd7e291393edb04daad83")
	// verifyHash(t, SHA3_256, input, "05d89ebd9e3ecb536ad11cac3bda51a7a81e043f7843274b49e7893ab161ffc6")
	// verifyHash(t, SHA3_384, input, "3b45a4e97d912b2cb05f6c4ea659714c3db95280f37117a05e679338a5064fd434b1c73164c51ec9687ce39096d7b7b7")
	// verifyHash(t, SHA3_512, input, "90f8c16c5e7d134deaf1c64a9ab79851ac7f7c1718c918c6ae902b84d8954de94b2d96bc2abf8fbd13a6b5d4f108c2ec0e64b912d379f4f970efa079c01a2eb7")
	// verifyHash(t, SM3, input, "")
}

func TestUnitHasherFromInvalidAlgorithm(t *testing.T) {
	_, err := SHA_NA.New()
	if err == nil {
		t.Fatal("Must fail.")
	}
}

func TestUnitHasherReset(t *testing.T) {
	hsr, err := SHA2_256.New()
	if err != nil {
		t.Fatal("Failed to extract new hash function: ", err)
	}

	if _, err := hsr.Write([]byte("random")); err != nil {
		t.Fatalf("Failed to write to hasher: %s.", err)
	}
	hsr.Reset()
	if _, err := hsr.Write([]byte("LAPTOP")); err != nil {
		t.Fatalf("Failed to write to hasher: %s.", err)
	}
	tmp, err := hsr.Imprint()
	if err != nil {
		t.Fatalf("Failed to extract imprint: %s.", err)
	}

	if !Equal(tmp, utils.StringToBin("0111a700b0c8066c47ecba05ed37bc14dcadb238552d86c659342d1d7e87b8772d")) {
		t.Fatalf("Result mismatch.")
	}
}

func TestUnitMultipleWrite(t *testing.T) {
	var (
		testWords    = []string{"correct ", "horse ", "battery ", "staple"}
		testExpected = []byte{0x01,
			0xc4, 0xbb, 0xcb, 0x1f, 0xbe, 0xc9, 0x9d, 0x65, 0xbf, 0x59, 0xd8, 0x5c, 0x8c, 0xb6, 0x2e, 0xe2,
			0xdb, 0x96, 0x3f, 0x0f, 0xe1, 0x06, 0xf4, 0x83, 0xd9, 0xaf, 0xa7, 0x3b, 0xd4, 0xe3, 0x9a, 0x8a}
	)

	hsr, err := SHA2_256.New()
	if err != nil {
		t.Fatal("Failed to extract new hash function: ", err)
	}
	for _, word := range testWords {
		if _, err := hsr.Write([]byte(word)); err != nil {
			t.Fatalf("Failed to write to hasher: %s.", err)
		}
	}
	result, err := hsr.Imprint()
	if err != nil {
		t.Fatalf("Failed to extract imprint: %s.", err)
	}

	if !Equal(result, testExpected) {
		t.Fatalf("Result mismatch.")
	}
}

func TestUnitMultipleWriteSum(t *testing.T) {
	var (
		testWords    = []string{"correct ", "horse ", "battery ", "staple"}
		testExpected = []byte{0x01,
			0xc4, 0xbb, 0xcb, 0x1f, 0xbe, 0xc9, 0x9d, 0x65, 0xbf, 0x59, 0xd8, 0x5c, 0x8c, 0xb6, 0x2e, 0xe2,
			0xdb, 0x96, 0x3f, 0x0f, 0xe1, 0x06, 0xf4, 0x83, 0xd9, 0xaf, 0xa7, 0x3b, 0xd4, 0xe3, 0x9a, 0x8a}
	)

	hsr, err := SHA2_256.New()
	if err != nil {
		t.Fatal("Failed to extract new hash function: ", err)
	}

	var prevImprint []byte
	for _, word := range testWords {
		if _, err := hsr.Write([]byte(word)); err != nil {
			t.Fatalf("Failed to write to hasher: %s.", err)
		}

		tmp, err := hsr.Imprint()
		if err != nil {
			t.Fatalf("Failed to extract imprint: %s.", err)
		}

		if Equal(prevImprint, tmp) {
			t.Fatalf("Results should not match.")
		}
		prevImprint = tmp
	}
	imprint, err := hsr.Imprint()
	if err != nil {
		t.Fatalf("Failed to extract imprint: %s.", err)
	}

	if !Equal(imprint, testExpected) {
		t.Fatalf("Result mismatch.")
	}
}

func TestUnitParallelHasher(t *testing.T) {
	var (
		testWords    = []string{"correct ", "horse ", "battery ", "staple"}
		testExpected = []byte{0x01,
			0xc4, 0xbb, 0xcb, 0x1f, 0xbe, 0xc9, 0x9d, 0x65, 0xbf, 0x59, 0xd8, 0x5c, 0x8c, 0xb6, 0x2e, 0xe2,
			0xdb, 0x96, 0x3f, 0x0f, 0xe1, 0x06, 0xf4, 0x83, 0xd9, 0xaf, 0xa7, 0x3b, 0xd4, 0xe3, 0x9a, 0x8a}
	)

	const nofReqs = 100
	respChan := make(chan []byte)
	for i := 0; i < nofReqs; i++ {
		go func(c chan []byte) {

			hsr, err := SHA2_256.New()
			if err != nil {
				t.Fatal("Failed to extract new hash function: ", err)
			}
			for _, word := range testWords {
				if _, err := hsr.Write([]byte(word)); err != nil {
					t.Fatalf("Failed to write to hasher: %s.", err)
				}
			}
			imprint, err := hsr.Imprint()
			if err != nil {
				t.Fatalf("Failed to extract imprint: %s.", err)
			}

			c <- imprint
		}(respChan)
	}

	nofResp := 0
	for {
		select {
		case result := <-respChan:
			if !Equal(result, testExpected) {
				t.Fatalf("Result mismatch.")
			}
			nofResp++
		default:
		}

		if nofResp == nofReqs {
			break
		}
	}
}

func TestUnitRegisterHash(t *testing.T) {
	RegisterHash(SM3, crypto.SHA256.New)

	const input = "Once I was blind but now I C!"
	verifyHash(t, SM3, input, "4d151c05f29a9757ff252ff1000fdcd28f88caaa52c020bc7d25e683890e7335")

	// Unregister the hash interface
	RegisterHash(SM3, nil)
}

func TestRegisterUnknownHash(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Fatal("Did no panic on unknown hash function.")
		}
	}()
	RegisterHash(95, nil)
}

func TestCheckDeprecatedFromUnknownAlgorithm(t *testing.T) {
	obsoleteTime, err := Algorithm(95).ObsoleteFrom()
	if err == nil || obsoleteTime != 0 {
		t.Fatal("Should not be possible to get obsolete date from unknown algorithm.")
	}

}

func TestCheckObsoleteFromUnknownAlgorithm(t *testing.T) {
	deprecatedTime, err := Algorithm(56).DeprecatedFrom()
	if err == nil || deprecatedTime != 0 {
		t.Fatal("Should not be possible to get deprecated date from unknown algorithm.")
	}
}

func TestGetStatusFromUnknownAlgorithm(t *testing.T) {
	status := Algorithm(36).StatusAt(65)
	if status != Unknown {
		t.Fatal("Unknown algorithm should have status unknown, but was: ", status)
	}
}

func TestGetSizeFromUnknownAlgorithm(t *testing.T) {
	size := Algorithm(19).Size()
	if size != -1 {
		t.Fatal("Unknown algorithm can not have anything but -1 as size.")
	}
}

func TestGetBlockSizeFromUnknownAlgorithm(t *testing.T) {
	size := Algorithm(45).BlockSize()
	if size != -1 {
		t.Fatal("Unknown algorithm can not have anything but -1 as block size.")
	}
}

func TestGetBlockSizeFromKnownAlgorithm(t *testing.T) {
	size := Algorithm(SHA2_512).BlockSize()
	if size != SHA2_512.BlockSize() {
		t.Fatal("Unexpected block blocksize for SHA2-512: ", size)
	}
}

func TestGetZeroImprintFromUnknownAlgorithm(t *testing.T) {
	imprint := Algorithm(59).ZeroImprint()
	if imprint != nil {
		t.Fatal("Unknown algorithm can not have zero imprint: ", imprint)
	}
}

func TestUnitHashFunc(t *testing.T) {
	hFunc, err := SHA2_256.HashFunc()
	if hFunc == nil || err != nil {
		t.Fatal("Must return a valid hash function.")
	}
}

func TestUnitHashFuncPanic(t *testing.T) {
	hFunc, err := SM3.HashFunc()
	if hFunc != nil || err == nil {
		t.Fatalf("SM3 is not registered.")
	}
}

func TestUnitDeprecatedFrom(t *testing.T) {
	list := ListDefined()
	for _, algo := range list {
		depTime, err := algo.DeprecatedFrom()
		if err != nil {
			t.Fatalf("Failed to get %s.DeprecatedFrom().", algo)
		}
		switch algo {
		case SHA1:
			if depTime == 0 {
				t.Error("SHA1 is deprecated.")
			}
		default:
			if depTime != 0 {
				t.Errorf("Only SHA1 is deprecated (%s).", algo)
			}
		}
	}
}

func TestUnitObsoleteFrom(t *testing.T) {
	list := ListDefined()
	for _, algo := range list {
		obsTime, err := algo.ObsoleteFrom()
		if err != nil {
			t.Fatalf("Failed to get %s.ObsoleteFrom().", algo)
		}
		if obsTime != 0 {
			t.Errorf("Non is obsolete (%s).", algo)
		}
	}
}

func TestUnitStatusAtDeprecated(t *testing.T) {
	// Verify SHA1
	if SHA1.StatusAt(1467331200-1) != Normal {
		t.Error("SHA1 should be Normal before deprecation date.")
	}
	if SHA1.StatusAt(time.Now().Unix()) != Deprecated {
		t.Error("SHA1 must be Deprecated after deprecation date.")
	}
}

func TestUnitStatusAtNormal(t *testing.T) {
	list := ListDefined()
	for _, algo := range list {
		if algo != SHA1 {
			if algo.StatusAt(time.Now().Unix()) != Normal {
				t.Errorf("%s should be Normal before deprecation date.", algo)
			}
		}
	}
}

func TestUnitStatusAtObsolete(t *testing.T) {
	list := ListDefined()
	for _, algo := range list {
		if algo.StatusAt(time.Now().Unix()) == Obsolete {
			t.Errorf("None of the functions are marked as obsolete. (see %s)", algo)
		}
	}
}

func TestUnitListSupported(t *testing.T) {
	if len(ListDefined()) <= len(ListSupported()) {
		t.Fatal("Not all available functions are supported.")
	}
}

func TestUnitHashString(t *testing.T) {
	const expected = "SHA-256"
	actual := SHA2_256.String()
	if !strings.EqualFold(expected, actual) {
		t.Errorf("Algorithm string mismatch. (%s!=%s)", expected, actual)
	}
}

func TestUnitNotTrusted(t *testing.T) {
	if SHA1.Trusted() == true {
		t.Error("SHA1 is not trusted")
	}
}

func TestUnitTrusted(t *testing.T) {
	list := ListDefined()
	for _, algo := range list {
		if algo != SHA1 {
			if !algo.Trusted() {
				t.Errorf("%s should be trusted.", algo)
			}
		}
	}
}

func TestUnitCryptoHashToImprint(t *testing.T) {

	var (
		testData = []struct {
			crtId  crypto.Hash
			ksiId  Algorithm
			digest string
		}{
			{crypto.SHA1, SHA1, "17feaf7afb41e469c907170915eab91aa9114c05"},
			{crypto.SHA256, SHA2_256, "4d151c05f29a9757ff252ff1000fdcd28f88caaa52c020bc7d25e683890e7335"},
			{crypto.RIPEMD160, RIPEMD160, "404a79f20439e1d82492ed73ad413b6d95d643a6"},
			{crypto.SHA384, SHA2_384, "4495385793894ac9a2cc1b2d8760da3ce50d14a193b19166417d503d853ad3588689e5a6b0e65675367394a207cac264"},
			{crypto.SHA512, SHA2_512, "2dcee3bebeeec061751c7e2c886fddb069502c3c71e1f70272d77a64c092e51b6a262d208939cc557de7650da347b08f643d515ff8009a7342454e73247761dd"},
			{crypto.SHA3_224, SHA3_224, "a6baf12a64284ac71f9cf63cb7cb60391b3cd7e291393edb04daad83"},
			{crypto.SHA3_256, SHA3_256, "05d89ebd9e3ecb536ad11cac3bda51a7a81e043f7843274b49e7893ab161ffc6"},
			{crypto.SHA3_384, SHA3_384, "3b45a4e97d912b2cb05f6c4ea659714c3db95280f37117a05e679338a5064fd434b1c73164c51ec9687ce39096d7b7b7"},
			{crypto.SHA3_512, SHA3_512, "90f8c16c5e7d134deaf1c64a9ab79851ac7f7c1718c918c6ae902b84d8954de94b2d96bc2abf8fbd13a6b5d4f108c2ec0e64b912d379f4f970efa079c01a2eb7"},
			// {SM3},
		}
	)

	for _, td := range testData {
		digest := utils.StringToBin(td.digest)
		imprint, err := CryptoHashToImprint(td.crtId, digest)
		if err != nil {
			t.Fatalf("Failed to convert crypto hash for crypto::%d. \n%s", td.crtId, err)
		}
		if imprint.Algorithm() != td.ksiId {
			t.Fatalf("Crypto hash and KSI Algorithm mismatch for crypto::%d and ksi::%s.", td.crtId, td.ksiId.String())
		}
		if !Equal(imprint.Digest(), digest) {
			t.Fatalf("Digest mismatch for crypto::%d.", td.crtId)
		}

	}
}

func TestUnitCryptoHashToImprintZero(t *testing.T) {

	var (
		testData = []struct {
			crtId crypto.Hash
			ksiId Algorithm
		}{
			{crypto.SHA1, SHA1},
			{crypto.SHA256, SHA2_256},
			{crypto.RIPEMD160, RIPEMD160},
			{crypto.SHA384, SHA2_384},
			{crypto.SHA512, SHA2_512},
			{crypto.SHA3_224, SHA3_224},
			{crypto.SHA3_256, SHA3_256},
			{crypto.SHA3_384, SHA3_384},
			{crypto.SHA3_512, SHA3_512},
			// {SM3},
		}
	)

	for _, td := range testData {
		zero, err := CryptoHashToImprint(td.crtId, nil)
		if err != nil {
			t.Fatalf("Failed to convert crypto hash for crypto::%d. \n%s", td.crtId, err)
		}
		if zero.Algorithm() != td.ksiId {
			t.Fatalf("Crypto hash and KSI Algorithm mismatch for crypto::%d and ksi::%s.", td.crtId, td.ksiId.String())
		}
		zeroBytes := make([]byte, td.ksiId.Size())
		if !Equal(zero.Digest(), zeroBytes) {
			t.Fatalf("Digest mismatch for crypto::%d.", td.crtId)
		}
	}
}

func TestUnitCryptoHashToImprintFailWithLength(t *testing.T) {
	var (
		testData = []struct {
			cId    crypto.Hash
			digest string
		}{
			{crypto.SHA256, "17feaf7afb41e469c907170915eab91aa9114c05"},
			{crypto.SHA1, "4d151c05f29a9757ff252ff1000fdcd28f88caaa52c020bc7d25e683890e7335"},
			{crypto.SHA384, "404a79f20439e1d82492ed73ad413b6d95d643a6"},
			{crypto.RIPEMD160, "4495385793894ac9a2cc1b2d8760da3ce50d14a193b19166417d503d853ad3588689e5a6b0e65675367394a207cac264"},
			{crypto.SHA512, "a6baf12a64284ac71f9cf63cb7cb60391b3cd7e291393edb04daad83"},
			{crypto.SHA3_224, "2dcee3bebeeec061751c7e2c886fddb069502c3c71e1f70272d77a64c092e51b6a262d208939cc557de7650da347b08f643d515ff8009a7342454e73247761dd"},
			{crypto.SHA3_384, "05d89ebd9e3ecb536ad11cac3bda51a7a81e043f7843274b49e7893ab161ffc6"},
			{crypto.SHA3_256, "3b45a4e97d912b2cb05f6c4ea659714c3db95280f37117a05e679338a5064fd434b1c73164c51ec9687ce39096d7b7b7"},
			{crypto.SHA3_384, "90f8c16c5e7d134deaf1c64a9ab79851ac7f7c1718c918c6ae902b84d8954de94b2d96bc2abf8fbd13a6b5d4f108c2ec0e64b912d379f4f970efa079c01a2eb7"},
			// {SM3},
		}
	)

	for _, td := range testData {
		imprint, err := CryptoHashToImprint(td.cId, utils.StringToBin(td.digest))
		if err == nil {
			t.Fatalf("Conversion must fail.")
		}
		if errors.KsiErr(err).Code() != errors.KsiInvalidFormatError {
			t.Fatalf("Failed with wrong error code.")
		}
		if imprint != nil {
			t.Fatalf("Imprint must not be returned.")
		}
	}
}

func TestUnitCryptoHashToImprintFailWithUnknown(t *testing.T) {
	imprint, err := CryptoHashToImprint(crypto.MD4, nil)
	if err == nil {
		t.Fatalf("Conversion must fail.")
	}
	if errors.KsiErr(err).Code() != errors.KsiUnknownHashAlgorithm {
		t.Fatalf("Failed with wrong error code.")
	}
	if imprint != nil {
		t.Fatalf("Imprint must not be returned.")
	}
}

func TestUnitWorkWithUninitialized(t *testing.T) {
	hasher := &DataHasher{}
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

	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("Operation on not initialized hasher object must not panic: %v!", r)
		}
	}()

	/* Following calls must not panic. */
	hasher.Reset()

	if s := hasher.BlockSize(); !(s < 0) {
		t.Fatalf("BlockSize for not initialized hasher must be 0, but is %v!", s)
	}

	if s := hasher.Size(); !(s < 0) {
		t.Fatalf("BlockSize for not initialized hasher must be 0, but is %v!", s)
	}
}
