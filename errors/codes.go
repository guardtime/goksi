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

package errors

// ErrorCode represent the error code value.
type ErrorCode uint16

const (
	// KsiNoError represent a successful result.
	KsiNoError = ErrorCode(0)

	/*
		Syntax errors
	*/

	// KsiInvalidArgumentError is in case of invalid function input argument (eg. nil pointer).
	KsiInvalidArgumentError = ErrorCode(0x100)
	// KsiInvalidFormatError the provided value is invalid (eg. out of range).
	KsiInvalidFormatError = ErrorCode(0x101)
	// KsiBufferOverflow is set in case of buffer or value overflow.
	KsiBufferOverflow = ErrorCode(0x104)
	// KsiInvalidPkiSignature is set in case of invalid PKI signature.
	KsiInvalidPkiSignature = ErrorCode(0x108)
	// KsiPkiCertificateNotTrusted is set in case the PKI signature is not trusted by the API.
	KsiPkiCertificateNotTrusted = ErrorCode(0x109)
	// KsiInvalidStateError is set in case the objects used are in an invalid state (eg. missing mandatory member value).
	KsiInvalidStateError = ErrorCode(0x10a)
	// KsiUnknownHashAlgorithm is set in case the hash algorithm ID is invalid or unknown to the API.
	KsiUnknownHashAlgorithm = ErrorCode(0x10b)
	/*
		System errors
	*/

	// KsiNetworkError is set in cse a network error occurred.
	KsiNetworkError = ErrorCode(0x200)
	// KsiHttpError is set in case an HTTP error has been received.
	KsiHttpError = ErrorCode(0x201)
	// KsiIoError is set in case IO error occurred.
	KsiIoError = ErrorCode(0x202)
	// KsiExtendNoSuitablePublication is set in case no suitable publication is available to extend the signature to.
	KsiExtendNoSuitablePublication = ErrorCode(0x208)
	// KsiVerificationFailure is a common signature verification failure.
	KsiVerificationFailure = ErrorCode(0x20a)
	// KsiHmacMismatch is set in case HMAC mismatch occurred.
	KsiHmacMismatch = ErrorCode(0x20e)
	// KsiPublicationsFileNotSignedWithPki is set in case the publications file is not signed.
	KsiPublicationsFileNotSignedWithPki = ErrorCode(0x20c)
	// KsiCryptoFailure is set in case cryptographic operation could not be performed. Likely causes are unsupported
	// cryptographic algorithms, invalid keys and lack of resources.
	KsiCryptoFailure = ErrorCode(0x20d)
	// KsiRequestIdMismatch the request ID in response does not match with request ID in request.
	KsiRequestIdMismatch = ErrorCode(0x210)
	// KsiHmacAlgorithmMismatch is set in case HMAC algorithm mismatch occurred.
	KsiHmacAlgorithmMismatch = ErrorCode(0x211)
	// KsiIncompatibleHashChain is set in case of incompatibility of calendar hash chains.
	KsiIncompatibleHashChain = ErrorCode(0x213)
	// KsiExternalError is set in case external error from 3rd party API (eg std library) is returned and wrapped automatically inside KsiError.
	KsiExternalError = ErrorCode(0x214)
	/*
		Generic service errors.
	*/

	// KsiServiceInvalidRequest is set in case a request had invalid format (could not be parsed as a PDU consisting of
	// header, payload, and MAC elements).
	KsiServiceInvalidRequest = ErrorCode(0x400)
	// KsiServiceAuthenticationFailure is set in case a request could not be authenticated (missing or unknown login
	// identifier, MAC check failure, etc).
	KsiServiceAuthenticationFailure = ErrorCode(0x401)
	// KsiServiceInvalidPayload is set in case a request contained invalid payload (unknown payload type, missing
	// mandatory elements, unknown critical elements, etc).
	KsiServiceInvalidPayload = ErrorCode(0x402)
	// KsiServiceInternalError is set in case server encountered an unspecified internal error.
	KsiServiceInternalError = ErrorCode(0x403)
	// KsiServiceUpstreamError is set in case server encountered unspecified critical errors connecting to upstream
	// servers.
	KsiServiceUpstreamError = ErrorCode(0x404)
	// KsiServiceUpstreamTimeout is set in case there is no response from upstream server.
	KsiServiceUpstreamTimeout = ErrorCode(0x405)
	// KsiServiceUnknownError is set in case in unknown error has been received from the server.
	KsiServiceUnknownError = ErrorCode(0x406)

	/*
		Aggregator errors.
	*/

	// KsiServiceAggrRequestTooLarge is set in case the request indicated client-side aggregation tree larger than
	// allowed for the client (retrying would not succeed either).
	KsiServiceAggrRequestTooLarge = ErrorCode(0x421)
	// KsiServiceAggrRequestOverQuota is set in case the request combined with other requests from the same client in
	// the same round would create an aggregation sub-tree larger than allowed for the client (retrying in a later round
	// could succeed).
	KsiServiceAggrRequestOverQuota = ErrorCode(0x422)
	// KsiServiceAggrTooManyRequests is set in case too many requests from the client in the same round (retrying in a
	// later round could succeed)
	KsiServiceAggrTooManyRequests = ErrorCode(0x423)
	// KsiServiceAggrInputTooLong is set in case input hash value in the client request is longer than the server allows.
	KsiServiceAggrInputTooLong = ErrorCode(0x424)

	/*
		Extender status codes.
	*/

	// KsiServiceExtenderInvalidTimeRange is set in case the request asked for a hash chain going backwards in time.
	KsiServiceExtenderInvalidTimeRange = ErrorCode(0x441)
	// KsiServiceExtenderDatabaseMissing is set in case the server misses the internal database needed to service the
	// request (most likely it has not been initialized yet).
	KsiServiceExtenderDatabaseMissing = ErrorCode(0x442)
	// KsiServiceExtenderDatabaseCorrupt is set in case the server's internal database is in an inconsistent state.
	KsiServiceExtenderDatabaseCorrupt = ErrorCode(0x443)
	// KsiServiceExtenderRequestTimeTooOld is set in case the request asked for hash values older than the oldest round
	// in the server's database.
	KsiServiceExtenderRequestTimeTooOld = ErrorCode(0x444)
	// KsiServiceExtenderRequestTimeTooNew is set in case the request asked for hash values newer than the newest round
	// in the server's database.
	KsiServiceExtenderRequestTimeTooNew = ErrorCode(0x445)
	// KsiServiceExtenderRequestTimeInFuture is set in case the request asked for hash values newer than the current
	// real time.
	KsiServiceExtenderRequestTimeInFuture = ErrorCode(0x446)

	// KsiNotImplemented indicates an invalid API state.
	KsiNotImplemented = ErrorCode(0xffff)
)

var errStrings = map[ErrorCode]string{
	KsiNoError: "No Error",

	KsiInvalidArgumentError:     "Invalid Argument",
	KsiInvalidFormatError:       "Invalid Format",
	KsiBufferOverflow:           "Buffer overflow",
	KsiInvalidPkiSignature:      "Invalid PKI signature",
	KsiPkiCertificateNotTrusted: "The PKI certificate is not trusted",
	KsiInvalidStateError:        "Invalid State",
	KsiUnknownHashAlgorithm:     "Unknown Hash Algorithm",

	KsiNetworkError:                     "Network Error",
	KsiHttpError:                        "HTTP error",
	KsiIoError:                          "IO Error",
	KsiExtendNoSuitablePublication:      "There is no suitable publication yet",
	KsiVerificationFailure:              "Verification failed",
	KsiHmacMismatch:                     "HMAC mismatch",
	KsiPublicationsFileNotSignedWithPki: "The publications file is not signed",
	KsiCryptoFailure:                    "Cryptographic failure",
	KsiRequestIdMismatch:                "Request ID mismatch",
	KsiHmacAlgorithmMismatch:            "HMAC algorithm mismatch",
	KsiIncompatibleHashChain:            "Incompatible calendar hash chain",
	KsiExternalError:                    "Common external error from 3rd party API",

	KsiServiceInvalidRequest:        "The request had invalid format",
	KsiServiceAuthenticationFailure: "The request could not be authenticated",
	KsiServiceInvalidPayload:        "The request contained invalid payload",
	KsiServiceInternalError:         "The server encountered an unspecified internal error",
	KsiServiceUpstreamError:         "The server encountered unspecified critical errors connecting to upstream servers",
	KsiServiceUpstreamTimeout:       "No response from upstream servers",
	KsiServiceUnknownError:          "Unknown service error",

	KsiServiceAggrRequestTooLarge:  "The request indicated client-side aggregation tree larger than allowed for the client",
	KsiServiceAggrRequestOverQuota: "The request combined with other requests from the same client in the same round would create an aggregation sub-tree larger than allowed for the client",
	KsiServiceAggrTooManyRequests:  "Too many requests from the client in the same round",
	KsiServiceAggrInputTooLong:     "Input hash value in the client request is longer than the server allows",

	KsiServiceExtenderInvalidTimeRange:    "The request asked for a hash chain going backwards in time",
	KsiServiceExtenderDatabaseMissing:     "The server misses the internal database needed to service the request",
	KsiServiceExtenderDatabaseCorrupt:     "The server's internal database is in an inconsistent state",
	KsiServiceExtenderRequestTimeTooOld:   "The request asked for hash values older than the oldest round in the server's database",
	KsiServiceExtenderRequestTimeTooNew:   "The request asked for hash values newer than the newest round in the server's database",
	KsiServiceExtenderRequestTimeInFuture: "The request asked for hash values newer than the current real time",

	KsiNotImplemented: "Not Implemented",
}

func (c ErrorCode) String() string {
	return errStrings[c]
}
