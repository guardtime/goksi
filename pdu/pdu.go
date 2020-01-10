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

// Package pdu defines the KSI data structures and provides their manipulation methods.
package pdu

import (
	"context"

	"github.com/guardtime/goksi/errors"
	"github.com/guardtime/goksi/hash"
	"github.com/guardtime/goksi/templates"
	"github.com/guardtime/goksi/tlv"
)

func init() {
	if err := templates.Register(&AggregationChain{}, "", 0x801); err != nil {
		panic(errors.KsiErr(err).AppendMessage("Failed to initialize 'AggregationChain' template."))
	}
	if err := templates.Register(&AggregatorReq{}, "", 0x220); err != nil {
		panic(errors.KsiErr(err).AppendMessage("Failed to initialize 'AggregatorReq' template."))
	}
	if err := templates.Register(&AggrReq{}, "", 0x02); err != nil {
		panic(errors.KsiErr(err).AppendMessage("Failed to initialize 'AggrReq' template."))
	}
	if err := templates.Register(&AggrResp{}, "", 0x02); err != nil {
		panic(errors.KsiErr(err).AppendMessage("Failed to initialize 'AggrResp' template."))
	}
	if err := templates.Register(&Config{}, "", 0x04); err != nil {
		panic(errors.KsiErr(err).AppendMessage("Failed to initialize 'Config' template."))
	}
	if err := templates.Register(&AggrAck{}, "", 0x05); err != nil {
		panic(errors.KsiErr(err).AppendMessage("Failed to initialize 'AggrAck' template."))
	}
	if err := templates.Register(&AggregatorResp{}, "", 0x221); err != nil {
		panic(errors.KsiErr(err).AppendMessage("Failed to initialize 'AggregatorResp' template."))
	}

	if err := templates.Register(&ExtenderReq{}, "", 0x320); err != nil {
		panic(errors.KsiErr(err).AppendMessage("Failed to initialize 'ExtenderReq' template."))
	}
	if err := templates.Register(&ExtReq{}, "", 0x02); err != nil {
		panic(errors.KsiErr(err).AppendMessage("Failed to initialize 'ExtReq' template."))
	}
	if err := templates.Register(&ExtResp{}, "", 0x02); err != nil {
		panic(errors.KsiErr(err).AppendMessage("Failed to initialize 'ExtResp' template."))
	}
	if err := templates.Register(&ExtenderResp{}, "", 0x321); err != nil {
		panic(errors.KsiErr(err).AppendMessage("Failed to initialize 'ExtenderResp' template."))
	}

	if err := templates.Register(&ChainLink{}, "", 0x0); err != nil {
		panic(errors.KsiErr(err).AppendMessage("Failed to initialize 'ChainLink' template."))
	}
	if err := templates.Register(&ChainLink{}, "ChainLinkL", 0x07); err != nil {
		panic(errors.KsiErr(err).AppendMessage("Failed to initialize 'ChainLinkL' template."))
	}
	if err := templates.Register(&ChainLink{}, "ChainLinkR", 0x08); err != nil {
		panic(errors.KsiErr(err).AppendMessage("Failed to initialize 'ChainLinkR' template."))
	}

	if err := templates.Register(&PublicationRec{}, "", 0x803); err != nil {
		panic(errors.KsiErr(err).AppendMessage("Failed to initialize 'PublicationRec' template."))
	}
	if err := templates.Register(&PublicationData{}, "", 0x10); err != nil {
		panic(errors.KsiErr(err).AppendMessage("Failed to initialize 'PublicationData' template."))
	}
	if err := templates.Register(&MetaData{}, "", 0x04); err != nil {
		panic(errors.KsiErr(err).AppendMessage("Failed to initialize 'MetaData' template."))
	}
}

// AggregatorPdu is the KSI Aggregator Protocol (KSIAP) used to deliver client requests to the server and KSI items
// (and also configuration parameters) from the server to the client. Different message types are used for upstream
// (child to parent) and downstream (parent to child) traffic.
type AggregatorPdu struct {
	// KSI elements.
	req  *AggregatorReq  `tlv:"220,nstd"`
	resp *AggregatorResp `tlv:"221,nstd"`
}

// AggregatorReq is used to deliver client requests to the server.
type AggregatorReq struct {
	// KSI elements.
	header     *Header       `tlv:"1,nstd,C1,IF"`
	aggrReq    *AggrReq      `tlv:"2,nstd"`
	confReq    *Config       `tlv:"4,nstd"`
	aggrAckReq *AggrAck      `tlv:"5,nstd"`
	mac        *hash.Imprint `tlv:"1f,imp,C1,IL"`

	ctx context.Context
}

// Header is the message header consisting of the following fields:
//  * 'login identifier': identifier of the client host for MAC key lookup. For portability, it is recommended to limit
//    the login identifiers to valid POSIX usernames (that is, they should contain only uppercase and lowercase letters
//    'a' to 'z' and 'A' to 'Z', digits '0' to '9', periods '.', underscores '_', and dashes '-'.
//  * 'instance identifier': a number identifying invocation of the sender.
//  * 'message identifier': message number for duplicate filtering.
// The instance and message identifier fields, when present, are used for filtering duplicate messages. The value of
// the 'instance identifier' field should increase every time the sending process is restarted. The 'message identifier'
// should sequentially number the messages within a process invocation. Having seen messages with a higher
// 'instance identifier' value from a client, a server may drop future messages with lower 'instance identifier' values
// assuming these are delayed messages from a previous invocation and thus no longer relevant. Similarly, a server may
// prioritize messages from a given client invocation by 'message identifier' values under the assumption that messages
// with lower values are more likely to be stale. Messages where the 'instance identifier' and 'message identifier'
// fields are absent should be considered unique. This is to accommodate short-lived client applications that typically
// send only a single request. For long-lived processes, the 'instance identifier' and 'message identifier' fields
// should be considered mandatory.
type Header struct {
	// KSI elements.
	loginID *string `tlv:"1,utf8,C1"`
	instID  *uint64 `tlv:"2,int,C0_1,E"`
	msgID   *uint64 `tlv:"3,int,C0_1,E"`
}

// AggrReq is an aggregation request message containing following data fields:
//  * 'request identifier': a number used to establish a relation between the request and the corresponding responses;
//  * 'request hash': either a hash value of the data to be signed or the root hash value of the client's aggregation tree;
//  * 'request level': the level value of the aggregation tree node from which the 'request hash' comes, or absent
//    if 'request hash' is a direct hash of client data (not an aggregation result).
type AggrReq struct {
	// KSI elements.
	id    *uint64       `tlv:"1,int,C1"`
	hash  *hash.Imprint `tlv:"2,imp,C1"`
	level *uint64       `tlv:"3,int,C0_1,E"`
}

// Config is service configuration.
// In order to start using KSIAP, a client must have the following information:
//  - parent server URI;
//  - its own client identifier;
//  - an (HMAC) authentication key.
// Using this minimal information, the client can obtain additional configuration data by sending the 'configuration
// request' within a protocol PDU. The server responds with a 'configuration' message with all applicable fields
// populated as follows:
//  * 'maximal level': maximum level value that the nodes in the client's aggregation tree are allowed to have (relevant
//    only in case of aggregator service);
//  * 'aggregation hash algorithm': identifier of the hash function that the client is recommended to use in its
//    aggregation trees (relevant only in case of aggregator service);
//  * 'aggregation period': recommended duration of client's aggregation round in milliseconds (relevant only in case
//    of aggregator service);
//  * 'maximum requests': maximum number of requests the client is allowed to send within one period of the recommended
//    duration;
//  * 'parent URI': parent server URI. Note that there may be several parent servers listed in the configuration.
//    Typically, these are all members of one cluster;
//  * 'calendar first time': aggregation time of the oldest calendar record the extender has (relevant only in case of
//    extender service);
//  * 'calendar last time': aggregation time of the newest calendar record the extender has (relevant only in case of
//    extender service).
// The server may also send configuration messages without an explicit request from the client. These may
// be triggered by a change in the server's own configuration, for example.
type Config struct {
	// KSI elements.
	maxLevel   *uint64   `tlv:"1,int,C0_1,E"`
	aggrAlgo   *uint64   `tlv:"2,int8,C0_1,E"`
	aggrPeriod *uint64   `tlv:"3,int,C0_1,E"`
	maxReq     *uint64   `tlv:"4,int,C0_1,E"`
	parentURI  *[]string `tlv:"10,utf8,C0_N"`
	calFirst   *uint64   `tlv:"11,int,C0_1"`
	calLast    *uint64   `tlv:"12,int,C0_1"`
}

// AggrAck is a client that can send acknowledgment requests to a server to verify if the server is reachable, and to estimate
// network latency for tuning its own aggregation schedule. The client sends a request message where the payload
// contains the 'aggregator acknowledgment request' record, optionally containing the time when client sent the request
// (according to client's local clock) in the 'request time' field.
// The server should respond immediately (without waiting for the end of its aggregation round) with an 'aggregator
// acknowledgment' message where all applicable fields are populated as follows:
//  * 'request time': the same value as in the corresponding client request, if present there;
//  * 'receipt time': the time when the request was received (according to server's local clock). If an aggregation request
//    was received in the same PDU as the acknowledgment request, the 'request time' metadata field of the generated
//    aggregation hash chain will have the same value as the 'receipt time' of the acknowledgment;
//  * 'acknowledgment time': the time when the acknowledgment was generated (according to server's local clock). Present
//    only if it substantially differs from 'receipt time' (added at the discretion of the server's implementation);
//  * 'aggregation delay': the time from receiving the client's request to the end of the server's current aggregation
//    round in milliseconds;
//  * 'aggregation period': duration of server's aggregation round in milliseconds;
//  * 'aggregation drift': the drift of the server's aggregation schedule in milliseconds. Normally the server would
//    start a new aggregation round every time the number of milliseconds since 1970-01-01T00:00:00Z is evenly
//    divisible by 'aggregation period'. To compensate for network latency and better align its aggregation schedule with
//    its parents, the server instead starts a new round when the division yields 'aggregation drift' as the remainder.
type AggrAck struct {
	// KSI elements.
	reqTime    *uint64 `tlv:"1,int,C0_1,E"`
	recvTime   *uint64 `tlv:"2,int,C0_1,E"`
	ackTime    *uint64 `tlv:"3,int,C0_1,E"`
	aggrDelay  *uint64 `tlv:"4,int,C0_1,E"`
	aggrPeriod *uint64 `tlv:"5,int,C0_1,E"`
	aggrDrift  *uint64 `tlv:"6,int,C0_1,E"`
}

// AggregatorResp used to deliver KSI items (and also configuration parameters) from the server to the client, as
// reaction to an aggregator request.
type AggregatorResp struct {
	// KSI elements.
	header   *Header       `tlv:"1,nstd,C1,IF,G0,!G1"`
	aggrResp *AggrResp     `tlv:"2,nstd,C0_1,&G0,!G1"`
	aggrErr  *Error        `tlv:"3,nstd,C1,!G0,G1"`
	confResp *Config       `tlv:"4,nstd,C0_1,&G0,!G1"`
	aggrAck  *AggrAck      `tlv:"5,nstd,C0_1,&G0,!G1"`
	mac      *hash.Imprint `tlv:"1f,imp,C1,IL,&G0,!G1"`
	// Raw TLV data for internal usage.
	rawTlv *tlv.Tlv `tlv:"basetlv"`
}

// AggrResp is a server's reaction to an aggregation request message. There may be several responses associated
// with an aggregation request. The responses can be matched to a request using the 'request identifier' field.
// An aggregator response message has the following data fields:
//  * 'request identifier': normally the same value as in the corresponding client request, with the following exceptions:
//    - if the request identifier was missing in the client request, the server responds with an INVALID PAYLOAD error
//      with the request identifier set to 0. Clients should avoid using 0 as a request identifier to prevent confusion
//      with this placeholder value;
//    - if the request identifier in the client request was too long, it is truncated to contain as many least significant
//      bits as the server can handle;
//    - handling of simultaneous requests with equal identifiers is implementation-defined. Possible actions include
//      ignoring the condition and responding to all requests, treating the requests as duplicates and only responding
//      to one of them, etc;
//  * 'status': a status code, where 0 means success and non-zero value is an error code;
//  * 'error message': an optional free-form error message;
//  * 'KSI item': a part of a KSI signature. There may be several KSI items in one aggregator response.
type AggrResp struct {
	// KSI elements.
	id       *uint64 `tlv:"1,int,C1,E"`
	status   *uint64 `tlv:"4,int,C1,E"`
	errorMsg *string `tlv:"5,utf8,C0_1"`
	// [08xx] Signature elements.
	aggrChainList *[]*AggregationChain `tlv:"801,nstd,C0_N"`
	calChain      *CalendarChain       `tlv:"802,nstd,C0_1,G0"`
	pubRec        *PublicationRec      `tlv:"803,nstd,C0_1,G2,!G1,&G0"`
	calAuthRec    *CalendarAuthRec     `tlv:"805,nstd,C0_1,G1,!G2,&G0"`
	rfc3161Rec    *RFC3161             `tlv:"806,nstd,C0_1"`
}

// AggregationChain is the aggregation hash chain structure consisting of the following fields:
//  * 'aggregation time': the completion time of the aggregation round from which the hash chain starts;
//  * 'chain index': a location pointer. Bit-strings that indicate the location of the component in a hash tree.
//    The bits represent the path from the root of the tree to the location of a hash value as a sequence of moves
//    from a parent node in the tree to either the left or right child (bit values 0 and 1, respectively);
//  * 'input hash' and an optional 'input data': the input for the computation specified by the hash chain;
//  * 'aggregation algorithm': the one-octet identifier of the hash function used to compute the output hash values of
//    the link structures;
//  * 'chain links': a sequence of left and right 'chain link' structures.
type AggregationChain struct {
	// KSI elements.
	aggrTime   *uint64       `tlv:"2,int,C1,E"`
	chainIndex *[]uint64     `tlv:"3,int,C1_N,E"`
	inputData  *[]byte       `tlv:"4,bin,C0_1"`
	inputHash  *hash.Imprint `tlv:"5,imp,C1"`
	aggrAlgo   *uint64       `tlv:"6,int8,C1,E"`
	chainLinks *[]*ChainLink `tlv:"7|8,nstd+tlvobj,C1_N"`
}

// CalendarChain is calendar hash chain structure consisting of:
//  * pubTime: publication time (time of the calendar root hash);
//  * aggrTime: aggregation time (optional, default value pubTime);
//  * input hash: the input for the computation specified by the hash chain;
//  * chainLinks: a sequence of 'left link' and 'right link' structures.
type CalendarChain struct {
	pubTime    *uint64       `tlv:"1,int,C1,E"`
	aggrTime   *uint64       `tlv:"2,int,C0_1,E"`
	inputHash  *hash.Imprint `tlv:"5,imp,C1"`
	chainLinks *[]*ChainLink `tlv:"7|8,tlvobj,C1_N"`
}

// CalendarAuthRec contains the following fields:
//  * 'published data': consists of a 'publication time' and a 'published hash';
//  * 'signature data': an authentication record for a calendar hash chain is created in the following way:
//    1. The 'publication time' of the calendar hash chain is stored as the 'publication time' field of the
//       'published data' structure.
//    2. The output hash of the calendar hash chain is computed and stored as the 'published hash' field of
//       the 'published data' structure.
//    3. The whole 'published data' structure (including the TLV header) is signed and the result is saved
//       as the 'signature data' structure.
type CalendarAuthRec struct {
	// KSI elements.
	pubData *PublicationData `tlv:"10,nstd,C1,F"`
	sigData *SignatureData   `tlv:"0b,nstd,C1"`
}

// PublicationRec represents the information related to a published hash value, possibly including the publication
// reference. Publication may also point (via a URI) to a hash database that is in electronic form and may contain
// several published hash values. A 'publication record' structure contains the following fields:
//  * 'published data': consists of a 'publication time' and a 'published hash';
//  * 'publication reference': an UTF-8 string that contains the bibliographic reference to a media outlet where the
//    publication appeared;
//  * 'publications repository URI': URI of a publications' repository (publication file).
type PublicationRec struct {
	// KSI elements.
	pubData   *PublicationData `tlv:"10,nstd,C1"`
	pubRef    *[]string        `tlv:"9,utf8,C0_N"`
	pubRepURI *[]string        `tlv:"a,utf8,C0_N"`
}

// SignatureData consists of:
//  * 'signature type': a signing algorithm and signature format identifier, as assigned by IANA, represented as an UTF-8
//    string containing a dotted decimal object identifier (OID);
//  * 'signature value': the signature itself, computed and formatted according to the specified method;
//  * 'certificate identifier' and optionally 'certificate repository URI', with the latter pointing to a repository (e.g.
//    a publication file) that contains the certificate identified by the 'certificate identifier'.
// As an example, the signature type "1.2.840.113549.1.1.11" (for "SHA-256 with RSA encryption") would indicate a
// signature formed by hashing the published data with the SHA2-256 algorithm and then signing the resulting hash value
// with an RSA private key.
type SignatureData struct {
	// KSI elements.
	sigType    *string `tlv:"1,utf8,C1"`
	sigValue   *[]byte `tlv:"2,bin,C1"`
	certID     *[]byte `tlv:"3,bin,C1"`
	certRepURI *string `tlv:"4,utf8,C0_1"`
}

// RFC3161 is the RFC 3161 compatibility record. An older implementation of the KSI service used the formats and
// protocols specified in the X.509 time-stamping standard. In that format, the hash value of the time-stamped datum was
// not signed directly, but via several intermediate structures:
//  1. The hash value of the original datum was entered into the MessageImprint field of the TSTInfo structure.
//  2. The hash value of the TSTInfo structure was entered into the MessageDigest field of the SignedAttributes structure.
//  3. Finally, the hash value of the SignedAttributes structure was actually signed.
// To facilitate conversion of legacy KSI signatures issued in the RFC 3161 format, the helper data structure is used,
// where the fields have the following meaning:
//  * 'aggregation time', 'chain index', 'input data' and 'input hash' fields have the same meaning as in the
//    'aggregation chain' structure.
//  * 'tstinfo prefix' and 'tstinfo suffix' fields contain the data preceding and succeeding the hash value within the
//    TSTInfo structure.
//  * 'tstinfo algorithm' field contains the one-octet identifier (as defined in Table 2) of the hash function used to
//    hash the TSTInfo structure.
//  * 'signed attributes prefix' and 'signed attributes suffix' fields contain the data preceding and succeeding the
//    hash value within the SignedAttributes structure.
//  * 'signed attributes algorithm' field contains the one-octet identifier of the hash function used to hash the
//    SignedAttributes structure.
// The record:
//  - belongs to the aggregation hash chain component that has the same 'aggregation time' value and the same sequence
//    of 'chain index' values;
//  - may only be applied to the first component of the aggregation chain (that is, where the input to the aggregation
//    is client data, not output of a previous aggregation);
//  - acts as a data conversion filter preprocessing the data before it becomes input to the aggregation chain.
type RFC3161 struct {
	aggrTime   *uint64       `tlv:"2,int,C1,E"`
	chainIndex *[]uint64     `tlv:"3,int,C1_N,E"`
	inputData  *[]byte       `tlv:"4,bin,C0_1"`
	inputHash  *hash.Imprint `tlv:"5,imp,C1"`

	tstInfoPrefix *[]byte `tlv:"10,bin,C1"`
	tstInfoSuffix *[]byte `tlv:"11,bin,C1"`
	tstInfoAlgo   *uint64 `tlv:"12,int8,C1,E"`

	sigAttrPrefix *[]byte `tlv:"13,bin,C1"`
	sigAttrSuffix *[]byte `tlv:"14,bin,C1"`
	sigAttrAlgo   *uint64 `tlv:"15,int8,C1,E"`
}

// MetaData is a sub-structure that provides the ability to incorporate client identity and other information about
// the request into the hash chain. It must contain the 'client identifier' field and may contain any combination
// of the 'machine identifier', 'sequence number', and 'request time' fields:
//  * 'client identifier': a (human-readable) textual representation of client identity;
//  * 'machine identifier': a (human-readable) identifier of the machine that requested the link structure
//    (unique at least within the cluster that shares a 'client identifier');
//  * 'sequence number': a local sequence number of a request assigned by the machine that created the link. Sequence
//    numbers enable determination of the temporal order of requests processed by the same machine even within one
//    aggregation round.
//  * 'request time': the time when the server received the request from the client, recorded as precisely as the server's
//    clock allows. This is another option for ordering of requests processed by the same machine within one aggregation
//    round.
//  * 'padding': an element whose purpose is to ensure that a 'metadata' value can't be confused with a 'sibling hash'
//    imprint. This element, with the 'non-critical' and 'forward' flags set, must be the first field in the 'metadata'
//    structure (thus the first octet of the value part of the structure is 7E, which is marked as invalid hash function
//    identifier. The value of this element must be either one octet 01 or two octets 01 01 to make the total
//    length of the metadata an even number (since hash functions have even-length output, the imprints embedding them
//    have odd length and consequently even-length metadata can't be confused with an imprint).
type MetaData struct {
	// KSI elements.
	padding    *[]byte `tlv:"1e,bin,C0_1,IF,F,N"`
	clientID   *string `tlv:"1,utf8,C1"`
	machineID  *string `tlv:"2,utf8,C0_1"`
	sequenceNr *uint64 `tlv:"3,int,C0_1,E"`
	reqTime    *uint64 `tlv:"4,int,C0_1,E"`

	// Raw TLV data for internal usage.
	rawTlv *tlv.Tlv `tlv:"basetlv"`
}

// ChainLink is hash chain link.
//
// For several reasons, each node in the aggregation tree includes a level indicator that must be strictly larger than
// the indicator in either child node. In most cases, the value in the parent node is one more than the values in the
// child nodes and can then be computed from the value of either child (one of which precedes the parent in the hash
// chain). However, if the aggregation tree is not perfectly balanced, the values in the child nodes may differ and, in
// this case, the level indicator must increase by more than one on the step from one child to the parent.
// The optional 'level correction' is used in the hash chain to indicate the correction amount (additional increase) in this case.
// Sibling data must consist of one, and only one, of the following three fields:
//  * 'sibling hash': an 'imprint' representing a hash value from the sibling node in the tree;
//  * 'metadata': a sub-structure that provides the ability to incorporate client identity and other information about
//    the request into the hash chain;
//  * 'legacy client identifier': a client identifier converted from a legacy signature.
//
// In case of calendar hash chain, each link field contains only a hash value from the calendar hash tree.
type ChainLink struct {
	// KSI elements.
	levelCorr   *uint64       `tlv:"1,int,C0_1,E"`
	siblingHash *hash.Imprint `tlv:"2,imp,C0_1,G0,!G1,!G2"`
	legacyID    *LegacyID     `tlv:"3,tlvobj,C0_1,G1,!G0,!G2"`
	metadata    *MetaData     `tlv:"4,nstd+tlvobj,C0_1,G2,!G0,!G1"`

	// Flags for identifying the chain link.
	isLeft     bool
	isCalendar bool
}

// LegacyID is a wrapper type for the legacy client identifier.
//
// A client identifier converted from a legacy signature. The value must consist of exactly 29 octets:
//  - The first two octets are fixed values 03 and 00.
//  - The value of the third octet (at most 25) defines the length of the embedded name and is followed by that many
//    octets of an UTF-8 string.
//  - Finally, the value is padded with 00 octets to the final length (note that at least one padding octet will exist
//    in any valid structure). For example, the name 'Test' is encoded as the sequence:
//    03 00 04 54=T 65=e 73=s 74=t 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
//    (all octet values in the example are given in hexadecimal).
// This option is present only to support conversion of existing signatures created before the structured 'metadata'
// field was introduced and thus must not be used in new signatures. Note that 03 is marked as invalid value for hash
// function identifier to ensure that a 'legacy client identifier' value can't be confused with a 'sibling hash' imprint.
type LegacyID struct {
	str    string
	rawTlv *tlv.Tlv
}

// PublicationData is the published data containing:
//  * 'publication time': represented as a 64-bit unsigned integer;
//  * 'published hash': output hash value of the calendar hash chain at the publication time.
type PublicationData struct {
	// KSI elements.
	pubTime *uint64       `tlv:"2,int,C1,E"`
	pubHash *hash.Imprint `tlv:"4,imp,C1"`
	// Raw TLV data for internal usage.
	rawTlv *tlv.Tlv `tlv:"basetlv"`
}

// Error is as a special case, where an error is returned in a reduced message, because the server lacks the information needed
// to populate at least some of the normally mandatory fields of the 'header' and 'mac' components of the full response.
type Error struct {
	status   *uint64 `tlv:"4,int,C1,E"`
	errorMsg *string `tlv:"5,utf8,C0_1"`
}

// PublicationsHeader is the publications file header consisting of:
//  * the version number of the file format;
//  * the creation time of the file;
//  * URI of the canonical distribution point of the file.
// The two latter fields are for the benefit of clients that may receive cached copies of the file and want to ensure
// these copies are not stale.
type PublicationsHeader struct {
	ver    *uint64 `tlv:"1,int,C1,E"`
	crTime *uint64 `tlv:"2,int,C1,E"`
	repURI *string `tlv:"3,utf8,C0_1"`
}

// CertificateRecord is a representation of a public key certificate for verifying authentication records, consisting
// of 'certificate identifier' and 'certificate value'.
type CertificateRecord struct {
	certID *[]byte `tlv:"1,bin,C1"`
	cert   *[]byte `tlv:"2,bin,C1"`
}

// ExtenderPdu is the KSI Extender Protocol (KSIEP) used to deliver client requests to the server and calendar hash
// chains (and also configuration parameters) from the server to the client. Different message types are used for
// upstream (child to parent) and downstream (parent to child) traffic.
type ExtenderPdu struct {
	req  *ExtenderReq  `tlv:"320,nstd"`
	resp *ExtenderResp `tlv:"321,nstd"`
}

// ExtenderReq is used to deliver client requests to the server.
type ExtenderReq struct {
	// KSI elements.
	header  *Header       `tlv:"1,nstd,C1,IF"`
	extReq  *ExtReq       `tlv:"2,nstd"`
	confReq *Config       `tlv:"4,nstd"`
	mac     *hash.Imprint `tlv:"1f,imp,C1,IL"`

	ctx context.Context
}

// ExtReq is an extension request message containing following data fields:
//  * 'request identifier: a number used to establish a relation between the request and the corresponding responses;
//  * 'aggregation time': the time of the aggregation round from which the calendar hash chain should start;
//  * 'publication time': the time of the calendar root hash value to which the aggregation hash value should be
//    connected by the calendar hash chain. Its absence means a request for a calendar hash chain from aggregation
//    time to the most recent calendar record the server has (the 'calendar last time' field in the response and
//    configuration messages).
type ExtReq struct {
	id       *uint64 `tlv:"1,int,C1,E"`
	aggrTime *uint64 `tlv:"2,int,C1,E"`
	pubTime  *uint64 `tlv:"3,int,C0_1,E"`
}

// ExtenderResp is used to deliver calendar hash chains (and also configuration parameters) from the server to the
// client.
type ExtenderResp struct {
	// KSI elements.
	header   *Header       `tlv:"1,nstd,C1,IF,G0,!G1"`
	extResp  *ExtResp      `tlv:"2,nstd,C0_1,&G0,!G1"`
	extErr   *Error        `tlv:"3,nstd,C1,!G0,G1"`
	confResp *Config       `tlv:"4,nstd,C0_1,&G0,!G1"`
	mac      *hash.Imprint `tlv:"1F,imp,C1,IL,&G0,!G1"`
	// Raw TLV data for internal usage.
	rawTlv *tlv.Tlv `tlv:"basetlv"`
}

// ExtResp is server's reaction to an extension request message. The response can be matched to the request using the
// 'request identifier' field. An extender response message has the following data fields:
//  * 'request identifier': normally the same value as in the corresponding client request, with the following exceptions:
//    - if the request identifier was missing in the client request, the server responds with an INVALID PAYLOAD error
//      with the request identifier set to 0. Clients should avoid using 0 as a request identifier to prevent confusion
//      with this placeholder value;
//    - if the request identifier in the client request was too long, it is truncated to contain as many least significant
//      bits as the server can handle;
//    - handling of simultaneous requests with equal identifiers is implementation-defined. Possible actions include
//      ignoring the condition and responding to all requests, treating the requests as duplicates and only responding
//      to one of them, etc;
//  * 'status': a status code, where 0 means success and non-zero value is an error code;
//  * 'error message': an optional free-form error message;
//  * 'calendar last time': aggregation time of the newest calendar record the extender has;
//  * 'calendar chain': a calendar hash chain that connects the global root hash value of the aggregation tree of the
//    round specified in the request to the published hash value specified in the request.
type ExtResp struct {
	id       *uint64        `tlv:"1,int,C1,E"`
	status   *uint64        `tlv:"4,int,C1,E"`
	errorMsg *string        `tlv:"5,utf8,C0_1"`
	calLast  *uint64        `tlv:"12,int,C0_1,E"`
	calChain *CalendarChain `tlv:"802,nstd,C0_1"`
}
