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

/*

Package ksi implements functionality for interacting with KSI service, including the core functions such as
signing of data, extending and verifying KSI signatures.

Note that the following tutorial is incremental, meaning the parameter names used in example code blocks are defined
in previous example blocks.


Logging

The subpackage log defines logging interface type log.Logger and a basic logger implementation for writing lines
to file.

By default logging is disabled. In order to enable logging of the API internals, an implementation to a logger has
to be registered in the log package, e.g. setting default logger:

	// Create an instance of default logger. Write log output to stdout.
	logger, err = log.New(level, nil)
	if err != nil {
		return
	}
	// Register the logger
	log.SetLogger(logger)

In order to disable logging, set logger to nil.



Errors

Almost every method of the API returns an error parameter alongside with a value (if applicable). All returned errors
are of type errors.KsiError. For troubleshooting, the KsiError provides following information:
	error code     - for error verification and recovery logic;
	error message  - a stack of human readable descriptive messages;
	stack trace    - the stack trace of the error registration;
	extended error - an error code, or error from e.g. std library.

Example usage of the KsiError:
	func func1() (byte, error) {
		return 0, errors.New(errors.KsiNotImplemented).AppendMessage("Missing implementation.")
	}

	func func2() error {
		f1value, err := func1()
		if err != nil {
			return err
		}
		...
		return nil
	}

	func main() {
		...

		log.Debug("Starting main.")

		if err := func2(); err != nil {
			err := errors.KsiErr(err)

			// Add additional message to the error.
			err.AppendMessage("Fatal error in main.")

			// Push the received error into the log.
			log.Error(err)

			// Exit with the error code set in the KsiError.
			os.Exit(int(err.Code()))
		}
		os.Exit(0)
	}

It is strongly advised to verify the returned error. In case it is not nil, most probably, it is indicating
fatal state and requires some sort of recovery logic.
Furthermore, all foreseen panics are wrapped into KsiError and returned via a function return error parameter.


For simplicity reasons, the error handling in this tutorial is mostly omitted.



Reading a KSI signature

A signature instance can be created in several ways by providing suitable initializer of type
	signature.Builder
to the signature constructor
	signature.New()

Following initializers:
	signature.BuildFromStream(r io.Reader)
	signature.BuildFromFile(path string)
are quite straight forward and do not require in further explanation.
However, following initializers will be explained more deeply.

A low level signing (also aggregation) request is responded by Aggregator server with an aggregation response.
In order to initialize a signature instance from an aggregation response use:
	signature.BuildFromAggregationResp(resp *pdu.AggregatorResp, level byte)

A low level extending request is responded by Extender server with an extending response.
In order to initialize a signature instance from an extending response use:
	signature.BuildFromExtendingResp(resp *pdu.ExtenderResp, sig *Signature, pubRec *pdu.PublicationRec)

In order to initialize a signature instance from a locally aggregated tree use:
	signature.BuildWithAggrChain(sig *Signature, aggrChain *pdu.AggregationChain)

For more detailed description about the initializers, refer the individual documentation.

Note that the signature.BuildNoVerify must be used with care as the returned signature instance will not be
verified for internal consistency. The common use case would be to initialize an erroneous KSI signature for
troubleshooting.
	sig, err := signature.New(signature.BuildNoVerify(signature.BuildFromFile("signature.ksig")))
	if err != nil {
		// In this case, most probably, the signature file TLV structure is corrupted.
		return err
	}



Saving signature

To save the signature to a file or database, the signature content has to be serialized first.
	bin, err := signature.Serialize()



Hashing data

Lets assume the data is provided by a io.Reader implementation (e.g. os.File). KSI defines an imprint structure, which
basically represents a hash value and consists of a one-octet hash function identifier concatenated with the hash
value itself. The subpackage hash provides such structure type hash.Imprint.

As only the hash of the original document is signed, we need to create a hash.Imprint object. This can be achieved
by using hash.DataHasher object. It can be created from any registered hash algorithm. We will use hash.Default.
	hasher, err := hash.Default.New()
	if _, err := io.Copy(hasher, docFile); err != nil {
		// Wrap the std library error.
		return errors.New(errors.KsiIoError).AppendMessage("Failed to add data to hasher.").SetExtError(err)
	}
	docHash, err := hasher.Imprint()
For more detailed information about hash algorithms and hashing, see subpackage hash documentation.



Publications file

A publications file type publications.File can be constructed using publications.NewFile() method with appropriate
initializer type publications.FileBuilder.


A more common use case would be to construct a publications file handler by calling publications.NewFileHandler()
with desired options of type publications.FileHandlerSetting.
	pubFileHandler, err := publications.NewFileHandler(
		publications.FileHandlerSetPublicationsURL("http://verify.guardtime.com/ksi-publications.bin"),
		publications.FileHandlerSetFileCertConstraint(publications.OidEmail, "publications@guardtime.com"),
	)



Create signature

To create a new KSI signature for a document hash, a new service.Signer instance has to be constructed.
	// Initialize signing service.
	signer, err := service.NewSigner(service.OptEndpoint("ksi+http://signingservice.somehost:1234", "user", "key"))
	// Sign the document hash.
	ksiSignature, err := signer.Sign(docHash)
Signing of multiple imprints can be performed in parallel using goroutines.



Extending signature

To extend an existing KSI signature, a new service.Extender instance has to be constructed.
	// Initialize extending service.
	extender, err := service.NewExtender(pubFileHandler,
		service.OptEndpoint("ksi+http://exteningservice.somehost:1234", "user", "key"),
	)
	// Extend the existing signature.
	extKsiSignature, err := extender.Extend(ksiSignature)
Extending of multiple signatures can be performed in parallel using goroutines.



Verify signature

Signatures are verified according to one or more policies. A verification policy is a set of ordered rules that verify
relevant signature properties. Verifying a signature according to a policy results in one of three possible outcomes:
	successful   - meaning that there is enough data to prove that the signature is correct.
	not possible - meaning that there is not enough data to prove or disprove the correctness of the signature.
	               Note that with some other policy it might still be possible to prove or disprove the correctness
	               of the signature.
	failed       - meaning that the signature is definitely invalid or the document does not match the signature.

The SDK provides the following predefined policies for verification:

Internal policy. This policy verifies the consistency of various internal components of the signature without
requiring any additional data from the user. The verified components are the aggregation chain, calendar chain
(optional), calendar authentication record (optional) and publication record (optional). Additionally, if a document
hash is provided, the signature is verified against it.

User provided publication string based policy. This policy verifies the signature's publication record against the
publication string. If necessary (and permitted), the signature is extended to the user publication. For conclusive
results the signature must either contain a publication record with a suitable publication or signature extending must
be allowed. Additionally, a publication string must be provided and an Extender should be configured (in case extending
is permitted).

Publications file based policy. This policy verifies the signature's publication record against a publication in the
publication file. If necessary (and permitted), the signature is extended to the publication. For conclusive results
the signature must either contain a publication record with a suitable publication or signature extending must be
allowed. Additionally, a publications file must be provided for lookup and an Extender should be configured (in case
extending is permitted).

Key-based policy. This policy verifies the PKI signature and calendar chain data in the calendar authentication record
of the signature. For conclusive results, a calendar hash chain and calendar authentication record must be present in
the signature. A trusted publication file must be provided for performing lookup of a matching certificate.

Calendar-based policy. This policy verifies signature's calendar hash chain against calendar database. If calendar hash
chain does not exist, signature is extended to head and its match with received calendar hash chain is verified. For
conclusive results the Extender must be configured. Note that input signature is not changed.

Default policy. This policy uses the previously mentioned policies in the specified order. Verification starts off
with internal verification and if successful, continues with publication-based and/or key-based verification,
depending on the availability of calendar chain, calendar authentication record or publication record in the signature.
The default policy tries all available verification policies until a signature correctness is proved or disproved and
is thus the recommended policy for verification unless some restriction dictates the use of a specific verification
policy.

Note that all of the policies perform internal verification as a prerequisite to the specific verification and a policy
will never result in a success if internal verification fails.

Note that the provided signature is never modified. In case any verification step requires a signature extending, only
the extended calendar hash chain is retrieved from Extender service and is used for further validation.

For the most basic verification the returned error parameter of signature.(Signature).Verify() can be checked.
	err = ksiSignature.Verify(signature.DefaultVerificationPolicy)

However, most probably the result will be an error because of the lack of essential data. The key to conclusive
verification is to provide as much data as possible without assuming too much from the signature itself. For most cases
this means that a publications file (or handler) and Extender should be provided. In some cases a permission for using
Extender has to be set as well. If the signature needs to be verified against a specific publication, publication string
has to be provided, etc. In order to specify optional parameters, signature.VerCtxOption should be used:
	err = ksiSignature.Verify(signature.DefaultVerificationPolicy,
		signature.VerCtxOptExtendingPermitted(true),
		signature.VerCtxOptCalendarProvider(extender),
		signature.VerCtxOptPublicationsFileHandler(pubFileHandler),
	)

Note that the constructor of new signature object (signature.New()) will perform verification based on
Internal policy by default, unless signature.BuildNoVerify is used.


For a detailed verification result, signature.(Policy).Verify() can be used. In this case a verification context must be
set up first.
	verCtx, err := signature.NewVerificationContext(ksiSignature,
		signature.VerCtxOptExtendingPermitted(true),
		signature.VerCtxOptCalendarProvider(extender),
		signature.VerCtxOptPublicationsFileHandler(pubFileHandler),
	)
	res, err := signature.DefaultVerificationPolicy.Verify(verCtx)
	verRes, err := verCtx.Result()

	fmt.Println("Verification info:")
	for _, pr := range verRes.PolicyResults() {
		fmt.Println(pr.PolicyName())
		for _, rr := range pr.RuleResults() {
			fmt.Println(rr)
		}
	}

	fmt.Println("Final result:")
	fmt.Println(verRes.FinalResult().String())
	switch res {
	case result.OK:
		fmt.Println("Verification successful.")
	case result.NA:
		fmt.Println("Verification inconclusive.")
	case result.FAIL:
		fmt.Println("Verification failed.")
	default:
		fmt.Println("Unexpected verification result.")
	}



HTTP Proxy Configuration

To use a proxy, you need to configure the proxy on your operating system.

Set the system environment variable: `http_proxy=user:pass@server:port`

In the Windows Control Panel:
	1) find the 'System' page and select 'Advanced system settings';
	2) select 'Environment Variables...';
	3) select 'New...' to create a new system variable;
	4) enter `http_proxy` in the name field and and proxy configuration (see above) in the value field.

In Linux, add the system variable to `/etc/bashrc`:
	export http_proxy=user:pass@server:port

Configuring authentication is not supported by the Windows Control Panel and Registry.



High Availability (HA) Configuration

More redundant connection to gateway can be achieved using HA feature of the service package. HA service combines
multiple other services, sends requests to all of them in parallel and gives back the first successful one.

To configure a HA service, you have to wrap the individual service endpoint configuration options into
service.OptHighAvailability option.
	// Initialize high availability signing service.
	haSigner, err := service.NewSigner(
		service.OptHighAvailability(service.OptEndpoint("ksi+http://signingservice.somehost1:1234", "user", "key")),
		// Use another network protocol. Incorporate the credentials into the URL.
		service.OptHighAvailability(service.OptEndpoint("ksi+tcp://usr:pass@signingservice.somehost2:1234", "", "")),
		// The next endpoint does not use default hash algorithm.
		service.OptHighAvailability(
			service.OptEndpoint("ksi+http://signingservice.somehost3:1234", "user", "key"),
			service.OptHmacAlgorithm(hash.SHA2_512),
		),
	)
Further interaction with the constructed haSigner are exactly the same as with basic signer described in previous
chapters.

The example shows configuration of HA signer. However, similar steps apply to Extender service configuration as well.



Acknowledgments

This product includes package github.com/fullsailor/pkcs7.

*/
package ksi

import (
	_ "github.com/guardtime/goksi/blocksigner"
	_ "github.com/guardtime/goksi/errors"
	_ "github.com/guardtime/goksi/hash"
	_ "github.com/guardtime/goksi/hmac"
	_ "github.com/guardtime/goksi/log"
	_ "github.com/guardtime/goksi/net"
	_ "github.com/guardtime/goksi/pdu"
	_ "github.com/guardtime/goksi/publications"
	_ "github.com/guardtime/goksi/service"
	_ "github.com/guardtime/goksi/signature"
	_ "github.com/guardtime/goksi/tlv"
	_ "github.com/guardtime/goksi/treebuilder"
)
