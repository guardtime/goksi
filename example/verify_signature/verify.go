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

package main

import (
	"crypto/x509/pkix"
	"encoding/asn1"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/guardtime/goksi/errors"
	"github.com/guardtime/goksi/log"
	"github.com/guardtime/goksi/publications"
	"github.com/guardtime/goksi/service"
	"github.com/guardtime/goksi/signature"
	"github.com/guardtime/goksi/signature/verify/result"
)

type argVal int

const (
	argProgName argVal = iota
	argInSigFile
	argExtURI
	argPubURI
	argCnstr
	nofArgs
)

func parseConstraints(data string) []pkix.AttributeTypeAndValue {
	tmp := make([]pkix.AttributeTypeAndValue, 0)
	cnstrs := strings.Split(data, ",")
	for _, c := range cnstrs {
		ovmap := strings.Split(c, "=")
		if len(ovmap) != 2 {
			continue
		}

		var oid asn1.ObjectIdentifier
		ostrs := strings.Split(ovmap[0], ".")
		for _, s := range ostrs {
			i, err := strconv.Atoi(s)
			if err != nil {
				os.Stderr.WriteString(err.Error())
			}
			oid = append(oid, i)
		}

		tmp = append(tmp, pkix.AttributeTypeAndValue{
			Type:  oid,
			Value: ovmap[1],
		})
	}
	return tmp
}

func main() {

	// Handle exit code.
	exit := 0xff
	defer func() { os.Exit(exit) }()

	/* Handle command line parameters. */
	if len(os.Args) != int(nofArgs) {
		fmt.Printf("Usage:\n")
		fmt.Printf("  %s <sig-file> <extender-uri> <pubfile-uri> <cert-cnstr>\n", os.Args[argProgName])
		exit = 1
		return
	}

	// Create log file.
	logFile, err := os.Create(strings.Join([]string{filepath.Base(os.Args[argProgName]), "log"}, "."))
	if err != nil {
		fmt.Println("Failed to create log file: ", err)
		exit = 1
		return
	}
	defer logFile.Close()
	// Initialize logger.
	logger, err := log.New(log.DEBUG, logFile)
	if err != nil {
		fmt.Println("Failed to initialize logger: ", err)
		exit = 1
		return
	}
	// Apply logger.
	log.SetLogger(logger)

	sig, err := signature.New(signature.BuildNoVerify(signature.BuildFromFile(os.Args[argInSigFile])))
	if err != nil {
		fmt.Println("Failed to open signature file: ", err)
		exit = int(errors.KsiErr(err).Code())
		return
	}

	pfHandler, err := publications.NewFileHandler(
		publications.FileHandlerSetPublicationsURL(os.Args[argPubURI]),
		publications.FileHandlerSetFileCertConstraints(parseConstraints(os.Args[argCnstr])),
	)
	if err != nil {
		fmt.Println("Failed to initialize publications file handler: ", err)
		exit = int(errors.KsiErr(err).Code())
		return
	}

	extender, err := service.NewExtender(pfHandler,
		service.OptEndpoint(os.Args[argExtURI], "", ""),
	)
	if err != nil {
		fmt.Println("Failed to initialize extender: ", err)
		exit = int(errors.KsiErr(err).Code())
		return
	}

	verCtx, err := signature.NewVerificationContext(sig,
		signature.VerCtxOptExtendingPermitted(true),
		signature.VerCtxOptCalendarProvider(extender),
		signature.VerCtxOptPublicationsFileHandler(pfHandler),
	)
	if err != nil {
		fmt.Println("Failed to initialize verification context: ", err)
		exit = int(errors.KsiErr(err).Code())
		return
	}

	fmt.Println("Verifying signature...")
	policy := signature.DefaultVerificationPolicy
	res, err := policy.Verify(verCtx)
	if err != nil {
		fmt.Println("Failed to complete signature verification due to an error: ", err)
		exit = int(errors.KsiErr(err).Code())
		return
	}
	verRes, err := verCtx.Result()
	if err != nil {
		fmt.Println("Failed to read verification result: ", err)
		exit = int(errors.KsiErr(err).Code())
		return
	}
	fmt.Println("Verification info:")
	for _, pr := range verRes.PolicyResults() {
		fmt.Println("Policy:", pr.PolicyName())
		for _, rr := range pr.RuleResults() {
			fmt.Println("Rule result:", rr)
		}
	}
	fmt.Println("Final result:", verRes.FinalResult().String())
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

	if res == result.FAIL {
		exit = 1
		return
	}

	exit = 0
	return
}
