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
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/guardtime/goksi/errors"
	"github.com/guardtime/goksi/hash"
	"github.com/guardtime/goksi/log"
	"github.com/guardtime/goksi/service"
)

type argVal int

const (
	argProgName argVal = iota
	argInDataFile
	argOutSigFile
	argAggrURI
	argAggrUser
	argAggrPass
	nofArgs
)

func main() {
	// Handle exit code.
	exit := 0
	defer func() { os.Exit(exit) }()

	/* Handle command line parameters. */
	if len(os.Args) != int(nofArgs) {
		fmt.Printf("Usage:\n")
		fmt.Printf("  %s <in-data-file> <out-sign-file> <aggregator-uri> <user> <pass> \n", os.Args[argProgName])
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

	// Create document hash.
	docFile, err := os.Open(os.Args[argInDataFile])
	if err != nil {
		fmt.Println("Failed to open document file: ", err)
		exit = 1
		return
	}
	defer docFile.Close()

	hsr, err := hash.Default.New()
	if err != nil {
		fmt.Println("Failed to initialize hasher.")
		exit = int(errors.KsiErr(err).Code())
		return
	}
	if _, err := io.Copy(hsr, docFile); err != nil {
		fmt.Println("Failed to write to hasher: ", err)
		exit = 1
		return
	}
	docHash, err := hsr.Imprint()
	if err != nil {
		fmt.Println("Failed to get document hash: ", err)
		exit = int(errors.KsiErr(err).Code())
		return
	}

	// Create singer instance.
	signer, err := service.NewSigner(
		service.OptEndpoint(os.Args[argAggrURI], os.Args[argAggrUser], os.Args[argAggrPass]),
	)
	if err != nil {
		fmt.Println("Failed to initialize signer: ", err)
		exit = int(errors.KsiErr(err).Code())
		return
	}
	// Create signing request.
	signature, err := signer.Sign(docHash)
	if err != nil {
		fmt.Println("Failed to sign document hash: ", err)
		exit = int(errors.KsiErr(err).Code())
		return
	}

	// Save the signature to file.
	bin, err := signature.Serialize()
	if err != nil {
		fmt.Println("Failed to serialize KSI signature: ", err)
		exit = int(errors.KsiErr(err).Code())
		return
	}
	sigFile, err := os.Create(os.Args[argOutSigFile])
	if err != nil {
		fmt.Println("Failed to create signature file: ", err)
		exit = 1
		return
	}
	defer sigFile.Close()
	if _, err := sigFile.Write(bin); err != nil {
		fmt.Println("Failed to write signature to file: ", err)
		exit = 1
		return
	}

	exit = 0
	return
}
