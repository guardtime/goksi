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
	"bufio"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/guardtime/goksi/blocksigner"
	"github.com/guardtime/goksi/errors"
	"github.com/guardtime/goksi/hash"
	"github.com/guardtime/goksi/log"
	"github.com/guardtime/goksi/service"
	"github.com/guardtime/goksi/signature"
	"github.com/guardtime/goksi/treebuilder"
)

const (
	exitOk = 0

	exitArgError = 1
	exitIoError  = 2
	exitApiError = 3

	exitUnknown = 0xff
)

func main() {
	// Handle exit code.
	exit := exitUnknown
	// Defer the os.Exit call to be last in queue.
	defer func() { os.Exit(exit) }()

	var (
		inLogFlagVal  string
		maskIVFlagVal string
		uriFlagVal    string
		helpFlagVal   bool
	)
	flag.StringVar(&inLogFlagVal, "i", "", "Path to the log file which records will be signed.")
	flag.StringVar(&maskIVFlagVal, "iv", "", "Initialization vector for blinding mask computation.")
	flag.StringVar(&uriFlagVal, "uri", "", "Specify the signing service URI (in following format schema://login:key@some.url:1234). ")
	flag.BoolVar(&helpFlagVal, "h", false, "Print usage.")
	flag.Usage = func() {
		fmt.Printf("Example application for using block signer feature.\n")
		fmt.Printf("Usage:\n")
		fmt.Printf("  %s [arguments]\n", os.Args[0])
		fmt.Printf("Arguments:\n")
		flag.PrintDefaults()
	}
	flag.Parse()
	if helpFlagVal == true {
		flag.Usage()
		exit = exitOk
		return
	}
	/* Verify command line parameters are set. */
	if inLogFlagVal == "" || len(uriFlagVal) == 0 {
		flag.Usage()
		exit = exitArgError
		return
	}

	// Create log file.
	logFile, err := os.Create(strings.Join([]string{filepath.Base(os.Args[0]), "log"}, "."))
	if err != nil {
		fmt.Println("Failed to create log file: ", err)
		exit = exitIoError
		return
	}
	defer func() { _ = logFile.Close() }()
	// Initialize logger.
	logger, err := log.New(log.DEBUG, logFile)
	if err != nil {
		fmt.Println("Failed to initialize logger: ", err)
		exit = exitIoError
		return
	}
	// Apply logger.
	log.SetLogger(logger)

	// Open the log file.
	inlogFile, err := os.Open(inLogFlagVal)
	if err != nil {
		fmt.Println("Failed to open document file: ", err)
		exit = exitIoError
		return
	}
	defer func() { _ = inlogFile.Close() }()
	scanner := bufio.NewScanner(inlogFile)

	hsr, err := hash.Default.New()
	if err != nil {
		fmt.Println("Failed to initialize hasher.")
		exit = int(errors.KsiErr(err).Code())
		return
	}

	// Create singer instance.
	signer, err := service.NewSigner(service.OptHighAvailability(service.OptEndpoint(uriFlagVal, "", "")))
	if err != nil {
		fmt.Println("Failed to initialize signer: ", err)
		exit = exitApiError
		return
	}

	// Create a new block.
	block, err := blocksigner.New(signer,
		treebuilder.TreeOptMaskingWithPreviousLeaf([]byte(maskIVFlagVal), hash.Default.ZeroImprint()),
	)
	if err != nil {
		fmt.Println("Failed to initialize block signer: ", err)
		exit = exitApiError
		return
	}

	// Scan the log file for records.
	for scanner.Scan() {

		hsr.Reset()

		// Compute log record hash value.
		if _, err = hsr.Write(scanner.Bytes()); err != nil {
			fmt.Println("Failed to write to hasher: ", err)
			exit = exitApiError
			return
		}
		recHash, err := hsr.Imprint()
		if err != nil {
			fmt.Println("Failed to get document hash: ", err)
			exit = exitApiError
			return
		}

		if err = block.AddNode(recHash); err != nil {
			fmt.Println("Failed to get document hash: ", err)
			exit = exitApiError
			return
		}
	}
	if err := scanner.Err(); err != nil {
		fmt.Println("Failed to read log file: ", err)
		exit = exitIoError
		return
	}

	// Define a signature file writer.
	sigFileWriter := func(sig *signature.Signature, name string) {
		// Save the signature to file.
		bin, err := sig.Serialize()
		if err != nil {
			fmt.Println("Failed to serialize KSI signature: ", err)
			exit = exitApiError
			return
		}
		sigFile, err := os.Create(name)
		if err != nil {
			fmt.Println("Failed to create signature file: ", err)
			exit = exitIoError
			return
		}
		defer func() { _ = sigFile.Close() }()
		if _, err := sigFile.Write(bin); err != nil {
			fmt.Println("Failed to write signature to file: ", err)
			exit = exitIoError
			return
		}
	}

	root, err := block.Sign()
	if err != nil {
		fmt.Println("Failed to sign the block: ", err)
		exit = exitApiError
		return
	}
	sigFileWriter(root, fmt.Sprintf("%s.root.ksig", inLogFlagVal))

	recSigs, _, err := block.Signatures()
	if err != nil {
		fmt.Println("Failed to extract log record signatures: ", err)
		exit = exitIoError
		return
	}
	for i, sig := range recSigs {
		sigFileWriter(sig, fmt.Sprintf("%s.rec.%d.ksig", inLogFlagVal, i))
	}

	exit = exitOk
	return
}
