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
	"flag"
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

const (
	exitOk = 0

	exitArgError = 1
	exitIoError  = 2
	exitApiError = 3

	exitUnknown = 0xff
)

type uriFlag []string

func (i *uriFlag) String() string {
	return fmt.Sprint(*i)
}

func (i *uriFlag) Set(value string) error {
	*i = append(*i, value)
	return nil
}

func main() {
	// Handle exit code.
	exit := exitUnknown
	// Defer the os.Exit call to be last in queue.
	defer func() { os.Exit(exit) }()

	var (
		inFlagVal   string
		outFlagVal  string
		uriFlagVal  uriFlag
		helpFlagVal bool
	)
	flag.StringVar(&inFlagVal, "i", "", "Path to the file to be hashed and signed.")
	flag.StringVar(&outFlagVal, "o", "", "Output signature file name.")
	flag.Var(&uriFlagVal, "uri", "Specify the signing service URI (in following format schema://login:key@some.url:1234). "+
		"Use multiple times for defining more than one endpoint.")
	flag.BoolVar(&helpFlagVal, "h", false, "Print usage.")
	flag.Usage = func() {
		fmt.Printf("Example application for using signing high availability feature.\n")
		fmt.Printf("Usage:\n")
		fmt.Printf("  %s arguments\n", os.Args[0])
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
	if inFlagVal == "" || outFlagVal == "" || len(uriFlagVal) == 0 {
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
	defer logFile.Close()
	// Initialize logger.
	logger, err := log.New(log.DEBUG, logFile)
	if err != nil {
		fmt.Println("Failed to initialize logger: ", err)
		exit = exitIoError
		return
	}
	// Apply logger.
	log.SetLogger(logger)

	// Create document hash.
	docFile, err := os.Open(inFlagVal)
	if err != nil {
		fmt.Println("Failed to open document file: ", err)
		exit = exitIoError
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
		exit = exitApiError
		return
	}
	docHash, err := hsr.Imprint()
	if err != nil {
		fmt.Println("Failed to get document hash: ", err)
		exit = exitApiError
		return
	}

	var opts []service.Option
	for _, uri := range uriFlagVal {
		opts = append(opts, service.OptHighAvailability(service.OptEndpoint(uri, "", "")))
	}

	// Create singer instance.
	signer, err := service.NewSigner(opts...)
	if err != nil {
		fmt.Println("Failed to initialize signer: ", err)
		exit = exitApiError
		return
	}
	// Create signing request.
	signature, err := signer.Sign(docHash)
	if err != nil {
		fmt.Println("Failed to sign document hash: ", err)
		exit = exitApiError
		return
	}

	// Save the signature to file.
	bin, err := signature.Serialize()
	if err != nil {
		fmt.Println("Failed to serialize KSI signature: ", err)
		exit = exitApiError
		return
	}
	sigFile, err := os.Create(outFlagVal)
	if err != nil {
		fmt.Println("Failed to create signature file: ", err)
		exit = exitIoError
		return
	}
	defer sigFile.Close()
	if _, err := sigFile.Write(bin); err != nil {
		fmt.Println("Failed to write signature to file: ", err)
		exit = exitIoError
		return
	}

	exit = exitOk
	return
}
