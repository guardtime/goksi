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

	// Define command line arguments.
	var (
		inLogFlagVal                string
		maskIVFlagVal               string
		uriFlagVal                  string
		persistRecordHashFlagVal    bool
		persistMetaDataFlagVal      bool
		persistAggregateHashFlagVal bool
		helpFlagVal                 bool
	)
	fs := flag.NewFlagSet(os.Args[0], flag.ContinueOnError)
	fs.StringVar(&inLogFlagVal, "i", "", "Path to the log file which records will be signed.")
	fs.StringVar(&maskIVFlagVal, "iv", "", "Initialization vector for blinding mask computation.")
	fs.StringVar(&uriFlagVal, "uri", "", "Specify the signing service URI (in following format schema://login:key@some.url:1234). ")
	fs.BoolVar(&persistRecordHashFlagVal, "rec", false, "Enables persistence of record hashes.")
	fs.BoolVar(&persistMetaDataFlagVal, "meta", false, "Enables persistence of metadata records.")
	fs.BoolVar(&persistAggregateHashFlagVal, "aggr", false, "Enables persistence of intermediate aggregate hashes.")
	fs.BoolVar(&helpFlagVal, "h", false, "Print usage.")
	fs.Usage = func() {
		fmt.Fprintf(fs.Output(), ""+
			"Example application for using block signer feature with block serialization. Block signer is "+
			"used to aggegate multiple hash values into single root hash value that is signed with KSI. "+
			"Instead of N signing only 1 signature is issued for N hash values. \n"+
			"\n"+
			"The application perfors following steps:\n"+
			"1. Every log line in the log file is hashed and appended to aggregation tree.\n"+
			"2. Local aggregation tree root hash value is signed with a single KSI signature.\n"+
			"3. Local aggregation tree and its KSI signature is serialized and saved to a file.\n"+
			"\n"+
			"Usage:\n"+
			"  %s [arguments]\n"+
			"Arguments:\n",
			os.Args[0])
		fs.PrintDefaults()
	}
	// Parse the user arguments.
	if err := fs.Parse(os.Args[1:]); err != nil {
		fmt.Println("Failed to parse command line arguments: ", err)
		exit = exitArgError
		return
	}
	if helpFlagVal == true {
		fs.Usage()
		exit = exitOk
		return
	}
	// Verify mandatory command line parameters are set.
	if inLogFlagVal == "" || len(uriFlagVal) == 0 {
		fs.Usage()
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

	// Open the input file.
	inLogFile, err := os.Open(inLogFlagVal)
	if err != nil {
		fmt.Println("Failed to open input log file: ", err)
		exit = exitIoError
		return
	}
	defer func() { _ = inLogFile.Close() }()
	scanner := bufio.NewScanner(inLogFile)

	var (
		serializer = &BlockSerializer{}
		treeOpt    []treebuilder.TreeOpt
	)
	if maskIVFlagVal != "" {
		treeOpt = append(treeOpt, treebuilder.TreeOptMaskingWithPreviousLeaf([]byte(maskIVFlagVal), hash.Default.ZeroImprint()))
	}
	if persistRecordHashFlagVal {
		treeOpt = append(treeOpt, treebuilder.TreeOptRecordListener(serializer))
	}
	if persistMetaDataFlagVal {
		treeOpt = append(treeOpt, treebuilder.TreeOptMetadataListener(serializer))
	}
	if persistAggregateHashFlagVal {
		treeOpt = append(treeOpt, treebuilder.TreeOptAggregateListener(serializer))
	}

	// Create singer instance.
	signer, err := service.NewSigner(service.OptHighAvailability(service.OptEndpoint(uriFlagVal, "", "")))
	if err != nil {
		fmt.Println("Failed to initialize signer: ", err)
		exit = exitApiError
		return
	}

	// Create a new block.
	block, err := blocksigner.New(signer, treeOpt...)
	if err != nil {
		fmt.Println("Failed to initialize block signer: ", err)
		exit = exitApiError
		return
	}

	// Scan the log file for records/lines.
	hsr, err := hash.Default.New()
	if err != nil {
		fmt.Println("Failed to initialize hasher.")
		exit = int(errors.KsiErr(err).Code())
		return
	}
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
			fmt.Println("Failed to hash log line: ", err)
			exit = exitApiError
			return
		}

		if err = block.AddNode(recHash); err != nil {
			fmt.Println("Failed to add log line hash to tree: ", err)
			exit = exitApiError
			return
		}
	}
	if err := scanner.Err(); err != nil {
		fmt.Println("Failed to read log file: ", err)
		exit = exitIoError
		return
	}

	// Sing the root hash of the block.
	root, err := block.Sign()
	if err != nil {
		fmt.Println("Failed to sign the block: ", err)
		exit = exitApiError
		return
	}
	if err := serializer.SetRootSignature(root); err != nil {
		fmt.Println("Failed to serialize signature: ", err)
		exit = exitApiError
		return
	}

	// Update block info.
	if err := serializer.SetHashAlgorithm(hash.Default); err != nil {
		fmt.Println("Failed to set hash algorithm: ", err)
		exit = exitApiError
		return
	}
	if maskIVFlagVal != "" {
		if err := serializer.SetIV([]byte(maskIVFlagVal)); err != nil {
			fmt.Println("Failed to set initialization vector: ", err)
			exit = exitApiError
			return
		}
		if err := serializer.SetLastHash(hash.Default.ZeroImprint()); err != nil {
			fmt.Println("Failed to set previous block hash value: ", err)
			exit = exitApiError
			return
		}
	}

	// Dump the block into a file.
	if err := serializer.SaveToFile(fmt.Sprintf("%s.blocksig.json", inLogFlagVal)); err != nil {
		fmt.Println("Failed to write block to file: ", err)
		exit = exitIoError
		return
	}
	exit = exitOk
	return
}
