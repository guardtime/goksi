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
	"github.com/guardtime/goksi/signature"
)

type argVal int

const (
	argProgName argVal = iota
	argInDir
	argAggrURI
	argAggrUser
	argAggrPass
	nofArgs
)

func printHelp(name string) {
	fmt.Printf("Usage:\n")
	fmt.Printf("  %s <in-directory> <aggregator-uri> <user> <pass> \n", name)
}

func main() {
	// Handle exit code.
	exit := 0xff
	defer func() { os.Exit(exit) }()

	/* Handle command line parameters. */
	if len(os.Args) != int(nofArgs) {
		printHelp(os.Args[argProgName])
		exit = 1
		return
	}
	if inf, err := os.Stat(os.Args[argInDir]); err != nil {
		fmt.Println("Failed to create log file: ", err)
		exit = 1
		return
	} else if !inf.IsDir() {
		fmt.Println("Input directory is not a directory.")
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

	// Create singer instance.
	signer, err := service.NewSigner(
		service.OptEndpoint(os.Args[argAggrURI], os.Args[argAggrUser], os.Args[argAggrPass]),
	)
	if err != nil {
		fmt.Println("Failed to initialize signer: ", err)
		exit = int(errors.KsiErr(err).Code())
		return
	}

	type result struct {
		id  int
		doc string
		sig *signature.Signature
		err error
	}
	workerCount := 0
	resultChan := make(chan *result)
	// Walk through the input directory and sign every regular file.
	err = filepath.Walk(os.Args[argInDir], func(path string, info os.FileInfo, err error) error {
		if err != nil {
			fmt.Println("Failed to walk through the input directory.")
			return err
		}
		if info.IsDir() {
			// Skip directories.
			return nil
		}

		workerCount++
		// Start a worker goroutine for hashing and signing the file asynchronously.
		go func(id int, docPath string, done chan *result) {
			docFile, err := os.Open(docPath)
			if err != nil {
				fmt.Printf("Failed to open file: %s\n", docPath)
				done <- &result{
					id:  id,
					doc: docPath,
					err: err,
				}
				return
			}
			defer docFile.Close()
			data := make([]byte, 4096)
			hsr, err := hash.Default.New()
			if err != nil {
				fmt.Println("Failed to initialize hasher.")
				done <- &result{
					id:  id,
					doc: docPath,
					err: err,
				}
				return
			}
			for {
				n, err := docFile.Read(data)
				if err != nil {
					if err == io.EOF {
						break
					}
					fmt.Println("Failed to read document.")
					done <- &result{
						id:  id,
						doc: docPath,
						err: err,
					}
					return
				}
				data = data[:n]
				if _, err := hsr.Write(data); err != nil {
					fmt.Println("Failed to write to hasher.")
					done <- &result{
						id:  id,
						doc: docPath,
						err: err,
					}
				}
			}
			docHsh, err := hsr.Imprint()
			if err != nil {
				fmt.Println("Failed to get document hash: ", err)
				done <- &result{
					id:  id,
					doc: docPath,
					err: err,
				}
				return
			}

			// Create signing request.
			sig, err := signer.Sign(docHsh)
			if err != nil {
				fmt.Println("Failed to sign document hash: ", err)
				done <- &result{
					id:  id,
					doc: docPath,
					err: err,
				}
				return
			}

			done <- &result{
				id:  id,
				doc: docPath,
				sig: sig,
				err: nil,
			}
		}(workerCount, path, resultChan)
		return nil
	})
	if err != nil {
		fmt.Println("Failed to walk through all documents: ", err)
		exit = int(errors.KsiErr(err, errors.KsiIoError).Code())
		return
	}

	// Wait for the workers to finish.
	var lastErr error
	for {
		res := <-resultChan
		if res.err != nil {
			// Just log the error and wait for all workers to finish.
			fmt.Println("Failed to sign document: ", res.doc)
			fmt.Println(err)
			lastErr = res.err
		}

		if res.sig != nil {
			// Save received KSI signature to file.
			bin, err := res.sig.Serialize()
			if err != nil {
				fmt.Println("Failed to serialize KSI signature: ", err)
				exit = int(errors.KsiErr(err).Code())
				return
			}
			sigFile, err := os.Create(strings.Join([]string{filepath.Base(res.doc), "ksig"}, "."))
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
		}

		// Verify if all responses have been received.
		workerCount--
		if workerCount == 0 {
			break
		}
	}

	// Handle error code.
	if lastErr != nil {
		exit = int(errors.KsiErr(err).Code())
		return
	}
	exit = 0
	return
}
