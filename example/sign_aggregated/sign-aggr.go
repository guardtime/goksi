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
	"github.com/guardtime/goksi/treebuilder"
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

	// Aggregate the content of the input directory using a tree builder.
	tree, err := treebuilder.New()
	if err != nil {
		fmt.Println("Failed to initialize tree builder: ", err)
		exit = int(errors.KsiErr(err).Code())
		return
	}
	err = filepath.Walk(os.Args[argInDir],
		func(path string, info os.FileInfo, err error) error {
			if err != nil {
				fmt.Println("Failed to walk through the input directory.")
				return err
			}
			if info.IsDir() {
				// Skip directories.
				return nil
			}

			docFile, err := os.Open(path)
			if err != nil {
				fmt.Printf("Failed to open file: %s\n", path)
				return err
			}
			defer docFile.Close()
			data := make([]byte, 4096)
			hsr, err := hash.Default.New()
			if err != nil {
				fmt.Println("Failed to initialize hasher.")
				return err
			}
			for {
				n, err := docFile.Read(data)
				if err != nil {
					if err == io.EOF {
						break
					}
					fmt.Println("Failed to write read document.")
					return err
				}
				data = data[:n]
				if _, err := hsr.Write(data); err != nil {
					fmt.Println("Failed to write to hasher.")
					return err
				}
			}
			docHash, err := hsr.Imprint()
			if err != nil {
				fmt.Println("Failed to get document hash.")
				return err
			}

			err = tree.AddNode(docHash, treebuilder.InputHashOptionUserContext(path))
			if err != nil {
				fmt.Println("Failed to add new leaf to the tree.")
				return err
			}

			return nil
		})
	if err != nil {
		fmt.Println("Failed to build tree: ", err)
		exit = int(errors.KsiErr(err).Code())
		return
	}
	// Aggregate the added leaf.
	rootHsh, rootLvl, err := tree.Aggregate()
	if err != nil {
		fmt.Println("Failed to close the tree: ", err)
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
	rootSig, err := signer.Sign(rootHsh, service.SignOptionLevel(rootLvl))
	if err != nil {
		fmt.Println("Failed to sign document hash: ", err)
		exit = int(errors.KsiErr(err).Code())
		return
	}

	leafs, err := tree.Leafs()
	if err != nil {
		fmt.Println("Failed to get tree leafs: ", err)
		exit = int(errors.KsiErr(err).Code())
		return
	}
	for _, l := range leafs {
		docFilePath, err := l.UserCtx()
		if err != nil {
			fmt.Println("Failed to get leaf user context: ", err)
			exit = int(errors.KsiErr(err).Code())
			return
		}

		aggrChain, err := l.AggregationChain()
		if err != nil {
			fmt.Println("Failed to get leaf aggregation hash chain: ", err)
			exit = int(errors.KsiErr(err).Code())
			return
		}

		sig, err := signature.New(signature.BuildWithAggrChain(rootSig, aggrChain))
		if err != nil {
			fmt.Println("Failed to construct KSI signature for a tree leaf: ", err)
			exit = int(errors.KsiErr(err).Code())
			return
		}
		// Save the signature to file.
		bin, err := sig.Serialize()
		if err != nil {
			fmt.Println("Failed to serialize KSI signature: ", err)
			exit = int(errors.KsiErr(err).Code())
			return
		}
		sigFile, err := os.Create(strings.Join([]string{filepath.Base(docFilePath.(string)), "ksig"}, "."))
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

	exit = 0
	return
}
