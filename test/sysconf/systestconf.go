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

package sysconf

import (
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/json"
	"os"
	"strconv"
	"strings"
)

type Configuration struct {
	Extender         Service
	Aggregator       Service
	Pubfile          Pubfile
	Schema           Schema
	HighAvailability HighAvailability
}

type Service struct {
	Host string
	Port string
	User string
	Pass string
	Hmac string
}

type Pubfile struct {
	Url   string
	Cnstr string

	cnstrDecoded *[]pkix.AttributeTypeAndValue
}

type Schema struct {
	Tcp  string
	Http string
}

type HighAvailability struct {
	Extender   []Service
	Aggregator []Service
}

func New(path string) (*Configuration, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer func() {
		if err := f.Close(); err != nil {
			panic(err)
		}
	}()

	decoder := json.NewDecoder(f)
	configuration := new(Configuration)
	if err = decoder.Decode(configuration); err != nil {
		return nil, err
	}
	return configuration, nil
}

func (s *Service) BuildURI(schema string) string {
	if s == nil {
		return ""
	}
	var b strings.Builder
	b.WriteString(schema)
	b.WriteString("://")
	if s.User != "" && s.Pass != "" {
		b.WriteString(s.User)
		b.WriteString(":")
		b.WriteString(s.Pass)
		b.WriteString("@")
	}
	b.WriteString(s.Host)
	b.WriteString(":")
	b.WriteString(s.Port)
	return b.String()
}

func (p *Pubfile) Constraints() []pkix.AttributeTypeAndValue {
	if p == nil {
		os.Stderr.WriteString("Invalid argument!")
		return nil
	}

	if p.cnstrDecoded == nil {
		tmp := make([]pkix.AttributeTypeAndValue, 0)
		cnstrs := strings.Split(p.Cnstr, ",")
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
		p.cnstrDecoded = &tmp
	}
	return *p.cnstrDecoded
}
