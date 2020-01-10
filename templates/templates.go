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

// Package templates implements the TLV template registry.
package templates

import (
	"fmt"
	"reflect"
	"sync"

	"github.com/guardtime/goksi/errors"
	"github.com/guardtime/goksi/tlv"
)

type tlvTemplates map[string]*tlv.Template
type templateRegistry struct {
	templates tlvTemplates
}

var (
	registry templateRegistry
	once     sync.Once
)

// Register registers a new TLV template for an object.
// Returns an error in case the template description is incorrect (see github.com/guardtime/goksi/tlv
// package documentation for help).
func Register(obj interface{}, name string, tag uint16) error {
	return getRegistry().addNewTemplate(reflect.TypeOf(obj), name, tag)
}

// Get returns a TLV templates for a given name.
// Note that the templates has to be registered prior via Register().
func Get(name string) (*tlv.Template, error) {
	if len(registry.templates) == 0 {
		return nil, errors.New(errors.KsiInvalidStateError).AppendMessage("TLV templates are not initialized.")
	}

	template, ok := getRegistry().templates[name]
	if !ok {
		return nil, errors.New(errors.KsiInvalidStateError).
			AppendMessage(fmt.Sprintf("TLV Template does not exist for: '%s'.", name))
	}

	return template, nil
}

// GetAll returns a list of registered TLV template names.
func GetAll() []string {
	if len(registry.templates) == 0 {
		return nil
	}

	keys := make([]string, 0, len(getRegistry().templates))
	for k := range getRegistry().templates {
		keys = append(keys, k)
	}
	return keys
}

func getRegistry() *templateRegistry {
	once.Do(func() {
		registry.templates = make(tlvTemplates)
	})
	return &registry
}

func (m *templateRegistry) addNewTemplate(t reflect.Type, name string, tag uint16) error {
	if m == nil {
		return errors.New(errors.KsiInvalidArgumentError)
	}

	if t.Kind() != reflect.Ptr || t.Elem().Kind() != reflect.Struct {
		return errors.New(errors.KsiInvalidFormatError).
			AppendMessage(fmt.Sprintf("Unsupported input type: %v.", t)).
			AppendMessage("Only pointer to struct is supported as input.")
	}

	if name == "" {
		name = t.Elem().Name()
	}

	if _, alreadyExists := m.templates[name]; alreadyExists {
		return errors.New(errors.KsiInvalidStateError).
			AppendMessage(fmt.Sprintf("TLV Template already exists for: '%s'.", name))
	}

	template, err := tlv.NewTemplate(tag)
	if err != nil {
		return errors.KsiErr(err).AppendMessage(fmt.Sprintf("Failed to create empty template for: '%s'.", name))
	}
	if err = template.SetPath(name); err != nil {
		return err
	}
	if err = template.Parse(t); err != nil {
		return errors.KsiErr(err).AppendMessage(fmt.Sprintf("Failed to construct template for: '%s'.", name))
	}

	m.templates[name] = template
	return nil
}
