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

package tlv

import (
	"fmt"

	"github.com/guardtime/goksi/errors"
)

type tlvRecord struct {
	origin *Template
	count  uint16
}

type parserState struct {
	objIndex           int
	mustBeLast         bool
	mustBeLastTemplate *Template
	path               []uint16
	records            []*tlvRecord
	groups             []uint16
}

// ParseNested parses TLV value part with given Template.
// When parsing is complete, list of nested TLVs should be under input TLV.
func (t *Tlv) ParseNested(tmpl *Template) error {
	if t == nil || tmpl == nil {
		return errors.New(errors.KsiInvalidArgumentError)
	}
	state := &parserState{
		path: []uint16{t.Tag},
	}
	return t.parseWithTemplateAndState(state, tmpl)
}

func tlvPathToString(path []uint16) string {
	tmp := ""
	for i, v := range path {
		if i > 0 {
			tmp += "."
		}
		tmp += fmt.Sprintf("%x", v)
	}
	return tmp
}

func (template *Template) checkIndexOnTheGo(state *parserState) error {
	if template == nil || state == nil {
		return errors.New(errors.KsiInvalidArgumentError)
	}
	topt := template.options
	if topt.expectedIndex == IWhatever {
		return nil
	} else if topt.expectedIndex == IFirst && state.objIndex != 0 {
		return errors.New(errors.KsiInvalidFormatError).
			AppendMessage(fmt.Sprintf("%s should be first, but is at position %v.", template.path, state.objIndex))
	} else if topt.expectedIndex >= IBase && state.objIndex != int(topt.expectedIndex) {
		return errors.New(errors.KsiInvalidFormatError).
			AppendMessage(fmt.Sprintf("%s should be at position %v, but is at position %v.",
				template.path, int(topt.expectedIndex), state.objIndex))
	} else if state.mustBeLast {
		return errors.New(errors.KsiInvalidFormatError).
			AppendMessage(fmt.Sprintf("%s should be the last TLV, instead of %s.",
				state.mustBeLastTemplate.path, template.path))
	}
	return nil
}

func (template *Template) checkCountUpperLimitOnTheGo(state *parserState, count uint16) error {
	if template == nil || state == nil {
		return errors.New(errors.KsiInvalidArgumentError)
	}
	topt := template.options
	if topt.expectedCount == Count0_N {
		return nil
	} else if topt.expectedCount == Count0_1 && count > 1 {
		return errors.New(errors.KsiInvalidFormatError).
			AppendMessage(fmt.Sprintf("%s count should be %s, but is %v.",
				template.path, topt.expectedCount.String(), count))
	} else if int(topt.expectedCount) > int(count) {
		return errors.New(errors.KsiInvalidFormatError).
			AppendMessage(fmt.Sprintf("%s count should be %s, but is %v.",
				template.path, topt.expectedCount.String(), count))
	}
	return nil
}

func (template *Template) checkCount(state *parserState) error {
	if template == nil || state == nil {
		return errors.New(errors.KsiInvalidArgumentError)
	}
	expectedCount := template.options.expectedCount

	// Verify group dependencies first.
	isInGroup := false
	if state.groups != nil && (template.options.groupID != GroupNone || len(template.options.dependencyGroup) != 0) {
	stateGroups:
		for _, g := range state.groups {
			// Is the element in the same group.
			if g == uint16(template.options.groupID) {
				isInGroup = true
				break stateGroups
			}
			// Is the element in dependant group.
			for _, depGroup := range template.options.dependencyGroup {
				if g == uint16(depGroup) {
					isInGroup = true
					break stateGroups
				}
			}
		}
	} else {
		isInGroup = true
	}

	// Verify element count.
	if isInGroup &&
		(expectedCount == Count1_N || expectedCount == Count0_1 || expectedCount > templateCount(0)) {
		count := uint16(0)
		for _, rec := range state.records {
			if rec.origin == template {
				count = rec.count
				break
			}
		}

		if (expectedCount == Count1_N && count == 0) ||
			(expectedCount >= CountBase && count != uint16(expectedCount)) ||
			(expectedCount == Count0_1 && count > 1) {
			return errors.New(errors.KsiInvalidFormatError).
				AppendMessage(fmt.Sprintf("%s count should be %s, but is %v.",
					template.path, expectedCount.String(), count))
		}
	}

	return nil
}

func (ps *parserState) checkCountFinal(templateList []*Template) error {
	if ps == nil {
		return errors.New(errors.KsiInvalidArgumentError)
	}
	// Loop over all templates and check if it is present.
	for _, t := range templateList {
		if err := t.checkCount(ps); err != nil {
			return err
		}
	}

	return nil
}

func (template *Template) isInConflictWith(state *parserState) error {
	if template == nil || state == nil {
		return errors.New(errors.KsiInvalidArgumentError)
	}
	if template.options.conflictingGroup == nil || len(template.options.conflictingGroup) == 0 {
		return nil
	}

	groups := state.groups

	for _, inConflictGroup := range template.options.conflictingGroup {
		for _, g := range groups {
			if g == uint16(inConflictGroup) {
				// TODO: How to resolve meaningful info?
				return errors.New(errors.KsiInvalidFormatError).
					AppendMessage(fmt.Sprintf("TLV (%s) is in conflict with group %v.", template.path, g))
			}
		}
	}

	return nil
}

func (template *Template) isMissingDependencies(state *parserState) error {
	if template == nil || state == nil {
		return errors.New(errors.KsiInvalidArgumentError)
	}
	if template.options.dependencyGroup == nil || len(template.options.dependencyGroup) == 0 {
		return nil
	}

	groups := state.groups

	for _, isNeededBy := range template.options.dependencyGroup {
		isDepResolved := false
		for _, g := range groups {
			if g == uint16(isNeededBy) {
				isDepResolved = true
				break
			}
		}

		if !isDepResolved {
			// TODO: How to resolve meaningful info?
			return errors.New(errors.KsiInvalidFormatError).
				AppendMessage(fmt.Sprintf("TLV (%s.%x) depends on missing group %v.",
					tlvPathToString(state.path), template.tag, isNeededBy))
		}
	}

	return nil
}

func (ps *parserState) checkGroupsFinal() error {
	if ps == nil {
		return errors.New(errors.KsiInvalidArgumentError)
	}
	for _, rec := range ps.records {
		err := rec.origin.isInConflictWith(ps)
		if err != nil {
			return err
		}

		err = rec.origin.isMissingDependencies(ps)
		if err != nil {
			return err
		}
	}

	return nil
}

func (ps *parserState) checkIndexFinal() error {
	if ps.records == nil || len(ps.records) == 0 {
		return nil
	}

	recCount := len(ps.records)

	// At first check the first and the last TLV.
	template := ps.records[0].origin
	expIndex := template.options.expectedIndex
	if expIndex != IWhatever && expIndex != ILast && expIndex != templateIndex(recCount-1) {
		return errors.New(errors.KsiInvalidStateError).AppendMessage(
			fmt.Sprintf("TLV (%s.%x) should be at position %v, but is at position %v.", tlvPathToString(ps.path), template.tag, expIndex, recCount-1))
	}

	if recCount > 1 {
		template = ps.records[recCount-1].origin
		expIndex = template.options.expectedIndex
		if expIndex != IWhatever && expIndex != IFirst && expIndex != IBase {
			return errors.New(errors.KsiInvalidStateError).AppendMessage(
				fmt.Sprintf("TLV (%s.%x) should be at position %v, but is at position %v.", tlvPathToString(ps.path), template.tag, expIndex, IBase))
		}
	}
	for i := 1; i < recCount-1; i++ {
		var rec *tlvRecord
		var position int

		position = recCount - 1 - i
		rec = ps.records[position]

		template := rec.origin
		expIndex := template.options.expectedIndex

		if expIndex == IWhatever {
			continue
		} else if expIndex == IFirst {
			return errors.New(errors.KsiInvalidStateError).AppendMessage(
				fmt.Sprintf("TLV (%s.%x) should be first, but is at position %v.", tlvPathToString(ps.path), template.tag, i))
		} else if expIndex == ILast {
			return errors.New(errors.KsiInvalidStateError).AppendMessage(
				fmt.Sprintf("TLV (%s.%x) should be the last TLV, but is at position %v.", tlvPathToString(ps.path), template.tag, i))
		} else if int(expIndex) != i {
			return errors.New(errors.KsiInvalidStateError).AppendMessage(
				fmt.Sprintf("TLV (%s.%x) should be at position %v, but is at position %v.", tlvPathToString(ps.path), template.tag, expIndex, i))
		}

	}

	return nil
}

func (ps *parserState) registerTlv(template *Template) error {
	return ps.registerInternal(template, false)
}

func (ps *parserState) registerInternal(template *Template, isSerialization bool) error {
	if ps == nil || template == nil {
		return errors.New(errors.KsiInvalidArgumentError)
	}

	// At first check if the index constraint holds.
	if !isSerialization {
		if err := template.checkIndexOnTheGo(ps); err != nil {
			return err
		}
	}

	// Register index increase.
	ps.objIndex++

	// Register Group.
	if template.options.groupID != GroupNone {
		addNew := true
		for _, g := range ps.groups {
			if g == uint16(template.options.groupID) {
				addNew = false
				break
			}
		}

		if addNew {
			ps.groups = append(ps.groups, uint16(template.options.groupID))
		}
	}

	// Register count.
	for _, v := range ps.records {
		if v.origin == template {
			v.count++
			if err := template.checkCountUpperLimitOnTheGo(ps, v.count); err != nil {
				return err
			}

			return nil
		}
	}

	if template.options.expectedIndex == ILast {
		ps.mustBeLast = true
		ps.mustBeLastTemplate = template
	}

	ps.records = append(ps.records, &tlvRecord{
		origin: template,
		count:  1,
	})

	return nil
}

func (ps *parserState) createChildState(of uint16) *parserState {
	return &parserState{
		path: append(append([]uint16(nil), ps.path...), of),
	}
}

func (t *Tlv) parseWithTemplateAndState(state *parserState, tmpl *Template) error {
	if state == nil || t == nil || tmpl == nil {
		return errors.New(errors.KsiInvalidArgumentError)
	}

	if !tmpl.IsMatchingTag(t.Tag) {
		return errors.New(errors.KsiInvalidFormatError).AppendMessage(
			fmt.Sprintf("TLV (%s) does not match with template tags %x.", tlvPathToString(state.path), tmpl.tag))
	}

	var (
		dataSize = len(t.value)
		dataLeft = dataSize
	)
	if tmpl.templateType == VTNested || tmpl.templateType == VTNestedTlvObj {
		for dataLeft > 0 {
			// Parse next TLV.
			tlv, err := NewTlv(ConstructFromSlice(t.value[(dataSize - dataLeft):]))
			if err != nil || tlv == nil {
				return errors.KsiErr(err).AppendMessage(
					fmt.Sprintf("TLV (%s) child element could not be parsed.", tlvPathToString(state.path)))
			}

			// Check if there is a matching TLV template.
			template, err := tmpl.getByTag(tlv.Tag)
			if err != nil {
				return errors.KsiErr(err).
					AppendMessage(fmt.Sprintf("Unexpected error while getting TLV (%s.%x) template.",
						tlvPathToString(state.path), tlv.Tag))
			}

			// Fail if Critical TLV is encountered that has no matching TLV template, or drop it if it is accepted.
			if template == nil {
				if tlv.NonCritical {
					if !tlv.ForwardUnknown {
						t.Nested = append(t.Nested, tlv)
					}

					dataLeft = dataLeft - int(tlv.Length())
					continue
				}
				return errors.New(errors.KsiInvalidFormatError).AppendMessage(
					fmt.Sprintf("TLV (%s.%x) template not found for a mandatory TLV.",
						tlvPathToString(state.path), tlv.Tag))
			}

			// Register TLV in parser state. Run some checks against constraints on the fly.
			if err = state.registerTlv(template); err != nil {
				return errors.KsiErr(err).AppendMessage(
					fmt.Sprintf("TLV (%s.%x) template could not be registered.", tlvPathToString(state.path), tlv.Tag))
			}

			// If it is a nested TLV, make a recursive call to resolve its internal structure.
			if template.templateType == VTNested || template.templateType == VTNestedTlvObj {
				if err = tlv.parseWithTemplateAndState(state.createChildState(tlv.Tag), template); err != nil {
					return errors.KsiErr(err).AppendMessage(
						fmt.Sprintf("TLV (%s.%x) could not be resolved.", tlvPathToString(state.path), template.tag))
				}
			}

			// Append extracted TLV.
			t.Nested = append(t.Nested, tlv)
			dataLeft = dataLeft - int(tlv.Length())
		}
	}

	// Final examination.
	err := state.checkCountFinal(tmpl.childTemplate)
	if err != nil {
		return errors.KsiErr(err).AppendMessage(
			fmt.Sprintf("TLV (%s) internal constraints failed.", tlvPathToString(state.path)))
	}
	err = state.checkGroupsFinal()
	if err != nil {
		return errors.KsiErr(err).AppendMessage(
			fmt.Sprintf("TLV (%s) internal constraints failed.", tlvPathToString(state.path)))
	}

	return nil
}
