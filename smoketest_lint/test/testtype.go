// SPDX-FileCopyrightText: 2023 Greenbone AG
//
// SPDX-License-Identifier: GPL-2.0-or-later

package test

import (
	"fmt"
	"regexp"
)

type parse func(string) string

func undeclared(line string) string {
	match := regexp.MustCompile(`^#!undeclared:(.*)$`).FindAllStringSubmatch(line, -1)

	if len(match) != 1 {
		return ""
	}
	if len(match[0]) != 2 {
		return ""
	}

	return fmt.Sprintf("The variable %s was not declared", match[0][1])
}

var testCaseTypes []parse

func init() {
	testCaseTypes = make([]parse, 0)
	testCaseTypes = append(testCaseTypes, undeclared)
}
