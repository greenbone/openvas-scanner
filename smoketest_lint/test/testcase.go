// SPDX-FileCopyrightText: 2023 Greenbone AG
//
// SPDX-License-Identifier: GPL-2.0-or-later

package test

import "fmt"

type testCase struct {
	msg    string
	line   int
	tested bool
}

type testError struct {
	line     int
	expected string
	occurred string
}

func (t testError) Error() string {
	return fmt.Sprintf("line %d:\nexpected: %s\noccurred: %s", t.line, t.expected, t.occurred)
}

func (t1 *testCase) test(t2 *testCase) error {
	if t1.line != t2.line {
		return nil
	}
	t1.tested = true
	t2.tested = true
	if t1.msg != t2.msg {
		return testError{
			t1.line,
			t1.msg,
			t2.msg,
		}
	}
	return nil
}
