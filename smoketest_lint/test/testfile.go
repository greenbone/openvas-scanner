// SPDX-FileCopyrightText: 2023 Greenbone AG
//
// SPDX-License-Identifier: GPL-2.0-or-later

package test

import (
	"bufio"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
)

type testFile struct {
	Name      string
	dir       string
	testCases []*testCase
}

// testFileFromPath Parses a Nasl file and creates testCases for a testFile
// based on
// specific comments within the file.
func testFileFromPath(path string, info os.FileInfo) (testFile, error) {
	// Error Handling
	if info.IsDir() {
		return testFile{}, fmt.Errorf("unable to parse %s: File is Directory", info.Name())
	}
	file, err := os.Open(path)
	if err != nil {
		return testFile{}, fmt.Errorf("unable to parse %s: %s", info.Name(), err)
	}

	// Prepare
	tc := testFile{
		info.Name(),
		filepath.Dir(path),
		make([]*testCase, 0),
	}
	i := 0
	// Scan File Line by Line
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		i = i + 1
		line := scanner.Text()

		// Make testcase out of line
		for _, tct := range testCaseTypes {
			msg := tct(line)
			if msg == "" {
				continue
			}
			tc.testCases = append(tc.testCases, &testCase{
				msg,
				i - 1,
				false,
			})
			break
		}
	}
	return tc, nil
}

// test tests the openvas-nasl-lint with file t. Note that file t must be
// parsed first. test return a list of unexpected events that occurred
// as a list of errors
func (t testFile) Test(openvasExe string) []error {
	errs := make([]error, 0)
	// run openvas-nasl-lint and collect output
	cmd := exec.Command(openvasExe, t.Name)
	cmd.Dir = t.dir
	// Ignoring ExitErrors as openvas-nasl-lint does not exit with 0 when errors
	// were found
	out, err := cmd.CombinedOutput()
	var target *exec.ExitError
	if err != nil && !errors.As(err, &target) {
		panic(fmt.Sprintf("Unable to run openvas-nasl-lint: %s", err))
	}

	// test output line by line
	lines := strings.Split(string(out), "\n")
	for _, line := range lines {
		// parse line into testCase
		if !strings.HasPrefix(line, "lib") {
			continue
		}
		matches := regexp.MustCompile(fmt.Sprintf("lib  nasl-Message: \\d\\d:\\d\\d:\\d\\d\\.\\d\\d\\d: \\[\\d*\\]\\(%s:(\\d*)\\) (.*)", t.Name)).FindAllStringSubmatch(line, -1)
		if matches == nil || len(matches[0]) != 3 {
			continue
		}
		lineNumber, err := strconv.Atoi(matches[0][1])
		if err != nil {
			continue
		}

		// testing
		tc := testCase{
			matches[0][2],
			lineNumber,
			false,
		}
		for _, test := range t.testCases {
			err := test.test(&tc)
			if err != nil {
				errs = append(errs, err)
			}
		}
		if !tc.tested {
			errs = append(errs, fmt.Errorf("on line %d the error '%s' occurred, but was not expected", tc.line, tc.msg))
		}
	}
	for _, tc := range t.testCases {
		if !tc.tested {
			errs = append(errs, fmt.Errorf("on line %d the error '%s' was expected, but did not occurred", tc.line, tc.msg))
		}
	}
	return errs
}

type testFiles struct {
	Tfs []testFile
}

func TestFiles() testFiles {
	return testFiles{
		make([]testFile, 0),
	}
}

// parse is a function designed to fit into a filepath.Walkfunc so a bunch of
// testFiles is created automatically given a Folder with nasl files.
func (t *testFiles) Parse(path string, info os.FileInfo, err error) error {
	if err != nil {
		fmt.Printf("Unable to parse %s: %s\n", path, err)
		return nil
	}
	if info.IsDir() {
		return nil
	}

	tf, err := testFileFromPath(path, info)
	if err != nil {
		return err
	}
	t.Tfs = append(t.Tfs, tf)
	return nil
}
