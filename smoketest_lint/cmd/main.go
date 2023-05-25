// SPDX-FileCopyrightText: 2023 Greenbone AG
//
// SPDX-License-Identifier: GPL-2.0-or-later

package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"

	"github.com/greenbone/openvas-scanner/smoketest_lint/test"
)

func main() {

	openvasExe := flag.String("e", "openvas-nasl-lint", "openvas-nasl-lint executable, must be either in $PATH, an absolute path or relative to the data folder")
	path := flag.String("d", "data", "data folder for the nasl test data")
	flag.Parse()

	tfs := test.TestFiles()
	fmt.Println("Parsing Nasl Test Files")
	err := filepath.Walk(*path, tfs.Parse)
	if err != nil {
		fmt.Printf("Unable to parse files in %s: %s\n", *path, err)
	}

	fmt.Println("Testing: Compare actual with expected output")
	for _, tf := range tfs.Tfs {
		errs := tf.Test(*openvasExe)
		if len(errs) > 0 {
			fmt.Printf("%d error(s) while processing %s:\n", len(errs), tf.Name)
			for _, err := range errs {
				fmt.Println(err)
			}
			os.Exit(1)
		}
	}
	fmt.Println("No errors were found")
}
