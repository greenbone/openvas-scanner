package main

import (
	"fmt"
	"path/filepath"

	"github.com/greenbone/openvas-scanner/smoketest_lint/test"
)

var path = "data"

func main() {

	tfs := test.TestFiles()
	err := filepath.Walk(path, tfs.Parse)
	if err != nil {
		fmt.Printf("Unable to parse files in %s: %s\n", path, err)
	}

	for _, tf := range tfs.Tfs {
		errs := tf.Test()
		if len(errs) > 0 {
			fmt.Printf("%d error(s) while processing %s:\n", len(errs), tf.Name)
			for _, err := range errs {
				fmt.Println(err)
			}
		}
	}

}
