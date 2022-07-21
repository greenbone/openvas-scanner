# smoke-test linter

Contains a bunch of predefined nasl finds which are used by a go program to test the expected functionality of openvas-nasl-lint.

To build and run the tests a Makefile is provided:
- make build - builds the file `run` in the root directory
- make run - runs the program `run` builded with `make build`
- make clean - removes the builded program `run`
- make all - automatically builds, runs and cleans

To verify in your local environment you need to have `go` installed:

```
make all
```

The current version supports two arguments:
- openvasDir - Location of the openvas-nasl-lint executable, has to be absolute or relative to test files directory. If `openvas-nasl-lint` is located within `$PATH` It can be left empty
- testFiles - Folder containing the nasl test files.