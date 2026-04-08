## rpmdb-rs

Rust implementation of rpmdb forked from [yybit/rpmdb-rs](https://github.com/yybit/rpmdb-rs), currently only supports reading package list

Available rpmdb format:
- bdb
- ndb
- sqlite3

# Test Data Setup

This crate requires test data located at `testdata`.


## Missing Test Data

If the files are not available tests will fail.

To generate the required test data, run:

```sh
sh prepare-test-data.sh
```

#### Example

```
let packages = rpmdb::read_packages("testdata/Packages".parse()?)?;
for package in packages {
    println!("{} {:?}", package.name, package.provides);
}
```


