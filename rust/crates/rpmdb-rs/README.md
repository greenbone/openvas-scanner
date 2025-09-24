## rpmdb-rs

Rust implementation of rpmdb forked from [yybit/rpmdb-rs](https://github.com/yybit/rpmdb-rs), currently only supports reading package list

Available rpmdb format:
- bdb
- ndb
- sqlite3


#### Example

```
let packages = rpmdb::read_packages("testdata/Packages".parse()?)?;
for package in packages {
    println!("{} {:?}", package.name, package.provides);
}
```
