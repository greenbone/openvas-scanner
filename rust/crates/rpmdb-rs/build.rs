use std::{path::Path, process::Command};

fn main() {
    let rpmdb_path = Path::new("testdata/rpmdb.sqlite");
    println!("cargo:rerun-if-changed=testdata/rpmdb.sqlite");

    if !rpmdb_path.exists() {
        println!("cargo:warning=Missing rpmdb.sqlite — running prepare-test-data.sh");
        // ignore failures.as it just relevant for tests, that fail anyway when the testdata is
        // missing
        let _ = Command::new("sh").arg("prepare-test-data.sh").status();
    }
}
