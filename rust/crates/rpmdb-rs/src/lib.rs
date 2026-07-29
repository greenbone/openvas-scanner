#[allow(dead_code)]
mod bdb;
mod entry;
mod errors;
mod ndb;
mod package;
#[allow(dead_code)]
mod rpmtags;

mod sqlite3;

use std::path::PathBuf;

use bdb::Bdb;
use entry::Hdrblob;
use errors::RpmdbError;
use ndb::Ndb;
use package::Package;
use sqlite3::SqliteDB;

#[cfg(test)]
const BDB_TEST_FILE: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../data/tests/rpmdb/Packages"
);
#[cfg(test)]
const NDB_TEST_FILE: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../data/tests/rpmdb/Packages.db"
);
#[cfg(test)]
const SQLITE_TEST_FILE: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../data/tests/rpmdb/rpmdb.sqlite"
);

#[allow(clippy::upper_case_acronyms)]
trait DBI {
    fn read(&mut self) -> Result<Vec<Vec<u8>>, RpmdbError>;
}

fn open(path: PathBuf) -> Result<Box<dyn DBI>, RpmdbError> {
    match SqliteDB::open(path.clone()) {
        Ok(db) => {
            return Ok(Box::new(db));
        }
        Err(RpmdbError::InvalidSqliteFile) => {}
        Err(e) => {
            return Err(e);
        }
    }

    match Ndb::open(path.clone()) {
        Ok(db) => {
            return Ok(Box::new(db));
        }
        Err(RpmdbError::InvalidNdbFile) => {}
        Err(e) => {
            return Err(e);
        }
    }

    Ok(Box::new(Bdb::open(path)?))
}

pub fn read_packages(path: PathBuf) -> Result<Vec<Package>, RpmdbError> {
    let mut db = open(path)?;

    let mut packages = Vec::new();
    let values = db.read()?;
    for value in values.clone() {
        let blob = Hdrblob::from_bytes(&value).map_err(|e| RpmdbError::ParseBlob(e.to_string()))?;
        let mut entries = blob
            .import(&value)
            .map_err(|e| RpmdbError::ParseBlob(e.to_string()))?;
        entries.sort_by_key(|e| e.info.offset);
        let pkg = Package::try_from(entries).map_err(|e| RpmdbError::ParseEntry(e.to_string()))?;
        packages.push(pkg);
    }

    Ok(packages)
}

#[cfg(test)]
mod tests {
    use crate::{BDB_TEST_FILE, NDB_TEST_FILE, SQLITE_TEST_FILE, open, read_packages};

    #[test]
    fn test_open() {
        open(BDB_TEST_FILE.parse().unwrap()).unwrap();
        open(SQLITE_TEST_FILE.parse().unwrap()).unwrap();
        open(NDB_TEST_FILE.parse().unwrap()).unwrap();
    }

    #[test]
    fn test_read_packages() {
        for path in [BDB_TEST_FILE, NDB_TEST_FILE, SQLITE_TEST_FILE] {
            let packages = read_packages(path.parse().unwrap()).unwrap();
            assert_eq!(packages.len(), 1);

            let package = &packages[0];
            assert_eq!(package.name, "test-package");
            assert_eq!(package.version, "1.2.3");
            assert_eq!(package.release, "4.test");
            assert_eq!(package.arch, "x86_64");
        }
    }
}
