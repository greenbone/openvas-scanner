use std::{
    fs::File,
    io::{BufReader, Read, Seek, SeekFrom},
    path::PathBuf,
};

use serde::Deserialize;

use crate::{DBI, errors::RpmdbError};

const NDB_SLOT_ENTRIES_PER_PAGE: u32 = 4096 / 16;
const NDB_HEADER_MAGIC: u32 =
    ('R' as u32) | ('p' as u32) << 8 | ('m' as u32) << 16 | ('P' as u32) << 24;
const NDB_DBVERSION: u32 = 0;

const NDB_BLOB_HEADER_SIZE: u32 = 16;
const NDB_SLOT_MAGIC: u32 =
    ('S' as u32) | ('l' as u32) << 8 | ('o' as u32) << 16 | ('t' as u32) << 24;

const NDB_BLOB_MAGIC: u32 =
    ('B' as u32) | ('l' as u32) << 8 | ('b' as u32) << 16 | ('S' as u32) << 24;

#[derive(Deserialize)]
struct NdbHeader {
    header_magic: u32,
    ndb_version: u32,
    _ndb_generation: u32,
    slot_npages: u32,
    _unused: [u32; 4],
}

#[derive(Deserialize)]
struct NdbSlotEntry {
    slot_magic: u32,
    pgk_index: u32,
    blk_offset: u32,
    _blk_count: u32,
}

#[derive(Deserialize)]
struct NdbBlobHeader {
    blob_magic: u32,
    pkg_index: u32,
    _blob_checksum: u32,
    blob_len: u32,
}

pub struct Ndb {
    reader: BufReader<File>,
    slots: Vec<NdbSlotEntry>,
}

impl Ndb {
    pub fn open(path: PathBuf) -> Result<Self, RpmdbError> {
        let file = File::open(&path)?;

        let mut reader = BufReader::new(file);

        let ndb_header: NdbHeader = bincode::deserialize_from(&mut reader)?;

        if ndb_header.header_magic != NDB_HEADER_MAGIC
            || ndb_header.slot_npages == 0
            || ndb_header.ndb_version != NDB_DBVERSION
        {
            return Err(RpmdbError::InvalidNdbFile);
        }

        if ndb_header.slot_npages > 2048 {
            let msg = format!("slot page limit exceeded: {}", ndb_header.slot_npages);
            return Err(RpmdbError::ParseNdbFile(msg));
        }

        let entry_size = ndb_header.slot_npages * NDB_SLOT_ENTRIES_PER_PAGE - 2;
        let mut slots: Vec<NdbSlotEntry> = Vec::with_capacity(entry_size as usize);
        for _ in 0..entry_size {
            let slot: NdbSlotEntry = bincode::deserialize_from(&mut reader)?;
            slots.push(slot);
        }

        Ok(Self { reader, slots })
    }
}

impl DBI for Ndb {
    fn read(&mut self) -> Result<Vec<Vec<u8>>, RpmdbError> {
        let mut blobs = Vec::new();
        for slot in &self.slots {
            if slot.slot_magic != NDB_SLOT_MAGIC {
                let msg = format!("bad slot magic: {}", slot.slot_magic);
                return Err(RpmdbError::ParseNdbFile(msg));
            }

            if slot.pgk_index == 0 {
                continue;
            }

            let offset = (slot.blk_offset * NDB_BLOB_HEADER_SIZE) as u64;
            self.reader.seek(SeekFrom::Start(offset))?;

            let ndb_blob_header: NdbBlobHeader = bincode::deserialize_from(&mut self.reader)?;
            if ndb_blob_header.blob_magic != NDB_BLOB_MAGIC {
                let msg = format!(
                    "unexpected NDB blob Magic for pkg {}: {}",
                    slot.pgk_index, ndb_blob_header.blob_magic
                );
                return Err(RpmdbError::ParseNdbFile(msg));
            }
            if ndb_blob_header.pkg_index != slot.pgk_index {
                let msg = format!("failed to find NDB blob for pkg {}", slot.pgk_index);
                return Err(RpmdbError::ParseNdbFile(msg));
            }

            let mut buf = vec![0; ndb_blob_header.blob_len as usize];
            self.reader.read_exact(&mut buf)?;

            blobs.push(buf);
        }

        Ok(blobs)
    }
}

#[cfg(test)]
mod tests {
    use super::Ndb;
    use crate::DBI;

    const NDB_FILE: &str = "testdata/Packages.db";

    #[test]
    fn test_read() {
        let mut db = Ndb::open(NDB_FILE.parse().unwrap()).unwrap();
        let blobs = db.read().unwrap();
        assert!(!blobs.is_empty())
    }
}
