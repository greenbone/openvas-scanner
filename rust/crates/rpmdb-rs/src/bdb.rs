use std::{
    fs::File,
    io::{Read, Seek, SeekFrom},
    path::PathBuf,
};

use serde::Deserialize;

use crate::{DBI, errors::RpmdbError};

const VALID_PAGE_SIZES: [u32; 8] = [512, 1024, 2048, 4096, 8192, 16384, 32768, 65536];

// the size (in bytes) of an in-page offset
const HASH_INDEX_ENTRY_SIZE: usize = 2;
// all DB pages have the same sized header (in bytes)
const PAGE_HEADER_SIZE: usize = 26;

const HASH_OFF_PAGE_SIZE: usize = 12; // (in bytes)

enum PageType {
    HashUnsorted = 2, // Hash pages created pre 4.6. DEPRECATED
    Overflow = 7,
    HashMetadata = 8,
    Hash = 13, // Sorted hash page.
    // https://github.com/berkeleydb/libdb/blob/v5.3.28/src/dbinc/db_page.h#L569-L573
    HashOffIndex = 3, // aka HOFFPAGE
}

fn hash_page_value_indexes(data: Vec<u8>, entries: u16) -> Result<Vec<u16>, RpmdbError> {
    if !entries.is_multiple_of(2) {
        let msg = format!("invalid entries {entries}");
        return Err(RpmdbError::ParseBdbFile(msg));
    }

    let hash_index_data =
        &data[PAGE_HEADER_SIZE..PAGE_HEADER_SIZE + (entries as usize) * HASH_INDEX_ENTRY_SIZE];

    let hash_index_values: Vec<u16> = hash_index_data
        .chunks_exact(2 * HASH_INDEX_ENTRY_SIZE)
        .map(|chunk| {
            u16::from_le_bytes([
                chunk[HASH_INDEX_ENTRY_SIZE],
                chunk[HASH_INDEX_ENTRY_SIZE + 1],
            ])
        })
        .collect();

    Ok(hash_index_values)
}

pub struct Bdb {
    file: File,
    hash_metadata: HashMetadataPage,
}

impl Bdb {
    pub fn open(path: PathBuf) -> Result<Bdb, RpmdbError> {
        let mut file = File::open(path.clone())?;
        let mut buffer = [0; 512];
        file.read_exact(&mut buffer)?;

        file.seek(SeekFrom::Start(0))?;

        let hash_metadata: HashMetadataPage = bincode::deserialize(&buffer)?;
        if !VALID_PAGE_SIZES.contains(&hash_metadata.generic.page_size) {
            let msg = format!("invalid page_size {}", hash_metadata.generic.page_size);
            return Err(RpmdbError::ParseBdbFile(msg));
        }
        Ok(Bdb {
            file,
            hash_metadata,
        })
    }

    fn hash_page_value_content(&mut self, entry: HashOffPageEntry) -> Result<Vec<u8>, RpmdbError> {
        let page_size = self.hash_metadata.generic.page_size as usize;

        let mut hash_value = Vec::new();
        let mut current_page_no = entry.page_no as usize;
        while current_page_no != 0 {
            self.file
                .seek(SeekFrom::Start((page_size * current_page_no) as u64))?;
            let mut current_page_buffer = vec![0; page_size];
            self.file.read_exact(&mut current_page_buffer)?;

            let current_page: HashPage = bincode::deserialize(&current_page_buffer)?;
            if current_page.page_type != (PageType::Overflow as u8) {
                continue;
            }
            let hash_value_bytes = if current_page.next_page_no == 0 {
                &current_page_buffer
                    [PAGE_HEADER_SIZE..PAGE_HEADER_SIZE + current_page.free_area_offset as usize]
            } else {
                &current_page_buffer[PAGE_HEADER_SIZE..]
            };

            hash_value.extend(hash_value_bytes);

            current_page_no = current_page.next_page_no as usize;
        }

        Ok(hash_value)
    }
}

impl DBI for Bdb {
    fn read(&mut self) -> Result<Vec<Vec<u8>>, RpmdbError> {
        let mut values = Vec::new();

        let page_size = self.hash_metadata.generic.page_size as usize;
        // let hash_values: Vec<u8> = Vec::new();
        for _ in 0..=self.hash_metadata.generic.last_page_no {
            let mut page_data = vec![0; page_size];
            self.file.read_exact(&mut page_data)?;

            let end_of_page_offset = self.file.stream_position()?;

            let hash_metadata: HashPage = bincode::deserialize(&page_data)?;

            if hash_metadata.page_type != (PageType::HashUnsorted as u8)
                && hash_metadata.page_type != (PageType::Hash as u8)
            {
                continue;
            }

            let hash_page_indexes =
                hash_page_value_indexes(page_data.clone(), hash_metadata.num_entries)?;
            for idx in hash_page_indexes {
                if page_data.get(idx as usize) != Some(&(PageType::HashOffIndex as u8)) {
                    continue;
                }

                let i = idx as usize;
                let entry: HashOffPageEntry =
                    bincode::deserialize(&page_data[i..i + HASH_OFF_PAGE_SIZE])?;

                let value = self.hash_page_value_content(entry)?;
                values.push(value);
            }

            self.file.seek(SeekFrom::Start(end_of_page_offset))?;
        }

        Ok(values)
    }
}

// source: https://github.com/berkeleydb/libdb/blob/5b7b02ae052442626af54c176335b67ecc613a30/src/dbinc/db_page.h#L73
#[derive(Debug, Deserialize)]
struct GenericMetadataPage {
    lsn: [u8; 8],
    page_no: u32,
    magic: u32,
    version: u32,
    page_size: u32,
    encryption_alg: u8,
    page_type: u8,
    meta_flags: u8,
    unused1: u8,
    free: u32,
    last_page_no: u32,
    n_parts: u32,
    key_count: u32,
    record_count: u32,
    flags: u32,
    unique_file_id: [u8; 19],
}

#[derive(Debug, Deserialize)]
struct HashMetadataPage {
    generic: GenericMetadataPage,
    max_bucket: u32,
    high_mask: u32,
    low_mask: u32,
    fill_factor: u32,
    num_keys: u32,
    char_key_hash: u32,
}

#[derive(Debug, Deserialize)]
struct HashPage {
    lsn: [u8; 8],
    page_no: u32,
    previous_page_no: u32,
    next_page_no: u32,
    num_entries: u16,
    free_area_offset: u16,
    tree_level: u8,
    page_type: u8,
}

#[derive(Debug, Deserialize)]
struct HashOffPageEntry {
    page_type: u8,
    unused: [u8; 3],
    page_no: u32,
    length: u32,
}

#[cfg(test)]
mod tests {
    use crate::{DBI, bdb::Bdb};

    #[test]
    fn test_open() {
        let bdb = Bdb::open("testdata/Packages".parse().unwrap()).unwrap();
        println!("{:?}", bdb.hash_metadata);
    }

    #[test]
    fn test_read() {
        let mut bdb = Bdb::open("testdata/Packages".parse().unwrap()).unwrap();
        println!("{:?}", bdb.hash_metadata);
        bdb.read().unwrap();
    }
}
