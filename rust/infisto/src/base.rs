// SPDX-FileCopyrightText: 2024 Greenbone AG
//
// SPDX-License-Identifier: GPL-2.0-or-later WITH x11vnc-openssl-exception

//! The base module contains the basic building blocks for the file store.

use std::{
    fs,
    io::{Read, Seek, Write},
    marker::PhantomData,
    path::{Path, PathBuf},
};

use serde::{Deserialize, Serialize};
#[derive(Serialize, Deserialize, Clone, Debug)]
/// The index is used to store the start and end position of a data set in the file.
pub struct Index {
    /// The start position of the data set in the file.
    pub start: usize,
    /// The end position of the data set in the file.
    pub end: usize,
}

/// The store is used to store and retrieve data from the file system.
///
/// It is meant to be a building block for other data stores to store encrypted data and cache the
/// index in memory.
///
/// Warning: When working with the same file from multiple threads, the store is not thread safe.
#[derive(Clone, Debug)]
pub struct IndexedFileStorer {
    /// The base path where the idx and dat files are stored.
    base: PathBuf,
}

#[derive(Debug, Clone, PartialEq, Eq)]
/// The error type for the store.
pub enum Error {
    /// The base directory could not be created.
    CreateBaseDir(std::io::ErrorKind),
    /// The file could not be opened.
    FileOpen(std::io::ErrorKind),
    /// The file could not be written to.
    Write(std::io::ErrorKind),
    /// The file could not be read from.
    Read(std::io::ErrorKind),
    /// The file could not be removed.
    Remove(std::io::ErrorKind),
    /// The file could not be sought.
    Seek(std::io::ErrorKind),
    /// The index could not be serialized.
    Serialize,
}
/// Is a storage that stores bytes by using a key.
pub trait IndexedByteStorage {
    /// Overrides, creates a file with the given data.
    ///
    /// It creates a idx file for byte ranges of that element and creates data file containing the
    /// given data.
    fn put<T>(&mut self, key: &str, data: T) -> Result<(), Error>
    where
        T: AsRef<[u8]>;
    /// Appends the given data to the file found via key.
    ///
    /// It enhances the index with the byte range of the given data and appends the given data to
    /// the file found via key.
    fn append<T>(&mut self, key: &str, data: T) -> Result<(), Error>
    where
        T: AsRef<[u8]>,
    {
        self.append_all(key, &[data])
    }
    /// Appends the given data to the file found via key.
    ///
    /// It enhances the index with the byte range of given data and appends the given data to the
    /// file found via key.
    fn append_all<T>(&mut self, key: &str, data: &[T]) -> Result<(), Error>
    where
        T: AsRef<[u8]>;
    /// Removes idx and data file of given key.
    fn remove(&mut self, key: &str) -> Result<(), Error>;
    /// Returns the data for the given key and range.
    fn by_range<T>(&self, key: &str, range: Range) -> Result<Vec<T>, Error>
    where
        T: TryFrom<Vec<u8>>,
    {
        let indices = self.indices(key)?;
        let filtered_indices = range.filter(&indices);
        self.by_indices(key, filtered_indices)
    }
    /// Returns the data for the given key and index.
    fn by_index<T>(&self, key: &str, index: &Index) -> Result<Option<T>, Error>
    where
        T: TryFrom<Vec<u8>>,
    {
        let data = self.by_indices(key, &[index.clone()])?;
        Ok(data.into_iter().next())
    }

    /// Returns the data for given key and all indices.
    fn by_indices<T>(&self, key: &str, indices: &[Index]) -> Result<Vec<T>, Error>
    where
        T: TryFrom<Vec<u8>>;

    /// Returns all the indices of the data for the given key.
    fn indices(&self, key: &str) -> Result<Vec<Index>, Error>;
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        let msg = match self {
            Error::CreateBaseDir(e) => format!("Could not create base directory: {}", e),
            Error::FileOpen(e) => format!("Could not open file: {}", e),
            Error::Write(e) => format!("Could not write to file: {}", e),
            Error::Read(e) => format!("Could not read from file: {}", e),
            Error::Remove(e) => format!("Could not remove file: {}", e),
            Error::Seek(e) => format!("Could not seek in file: {}", e),
            Error::Serialize => "Could not serialize index".to_string(),
        };
        write!(f, "{}", msg)
    }
}

impl std::error::Error for Error {}

impl IndexedFileStorer {
    /// Verifies if the base path exists and creates it if not before returning the store.
    pub fn init<P>(path: P) -> Result<IndexedFileStorer, Error>
    where
        P: AsRef<Path>,
    {
        let path = path.as_ref();
        if !path.exists() {
            std::fs::create_dir_all(path)
                .map_err(|e| e.kind())
                .map_err(Error::CreateBaseDir)?;
        }
        Ok(IndexedFileStorer {
            base: PathBuf::from(path),
        })
    }

    /// Creates a new index element and stored the element in the file.
    pub fn create<T>(&self, id: &str, element: T) -> Result<Vec<Index>, Error>
    where
        T: AsRef<[u8]>,
    {
        let element = element.as_ref();
        let index = vec![Index {
            start: 0,
            end: element.len(),
        }];
        self.store_index(&index, id)?;
        let fn_name = format!("{}.dat", id);
        let path = Path::new(&self.base).join(fn_name);
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .open(path)
            .map_err(|e| e.kind())
            .map_err(Error::FileOpen)?;
        file.write_all(element)
            .map_err(|e| e.kind())
            .map_err(Error::Write)?;

        Ok(index)
    }

    fn store_index(&self, index: &[Index], id: &str) -> Result<(), Error> {
        let fn_name = format!("{}.idx", id);
        let to_store = rmp_serde::to_vec(index).map_err(|_e| Error::Serialize)?;

        let path = Path::new(&self.base).join(fn_name);
        let mut file = std::fs::OpenOptions::new()
            .truncate(true)
            .create(true)
            .write(true)
            .open(path)
            .map_err(|e| e.kind())
            .map_err(Error::FileOpen)?;
        file.write_all(&to_store)
            .map_err(|e| e.kind())
            .map_err(Error::Write)?;
        Ok(())
    }

    /// Gets the data from the file by using the given index.
    pub fn data_by_index(&self, key: &str, idx: &Index) -> Result<Vec<u8>, Error> {
        let fn_name = format!("{}.dat", key);
        let path = Path::new(&self.base).join(fn_name);
        let mut file = std::fs::OpenOptions::new()
            .read(true)
            .open(path)
            .map_err(|e| e.kind())
            .map_err(Error::FileOpen)?;
        let mut buffer = vec![0; idx.end - idx.start];
        file.seek(std::io::SeekFrom::Start(idx.start as u64))
            .map_err(|e| e.kind())
            .map_err(Error::Seek)?;
        file.read_exact(&mut buffer)
            .map_err(|e| e.kind())
            .map_err(Error::Read)?;
        Ok(buffer)
    }

    /// Load the index from the file.
    ///
    /// This should be rarely used as the index is usually returned when storing data.
    /// The caller should rather cache the index.
    pub fn load_index(&self, key: &str) -> Result<Vec<Index>, Error> {
        let fn_name = format!("{}.idx", key);
        let path = Path::new(&self.base).join(fn_name);
        let mut file = std::fs::OpenOptions::new()
            .read(true)
            .open(path)
            .map_err(|e| e.kind())
            .map_err(Error::FileOpen)?;
        let mut buffer = vec![];
        file.read_to_end(&mut buffer)
            .map_err(|e| e.kind())
            .map_err(Error::Read)?;

        let index = rmp_serde::from_slice(&buffer).map_err(|_e| Error::Serialize)?;
        Ok(index)
    }

    /// Appends the given data to the file and enlarges the index.
    pub fn append<T>(&self, key: &str, index: &[Index], data: T) -> Result<Vec<Index>, Error>
    where
        T: AsRef<[u8]>,
    {
        self.append_all_index(key, index, &[data])
    }

    /// Appends all given data sets to the file and enlarges the index.
    pub fn append_all_index<T>(
        &self,
        key: &str,
        index: &[Index],
        data: &[T],
    ) -> Result<Vec<Index>, Error>
    where
        T: AsRef<[u8]>,
    {
        let fn_name = format!("{}.dat", key);
        let path = Path::new(&self.base).join(fn_name);
        let mut file = std::fs::OpenOptions::new()
            .append(true)
            .open(path)
            .map_err(|e| e.kind())
            .map_err(Error::FileOpen)?;
        let mut index = index.to_vec();
        index.reserve(data.len());
        let mut start = index.last().map(|e| e.end).unwrap_or(0);
        for d in data {
            let b = d.as_ref();
            file.write_all(b)
                .map_err(|e| e.kind())
                .map_err(Error::Write)?;
            let end = start + b.len();
            let idx = Index { start, end };
            index.push(idx);
            start = end;
        }
        self.store_index(&index, key)?;
        Ok(index)
    }

    /// Removes dat and idx files from the file system.
    pub fn clean(&self, key: &str) -> Result<(), Error> {
        let dat_fn = format!("{}.dat", key);
        let dat_path = Path::new(&self.base).join(dat_fn);
        fs::remove_file(dat_path)
            .map_err(|e| e.kind())
            .map_err(Error::Remove)?;
        let idx_fn = format!("{}.idx", key);
        let idx_path = Path::new(&self.base).join(idx_fn);
        fs::remove_file(idx_path)
            .map_err(|e| e.kind())
            .map_err(Error::Remove)?;
        Ok(())
    }

    /// Removes base dir and all its content.
    ///
    /// # Safety
    /// Does remove the whole base dir and its content.
    /// Do not use carelessly.
    pub unsafe fn remove_base(self) -> Result<(), Error> {
        fs::remove_dir_all(self.base)
            .map_err(|e| e.kind())
            .map_err(Error::Remove)
            .map(|_| ())
    }
}

impl IndexedByteStorage for IndexedFileStorer {
    fn put<T>(&mut self, key: &str, data: T) -> Result<(), Error>
    where
        T: AsRef<[u8]>,
    {
        self.create(key, data).map(|_| ())
    }

    fn append_all<T>(&mut self, key: &str, data: &[T]) -> Result<(), Error>
    where
        T: AsRef<[u8]>,
    {
        if data.is_empty() {
            return Ok(());
        }
        let result = self.load_index(key);
        match result {
            Ok(i) => self.append_all_index(key, &i, data).map(|_| ()),
            Err(Error::FileOpen(ioe)) => match ioe {
                std::io::ErrorKind::NotFound => {
                    let initial_index = self.create(key, &data[0])?;
                    self.append_all_index(key, &initial_index, &data[1..])
                        .map(|_| ())
                }
                _ => Err(Error::FileOpen(ioe)),
            },
            Err(e) => Err(e),
        }
    }

    fn remove(&mut self, key: &str) -> Result<(), Error> {
        self.clean(key)
    }

    fn indices(&self, key: &str) -> Result<Vec<Index>, Error> {
        self.load_index(key)
    }

    fn by_indices<T>(&self, key: &str, indices: &[Index]) -> Result<Vec<T>, Error>
    where
        T: TryFrom<Vec<u8>>,
    {
        let start = indices.first().map(|e| e.start).unwrap_or(0);
        let end = indices.last().map(|e| e.end).unwrap_or(0);
        let index = Index { start, end };
        let data = self.data_by_index(key, &index)?;
        let mut result = Vec::new();
        for i in indices {
            // on an limiting range (e.g. from or between) the data does not contain
            // all previous data, so we need to subtract the start of the first index
            // to get the correcte byte range.
            match data[(i.start - start)..(i.end - start)].to_vec().try_into() {
                Ok(d) => result.push(d),
                Err(_) => return Err(Error::Serialize),
            }
        }
        Ok(result)
    }
}

/// Is an indexed file storage that caches the index of the last 5 files.
#[derive(Clone)]
pub struct CachedIndexFileStorer {
    base: IndexedFileStorer,
    cache: [Option<(String, Vec<Index>)>; 5],
}

#[derive(Debug)]
/// Range to define which indices to load.
pub enum Range {
    /// Returns all indices
    All,
    /// Returns indices from the given start
    From(usize),
    /// Returns indices until the given end
    Until(usize),
    /// Returns indices between the given start and end
    Between(usize, usize),
    /// Returns the bytes definition of the given index
    ///
    /// Starts at zero.
    Single(usize),
}

impl Range {
    /// Filters the given index by the range.
    pub fn filter<'a>(&'a self, fi: &'a [Index]) -> &'a [Index] {
        match self {
            Range::All => fi,
            Range::From(i) => {
                let i = *i;
                if i >= fi.len() {
                    return &[];
                }
                &fi[i..]
            }
            Range::Until(i) => {
                let i = if *i > fi.len() { fi.len() } else { *i };
                &fi[..i]
            }
            Range::Between(s, e) => {
                let s = *s;
                let e = *e;
                if s >= fi.len() {
                    return &[];
                }
                let e = if e > fi.len() { fi.len() } else { e };
                &fi[s..e]
            }
            Range::Single(i) => {
                let i = *i;
                if i >= fi.len() {
                    return &[];
                }
                &fi[i..=i]
            }
        }
    }
}

impl CachedIndexFileStorer {
    /// Initializes the storage.
    pub fn init<P>(base: P) -> Result<Self, Error>
    where
        P: AsRef<Path>,
    {
        let base = IndexedFileStorer::init(base)?;
        let cache = [None, None, None, None, None];
        Ok(Self { base, cache })
    }
    fn find_index(&self, key: &str) -> Option<(usize, &Vec<Index>)> {
        for i in 0..self.cache.len() {
            if let Some((k, v)) = &self.cache[i] {
                if k == key {
                    return Some((i, v));
                }
            }
        }
        None
    }
}

impl IndexedByteStorage for CachedIndexFileStorer {
    /// Overwrites the data for the given key.
    fn put<T>(&mut self, key: &str, data: T) -> Result<(), Error>
    where
        T: AsRef<[u8]>,
    {
        // check if key is already in cache
        let index = self.find_index(key).map(|(i, _)| i);
        if let Some(i) = index {
            self.cache.swap(0, i);
        } else {
            // remove oldest entry by overwriting it later
            for i in (1..self.cache.len()).rev() {
                self.cache.swap(i - 1, i);
            }
        }
        let result = self.base.create(key, data)?;
        self.cache[0] = Some((key.to_string(), result));
        Ok(())
    }

    /// Append the given data to the file and enlarges the index.
    fn append<T>(&mut self, key: &str, data: T) -> Result<(), Error>
    where
        T: AsRef<[u8]>,
    {
        self.append_all(key, &[data])
    }

    /// Append all given data sets to the file and enlarges the index.
    fn append_all<T>(&mut self, key: &str, data: &[T]) -> Result<(), Error>
    where
        T: AsRef<[u8]>,
    {
        let (ci, result) = if let Some((ci, fi)) = self.find_index(key) {
            (ci, self.base.append_all_index(key, fi, data)?)
        } else {
            let result = self.base.load_index(key);
            match result {
                Ok(i) => (
                    self.cache.len() - 1,
                    self.base.append_all_index(key, &i, data)?,
                ),
                Err(Error::FileOpen(ioe)) => match ioe {
                    std::io::ErrorKind::NotFound if !data.is_empty() => {
                        let initial_index = self.base.create(key, &data[0])?;

                        let end_index =
                            self.base
                                .append_all_index(key, &initial_index, &data[1..])?;
                        (self.cache.len() - 1, end_index)
                    }
                    std::io::ErrorKind::NotFound if data.is_empty() => (0, vec![]),
                    _ => return Err(Error::FileOpen(ioe)),
                },
                Err(e) => return Err(e),
            }
        };

        for i in (1..=ci).rev() {
            self.cache.swap(i - 1, i);
        }
        self.cache[0] = Some((key.to_string(), result));
        Ok(())
    }

    /// Removes dat and idx files from the file system.
    fn remove(&mut self, key: &str) -> Result<(), Error> {
        self.base.clean(key)?;
        for i in 0..self.cache.len() {
            if let Some((k, _)) = &self.cache[i] {
                if k == key {
                    self.cache[i] = None;
                }
            }
        }
        Ok(())
    }

    fn indices(&self, key: &str) -> Result<Vec<Index>, Error> {
        if let Some((_, fi)) = self.find_index(key) {
            Ok(fi.clone())
        } else {
            self.base.load_index(key)
        }
    }

    fn by_indices<T>(&self, key: &str, indices: &[Index]) -> Result<Vec<T>, Error>
    where
        T: TryFrom<Vec<u8>>,
    {
        self.base.by_indices(key, indices)
    }
}

/// Iterator over the data of a file.
pub struct IndexedByteStorageIterator<S, T> {
    current: usize,
    indices: Vec<Index>,
    storage: S,
    key: String,
    _phantom: PhantomData<T>,
}

impl<S, T> IndexedByteStorageIterator<S, T>
where
    S: IndexedByteStorage,
{
    fn load_indices(key: &str, storage: &S) -> Result<Vec<Index>, Error> {
        match storage.indices(key) {
            Ok(i) => Ok(i),
            Err(Error::FileOpen(ioe)) => match ioe {
                std::io::ErrorKind::NotFound => Ok(vec![]),
                _ => Err(Error::FileOpen(ioe)),
            },
            Err(e) => Err(e),
        }
    }

    /// Creates a new instance for all indices of given key.
    pub fn new(key: &str, storage: S) -> Result<Self, Error> {
        let indices = Self::load_indices(key, &storage)?;
        Ok(Self {
            current: 0,
            indices,
            storage,
            key: key.to_string(),
            _phantom: PhantomData,
        })
    }

    /// Creates a new instance for indices found by range of given key.
    pub fn by_range(key: &str, storage: S, range: Range) -> Result<Self, Error> {
        let indices = Self::load_indices(key, &storage)?;
        let indices: Vec<Index> = range.filter(&indices).to_vec();
        Ok(Self {
            current: 0,
            indices,
            storage,
            key: key.to_string(),
            _phantom: PhantomData,
        })
    }
}

impl<S, T> Iterator for IndexedByteStorageIterator<S, T>
where
    S: IndexedByteStorage,
    T: TryFrom<Vec<u8>>,
{
    type Item = Result<T, Error>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.current >= self.indices.len() {
            return None;
        }
        let result = self
            .storage
            .by_index(&self.key, &self.indices[self.current]);
        self.current += 1;
        match result {
            Ok(None) => None,
            Ok(Some(result)) => Some(Ok(result)),
            Err(e) => Some(Err(e)),
        }
    }
}

#[cfg(test)]
mod iter {
    use super::*;
    const BASE: &str = "/tmp/openvasd/unittest";

    #[test]
    fn empty() {
        let key = "indexed_empty";
        let store = CachedIndexFileStorer::init(BASE).unwrap();
        let mut iter: IndexedByteStorageIterator<_, Vec<u8>> =
            IndexedByteStorageIterator::new(key, store).unwrap();
        assert_eq!(iter.next(), None);
    }

    #[test]
    fn single() {
        let key = "indexed_single";
        let mut store = CachedIndexFileStorer::init(BASE).unwrap();
        store.put(key, "Hello World".as_bytes()).unwrap();
        let mut iter = IndexedByteStorageIterator::new(key, store.clone()).unwrap();
        assert_eq!(iter.next(), Some(Ok("Hello World".as_bytes().to_vec())));
        assert_eq!(iter.next(), None);
        store.remove(key).unwrap();
    }
}

#[cfg(test)]
mod cached {
    use super::*;
    const BASE: &str = "/tmp/openvasd/unittest";

    #[test]
    fn invalid_ranges() {
        let mut store = CachedIndexFileStorer::init(BASE).unwrap();
        store.put("a", "Hello World".as_bytes()).unwrap();
        let result = store
            .by_range::<Vec<u8>>("a", Range::Between(1, 1000))
            .unwrap();
        assert_eq!(result.len(), 0);
    }

    #[test]
    fn index_order() {
        let mut keys = ["a", "b", "c", "d", "e", "f"];
        let mut store = CachedIndexFileStorer::init(BASE).unwrap();
        for k in &keys {
            store.put(k, "Hello World".as_bytes()).unwrap();
        }
        let ordered_keys = store
            .cache
            .iter()
            .map(|e| e.as_ref().unwrap().0.as_str())
            .collect::<Vec<_>>();
        assert_eq!(ordered_keys, ["f", "e", "d", "c", "b"]);
        for k in &keys {
            store.base.clean(k).unwrap();
        }

        keys.reverse();
        for k in &keys {
            store.put(k, "Hello World".as_bytes()).unwrap();
        }
        let ordered_keys = store
            .cache
            .iter()
            .map(|e| e.as_ref().unwrap().0.as_str())
            .collect::<Vec<_>>();
        assert_eq!(ordered_keys, ["a", "b", "f", "e", "d"]);
        keys.reverse();
        for k in &keys {
            store.append(k, "Hello World".as_bytes()).unwrap();
        }
        let ordered_keys = store
            .cache
            .iter()
            .map(|e| e.as_ref().unwrap().0.as_str())
            .collect::<Vec<_>>();
        assert_eq!(ordered_keys, ["f", "e", "d", "c", "b"]);
    }

    #[test]
    fn append_all_and_ranges() {
        let key = "test_cached_append_all";
        let amount = 1000;
        fn random_data() -> Vec<u8> {
            use rand::RngCore;
            let mut rng = rand::thread_rng();
            let mut data = vec![0; 1024];
            rng.fill_bytes(&mut data);
            data
        }
        let mut data = Vec::with_capacity(amount);
        for _ in 0..amount {
            data.push(random_data());
        }

        let mut store = CachedIndexFileStorer::init(BASE).unwrap();
        store.put(key, "Hello World".as_bytes()).unwrap();
        store.append_all(key, &data).unwrap();
        let results_all: Vec<Vec<u8>> = store.by_range(key, Range::All).unwrap();
        assert_eq!(results_all.len(), amount + 1);
        assert_eq!(results_all[0], "Hello World".as_bytes());
        let results: Vec<Vec<u8>> = store.by_range(key, Range::Between(1, amount + 1)).unwrap();
        let results_from: Vec<Vec<u8>> = store.by_range(key, Range::From(1)).unwrap();
        let results_until: Vec<Vec<u8>> = store.by_range(key, Range::Until(amount + 1)).unwrap();
        assert_eq!(results_until[0], results_all[0]);

        for i in 0..amount {
            assert_eq!(results[i], data[i]);
            assert_eq!(results[i], results_from[i]);
            // include the first element
            assert_eq!(results[i], results_until[i + 1]);
            assert_eq!(results[i], results_all[i + 1]);
        }
        store.remove(key).unwrap();
    }

    #[test]
    fn create_on_append() {
        let key = "create_on_append";
        let mut store = CachedIndexFileStorer::init(BASE).unwrap();
        store.append(key, "Hello World".as_bytes()).unwrap();
        let results: Vec<Vec<u8>> = store.by_range(key, Range::All).unwrap();
        assert_eq!(results.len(), 1);
        assert_eq!(results[0], "Hello World".as_bytes());
        store.remove(key).unwrap();
    }
}

#[cfg(test)]
mod indexed {

    use super::*;
    const BASE: &str = "/tmp/openvasd/unittest";
    #[test]
    fn storage_single_file() {
        let key = "test";
        let store = IndexedFileStorer::init(BASE).unwrap();
        let result = store.create(key, "Hello World".as_bytes()).unwrap();
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].start, 0);
        assert_eq!(result[0].end, 11);
        let data = store.data_by_index(key, &result[0]).unwrap();
        assert_eq!(data, "Hello World".as_bytes());
        let index = store.load_index(key).unwrap();
        assert_eq!(index.len(), 1);
        assert_eq!(index[0].start, 0);
        assert_eq!(index[0].end, 11);
        store.clean(key).unwrap();
    }

    #[test]
    fn append_to_file() {
        let key = "test_append";
        let store = IndexedFileStorer::init(BASE).unwrap();
        let idx = store.create(key, "Hello World".as_bytes()).unwrap();
        store
            .append(key, &idx, "The world does not care.".as_bytes())
            .unwrap();
        let index = store.load_index(key).unwrap();
        assert_eq!(index.len(), 2);
        assert_eq!(index[0].start, 0);
        assert_eq!(index[0].end, 11);
        assert_eq!(index[1].start, 11);
        assert_eq!(index[1].end, 35);
        let data = store.data_by_index(key, &index[0]).unwrap();
        assert_eq!(data, "Hello World".as_bytes());
        let data = store.data_by_index(key, &index[1]).unwrap();
        assert_eq!(data, "The world does not care.".as_bytes());
        store.clean(key).unwrap();
    }

    #[test]
    fn append_all() {
        let key = "test_append_all";
        let amount = 1000;
        fn random_data() -> Vec<u8> {
            use rand::RngCore;
            let mut rng = rand::thread_rng();
            let mut data = vec![0; 1024];
            rng.fill_bytes(&mut data);
            data
        }
        let mut data = Vec::with_capacity(amount);
        for _ in 0..amount {
            data.push(random_data());
        }

        let store = IndexedFileStorer::init(BASE).unwrap();
        let idx = store.create(key, "Hello World".as_bytes()).unwrap();
        let index = store.append_all_index(key, &idx, &data).unwrap();
        assert_eq!(index.len(), amount + 1);
        assert_eq!(index[0].start, 0);
        assert_eq!(index[0].end, 11);
        for i in 1..amount + 1 {
            assert_eq!(index[i].start, index[i - 1].end);
            assert_eq!(index[i].end, index[i - 1].end + 1024);
            let dr = store.data_by_index(key, &index[i]).unwrap();
            assert_eq!(dr, data[i - 1]);
        }
        store.clean(key).unwrap();
    }
}
