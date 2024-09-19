# Indexed file storage

Is a library to store data on to disk and fetch elements from that rather than loading the whole file.

## CachedIndexFileStorer

Caches the last files idx files into memory.

```
use scannerlib::storage::infisto::IndexedByteStorage;
let base = "/tmp/openvasd/storage";
let name = "readme_cached";
let mut store = scannerlib::storage::infisto::CachedIndexFileStorer::init(base).unwrap();
store.put(name, "Hello World".as_bytes()).unwrap();
store.append_all(name, &["a".as_bytes(), "b".as_bytes()]).unwrap();
let data: Vec<Vec<u8>> = store.by_range(name, scannerlib::storage::infisto::Range::Between(1, 3)).unwrap();
assert_eq!(data.len(), 2);
assert_eq!(&data[0], "a".as_bytes());
assert_eq!(&data[1], "b".as_bytes());
store.remove(name).unwrap();
```

## ChaCha20IndexFileStorer

Encryptes the given data with chacha20 before storing it.

```
use scannerlib::storage::infisto::IndexedByteStorage;
let base = "/tmp/openvasd/storage";
let name = "readme_crypt";
let key = "changeme";
let store = scannerlib::storage::infisto::CachedIndexFileStorer::init(base).unwrap();
let mut store = scannerlib::storage::infisto::ChaCha20IndexFileStorer::new(store, key);
store.put(name, "Hello World".as_bytes()).unwrap();
store.append_all(name, &["a".as_bytes(), "b".as_bytes()]).unwrap();
let data: Vec<Vec<u8>> = store.by_range(name, scannerlib::storage::infisto::Range::Between(1, 3)).unwrap();
assert_eq!(data.len(), 2);
assert_eq!(&data[0], "a".as_bytes());
assert_eq!(&data[1], "b".as_bytes());
store.remove(name).unwrap();
```

## IndexedByteStorageIterator

Instead of loading all elements at once it allows to fetch single elements when required.
 
```
use scannerlib::storage::infisto::IndexedByteStorage;
let base = "/tmp/openvasd/storage";
let name = "readme_iter";
let key = "changeme";
let mut store = scannerlib::storage::infisto::CachedIndexFileStorer::init(base).unwrap();
store.put(name, "Hello World".as_bytes()).unwrap();
let mut iter: scannerlib::storage::infisto::IndexedByteStorageIterator<_, Vec<u8>> =
    scannerlib::storage::infisto::IndexedByteStorageIterator::new(name, store.clone()).unwrap();
assert_eq!(iter.next(), Some(Ok("Hello World".as_bytes().to_vec())));
assert_eq!(iter.next(), None);
store.remove(name).unwrap();
```

