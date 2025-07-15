use serde::de::DeserializeOwned;
use serde_json::{self, Deserializer};
use std::io::{self, Read};
// copied from
// https://stackoverflow.com/questions/68641157/how-can-i-stream-elements-from-inside-a-json-array-using-serde-json?noredirect=1#comment121310322_68641157
// Currently it does not seem that serde directly supports streaming elements of a large list,
// however as the vt-metadata is a very large list of models::NVT and we need to store each element
// into the database we need a possibility to yield each element to be stored.
//
// Otherwise we need to iterate multiple times of that list which takes too long.

fn read_skipping_ws(mut reader: impl Read) -> io::Result<u8> {
    loop {
        let mut byte = 0u8;
        reader.read_exact(std::slice::from_mut(&mut byte))?;
        if !byte.is_ascii_whitespace() {
            return Ok(byte);
        }
    }
}

fn invalid_data(msg: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, msg)
}

fn deserialize_single<T: DeserializeOwned, R: Read>(reader: R) -> io::Result<T> {
    let next_obj = Deserializer::from_reader(reader).into_iter::<T>().next();
    match next_obj {
        Some(result) => result.map_err(Into::into),
        None => Err(invalid_data("premature EOF")),
    }
}

fn yield_next_obj<T: DeserializeOwned, R: Read>(
    mut reader: R,
    at_start: &mut bool,
) -> io::Result<Option<T>> {
    if !*at_start {
        *at_start = true;
        if read_skipping_ws(&mut reader)? == b'[' {
            // read the next char to see if the array is empty
            let peek = read_skipping_ws(&mut reader)?;
            if peek == b']' {
                Ok(None)
            } else {
                let obj = deserialize_single(io::Cursor::new([peek]).chain(reader))?;
                Ok(Some(obj))
            }
        } else {
            Err(invalid_data("`[` not found"))
        }
    } else {
        match read_skipping_ws(&mut reader)? {
            b',' => deserialize_single(reader).map(Some),
            b']' => Ok(None),
            _ => Err(invalid_data("`,` or `]` not found")),
        }
    }
}

pub fn iter_json_array<T: DeserializeOwned, R: Read>(
    mut reader: R,
) -> impl Iterator<Item = Result<T, io::Error>> {
    let mut at_start = false;
    std::iter::from_fn(move || yield_next_obj(&mut reader, &mut at_start).transpose())
}
