// SPDX-FileCopyrightText: 2023 Greenbone AG
//
// SPDX-License-Identifier: GPL-2.0-or-later WITH x11vnc-openssl-exception

#![doc = include_str!("README.md")]

use std::{
    io::{self, Write},
    sync::Mutex,
};

use crate::storage::{
    self, Dispatcher, Remover, Retriever, ScanID, StorageError,
    inmemory::kb::InMemoryKbStorage,
    items::{
        kb::{GetKbContextKey, KbContextKey, KbItem},
        nvt::{Feed, FeedVersion, FileName, Nvt, Oid},
        result::{ResultContextKeySingle, ResultItem},
    },
};

/// Wraps write calls of json elements to be as list.
///
/// This allows to stream elements within an run to be written as an array without having to cache
/// the elements upfront.
/// It is done by using write_all and verify if it is the first call. If it is it will write `[`
/// before the given byte slice otherwise it will print a `,`.
/// The user of this struct must use `write_all` and cannot rely on `write` additionally the user
/// must ensure that `end` is called when the array should be closed.
pub struct ArrayWrapper<W> {
    w: W,
    first: bool,
}

impl<W> ArrayWrapper<W>
where
    W: Write,
{
    /// Creates a new JsonArrayWrapper
    pub fn new(w: W) -> Self {
        Self { first: true, w }
    }
    /// Must be called on the end of the complete run.
    ///
    /// This is to ensure that an enclosed `]` is printed.
    pub fn end(&mut self) -> io::Result<()> {
        self.w.write_all(b"]")
    }
}

impl<W> Write for ArrayWrapper<W>
where
    W: Write,
{
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.w.write(buf)
    }

    fn write_all(&mut self, buf: &[u8]) -> io::Result<()> {
        if self.first {
            self.w.write_all(b"[")?;
            self.first = false;
        } else {
            self.w.write_all(b",")?;
        }
        self.w.write_all(buf)?;
        Ok(())
    }

    fn flush(&mut self) -> io::Result<()> {
        self.w.flush()
    }
}

/// It will transform a Nvt to json and write it into the given Writer.
pub struct JsonStorage<W: Write> {
    w: Mutex<W>,
    kbs: InMemoryKbStorage,
}
impl<S> JsonStorage<S>
where
    S: Write,
{
    /// Creates a new JsonStorage
    pub fn new(w: S) -> Self {
        Self {
            w: Mutex::new(w),
            kbs: Default::default(),
        }
    }

    fn as_json(&self, nvt: Nvt) -> Result<(), storage::StorageError> {
        let mut context = self.w.lock()?;
        serde_json::to_vec(&nvt)
            .map_err(|e| StorageError::Dirty(format!("{e:?}")))
            .and_then(|x| context.write_all(&x).map_err(StorageError::from))
    }
}

impl<S: Write> Dispatcher<KbContextKey> for JsonStorage<S> {
    type Item = KbItem;
    fn dispatch(&self, key: KbContextKey, item: Self::Item) -> Result<(), StorageError> {
        self.kbs.dispatch(key, item)
    }
}

impl<S: Write> Retriever<KbContextKey> for JsonStorage<S> {
    type Item = Vec<KbItem>;
    fn retrieve(&self, key: &KbContextKey) -> Result<Option<Self::Item>, StorageError> {
        self.kbs.retrieve(key)
    }
}

impl<S: Write> Retriever<GetKbContextKey> for JsonStorage<S> {
    type Item = Vec<(String, Vec<KbItem>)>;
    fn retrieve(&self, key: &GetKbContextKey) -> Result<Option<Self::Item>, StorageError> {
        self.kbs.retrieve(key)
    }
}

impl<S: Write> Remover<KbContextKey> for JsonStorage<S> {
    type Item = Vec<KbItem>;
    fn remove(&self, key: &KbContextKey) -> Result<Option<Self::Item>, StorageError> {
        self.kbs.remove(key)
    }
}

impl<S: Write> Dispatcher<FileName> for JsonStorage<S> {
    type Item = Nvt;
    fn dispatch(&self, _: FileName, item: Self::Item) -> Result<(), StorageError> {
        self.as_json(item)
    }
}

impl<S: Write> Dispatcher<FeedVersion> for JsonStorage<S> {
    type Item = String;
    fn dispatch(&self, _: FeedVersion, _: Self::Item) -> Result<(), StorageError> {
        // TODO: Feed information is currently not written to the output json
        Ok(())
    }
}

impl<S: Write> Retriever<FeedVersion> for JsonStorage<S> {
    type Item = String;
    fn retrieve(&self, _: &FeedVersion) -> Result<Option<Self::Item>, StorageError> {
        unimplemented!()
    }
}

impl<S: Write> Retriever<Feed> for JsonStorage<S> {
    type Item = Vec<Nvt>;
    fn retrieve(&self, _: &Feed) -> Result<Option<Self::Item>, StorageError> {
        unimplemented!()
    }
}

impl<S: Write> Retriever<Oid> for JsonStorage<S> {
    type Item = Nvt;
    fn retrieve(&self, _: &Oid) -> Result<Option<Self::Item>, StorageError> {
        unimplemented!()
    }
}

impl<S: Write> Retriever<FileName> for JsonStorage<S> {
    type Item = Nvt;
    fn retrieve(&self, _: &FileName) -> Result<Option<Self::Item>, StorageError> {
        unimplemented!()
    }
}

impl<S: Write> Dispatcher<ScanID> for JsonStorage<S> {
    type Item = ResultItem;
    fn dispatch(&self, _: ScanID, _: Self::Item) -> Result<(), StorageError> {
        unimplemented!()
    }
}
impl<S: Write> Retriever<ResultContextKeySingle> for JsonStorage<S> {
    type Item = ResultItem;
    fn retrieve(&self, _: &ResultContextKeySingle) -> Result<Option<Self::Item>, StorageError> {
        unimplemented!()
    }
}
impl<S: Write> Retriever<ScanID> for JsonStorage<S> {
    type Item = Vec<ResultItem>;
    fn retrieve(&self, _: &ScanID) -> Result<Option<Self::Item>, StorageError> {
        unimplemented!()
    }
}
impl<S: Write> Remover<ResultContextKeySingle> for JsonStorage<S> {
    type Item = ResultItem;
    fn remove(&self, _: &ResultContextKeySingle) -> Result<Option<Self::Item>, StorageError> {
        unimplemented!()
    }
}
impl<S: Write> Remover<ScanID> for JsonStorage<S> {
    type Item = Vec<ResultItem>;
    fn remove(&self, _: &ScanID) -> Result<Option<Self::Item>, StorageError> {
        unimplemented!()
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use crate::storage::items::nvt::{
        ACT, NvtPreference, NvtRef, PreferenceType,
        TagKey::{self, *},
        TagValue,
    };

    use super::*;

    fn name_to_oid_fake(name: &str) -> String {
        name.as_bytes()
            .iter()
            .map(|x| x.to_string())
            .collect::<Vec<String>>()
            .join(".")
    }

    fn generate_tags() -> BTreeMap<TagKey, TagValue> {
        let ts = "2012-09-23 02:15:34 -0400";
        BTreeMap::from([
            (Affected, TagValue::parse(Affected, "Affected").unwrap()),
            (CreationDate, TagValue::parse(CreationDate, ts).unwrap()),
            (
                CvssBaseVector,
                // TODO use proper Cvss2
                TagValue::parse(CvssBaseVector, "AV:N/AC:H/PR:N/UI:N/S:C/C:N/I:H/A:N").unwrap(),
            ),
            (Deprecated, TagValue::parse(Deprecated, "TRUE").unwrap()),
            (Impact, TagValue::parse(Impact, "Impact").unwrap()),
            (Insight, TagValue::parse(Insight, "Insight").unwrap()),
            (
                LastModification,
                TagValue::parse(LastModification, ts).unwrap(),
            ),
            (Qod, TagValue::parse(Qod, "30").unwrap()),
            (QodType, TagValue::parse(QodType, "exploit").unwrap()),
            (SeverityDate, TagValue::parse(SeverityDate, ts).unwrap()),
            (
                SeverityOrigin,
                TagValue::parse(SeverityOrigin, "SeverityOrigin").unwrap(),
            ),
            (
                SeverityVector,
                TagValue::parse(
                    SeverityVector,
                    "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:C/C:N/I:H/A:N",
                )
                .unwrap(),
            ),
            (Solution, TagValue::parse(Solution, "Solution").unwrap()),
            (
                SolutionMethod,
                TagValue::parse(SolutionMethod, "SolutionMethod").unwrap(),
            ),
            (
                SolutionType,
                TagValue::parse(SolutionType, "Mitigation").unwrap(),
            ),
            (Summary, TagValue::parse(Summary, "Summary").unwrap()),
            (Vuldetect, TagValue::parse(Vuldetect, "Vuldetect").unwrap()),
        ])
    }
    fn generate_preferences() -> Vec<NvtPreference> {
        [
            PreferenceType::CheckBox,
            PreferenceType::Entry,
            PreferenceType::File,
            PreferenceType::Password,
            PreferenceType::Radio,
            PreferenceType::SshLogin,
        ]
        .into_iter()
        .enumerate()
        .map(|(i, t)| NvtPreference {
            id: Some(i as i32),
            class: t,
            name: i.to_string(),
            default: i.to_string(),
        })
        .collect()
    }
    fn generate_nvt(name: &str, category: ACT) -> Nvt {
        Nvt {
            oid: name_to_oid_fake(name),
            name: "zeroone".to_owned(),
            filename: "zeroone.nasl".to_owned(),
            tag: generate_tags(),
            dependencies: vec!["zero.nasl".to_owned()],
            required_keys: vec!["hostname/test".to_owned()],
            mandatory_keys: vec!["hostname/te".to_owned()],
            excluded_keys: vec!["hostname/prod".to_owned()],
            required_ports: vec!["22".to_owned()],
            required_udp_ports: vec!["21".to_owned()],
            references: generate_references(),
            preferences: generate_preferences(),
            category,
            family: "family".to_owned(),
        }
    }

    fn generate_references() -> Vec<NvtRef> {
        vec![NvtRef {
            class: "URL".to_owned(),
            id: "unix:///var/lib/really.sock".to_owned(),
        }]
    }

    #[test]
    fn single_json() {
        let nvt = generate_nvt("test", ACT::DestructiveAttack);
        let mut buf = Vec::with_capacity(1208);
        let dispatcher = JsonStorage::new(&mut buf);
        dispatcher.as_json(nvt.clone()).unwrap();
        let single_json = String::from_utf8(buf).unwrap();
        let result: Nvt = serde_json::from_str(&single_json).unwrap();
        assert_eq!(result, nvt);
    }

    #[test]
    fn array_wrapper() {
        let mut buf = Vec::with_capacity(1208 * 11);
        let mut ja = ArrayWrapper::new(&mut buf);
        let dispatcher = JsonStorage::new(&mut ja);
        for nvt in [
            ACT::Init,
            ACT::Scanner,
            ACT::Settings,
            ACT::GatherInfo,
            ACT::Attack,
            ACT::MixedAttack,
            ACT::DestructiveAttack,
            ACT::Denial,
            ACT::KillHost,
            ACT::Flood,
            ACT::End,
        ]
        .into_iter()
        .enumerate()
        .map(|(i, c)| generate_nvt(&i.to_string(), c))
        {
            dispatcher.as_json(nvt).unwrap();
        }
        ja.end().unwrap();

        let json_arr = String::from_utf8(buf).unwrap();
        let result: Vec<Nvt> = serde_json::from_str(&json_arr).unwrap();
        assert_eq!(result.len(), 11);
    }
}
