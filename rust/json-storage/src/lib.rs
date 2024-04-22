// SPDX-FileCopyrightText: 2023 Greenbone AG
//
// SPDX-License-Identifier: GPL-2.0-or-later WITH x11vnc-openssl-exception

#![doc = include_str!("../README.md")]
#![warn(missing_docs)]

use std::{
    io::{self, Write},
    sync::{Arc, Mutex},
};

use storage::{self, item::PerItemDispatcher, Kb, NotusAdvisory, StorageError};

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
        self.w.write_all(&[b']'])
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
            self.w.write_all(&[b'['])?;
            self.first = false;
        } else {
            self.w.write_all(&[b','])?;
        }
        self.w.write_all(buf)?;
        Ok(())
    }

    fn flush(&mut self) -> io::Result<()> {
        self.w.flush()
    }
}

/// It will transform a Nvt to json and write it into the given Writer.
pub struct ItemDispatcher<W>
where
    W: Write,
{
    w: Arc<Mutex<W>>,
    kbs: Arc<Mutex<Vec<Kb>>>,
}
impl<S> ItemDispatcher<S>
where
    S: Write,
{
    /// Creates a new JsonNvtDispatcher
    ///
    pub fn new(w: S) -> Self {
        Self {
            w: Arc::new(Mutex::new(w)),
            kbs: Arc::new(Mutex::new(Vec::new())),
        }
    }

    /// Returns a new instance as a Dispatcher
    pub fn as_dispatcher<K>(w: S) -> PerItemDispatcher<Self, K>
    where
        K: AsRef<str>,
    {
        PerItemDispatcher::new(Self::new(w))
    }

    fn as_json(&self, nvt: storage::item::Nvt) -> Result<(), storage::StorageError> {
        let mut context = self.w.lock().map_err(StorageError::from)?;
        serde_json::to_vec(&nvt)
            .map_err(|e| StorageError::Dirty(format!("{e:?}")))
            .and_then(|x| context.write_all(&x).map_err(StorageError::from))
    }
}

impl<S, K> storage::item::ItemDispatcher<K> for ItemDispatcher<S>
where
    S: Write,
{
    fn dispatch_nvt(&self, nvt: storage::item::Nvt) -> Result<(), storage::StorageError> {
        self.as_json(nvt)
    }

    fn dispatch_feed_version(&self, _: String) -> Result<(), storage::StorageError> {
        // the feed information are currently not within the output json
        Ok(())
    }

    fn dispatch_kb(&self, _: &K, kb: Kb) -> Result<(), StorageError> {
        let mut kbs = self.kbs.lock().map_err(StorageError::from)?;
        let mut context = self.w.lock().map_err(StorageError::from)?;
        serde_json::to_vec(&kb)
            .map_err(|e| StorageError::Dirty(format!("{e:?}")))
            .and_then(|x| context.write_all(&x).map_err(StorageError::from))?;
        kbs.push(kb);
        Ok(())
    }

    fn dispatch_advisory(
        &self,
        _: &str,

        _: Box<Option<NotusAdvisory>>,
    ) -> Result<(), StorageError> {
        Ok(())
    }
}

impl<S, K> storage::Retriever<K> for ItemDispatcher<S>
where
    S: Write,
    K: 'static,
{
    fn retrieve(
        &self,
        _: &K,
        scope: storage::Retrieve,
    ) -> Result<Box<dyn Iterator<Item = storage::Field>>, StorageError> {
        Ok(match scope {
            // currently not supported
            storage::Retrieve::NVT(_) | storage::Retrieve::NotusAdvisory(_) => {
                Box::new([].into_iter())
            }
            storage::Retrieve::KB(s) => Box::new({
                let kbs = self.kbs.lock().map_err(StorageError::from)?;
                let kbs = kbs.clone();
                kbs.into_iter()
                    .filter(move |x| x.key == s)
                    .map(|x| storage::Field::KB(x.clone()))
            }),
        })
    }

    fn retrieve_by_field(
        &self,
        _: storage::Field,
        _: storage::Retrieve,
    ) -> Result<Box<dyn Iterator<Item = (K, storage::Field)>>, StorageError> {
        Ok(Box::new([].into_iter()))
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use storage::item::{Nvt, ACT};

    use super::*;

    fn name_to_oid_fake(name: &str) -> String {
        name.as_bytes()
            .iter()
            .map(|x| x.to_string())
            .collect::<Vec<String>>()
            .join(".")
    }

    fn generate_tags() -> BTreeMap<storage::item::TagKey, storage::item::TagValue> {
        use storage::item::TagKey::*;
        use storage::item::TagValue;
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
    fn generate_preferences() -> Vec<storage::item::NvtPreference> {
        use storage::item::NvtPreference;
        use storage::item::PreferenceType;
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

    fn generate_references() -> Vec<storage::item::NvtRef> {
        use storage::item::NvtRef;
        vec![NvtRef {
            class: "URL".to_owned(),
            id: "unix:///var/lib/really.sock".to_owned(),
        }]
    }

    #[test]
    fn single_json() {
        let nvt = generate_nvt("test", ACT::DestructiveAttack);
        let mut buf = Vec::with_capacity(1208);
        let dispatcher = super::ItemDispatcher::new(&mut buf);
        dispatcher.as_json(nvt.clone()).unwrap();
        let single_json = String::from_utf8(buf).unwrap();
        let result: Nvt = serde_json::from_str(&single_json).unwrap();
        assert_eq!(result, nvt);
    }

    #[test]
    fn array_wrapper() {
        let mut buf = Vec::with_capacity(1208 * 11);
        let mut ja = ArrayWrapper::new(&mut buf);
        let dispatcher = super::ItemDispatcher::new(&mut ja);
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
