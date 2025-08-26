use std::{
    collections::HashSet,
    hash::Hash,
    io::{self, Cursor},
    mem,
};

use anyhow::{Context, Result, anyhow};
use byteorder::{BigEndian, ByteOrder, ReadBytesExt};
use serde::Deserialize;

use super::rpmtags::*;

// ref. https://github.com/rpm-software-management/rpm/blob/rpm-4.14.3-release/lib/header.c#L121-L122
const REGION_TAG_COUNT: i32 = mem::size_of::<EntryInfo>() as i32;
const REGION_TAG_TYPE: u32 = 7;

// ref. https://github.com/rpm-software-management/rpm/blob/rpm-4.14.3-release/lib/header.c#L113
const HEADER_MAX_BYTES: usize = 256 * 1024 * 1024;

const TYPE_SIZES: [i32; 16] = [
    0,  // RPM_NULL_TYPE
    1,  // RPM_CHAR_TYPE
    1,  // RPM_INT8_TYPE
    2,  // RPM_INT16_TYPE
    4,  // RPM_INT32_TYPE
    8,  // RPM_INT64_TYPE
    -1, // RPM_STRING_TYPE
    1,  // RPM_BIN_TYPE
    -1, // RPM_STRING_ARRAY_TYPE
    -1, // RPM_I18NSTRING_TYPE
    0, 0, 0, 0, 0, 0,
];

const TYPE_ALIGN: [i32; 16] = [
    1, // RPM_NULL_TYPE
    1, // RPM_CHAR_TYPE
    1, // RPM_INT8_TYPE
    2, // RPM_INT16_TYPE
    4, // RPM_INT32_TYPE
    8, // RPM_INT64_TYPE
    1, // RPM_STRING_TYPE
    1, // RPM_BIN_TYPE
    1, // RPM_STRING_ARRAY_TYPE
    1, // RPM_I18NSTRING_TYPE
    0, 0, 0, 0, 0, 0,
];

// ref. https://github.com/rpm-software-management/rpm/blob/rpm-4.14.3-release/lib/header_internal.h#L14-L20
#[derive(Deserialize, Clone, Debug)]
pub(crate) struct EntryInfo {
    pub(crate) tag: i32,
    pub(crate) _type: u32,
    pub(crate) offset: i32,
    pub(crate) count: u32,
}

impl EntryInfo {
    fn ei2h(&self) -> EntryInfo {
        EntryInfo {
            tag: BigEndian::read_i32(&self.tag.to_le_bytes()),
            _type: BigEndian::read_u32(&self._type.to_le_bytes()),
            offset: BigEndian::read_i32(&self.offset.to_le_bytes()),
            count: BigEndian::read_u32(&self.count.to_le_bytes()),
        }
    }
}

// ref. https://github.com/rpm-software-management/rpm/blob/rpm-4.14.3-release/lib/header.c#L88-L94
#[derive(Debug)]
pub(crate) struct IndexEntry {
    pub(crate) info: EntryInfo,
    pub(crate) _length: isize,
    pub(crate) _rdlen: isize,
    pub(crate) data: Vec<u8>,
}

impl IndexEntry {
    pub(crate) fn read_i32(&self) -> Result<i32> {
        let mut cursor = Cursor::new(&self.data);
        Ok(cursor.read_i32::<BigEndian>()?)
    }

    pub(crate) fn read_string(&self) -> Result<String> {
        let value = String::from_utf8_lossy(&self.data)
            .trim_end_matches('\x00')
            .to_string();
        Ok(value)
    }

    pub(crate) fn read_i32_array(&self) -> Result<Vec<i32>> {
        let mut cursor = Cursor::new(&self.data);
        let mut values = Vec::new();
        for _ in 0..self.info.count {
            let value = match cursor.read_i32::<BigEndian>() {
                Ok(value) => value,
                Err(ref err) if err.kind() == io::ErrorKind::UnexpectedEof => break,
                Err(err) => return Err(err.into()),
            };
            values.push(value);
        }
        Ok(values)
    }

    pub(crate) fn read_string_array(&self) -> Result<Vec<String>> {
        let values: Vec<String> = self
            .data
            .split(|&b| b == 0)
            .filter(|slice| !slice.is_empty())
            .map(|slice| String::from_utf8_lossy(slice).into_owned())
            .collect();

        Ok(values)
    }
}

impl Hash for IndexEntry {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.info.tag.hash(state);
    }
}

impl PartialEq for IndexEntry {
    fn eq(&self, other: &Self) -> bool {
        self.info.tag == other.info.tag
    }
}

impl Eq for IndexEntry {}

// ref. https://github.com/rpm-software-management/rpm/blob/rpm-4.14.3-release/lib/header_internal.h#L23
pub(crate) struct Hdrblob {
    pe_list: Vec<EntryInfo>,
    il: i32,
    dl: i32,
    _pvlen: i32,
    data_start: i32,
    data_end: i32,
    region_tag: i32,
    ril: i32,
    rdl: i32,
}

impl Hdrblob {
    pub(crate) fn from_bytes(data: &[u8]) -> Result<Hdrblob> {
        let mut cursor = Cursor::new(&data);

        let il = cursor.read_i32::<BigEndian>()?;
        let dl = cursor.read_i32::<BigEndian>()?;

        let entry_info_size = mem::size_of::<EntryInfo>() as i32;
        let il_size = 4;
        let dl_size = 4;
        let data_start = il_size + dl_size + il * entry_info_size;
        let pvlen = il_size + dl_size + il * entry_info_size + dl;
        let data_end = data_start + dl;
        if il < 1 {
            return Err(anyhow!("region no tags error"));
        }

        let mut pe_list = Vec::new();
        for _ in 0..il {
            let pe: EntryInfo = bincode::deserialize_from(&mut cursor)?;
            pe_list.push(pe);
        }

        if pvlen >= HEADER_MAX_BYTES as i32 {
            return Err(anyhow!(
                "blob size {} BAD, 8 + 16 * il({}) + dl({})",
                pvlen,
                il,
                dl
            ));
        }

        let mut blob = Hdrblob {
            pe_list,
            il,
            dl,
            _pvlen: pvlen,
            data_start,
            data_end,
            region_tag: 0,
            ril: 0,
            rdl: 0,
        };
        blob.verify_region(data)?;
        blob.verify_info(data)?;

        Ok(blob)
    }

    pub(crate) fn import(&self, data: &[u8]) -> Result<Vec<IndexEntry>> {
        let mut index_entries;
        let dribble_index_entries;
        let mut rdlen;

        let entry: EntryInfo = self.pe_list.first().context("empty pe list")?.ei2h();
        if entry.tag >= RPMTAG_HEADERI18NTABLE {
            (index_entries, rdlen) = region_swab(
                data,
                self.pe_list.clone(),
                0,
                self.data_start,
                self.data_end,
            )
            .map_err(|e| anyhow!("failed to parse legacy index entries:{}", e))?;
        } else {
            let ril = if entry.offset == 0 { self.il } else { self.ril };

            // ref. https://github.com/rpm-software-management/rpm/blob/rpm-4.14.3-release/lib/header.c#L917
            (index_entries, rdlen) = region_swab(
                data,
                self.pe_list[1..ril as usize].to_vec(),
                0,
                self.data_start,
                self.data_end,
            )?;
            if rdlen < 0 {
                return Err(anyhow!("invalid region length"));
            }

            if self.ril < self.pe_list.len() as i32 - 1 {
                (dribble_index_entries, rdlen) = region_swab(
                    data,
                    self.pe_list[ril as usize..].to_vec(),
                    rdlen,
                    self.data_start,
                    self.data_end,
                )?;
                if rdlen < 0 {
                    return Err(anyhow!("invalid length of dribble entries"));
                }
                index_entries.extend(dribble_index_entries);

                index_entries = index_entries
                    .into_iter()
                    .collect::<HashSet<_>>()
                    .into_iter()
                    .collect::<Vec<_>>();
            }
            rdlen += mem::size_of::<EntryInfo>() as i32;
        }

        if rdlen != self.dl {
            return Err(anyhow!(
                "the calculated length ({}) is different from the data length ({})",
                rdlen,
                self.dl
            ));
        }

        Ok(index_entries)
    }

    // ref. https://github.com/rpm-software-management/rpm/blob/rpm-4.14.3-release/lib/header.c#L1791
    fn verify_region(&mut self, data: &[u8]) -> Result<()> {
        let pe = self.pe_list.first().context("invalid pe_list index")?;
        let mut einfo = pe.ei2h();

        let mut region_tag: i32 = 0;
        if [
            RPMTAG_HEADERIMAGE,
            RPMTAG_HEADERSIGNATURES,
            RPMTAG_HEADERIMMUTABLE,
        ]
        .contains(&einfo.tag)
        {
            region_tag = einfo.tag;
        }

        if einfo.tag != region_tag {
            return Ok(());
        }

        if !(einfo._type == REGION_TAG_TYPE && einfo.count == REGION_TAG_COUNT as u32) {
            return Err(anyhow!("invalid region tag"));
        }

        if hdrchk_range(self.dl, einfo.offset + REGION_TAG_COUNT) {
            return Err(anyhow!("invalid region offset"));
        }

        // ref. https://github.com/rpm-software-management/rpm/blob/rpm-4.14.3-release/lib/header.c#L1842
        let region_end = self.data_start + einfo.offset;
        let trailer: EntryInfo = bincode::deserialize(
            &data[region_end as usize..(region_end + REGION_TAG_COUNT) as usize],
        )?;

        self.rdl = region_end + REGION_TAG_COUNT - self.data_start;

        if region_tag == RPMTAG_HEADERSIGNATURES && einfo.tag == RPMTAG_HEADERIMAGE {
            einfo.tag = RPMTAG_HEADERSIGNATURES;
        }

        if !(einfo.tag == region_tag
            && einfo._type == REGION_TAG_TYPE
            && einfo.count == REGION_TAG_COUNT as u32)
        {
            return Err(anyhow!("invalid region trailer"));
        }

        einfo = trailer.ei2h();
        einfo.offset = -einfo.offset;
        // NOTE: blob.ril = einfo.Offset / int32(unsafe.Sizeof(blob.peList[0]))
        self.ril = einfo.offset / REGION_TAG_COUNT;
        if (einfo.offset % REGION_TAG_COUNT) != 0
            || hdrchk_range(self.il, self.ril)
            || hdrchk_range(self.dl, self.rdl)
        {
            return Err(anyhow!("invalid region size, region {}", region_tag));
        }
        self.region_tag = region_tag;

        Ok(())
    }

    fn verify_info(&self, data: &[u8]) -> Result<()> {
        let mut end: i32 = 0;
        let pe_offset = if self.region_tag != 0 { 1 } else { 0 };

        for pe in &self.pe_list[pe_offset..] {
            let info = pe.ei2h();

            if end > info.offset {
                return Err(anyhow!("invalid offset info: {:?}", info));
            }

            if hdrchk_tag(info.tag) {
                return Err(anyhow!("invalid tag info: {:?}", info));
            }

            if hdrchk_type(info._type) {
                return Err(anyhow!("invalid type info: {:?}", info));
            }

            if hdrchk_align(info._type, info.offset) {
                return Err(anyhow!("invalid align info: {:?}", info));
            }

            if hdrchk_range(self.dl, info.offset) {
                return Err(anyhow!("invalid range info: {:?}", info));
            }

            let length = data_length(
                data,
                info._type,
                info.count,
                self.data_start + info.offset,
                self.data_end,
            );
            end = info.offset + length as i32;
            if hdrchk_range(self.dl, end) || length <= 0 {
                return Err(anyhow!("invalid data length info: {:?}", info));
            }
        }

        Ok(())
    }
}

// ref. https://github.com/rpm-software-management/rpm/blob/rpm-4.14.3-release/lib/header.c#L498
fn region_swab(
    data: &[u8],
    pe_list: Vec<EntryInfo>,
    mut dl: i32,
    data_start: i32,
    data_end: i32,
) -> Result<(Vec<IndexEntry>, i32)> {
    let mut index_entries = Vec::new();
    for (i, pe) in pe_list.iter().enumerate() {
        let info = pe.ei2h();
        let start = data_start + info.offset;
        if start >= data_end {
            return Err(anyhow!("invalid data offset"));
        }

        let length = if i < pe_list.len() - 1 && TYPE_SIZES.get(info._type as usize) == Some(&-1) {
            let mut pe_offset = pe_list.get(i + 1).context("invalid pe_list index")?.offset;
            pe_offset = BigEndian::read_i32(&pe_offset.to_le_bytes());
            (pe_offset - info.offset) as isize
        } else {
            data_length(data, info._type, info.count, start, data_end)
        };
        if length < 0 {
            return Err(anyhow!("invalid data length"));
        }

        let end = start as isize + length;

        index_entries.push(IndexEntry {
            info: info.clone(),
            _length: length,
            _rdlen: 0,
            data: Vec::from(&data[start as usize..end as usize]),
        });

        dl += length as i32 + align_diff(info._type, dl as u32);
    }
    Ok((index_entries, dl))
}

// ref. https://github.com/rpm-software-management/rpm/blob/rpm-4.14.3-release/lib/header.c#L440
fn data_length(data: &[u8], t: u32, count: u32, start: i32, data_end: i32) -> isize {
    match t {
        RPM_STRING_TYPE if count != 1 => -1,
        RPM_STRING_TYPE => strtaglen(data, 1, start, data_end),
        RPM_STRING_ARRAY_TYPE | RPM_I18NSTRING_TYPE => strtaglen(data, count, start, data_end),
        _ => {
            if TYPE_SIZES.get(t as usize) == Some(&-1) {
                return -1;
            }
            let idx = (t & 0xf) as usize;
            let l = TYPE_SIZES.get(idx).unwrap_or(&0) * count as i32;
            if l < 0 || data_end > 0 && start + l > data_end {
                -1
            } else {
                l as isize
            }
        }
    }
}

// ref. https://github.com/rpm-software-management/rpm/blob/rpm-4.14.3-release/lib/header.c#L408
fn strtaglen(data: &[u8], count: u32, start: i32, data_end: i32) -> isize {
    let mut length: isize = 0;
    if start >= data_end {
        return -1;
    }

    for _ in (1..=count).rev() {
        let offset = start + length as i32;
        if offset > data.len() as i32 {
            return -1;
        }
        if let Some(i) = data[offset as usize..data_end as usize]
            .iter()
            .position(|&x| x == 0x00)
        {
            length += i as isize + 1
        }
    }
    length
}

// ref. https://github.com/rpm-software-management/rpm/blob/rpm-4.14.3-release/lib/header.c#L353
fn align_diff(t: u32, align_size: u32) -> i32 {
    match TYPE_SIZES.get(t as usize) {
        Some(&i) if i > 1 => {
            let diff = i - (align_size as i32 % i);
            if diff != i { diff } else { 0 }
        }
        _ => 0,
    }
}

fn hdrchk_range(dl: i32, offset: i32) -> bool {
    offset < 0 || offset > dl
}

fn hdrchk_tag(tag: i32) -> bool {
    tag < HEADER_I18NTABLE
}

fn hdrchk_type(t: u32) -> bool {
    t > RPM_MAX_TYPE
}

fn hdrchk_align(t: u32, offset: i32) -> bool {
    let value = offset & (TYPE_ALIGN.get(t as usize).unwrap_or(&0) - 1);
    value != 0
}
