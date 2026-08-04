// SPDX-FileCopyrightText: 2023 Greenbone AG
//
// SPDX-License-Identifier: GPL-2.0-or-later WITH x11vnc-openssl-exception

use std::str::FromStr;

use crate::models::{ACT, PreferenceType};
use crate::nasl::prelude::*;
use crate::nasl::utils::function::StringOrData;
use crate::storage::items::nvt::{NvtPreference, NvtRef, TagKey, TagValue};

#[nasl_function]
pub fn script_timeout(ctx: &ScanCtx, timeout: u64) {
    ctx.nvt_mut()
        .as_mut()
        .unwrap()
        .preferences
        .push(NvtPreference {
            id: Some(0),
            name: "timeout".to_owned(),
            class: PreferenceType::Entry,
            default: timeout.to_string(),
        });
}

#[nasl_function]
pub fn script_category(ctx: &ScanCtx, category: ACT) {
    ctx.nvt_mut().as_mut().unwrap().category = category;
}

#[nasl_function]
pub fn script_name(ctx: &ScanCtx, name: StringOrData) {
    ctx.nvt_mut().as_mut().unwrap().name = name.string().into();
}

#[nasl_function]
pub fn script_version(_version: String) {}

#[nasl_function]
pub fn script_copyright(_copyright: String) {}

#[nasl_function]
pub fn script_family(ctx: &ScanCtx, family: String) {
    ctx.nvt_mut().as_mut().unwrap().family = family;
}

#[nasl_function]
pub fn script_oid(ctx: &ScanCtx, oid: String) {
    ctx.nvt_mut().as_mut().unwrap().oid = oid;
}

#[nasl_function]
pub fn script_filename(ctx: &ScanCtx, filename: String) {
    ctx.nvt_mut().as_mut().unwrap().filename = filename;
}

#[nasl_function]
pub fn script_dependencies(ctx: &ScanCtx, dependencies: CheckedPositionals<String>) {
    ctx.nvt_mut()
        .as_mut()
        .unwrap()
        .dependencies
        .extend(dependencies);
}

#[nasl_function]
pub fn script_exclude_keys(ctx: &ScanCtx, keys: CheckedPositionals<StringOrData>) {
    ctx.nvt_mut()
        .as_mut()
        .unwrap()
        .excluded_keys
        .extend(keys.into_iter().map(|x| x.string().into()));
}

#[nasl_function(named(re))]
pub fn script_mandatory_keys(ctx: &ScanCtx, re: Option<String>, keys: CheckedPositionals<String>) {
    let mut keys: Vec<String> = keys.into_iter().collect();
    if let Some(re) = re {
        keys.push(re);
    }

    if let Some((remove, _)) = keys.last().and_then(|value| value.rsplit_once('=')) {
        let remove = remove.to_owned();
        keys.retain(|value| !value.starts_with(&remove) || value.contains('='));
    }
    ctx.nvt_mut().as_mut().unwrap().mandatory_keys.extend(keys);
}

#[nasl_function]
pub fn script_require_ports(ctx: &ScanCtx, ports: CheckedPositionals<&NaslValue>) {
    ctx.nvt_mut()
        .as_mut()
        .unwrap()
        .required_ports
        .extend(ports.iter().map(|port| port.to_string()));
}

#[nasl_function]
pub fn script_require_udp_ports(ctx: &ScanCtx, ports: CheckedPositionals<&NaslValue>) {
    ctx.nvt_mut()
        .as_mut()
        .unwrap()
        .required_udp_ports
        .extend(ports.iter().map(|port| port.to_string()));
}

#[nasl_function]
pub fn script_require_keys(ctx: &ScanCtx, keys: CheckedPositionals<String>) {
    ctx.nvt_mut().as_mut().unwrap().required_keys.extend(keys);
}

#[nasl_function]
pub fn script_cve_id(ctx: &ScanCtx, cves: CheckedPositionals<String>) {
    ctx.nvt_mut()
        .as_mut()
        .unwrap()
        .references
        .extend(cves.into_iter().map(|cve| ("cve", cve).into()));
}

#[nasl_function(named(name, value))]
pub fn script_tag(ctx: &ScanCtx, name: &str, value: &NaslValue) -> Result<(), FnError> {
    let key: TagKey = name.parse()?;
    match TagValue::parse(key, value)? {
        TagValue::Null => {}
        value => {
            ctx.nvt_mut().as_mut().unwrap().tag.insert(key, value);
        }
    }
    Ok(())
}

#[nasl_function(named(name, value))]
pub fn script_xref(ctx: &ScanCtx, name: String, value: String) {
    ctx.nvt_mut().as_mut().unwrap().references.push(NvtRef {
        class: name,
        id: value,
    });
}

#[nasl_function(named(name, value, id, r#type))]
pub fn script_add_preference(
    ctx: &ScanCtx,
    name: StringOrData,
    value: NaslValue,
    r#type: StringOrData,
    id: Option<i32>,
) -> Result<(), FnError> {
    ctx.nvt_mut()
        .as_mut()
        .unwrap()
        .preferences
        .push(NvtPreference {
            id,
            class: PreferenceType::from_str(&r#type.string())?,
            name: name.string().into(),
            default: value.to_string(),
        });
    Ok(())
}

function_set! {
    Description,
    (
        script_timeout,
        script_category,
        script_name,
        script_version,
        script_copyright,
        script_family,
        script_oid,
        script_filename,
        script_dependencies,
        script_exclude_keys,
        script_mandatory_keys,
        script_require_ports,
        script_require_udp_ports,
        script_require_keys,
        script_cve_id,
        script_tag,
        script_xref,
        script_add_preference,
    )
}

#[derive(Debug, Clone, Copy, Default)]
pub struct Description;
