// SPDX-FileCopyrightText: 2023 Greenbone AG
//
// SPDX-License-Identifier: GPL-2.0-or-later WITH x11vnc-openssl-exception

use std::str::FromStr;

use crate::models::{ACT, PreferenceType};
use crate::nasl::prelude::*;
use crate::nasl::utils::function::StringOrData;
use crate::storage::items::nvt::{NvtPreference, NvtRef, TagKey, TagValue};

#[nasl_function]
pub fn script_timeout(script_ctx: &mut ScriptCtx, timeout: u64) {
    script_ctx.vt_mut().preferences.push(NvtPreference {
        id: Some(0),
        name: "timeout".to_owned(),
        class: PreferenceType::Entry,
        default: timeout.to_string(),
    });
}

#[nasl_function]
pub fn script_category(script_ctx: &mut ScriptCtx, category: ACT) {
    script_ctx.vt_mut().category = category;
}

#[nasl_function]
pub fn script_name(script_ctx: &mut ScriptCtx, name: StringOrData) {
    script_ctx.vt_mut().name = name.string().into();
}

#[nasl_function]
pub fn script_version(_version: String) {}

#[nasl_function]
pub fn script_copyright(_copyright: String) {}

#[nasl_function]
pub fn script_family(script_ctx: &mut ScriptCtx, family: String) {
    script_ctx.vt_mut().family = family;
}

#[nasl_function]
pub fn script_oid(script_ctx: &mut ScriptCtx, oid: String) {
    script_ctx.vt_mut().oid = oid;
}

#[nasl_function]
pub fn script_filename(script_ctx: &mut ScriptCtx, filename: String) {
    script_ctx.vt_mut().filename = filename;
}

#[nasl_function]
pub fn script_dependencies(script_ctx: &mut ScriptCtx, dependencies: CheckedPositionals<String>) {
    script_ctx.vt_mut().dependencies.extend(dependencies);
}

#[nasl_function]
pub fn script_exclude_keys(script_ctx: &mut ScriptCtx, keys: CheckedPositionals<StringOrData>) {
    script_ctx
        .vt_mut()
        .excluded_keys
        .extend(keys.into_iter().map(|x| x.string().into()));
}

#[nasl_function(named(re))]
pub fn script_mandatory_keys(
    script_ctx: &mut ScriptCtx,
    re: Option<String>,
    keys: CheckedPositionals<String>,
) {
    let mut keys: Vec<String> = keys.into_iter().collect();
    if let Some(re) = re {
        keys.push(re);
    }

    if let Some((remove, _)) = keys.last().and_then(|value| value.rsplit_once('=')) {
        let remove = remove.to_owned();
        keys.retain(|value| !value.starts_with(&remove) || value.contains('='));
    }
    script_ctx.vt_mut().mandatory_keys.extend(keys);
}

#[nasl_function]
pub fn script_require_ports(script_ctx: &mut ScriptCtx, ports: CheckedPositionals<&NaslValue>) {
    script_ctx
        .vt_mut()
        .required_ports
        .extend(ports.iter().map(|port| port.to_string()));
}

#[nasl_function]
pub fn script_require_udp_ports(script_ctx: &mut ScriptCtx, ports: CheckedPositionals<&NaslValue>) {
    script_ctx
        .vt_mut()
        .required_udp_ports
        .extend(ports.iter().map(|port| port.to_string()));
}

#[nasl_function]
pub fn script_require_keys(script_ctx: &mut ScriptCtx, keys: CheckedPositionals<String>) {
    script_ctx.vt_mut().required_keys.extend(keys);
}

#[nasl_function]
pub fn script_cve_id(script_ctx: &mut ScriptCtx, cves: CheckedPositionals<String>) {
    script_ctx
        .vt_mut()
        .references
        .extend(cves.into_iter().map(|cve| ("cve", cve).into()));
}

#[nasl_function(named(name, value))]
pub fn script_tag(
    script_ctx: &mut ScriptCtx,
    name: &str,
    value: &NaslValue,
) -> Result<(), FnError> {
    let key: TagKey = name.parse()?;
    match TagValue::parse(key, value)? {
        TagValue::Null => {}
        value => {
            script_ctx.vt_mut().tag.insert(key, value);
        }
    }
    Ok(())
}

#[nasl_function(named(name, value))]
pub fn script_xref(script_ctx: &mut ScriptCtx, name: String, value: String) {
    script_ctx.vt_mut().references.push(NvtRef {
        class: name,
        id: value,
    });
}

#[nasl_function(named(name, value, id, r#type))]
pub fn script_add_preference(
    script_ctx: &mut ScriptCtx,
    name: StringOrData,
    value: NaslValue,
    r#type: StringOrData,
    id: Option<i32>,
) -> Result<(), FnError> {
    script_ctx.vt_mut().preferences.push(NvtPreference {
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
