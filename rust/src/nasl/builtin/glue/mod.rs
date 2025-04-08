// SPDX-FileCopyrightText: 2025 Greenbone AG
//
// SPDX-License-Identifier: GPL-2.0-or-later WITH x11vnc-openssl-exception
use crate::nasl::prelude::*;
use crate::storage::items::nvt::NvtPreference;

#[nasl_function(named(id))]
fn script_get_preference(
    register: &Register,
    config: &Context,
    id: Option<usize>,
    name: CheckedPositionals<String>,
) -> Result<NaslValue, FnError> {
    // A parameter ID is given. Search for the param in the scan config, otherwise try the default value from the NVT metadata
    if let Some(id) = id {
        match register.script_param(id) {
            Some(v) => return Ok(v),
            None => {
                if let Some(nvt) = config.nvt() {
                    let prefs: Vec<NvtPreference> = nvt
                        .preferences
                        .into_iter()
                        .filter_map(|p| {
                            if p.id == Some(id as i32) {
                                Some(p)
                            } else {
                                None
                            }
                        })
                        .collect::<Vec<NvtPreference>>();
                    if !prefs.is_empty() {
                        return Ok(NaslValue::String(prefs[0].default().to_string()));
                    }
                }
            }
        }
    }

    // A parameter name is given. Search for the param in NVT metadata to get the ID.
    // Then, searches with the ID in the scan config, otherwise returns the default value from the NVT metadata.
    for pref_name in name.into_iter() {
        if let Some(nvt) = config.nvt() {
            let prefs: Vec<NvtPreference> = nvt
                .preferences
                .into_iter()
                .filter_map(|p| if p.name == *pref_name { Some(p) } else { None })
                .collect::<Vec<NvtPreference>>();

            if !prefs.is_empty() {
                return Ok(register
                    .script_param(prefs[0].id().unwrap() as usize)
                    .or_else(|| Some(NaslValue::String(prefs[0].default().to_string())))
                    .unwrap());
            }
        }
    }

    Ok(NaslValue::Null)
}

/// The description builtin function
pub struct Glue;

function_set! {
    Glue,
    (
        script_get_preference,
    )
}
