// SPDX-FileCopyrightText: 2025 Greenbone AG
//
// SPDX-License-Identifier: GPL-2.0-or-later WITH x11vnc-openssl-exception
use crate::nasl::prelude::*;

#[nasl_function(named(id))]
fn script_get_preference(
    register: &Register,
    config: &Context,
    name: Option<String>,
    id: Option<usize>,
) -> Option<NaslValue> {
    // A parameter ID is given. Search for the param in the scan config, otherwise try the default value from the NVT metadata
    if let Some(id) = id {
        match register.script_param(id) {
            Some(v) => return Some(v),
            None => {
                if let Some(pref) = config.nvt().clone().and_then(|nvt| {
                    nvt.preferences
                        .into_iter()
                        .find(|p| p.id == Some(id as i32))
                }) {
                    return Some(pref.default().to_string().into());
                }
            }
        }
    }

    // A parameter name is given. Search for the param in NVT metadata to get the ID.
    // Then, search with the ID in the scan config, otherwise return the default value from the NVT metadata.
    if let Some(pref_name) = name {
        if let Some(pref) = config
            .nvt()
            .clone()
            .and_then(|nvt| nvt.preferences.into_iter().find(|p| p.name == pref_name))
        {
            return register
                .script_param(pref.id().unwrap() as usize)
                .or_else(|| Some(NaslValue::String(pref.default().to_string())));
        }
    }
    None
}

/// The description builtin function
pub struct Preferences;

function_set! {
    Preferences,
    (
        script_get_preference,
    )
}
