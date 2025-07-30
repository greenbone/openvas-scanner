// SPDX-FileCopyrightText: 2023 Greenbone AG
//
// SPDX-License-Identifier: GPL-2.0-or-later WITH x11vnc-openssl-exception
use std::fmt::{Display, Formatter};

/// Action to perform on a scan
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, PartialEq, Eq, PartialOrd, Ord)]
pub struct ScanAction {
    pub action: Action,
}

/// Enum representing possible actions
#[derive(
    Debug, Copy, Clone, serde::Serialize, serde::Deserialize, PartialEq, Eq, PartialOrd, Ord,
)]
#[serde(rename_all = "snake_case")]
pub enum Action {
    /// Start a scan
    Start,
    /// Stop a scan
    Stop,
}

impl Display for Action {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Action::Start => write!(f, "start"),
            Action::Stop => write!(f, "stop"),
        }
    }
}

impl From<Action> for ScanAction {
    fn from(value: Action) -> Self {
        Self { action: value }
    }
}

#[cfg(test)]
mod test {
    #[test]
    fn from_json() {
        let json = r#"{"action": "start"}"#;
        let result: super::ScanAction = serde_json::from_str(json).unwrap();
        assert_eq!(
            result,
            super::ScanAction {
                action: super::Action::Start
            }
        );
    }
}
