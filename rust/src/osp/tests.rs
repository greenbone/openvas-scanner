// SPDX-FileCopyrightText: 2023 Greenbone AG
//
// SPDX-License-Identifier: GPL-2.0-or-later WITH x11vnc-openssl-exception

#[cfg(test)]
mod tests {
    use std::fs::read_to_string;

    use crate::osp::{Response, Scan, ScanStatus};

    fn load_response(filename: &str) -> Scan {
        let path = format!("data/osp/{filename}");
        let xml = read_to_string(path).unwrap();
        let response: Response = quick_xml::de::from_str(&xml).unwrap();
        response.try_into().unwrap()
    }

    #[test]
    fn finished() {
        let scan = load_response("response_finished.xml");
        assert_eq!(scan.status, ScanStatus::Finished);
        let results: Vec<models::Result> = scan.results.into();
        assert_eq!(results.len(), 113);
    }

    #[test]
    fn running() {
        let scan = load_response("response_running.xml");
        assert_eq!(scan.status, ScanStatus::Running);
    }
    #[test]
    fn queued() {
        let scan = load_response("response_queued.xml");
        assert_eq!(scan.status, ScanStatus::Queued);
    }
}
