// SPDX-FileCopyrightText: 2023 Greenbone AG
//
// SPDX-License-Identifier: GPL-2.0-or-later WITH x11vnc-openssl-exception

#[cfg(test)]
mod tests {

    fn load_response(filename: &str) -> osp::Scan {
        let path = format!("../osp/tests/{filename}");
        let xml = std::fs::read_to_string(path).unwrap();
        let response: osp::Response = quick_xml::de::from_str(&xml).unwrap();
        response.try_into().unwrap()
    }

    #[test]
    fn finished() {
        let scan = load_response("response_finished.xml");
        assert_eq!(scan.status, osp::ScanStatus::Finished);
        let results: Vec<models::Result> = scan.results.into();
        assert_eq!(results.len(), 113);
    }

    #[test]
    fn running() {
        let scan = load_response("response_running.xml");
        assert_eq!(scan.status, osp::ScanStatus::Running);
    }
    #[test]
    fn queued() {
        let scan = load_response("response_queued.xml");
        assert_eq!(scan.status, osp::ScanStatus::Queued);
    }
}
