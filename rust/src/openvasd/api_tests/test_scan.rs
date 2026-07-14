use std::ops::{Range, RangeInclusive};

use http::StatusCode;
use reqwest::Method;
use scannerlib::models::{self, Scan};

use super::test_builder::{OpenvasdInstance, Response, WaitFor};

impl OpenvasdInstance {
    pub async fn create_scan(&self, scan: Scan) -> TestScan<'_> {
        self.create_scan_at("/scans", scan).await
    }

    #[allow(unused)]
    pub async fn create_container_image_scan(&self, scan: Scan) -> TestScan<'_> {
        self.create_scan_at("/container-image-scanner/scans", scan)
            .await
    }

    async fn create_scan_at(&self, scans_path: &'static str, scan: Scan) -> TestScan<'_> {
        let scan_id = self
            .request(Method::POST, scans_path)
            .json(scan.clone())
            .await
            .assert_status(StatusCode::CREATED)
            .body_str();

        let test_scan = TestScan::new(self, scans_path, scan_id);

        let stored_scan = test_scan
            .get()
            .await
            .assert_status(StatusCode::OK)
            .body::<Scan>();
        assert_eq!(*stored_scan.scan_id, scan.scan_id);

        test_scan
    }
}

pub struct TestScan<'a> {
    instance: &'a OpenvasdInstance,
    scans_path: &'static str,
    scan_id: String,
}

impl<'a> TestScan<'a> {
    pub fn new(instance: &'a OpenvasdInstance, scans_path: &'static str, scan_id: String) -> Self {
        Self {
            instance,
            scans_path,
            scan_id,
        }
    }

    fn scan_path(&self) -> String {
        format!("{}/{}", self.scans_path, self.scan_id)
    }

    fn status_path(&self) -> String {
        format!("{}/status", self.scan_path())
    }

    fn results_path(&self) -> String {
        format!("{}/results", self.scan_path())
    }

    pub async fn get(&self) -> Response {
        self.instance.request(Method::GET, self.scan_path()).await
    }

    pub async fn start(&self) -> Response {
        let response = self
            .instance
            .request(Method::POST, self.scan_path())
            .json(models::ScanAction::from(models::Action::Start))
            .await;
        response.assert_status(StatusCode::NO_CONTENT);
        response
    }

    pub async fn status(&self) -> Response {
        let response = self.instance.request(Method::GET, self.status_path()).await;
        response.assert_status(StatusCode::OK);
        response
    }

    pub async fn wait_for(&self, wait_for: impl Into<WaitFor>) -> Response {
        let response = self
            .instance
            .request(Method::GET, self.status_path())
            .wait_for(wait_for)
            .await;
        response.assert_status(StatusCode::OK);
        response
    }

    pub async fn get_results(&self) -> Response {
        let response = self
            .instance
            .request(Method::GET, self.results_path())
            .await;
        response.assert_status(StatusCode::OK);
        response
    }

    pub async fn get_result(&self, result: impl TestScanResultPath) -> Response {
        self.instance
            .request(Method::GET, result.path(&self.results_path()))
            .await
    }

    pub async fn delete(&self) -> Response {
        let response = self
            .instance
            .request(Method::DELETE, self.scan_path())
            .await;
        response.assert_status(StatusCode::NO_CONTENT);
        response
    }
}

pub trait TestScanResultPath {
    fn path(self, results_path: &str) -> String;
}

impl TestScanResultPath for usize {
    fn path(self, results_path: &str) -> String {
        format!("{results_path}/{self}")
    }
}

impl TestScanResultPath for Range<usize> {
    fn path(self, results_path: &str) -> String {
        format!("{results_path}?range={}-{}", self.start, self.end)
    }
}

impl TestScanResultPath for RangeInclusive<usize> {
    fn path(self, results_path: &str) -> String {
        let (start, end) = self.into_inner();
        format!("{results_path}?range={start}-{end}")
    }
}
