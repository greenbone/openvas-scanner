use greenbone_scanner_framework::prelude::*;
use http_body_util::BodyExt;
pub struct Endpoints {}
impl PostScans for Endpoints {
    fn post_scans(
        &self,
        client_id: String,
        scan: models::Scan,
    ) -> std::pin::Pin<Box<dyn Future<Output = Result<String, PostScansError>> + Send + '_>> {
        todo!()
    }
}

impl ContainsScanID for Endpoints {
    fn contains_scan_id<'a>(
        &'a self,
        client_id: &'a str,
        scan_id: &'a str,
    ) -> std::pin::Pin<Box<dyn Future<Output = bool> + Send + 'a>> {
        todo!()
    }
}

impl GetScans for Endpoints {
    fn get_scans(
        &self,
        client_id: String,
    ) -> greenbone_scanner_framework::StreamResult<'static, String, GetScansError> {
        todo!()
    }
}

impl GetScansID for Endpoints {
    fn get_scans_id(
        &self,
        client_id: String,
        scan_id: String,
    ) -> std::pin::Pin<Box<dyn Future<Output = Result<models::Scan, GetScansIDError>> + Send>> {
        todo!()
    }
}
impl GetScansIDResults for Endpoints {
    fn get_scans_id_results(
        &self,
        client_id: String,
        scan_id: String,
        from: Option<usize>,
        to: Option<usize>,
    ) -> greenbone_scanner_framework::StreamResult<'static, models::Result, GetScansIDResultsError>
    {
        todo!()
    }
}
impl GetScansIDResultsID for Endpoints {
    fn get_scans_id_results_id(
        &self,
        client_id: String,
        scan_id: String,
        result_id: usize,
    ) -> std::pin::Pin<
        Box<dyn Future<Output = Result<models::Result, GetScansIDResultsIDError>> + Send + '_>,
    > {
        todo!()
    }
}
impl GetScansIDStatus for Endpoints {
    fn get_scans_id_status(
        &self,
        client_id: String,
        scan_id: String,
    ) -> std::pin::Pin<
        Box<dyn Future<Output = Result<models::Status, GetScansIDStatusError>> + Send + '_>,
    > {
        todo!()
    }
}
impl PostScansID for Endpoints {
    fn post_scans_id(
        &self,
        client_id: String,
        scan_id: String,
        action: models::Action,
    ) -> std::pin::Pin<Box<dyn Future<Output = Result<(), PostScansIDError>> + Send + '_>> {
        todo!()
    }
}
impl DeleteScansID for Endpoints {
    fn delete_scans_id(
        &self,
        client_id: String,
        id: String,
    ) -> std::pin::Pin<Box<dyn Future<Output = Result<(), DeleteScansIDError>> + Send + '_>> {
        todo!()
    }
}
