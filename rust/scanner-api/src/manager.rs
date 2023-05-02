use models::{Action, Result as ScanResult, Scan, Status};

use crate::error::APIError;

pub type ScanID = String;
pub type OID = String;

/// ScanManager trait. Used for the API to interact with the Scan Management.
pub trait ScanManager {
    /// Create a new Scan with a unique Scan ID
    fn create_scan(&mut self, scan: Scan) -> Result<ScanID, APIError>;
    /// Perform an action on a scan
    fn scan_action(&mut self, scan_id: ScanID, action: Action) -> Result<(), APIError>;
    /// Get meta information about a scan
    fn get_scan(&self, id: ScanID) -> Result<Scan, APIError>;
    /// Get result information about a scan
    fn get_results(
        &self,
        id: ScanID,
        first: Option<usize>,
        last: Option<usize>,
    ) -> Result<Vec<ScanResult>, APIError>;
    /// Get status information about a scan
    fn get_status(&self, id: ScanID) -> Result<Status, APIError>;
    /// Delete a scan
    fn delete_scan(&mut self, id: ScanID) -> Result<(), APIError>;
}

/// Interface for the webserver to handle VT requests.
pub trait VTManager {
    /// Get a list of available OIDs. All OIDs are unique.
    fn get_oids(&self) -> &Vec<String>;

    /// Add an OID to the list of available OIDs. As all OIDs must be unique, known ones will get
    /// ignored.
    fn add_oid(&mut self, oid: String);

    /// Remove an OID of the list of available OIDs. If the OID is unknown nothing happens.
    fn remove_oid(&mut self, oid: String);
}
