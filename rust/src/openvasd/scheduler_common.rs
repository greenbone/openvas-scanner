use crate::database::{dao::DAOError, sqlite::state_change::ScanStateController};

pub(crate) async fn fetch_requested_scans(
    scan_state: &ScanStateController,
    max_concurrent_scan: usize,
) -> Result<Vec<i64>, DAOError> {
    let limit: Option<i64> = if max_concurrent_scan > 0 {
        let running = scan_state.count_scans_in_state("running").await?;
        Some(if running >= max_concurrent_scan {
            0
        } else {
            (max_concurrent_scan - running) as i64
        })
    } else {
        None
    };

    scan_state.fetch_scans_in_state("requested", limit).await
}
