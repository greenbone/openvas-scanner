use tracing::error;

use crate::{
    models::{self, ScanID, VT},
    nasl::utils::context::Target,
};

#[derive(Debug, Default)]
pub struct Scan {
    pub targets: Vec<Target>,
    pub scan_id: ScanID,
    pub vts: Vec<VT>,
}

fn try_resolve(host: &str) -> Option<Target> {
    let resolved = Target::resolve_hostname(host);
    if resolved.is_none() {
        error!("Unresolvable hostname: {host}");
    }
    resolved
}

impl Scan {
    /// Turns the given `models::Scan` into a `scanner::Scan` by
    /// attempting to resolve each given target (either by parsing as
    /// an IP address or by resolving the hostname. If hostname
    /// resolution fails for a target, this emits an error and
    /// proceeds with the remaining targets.
    pub fn from_resolvable_hosts(scan: models::Scan) -> Self {
        let targets = scan
            .target
            .hosts
            .iter()
            .flat_map(|x| try_resolve(x))
            .collect();
        Self {
            targets,
            scan_id: scan.scan_id,
            vts: scan.vts,
        }
    }

    /// Turns the given `models::Scan` into a `scanner::Scan` by
    /// attempting to resolve each given target (either by parsing as
    /// an IP address or by resolving the hostname. If hostname
    /// resolution fails for a target, emits an error and
    /// defaults to localhost instead.
    pub fn default_to_localhost(scan: models::Scan) -> Self {
        let targets = scan
            .target
            .hosts
            .iter()
            .map(|x| try_resolve(x).unwrap_or(Target::localhost()))
            .collect();
        Self {
            targets,
            scan_id: scan.scan_id,
            vts: scan.vts,
        }
    }
}
