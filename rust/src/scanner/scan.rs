use tracing::error;

use crate::{
    models::{self, AliveTestMethods, Port, ScanID, VT},
    nasl::utils::scan_ctx::{Ports, Target},
};

use super::preferences::preference::ScanPrefs;

#[derive(Debug, Default)]
pub struct Scan {
    pub targets: Vec<Target>,
    pub ports: Ports,
    pub scan_id: ScanID,
    pub vts: Vec<VT>,
    pub scan_preferences: ScanPrefs,
    pub alive_test_methods: Vec<AliveTestMethods>,
    pub alive_test_ports: Vec<Port>,
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
            ports: scan.target.ports.into(),
            scan_id: scan.scan_id,
            vts: scan.vts,
            scan_preferences: scan.scan_preferences,
            alive_test_methods: scan.target.alive_test_methods,
            alive_test_ports: scan.target.alive_test_ports,
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
            ports: scan.target.ports.into(),
            scan_id: scan.scan_id,
            vts: scan.vts,
            scan_preferences: scan.scan_preferences,
            alive_test_methods: scan.target.alive_test_methods,
            alive_test_ports: scan.target.alive_test_ports,
        }
    }
}
