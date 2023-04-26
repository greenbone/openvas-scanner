use std::sync::Arc;

use crate::{
    manager::ScanManager, manager::VTManager, routes::*, scan_manager::DefaultScanManager,
    vt_manager::DefaultVTManager,
};

use rocket::{
    async_trait,
    fairing::{Fairing, Info, Kind},
    http::Header,
    routes,
    tokio::sync::RwLock,
    Build, Request, Response, Rocket,
};

type ScanManagerType = Arc<RwLock<dyn ScanManager + Send + Sync>>;
type VTManagerType = Arc<RwLock<dyn VTManager + Send + Sync>>;

/// Manager to handle requests regarding Scans and VTs
pub struct Manager {
    /// handles scan related stuff
    pub scan_manager: ScanManagerType,
    /// Handles vt related stuff
    pub vt_manager: VTManagerType,
}

/// Contains version and authentication information. Is meant to be put into the header of
/// responses.
struct HeadInformation {
    pub api_version: String,
    pub feed_version: String,
    pub authentication: String,
}

#[async_trait]
impl Fairing for HeadInformation {
    fn info(&self) -> Info {
        Info {
            name: "HEAD version Info",
            kind: Kind::Response,
        }
    }

    async fn on_response<'r>(&self, _: &'r Request<'_>, response: &mut Response<'r>) {
        response.adjoin_header(Header::new("api-version", self.api_version.to_owned()));
        response.adjoin_header(Header::new("feed-version", self.feed_version.to_owned()));
        response.adjoin_header(Header::new(
            "authentication",
            self.authentication.to_owned(),
        ));
    }
}

/// This is a Webserver meant to be used as an API to a given ScanManager
pub struct Webserver {
    manager: Manager,
    head_info: HeadInformation,
}

impl Webserver {
    /// Create a new Webserver with a given ScanManager
    pub fn new(
        scan_manager: impl ScanManager + 'static + Send + Sync,
        vt_manager: impl VTManager + 'static + Send + Sync,
    ) -> Self {
        Webserver {
            manager: Manager {
                scan_manager: Arc::new(RwLock::new(scan_manager)),
                vt_manager: Arc::new(RwLock::new(vt_manager)),
            },
            // TODO: Get HeadInfo from Caller
            head_info: HeadInformation {
                api_version: "0.1".to_string(),
                feed_version: "0.1".to_string(),
                authentication: "api-key,x.509".to_string(),
            },
        }
    }

    /// Start the Webserver
    pub fn run(self) -> Rocket<Build> {
        rocket::build()
            .mount(
                "/",
                routes![
                    get_header,
                    create_scan,
                    scan_action,
                    get_scan,
                    get_results_wo_range,
                    get_results_w_range,
                    get_status,
                    delete_scan,
                    get_oids,
                ],
            )
            .manage(self.manager)
            .attach(self.head_info)
    }
}

impl Default for Webserver {
    /// Create a new Webserver with default manager
    fn default() -> Self {
        Self::new(DefaultScanManager::new(), DefaultVTManager::new())
    }
}
