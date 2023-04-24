use rocket::launch;
use scanner_api::{
    scan_manager::DefaultScanManager, vt_manager::DefaultVTManager, webserver::Webserver,
};

#[launch]
fn rocket() -> _ {
    let ws = Webserver::new(DefaultScanManager::new(), DefaultVTManager::new());
    ws.run()
}
