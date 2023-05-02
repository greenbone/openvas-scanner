use rocket::launch;
use scanner_api::webserver::Webserver;

#[launch]
fn rocket() -> _ {
    let ws = Webserver::default();
    ws.run()
}
