use rocket::{
    async_trait,
    fairing::{Fairing, Info, Kind},
    http::Header,
    Request, Response,
};

/// Contains version and authentication information. Is meant to be put into the header of
/// responses.
pub struct HeadInformation {
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
