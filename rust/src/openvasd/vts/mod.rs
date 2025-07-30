use greenbone_scanner_framework::{GetVts, prelude::*};
pub struct Endpoints {}

impl GetVts for Endpoints {
    fn get_oids(
        &self,
        client_id: std::sync::Arc<greenbone_scanner_framework::entry::ClientIdentifier>,
    ) -> std::pin::Pin<
        Box<
            dyn Future<Output = Result<Vec<String>, greenbone_scanner_framework::GetVTsError>>
                + Send,
        >,
    > {
        todo!()
    }
}
