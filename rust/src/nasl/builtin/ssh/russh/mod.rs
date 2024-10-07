use russh::client::Session;
use tokio::sync::Mutex;

use crate::nasl::{
    prelude::*,
    utils::{IntoFunctionSet, StoredFunctionSet},
};

#[derive(Default)]
pub struct Ssh {
    sessions: Vec<Mutex<Session>>,
}

impl Ssh {
    #[nasl_function]
    async fn ssh_connect(&mut self) {
        todo!()
    }
}

impl IntoFunctionSet for Ssh {
    type State = Ssh;

    fn into_function_set(self) -> StoredFunctionSet<Self::State> {
        let mut set = StoredFunctionSet::new(self);

        set.async_stateful_mut("ssh_connect", Ssh::ssh_connect);
        set
    }
}
