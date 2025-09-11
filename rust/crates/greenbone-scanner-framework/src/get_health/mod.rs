mod alive;
mod ready;
mod started;

pub use alive::{Alive, GetHealthAlive};
pub use ready::{GetHealthReady, Ready};
pub use started::{GetHealthStarted, Started};

use std::pin::Pin;

use crate::{Endpoint, Handler};

/// A http request handler that always returns the same response, no
/// matter the input.
/// This type implements `Handler` for every endpoint with
/// `Endpoint::Out = T`
pub struct Always<T>(pub T);

impl<E: Endpoint<Out = T>, T: Clone + Send + Sync + 'static> Handler<E> for Always<T> {
    fn call(&self, _: E::In) -> Pin<Box<dyn Future<Output = E::Out> + Send>> {
        let cloned = self.0.clone();
        Box::pin(async move { cloned })
    }
}
