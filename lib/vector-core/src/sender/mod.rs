pub mod errors;
use crate::event::Event;
pub use errors::{ClosedError, StreamSendError};
use futures::Future;
use smallvec::SmallVec;

pub trait EventTx {
    fn send(&mut self, evts: SmallVec<[Event; 1]>) -> impl Future<Output = std::result::Result<(), ClosedError>> + Send + '_;
}
