use std::future::Future;
use bytes::Bytes;
use crate::event::Event;

pub trait HttpEventEncoder<Output> {
    // The encoder handles internal event emission for Error and EventsDropped.
    fn encode_event(&mut self, event: Event) -> Option<Output>;
}

pub trait HttpSink: Send + Sync + 'static {
    type Input;
    type Output;
    type Encoder: HttpEventEncoder<Self::Input>;

    fn build_encoder(&self) -> Self::Encoder;
    fn build_request(
        &self,
        events: Self::Output,
    ) -> impl Future<Output = crate::Result<http::Request<Bytes>>> + Send;
}