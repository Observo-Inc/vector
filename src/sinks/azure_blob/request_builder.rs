use std::sync::Arc;
use bytes::Bytes;
use chrono::Utc;
use uuid::Uuid;
use vector_lib::request_metadata::RequestMetadata;
use vector_lib::EstimatedJsonEncodedSizeOf;

use crate::{
    event::{Event, Finalizable},
    sinks::{
        azure_common::config::{AzureBlobMetadata, AzureBlobRequest},
        util::{
            encoding::Encoder,
            metadata::RequestMetadataBuilder, request_builder::EncodeResult, Compression,
            RequestBuilder,
        },
    },
};

#[derive(Clone)]
pub struct AzureBlobRequestOptions {
    pub container_name: String,
    pub blob_time_format: String,
    pub blob_append_uuid: bool,
    pub encoder: Arc<dyn Encoder<Vec<Event>> + Send + Sync>,
    pub compression: Compression,
    pub blob_extension: Option<String>,
    pub content_type: &'static str,
}

impl RequestBuilder<(String, Vec<Event>)> for AzureBlobRequestOptions {
    type Metadata = AzureBlobMetadata;
    type Events = Vec<Event>;
    type Encoder = Arc<dyn Encoder<Vec<Event>> + Send + Sync>;
    type Payload = Bytes;
    type Request = AzureBlobRequest;
    type Error = std::io::Error;

    fn compression(&self) -> Compression {
        self.compression
    }

    fn encoder(&self) -> &Self::Encoder {
        &self.encoder
    }

    fn split_input(
        &self,
        input: (String, Vec<Event>),
    ) -> (Self::Metadata, RequestMetadataBuilder, Self::Events) {
        let (partition_key, mut events) = input;
        let finalizers = events.take_finalizers();
        let azure_metadata = AzureBlobMetadata {
            partition_key,
            count: events.len(),
            byte_size: events.estimated_json_encoded_size_of(),
            finalizers,
        };

        let builder = RequestMetadataBuilder::from_events(&events);

        (azure_metadata, builder, events)
    }

    fn build_request(
        &self,
        mut azure_metadata: Self::Metadata,
        request_metadata: RequestMetadata,
        payload: EncodeResult<Self::Payload>,
    ) -> Self::Request {
        let blob_name = {
            let formatted_ts = Utc::now().format(self.blob_time_format.as_str());

            self.blob_append_uuid
                .then(|| format!("{}-{}", formatted_ts, Uuid::new_v4().hyphenated()))
                .unwrap_or_else(|| formatted_ts.to_string())
        };

        let extension = if self.blob_extension.is_some()
            && self.blob_extension.clone().unwrap() == "parquet"  {
            self.blob_extension.clone().unwrap()
        } else {
            self.compression.extension().to_string()
        };
        azure_metadata.partition_key = format!(
            "{}{}.{}",
            azure_metadata.partition_key, blob_name, extension
        );

        let blob_data = payload.into_payload();

        debug!(
            message = "Sending events.",
            bytes = ?blob_data.len(),
            events_len = ?azure_metadata.count,
            blob = ?azure_metadata.partition_key,
            container = ?self.container_name,
        );

        AzureBlobRequest {
            blob_data,
            content_encoding: self.compression.content_encoding(),
            content_type: self.content_type,
            metadata: azure_metadata,
            request_metadata,
        }
    }
}

