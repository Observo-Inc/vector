/**
This file is NOT part of the open-source components licensed under the Mozilla Public License, v. 2.0 (MPL-2.0).
Proprietary and Confidential – © 2025 Observo Inc.
Unauthorized copying, modification, distribution, or disclosure of this file, via any medium, is strictly prohibited.
This file is distributed separately and is not subject to the terms of the MPL-2.0.
**/
use std::net::SocketAddr;
use std::time::Duration;
use bytes::Bytes;
use chrono::Utc;
use vrl::compiler::conversion::Conversion;
use vrl::core::Value;
use vrl::{metadata_path, path};
use vrl::path::PathPrefix;
use crate::sources::Source;
use crate::tls::MaybeTlsSettings;
pub use stcp::{STcpSource, STcpAcker};
pub use stcp::stcp_decoder::{STcpDecoder, STcpDecoderError, STcpEventsFrame};
use vector_lib::config::{log_schema, DataType, LegacyKey, LogNamespace, SourceOutput};
use crate::config::{SourceConfig, SourceContext};
use crate::config::Resource;
use crate::event::Event;
use super::util::net::TcpSource;
use stcp::config::{STcpConfig, NAME};

#[async_trait::async_trait]
#[typetag::serde(name = "stcp")]
impl SourceConfig for STcpConfig {

    async fn build(&self, cx: SourceContext) -> vector_common::Result<Source> {
        let log_namespace = cx.log_namespace(self.log_namespace);
        let source = STcpSource {
            timestamp_converter: Conversion::Timestamp(cx.globals.timezone()),
            legacy_host_key_path: log_schema().host_key().map(|k| k.clone()),
            log_namespace,
        };
        let shutdown_secs = Duration::from_secs(30);
        let tls_config = self.tls.as_ref();
        let tls_client_metadata_key = self
            .tls
            .as_ref()
            .and_then(|tls| tls.client_metadata_key.clone())
            .and_then(|k| k.path);

        let tls = MaybeTlsSettings::from_config(
            tls_config.map(|c| &c.tls_config),
            true)?;
        source.run(
            self.address,
            self.keepalive,
            shutdown_secs,
            tls,
            tls_client_metadata_key,
            self.receive_buffer_bytes,
            None,
            cx,
            self.acknowledgements,
            self.connection_limit,
            None,
            self.typetag_name(),
            log_namespace,
        )
    }

    fn outputs(&self, global_log_namespace: LogNamespace) -> Vec<SourceOutput> {
        // There is a global and per-source `log_namespace` config.
        // The source config overrides the global setting and is merged here.
        vec![SourceOutput::new_maybe_logs(
            DataType::Log,
            self.schema_definition(global_log_namespace.merge(self.log_namespace)),
        )]
    }

    fn resources(&self) -> Vec<Resource> {
        vec![self.address.as_tcp_resource()]
    }

    fn can_acknowledge(&self) -> bool {
        true
    }
}


impl TcpSource for STcpSource {
    type Error = STcpDecoderError;
    type Item = STcpEventsFrame;
    type Decoder = STcpDecoder;
    type Acker = STcpAcker;

    fn decoder(&self) -> Self::Decoder {
        STcpDecoder::new()
    }

    fn handle_events(&self, events: &mut [Event], host: SocketAddr) {
        let now = Utc::now();
        for event in events {
            let log = event.as_mut_log();

            self.log_namespace.insert_vector_metadata(
                log,
                log_schema().source_type_key(),
                path!("source_type"),
                Bytes::from_static(NAME.as_bytes()),
            );

            let legacy_host_key = self
                .legacy_host_key_path
                .as_ref()
                .map(LegacyKey::InsertIfEmpty);

            self.log_namespace.insert_source_metadata(
                NAME,
                log,
                legacy_host_key,
                path!("host"),
                host.ip().to_string(),
            );

            let log_timestamp = log.get("metadata.event_timestamp").and_then(|timestamp| {
                self.timestamp_converter
                    .convert::<Value>(timestamp.coerce_to_bytes())
                    .ok()
            });

            match self.log_namespace {
                LogNamespace::Vector => {
                    if let Some(timestamp) = log_timestamp {
                        log.insert(metadata_path!(NAME, "timestamp"), timestamp);
                    }
                    log.insert(metadata_path!("vector", "ingest_timestamp"), now);
                }
                LogNamespace::Legacy => {
                    if let Some(timestamp_key) = log_schema().timestamp_key() {
                        log.insert(
                            (PathPrefix::Event, timestamp_key),
                            log_timestamp.unwrap_or_else(|| Value::from(now)),
                        );
                    }
                }
            }
        }
    }

    fn build_acker(&self, frames: &[Self::Item]) -> Self::Acker {
        STcpAcker::new(frames)
    }
}
