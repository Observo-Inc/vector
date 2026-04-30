//! The `vector` source. See [VectorConfig].
use std::net::SocketAddr;

use chrono::Utc;
use futures::TryFutureExt;
use tonic::{Request, Response, Status};
use vector_lib::codecs::NativeDeserializerConfig;
use vector_lib::configurable::configurable_component;
use vector_lib::internal_event::{CountByteSize, InternalEventHandle as _};
use vector_lib::{
    config::LogNamespace,
    event::{BatchNotifier, BatchStatus, BatchStatusReceiver, Event},
    EstimatedJsonEncodedSizeOf,
};

use crate::{
    config::{
        DataType, GenerateConfig, Resource, SourceAcknowledgementsConfig, SourceConfig,
        SourceContext, SourceOutput,
    },
    internal_events::{EventsReceived, StreamClosedError},
    proto::vector as proto,
    serde::bool_or_struct,
    sources::{
        util::{grpc::run_grpc_server, JwtAuth, JwtAuthConfig, JwtAuthError},
        Source,
    },
    tls::{MaybeTlsSettings, TlsEnableableConfig},
    SourceSender,
};

/// Marker type for version two of the configuration for the `vector` source.
#[configurable_component]
#[derive(Clone, Debug)]
enum VectorConfigVersion {
    /// Marker value for version two.
    #[serde(rename = "2")]
    V2,
}

#[derive(Debug, Clone)]
struct Service {
    pipeline: SourceSender,
    acknowledgements: bool,
    log_namespace: LogNamespace,
    /// Present when JWT authentication is enabled.
    auth: Option<JwtAuth>,
}

#[tonic::async_trait]
impl proto::Service for Service {
    async fn push_events(
        &self,
        request: Request<proto::PushEventsRequest>,
    ) -> Result<Response<proto::PushEventsResponse>, Status> {
        if let Some(auth) = &self.auth {
            let metadata = request.metadata();
            let authorization = metadata.get("authorization").and_then(|v| v.to_str().ok());
            let site_id = metadata.get("x-site-id").and_then(|v| v.to_str().ok());
            auth.validate(authorization, site_id).map_err(|e| match e {
                JwtAuthError::InvalidToken(msg) => Status::unauthenticated(msg),
                JwtAuthError::MissingMembershipValue => {
                    Status::unauthenticated("missing x-site-id metadata header")
                }
                JwtAuthError::MembershipNotAuthorized => {
                    Status::permission_denied("site ID not authorized by this token")
                }
            })?;
        }

        let mut events: Vec<Event> = request
            .into_inner()
            .events
            .into_iter()
            .map(Event::from)
            .collect();

        let now = Utc::now();
        for event in &mut events {
            if let Event::Log(ref mut log) = event {
                self.log_namespace.insert_standard_vector_source_metadata(
                    log,
                    VectorConfig::NAME,
                    now,
                );
            }
        }

        let count = events.len();
        let byte_size = events.estimated_json_encoded_size_of();
        let events_received = register!(EventsReceived);
        events_received.emit(CountByteSize(count, byte_size));

        let receiver = BatchNotifier::maybe_apply_to(self.acknowledgements, &mut events);

        self.pipeline
            .clone()
            .send_batch(events)
            .map_err(|error| {
                let message = error.to_string();
                emit!(StreamClosedError { count });
                Status::unavailable(message)
            })
            .and_then(|_| handle_batch_status(receiver))
            .await?;

        Ok(Response::new(proto::PushEventsResponse {}))
    }

    // TODO: figure out a way to determine if the current Vector instance is "healthy".
    async fn health_check(
        &self,
        _: Request<proto::HealthCheckRequest>,
    ) -> Result<Response<proto::HealthCheckResponse>, Status> {
        let message = proto::HealthCheckResponse {
            status: proto::ServingStatus::Serving.into(),
        };

        Ok(Response::new(message))
    }
}

async fn handle_batch_status(receiver: Option<BatchStatusReceiver>) -> Result<(), Status> {
    let status = match receiver {
        Some(receiver) => receiver.await,
        None => BatchStatus::Delivered,
    };

    match status {
        BatchStatus::Errored => Err(Status::internal("Delivery error")),
        BatchStatus::Rejected => Err(Status::data_loss("Delivery failed")),
        BatchStatus::Delivered => Ok(()),
    }
}

/// Configuration for the `vector` source.
#[configurable_component(source("vector", "Collect observability data from a Vector instance."))]
#[derive(Clone, Debug)]
#[serde(deny_unknown_fields)]
pub struct VectorConfig {
    /// Version of the configuration.
    version: Option<VectorConfigVersion>,

    /// The socket address to listen for connections on.
    ///
    /// It _must_ include a port.
    pub address: SocketAddr,

    #[configurable(derived)]
    #[serde(default)]
    tls: Option<TlsEnableableConfig>,

    #[configurable(derived)]
    #[serde(default, deserialize_with = "bool_or_struct")]
    acknowledgements: SourceAcknowledgementsConfig,

    /// The namespace to use for logs. This overrides the global setting.
    #[serde(default)]
    #[configurable(metadata(docs::hidden))]
    pub log_namespace: Option<bool>,

    /// JWT authentication settings.
    ///
    /// When omitted, all incoming requests are accepted without authentication.
    /// See [`JwtAuthConfig`] for full documentation.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub auth: Option<JwtAuthConfig>,
}

impl VectorConfig {
    /// Creates a `VectorConfig` with the given address.
    pub fn from_address(addr: SocketAddr) -> Self {
        Self {
            address: addr,
            ..Default::default()
        }
    }
}

impl Default for VectorConfig {
    fn default() -> Self {
        Self {
            version: None,
            address: "0.0.0.0:6000".parse().unwrap(),
            tls: None,
            acknowledgements: Default::default(),
            log_namespace: None,
            auth: None,
        }
    }
}

impl GenerateConfig for VectorConfig {
    fn generate_config() -> toml::Value {
        toml::Value::try_from(VectorConfig::default()).unwrap()
    }
}

#[async_trait::async_trait]
#[typetag::serde(name = "vector")]
impl SourceConfig for VectorConfig {
    async fn build(&self, cx: SourceContext) -> crate::Result<Source> {
        let tls_settings = MaybeTlsSettings::from_config(self.tls.as_ref(), true)?;
        let acknowledgements = cx.do_acknowledgements(self.acknowledgements);
        let log_namespace = cx.log_namespace(self.log_namespace);

        let auth = self.auth.as_ref().map(|cfg| cfg.build()).transpose()?;

        let service = proto::Server::new(Service {
            pipeline: cx.out,
            acknowledgements,
            log_namespace,
            auth,
        })
        .accept_compressed(tonic::codec::CompressionEncoding::Gzip)
        // Tonic added a default of 4MB in 0.9. This replaces the old behavior.
        .max_decoding_message_size(usize::MAX);

        let source =
            run_grpc_server(self.address, tls_settings, service, cx.shutdown).map_err(|error| {
                error!(message = "Source future failed.", %error);
            });

        Ok(Box::pin(source))
    }

    fn outputs(&self, global_log_namespace: LogNamespace) -> Vec<SourceOutput> {
        let log_namespace = global_log_namespace.merge(self.log_namespace);

        let schema_definition = NativeDeserializerConfig
            .schema_definition(log_namespace)
            .with_standard_vector_source_metadata();

        vec![SourceOutput::new_maybe_logs(
            DataType::all_bits(),
            schema_definition,
        )]
    }

    fn resources(&self) -> Vec<Resource> {
        vec![Resource::tcp(self.address)]
    }

    fn can_acknowledge(&self) -> bool {
        true
    }
}

#[cfg(test)]
mod test {
    use vector_lib::lookup::owned_value_path;
    use vector_lib::{config::LogNamespace, schema::Definition};
    use vrl::value::{kind::Collection, Kind};

    use crate::config::SourceConfig;

    use super::VectorConfig;

    #[test]
    fn generate_config() {
        crate::test_util::test_generate_config::<super::VectorConfig>();
    }

    #[test]
    fn output_schema_definition_vector_namespace() {
        let config = VectorConfig::default();

        let definitions = config
            .outputs(LogNamespace::Vector)
            .remove(0)
            .schema_definition(true);

        let expected_definition =
            Definition::new_with_default_metadata(Kind::any(), [LogNamespace::Vector])
                .with_metadata_field(
                    &owned_value_path!("vector", "source_type"),
                    Kind::bytes(),
                    None,
                )
                .with_metadata_field(
                    &owned_value_path!("vector", "ingest_timestamp"),
                    Kind::timestamp(),
                    None,
                );

        assert_eq!(definitions, Some(expected_definition))
    }

    #[test]
    fn output_schema_definition_legacy_namespace() {
        let config = VectorConfig::default();

        let definitions = config
            .outputs(LogNamespace::Legacy)
            .remove(0)
            .schema_definition(true);

        let expected_definition = Definition::new_with_default_metadata(
            Kind::object(Collection::empty()),
            [LogNamespace::Legacy],
        )
        .with_event_field(&owned_value_path!("source_type"), Kind::bytes(), None)
        .with_event_field(&owned_value_path!("timestamp"), Kind::timestamp(), None);

        assert_eq!(definitions, Some(expected_definition))
    }
}

#[cfg(feature = "sinks-vector")]
#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        config::{SinkConfig as _, SinkContext},
        sinks::vector::VectorConfig as SinkConfig,
        test_util, SourceSender,
    };
    use vector_lib::assert_event_data_eq;
    use vector_lib::config::log_schema;

    async fn run_test(vector_source_config_str: &str, addr: SocketAddr) {
        let config = format!(r#"address = "{}""#, addr);
        let source: VectorConfig = toml::from_str(&config).unwrap();

        let (tx, rx) = SourceSender::new_test();
        let server = source
            .build(SourceContext::new_test(tx, None))
            .await
            .unwrap();
        tokio::spawn(server);
        test_util::wait_for_tcp(addr).await;

        // Ideally, this would be a fully custom agent to send the data,
        // but the sink side already does such a test and this is good
        // to ensure interoperability.
        let sink: SinkConfig = toml::from_str(vector_source_config_str).unwrap();
        let cx = SinkContext::default();
        let (sink, _) = sink.build(cx).await.unwrap();

        let (mut events, stream) = test_util::random_events_with_stream(100, 100, None);
        sink.run(stream).await.unwrap();

        for event in &mut events {
            event.as_mut_log().insert(
                log_schema().source_type_key_target_path().unwrap(),
                "vector",
            );
        }

        let output = test_util::collect_ready(rx).await;
        assert_event_data_eq!(events, output);
    }

    #[tokio::test]
    async fn receive_message() {
        let addr = test_util::next_addr();

        let config = format!(r#"address = "{}""#, addr);
        run_test(&config, addr).await;
    }

    #[tokio::test]
    async fn receive_compressed_message() {
        let addr = test_util::next_addr();

        let config = format!(
            r#"address = "{}"
            compression=true"#,
            addr
        );
        run_test(&config, addr).await;
    }

    // ── JWT auth integration tests ───────────────────────────────────────────
    //
    // These tests require `sources-utils-jwt-auth` (for jsonwebtoken) in addition
    // to the `sinks-vector` feature already guarding this module.

    #[cfg(feature = "sources-utils-jwt-auth")]
    mod jwt_auth_tests {
        use std::collections::HashMap;
        use std::time::{SystemTime, UNIX_EPOCH};

        use jsonwebtoken::{encode, Algorithm, EncodingKey, Header};
        use vector_lib::event::{BatchNotifier, BatchStatus};

        use super::*;

        const TEST_PRIVATE_KEY: &str = "-----BEGIN PRIVATE KEY-----
MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQDJ5D7lpMrGJpl7
zCcZ73XqbzBaagaPa9QDoGmypTbOoiysnnmcTHfy+wcP2aBlDTC8aB+7iPdZr0tA
ENdzIQ0/kZFBWCdwqAtQYDyfGuZx9y+3E9I8RFleDqDSwA6aUrSoesC9OBHztebX
0m4T9dAWzn8Vr3CYKVpp4XcYwfX6iWszCm43zv4fCJu/qYX67IvOP8h66OMBZ8s7
A4K15z1n8ScI3R6v6amc94iB7z2B9hdvuoTKk89dF5XGxE1ZVnIzSPr/8/oQQJgG
RaYqQAViy4kPmctW4uaI9ajQPIQe58LpNh1lDw+aLRHO/e0SCqbUNARTLSdSIwNV
3dltWgS9AgMBAAECggEAHPo4NuDYw+kdZYHvaM8QdyYfZBLMv0AkTaL0GNKS08S+
McaLQO5O1x7FrDY5yddDU/+D8nhdvE8nN1pTejBXxPSBS0Y6XvaXrSErAlErm1b1
z8q2BbVvuErUNXugfPD7AiWgTWhjVz4YFIkdCJtjEyrvXa7xM73XvtPAMtsAEcXv
MgeRaZVdIledQUozu72RfPuG0yYWG5j+1W1IjNDcuLvld+RrZZ6JqyedhHMwlsFU
bi1DDGaBvp7jkDr6hDp81dqUVposvq+yw3THoyDnQCNxrSCfDpRkYk7DWJKVD8XS
6GvFHuHfaktzm+KkUHBQAebGn6qM+3QBIOWXZkHBdwKBgQDwhVtLUNnz7LLOlAxH
/IF5WM96DoPilOG548yMt/81Zez9QzgJXhxefhCpl2ZQDUCWr9CFvn+98XFai8jt
voVQMV23AGi6nJJ+jGw9koQUt/uYAxZ4U8tG0KqxVGhmrab1MfTpLp2mQWkJN7y1
Hk5moPHwpQhxW73qlzwR8Ug8FwKBgQDW4nX8ZvFfmyJcrckquh0KMpILe5i+klmd
ENU7TmlQ8Sq1QX2j+w4gOWpUR6/bnij1XeEsI21z10Sv3yEgu2E8V7Cqf9mJX0in
+H5+WpEbTHqgfWhA8wXoZIizRfHDKOsOnhNmTFMBBrcp0zd4V1N1xH+APkw1q3jF
YxnmMAMmSwKBgBH5xYLxffiO/iYWRnyy0HJjQs5ae1zZx6z+63Cw56/z+CxNc8iv
cetV/KTQHeNpuiQI68qzHBT0EIa138R08r21ks10iF86CHDQyd4oLxrlTTZlNK61
hIG8YqVyK4NRAyNcInOy+jFMvi7kLYRTyYQ+DxbvHpxqQN1hhCnLIJztAoGAakX9
zCKtZXc3+1YHk5YQHqb8C6nI1RdUMpXMn1QcSee8E4CcPqk/RzieGaiKlLcX0qHn
ZwjubMgeNEzJ+YIyiMFloi0wzPvO1yPSi3MHKNUeIJllIhoO5ewyn1cMRlTKS6Rq
O8Grm2pS0+CeImot4KSZ2jb1QeXYCOcGPA2qwRkCgYEAnCI12DQuInN8nLEo4qtq
XEgyvUZ0fGaezcmeT4hhY94l0/HXS0D0qXs/f/rvfFFnvRYlEyiycA4pClkNRNkM
TM9RBaFTEKw9NQP895KUx6hHIAM/LB1Qyf7cDixtwf8ly7Gqhx4vU9tCiiDGSr9Z
T+QEb2Rxj5SJ8cGbNr+NAEI=
-----END PRIVATE KEY-----";

        const TEST_PUBLIC_KEY: &str = "-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAyeQ+5aTKxiaZe8wnGe91
6m8wWmoGj2vUA6BpsqU2zqIsrJ55nEx38vsHD9mgZQ0wvGgfu4j3Wa9LQBDXcyEN
P5GRQVgncKgLUGA8nxrmcfcvtxPSPERZXg6g0sAOmlK0qHrAvTgR87Xm19JuE/XQ
Fs5/Fa9wmClaaeF3GMH1+olrMwpuN87+Hwibv6mF+uyLzj/IeujjAWfLOwOCtec9
Z/EnCN0er+mpnPeIge89gfYXb7qEypPPXReVxsRNWVZyM0j6//P6EECYBkWmKkAF
YsuJD5nLVuLmiPWo0DyEHufC6TYdZQ8Pmi0Rzv3tEgqm1DQEUy0nUiMDVd3ZbVoE
vQIDAQAB
-----END PUBLIC KEY-----";

        fn now_secs() -> u64 {
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs()
        }

        fn make_token(extra: HashMap<&str, serde_json::Value>) -> String {
            let mut claims = serde_json::Map::new();
            claims.insert("sub".into(), serde_json::json!("test-agent"));
            claims.insert("exp".into(), serde_json::json!(now_secs() + 3600));
            claims.insert("site_ids".into(), serde_json::json!(["site-123"]));
            for (k, v) in extra {
                claims.insert(k.into(), v);
            }
            let key = EncodingKey::from_rsa_pem(TEST_PRIVATE_KEY.as_bytes()).unwrap();
            encode(&Header::new(Algorithm::RS256), &claims, &key).unwrap()
        }

        /// Builds a source and sink, runs `events` through them, and returns the
        /// final `BatchStatus` seen by the sender.
        async fn run_auth_pair(
            source_auth_toml: &str,
            sink_auth_toml: &str,
        ) -> BatchStatus {
            let addr = test_util::next_addr();

            let source: VectorConfig = toml::from_str(&format!(
                "address = \"{addr}\"\n{source_auth_toml}"
            ))
            .unwrap();

            let (tx, _rx) = SourceSender::new_test();
            let server = source
                .build(SourceContext::new_test(tx, None))
                .await
                .unwrap();
            tokio::spawn(server);
            test_util::wait_for_tcp(addr).await;

            let sink_toml = format!("address = \"http://{addr}/\"\n{sink_auth_toml}");
            let sink_cfg: SinkConfig = toml::from_str(&sink_toml).unwrap();
            let (sink, _) = sink_cfg.build(SinkContext::default()).await.unwrap();

            let (batch, receiver) = BatchNotifier::new_with_receiver();
            let (_, stream) = test_util::random_lines_with_stream(8, 5, Some(batch));
            sink.run(stream).await.unwrap();

            receiver.await
        }

        #[tokio::test]
        async fn valid_token_and_site_id_delivers() {
            let token = make_token(HashMap::new());
            let source_auth = format!(
                r#"[auth]
public_key.type  = "inline"
public_key.value = "{}"
membership_claim = "site_ids""#,
                TEST_PUBLIC_KEY.replace('\n', "\\n")
            );
            let sink_auth = format!(
                r#"[auth]
site_id             = "site-123"
jwt_token.type      = "inline"
jwt_token.value     = "{token}""#
            );
            assert_eq!(
                run_auth_pair(&source_auth, &sink_auth).await,
                BatchStatus::Delivered
            );
        }

        #[tokio::test]
        async fn legacy_sink_without_auth_is_accepted() {
            // Source has auth configured, sink sends no token → legacy fallback allows through.
            let source_auth = format!(
                r#"[auth]
public_key.type  = "inline"
public_key.value = "{}"
membership_claim = "site_ids""#,
                TEST_PUBLIC_KEY.replace('\n', "\\n")
            );
            assert_eq!(
                run_auth_pair(&source_auth, "").await,
                BatchStatus::Delivered
            );
        }

        #[tokio::test]
        async fn invalid_token_is_rejected() {
            let source_auth = format!(
                r#"[auth]
public_key.type  = "inline"
public_key.value = "{}"
membership_claim = "site_ids""#,
                TEST_PUBLIC_KEY.replace('\n', "\\n")
            );
            let sink_auth = r#"[auth]
site_id         = "site-123"
jwt_token.type  = "inline"
jwt_token.value = "not.a.valid.jwt""#;
            assert_eq!(
                run_auth_pair(&source_auth, sink_auth).await,
                BatchStatus::Rejected
            );
        }

        #[tokio::test]
        async fn unauthorized_site_id_is_rejected() {
            let token = make_token(HashMap::new()); // site_ids = ["site-123"]
            let source_auth = format!(
                r#"[auth]
public_key.type  = "inline"
public_key.value = "{}"
membership_claim = "site_ids""#,
                TEST_PUBLIC_KEY.replace('\n', "\\n")
            );
            let sink_auth = format!(
                r#"[auth]
site_id             = "site-not-in-token"
jwt_token.type      = "inline"
jwt_token.value     = "{token}""#
            );
            assert_eq!(
                run_auth_pair(&source_auth, &sink_auth).await,
                BatchStatus::Rejected
            );
        }

        #[tokio::test]
        async fn source_without_auth_accepts_all_requests() {
            // Source has no auth config; any sink (with or without a token) is accepted.
            assert_eq!(
                run_auth_pair("", "").await,
                BatchStatus::Delivered
            );
        }
    }
}
