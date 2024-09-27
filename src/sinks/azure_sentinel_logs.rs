use azure_core::auth::TokenCredential;
use azure_identity::{AutoRefreshingTokenCredential, ClientSecretCredential, TokenCredentialOptions};
use bytes::{BufMut, Bytes, BytesMut};
use flate2::write::{GzEncoder, ZlibEncoder};
use futures::{FutureExt, SinkExt};
use http::{
    header,
    header::{HeaderMap, HeaderValue},
    Request, StatusCode, Uri,
};
use hyper::Body;
use lookup::lookup_v2::OptionalValuePath;
use lookup::{OwnedValuePath, PathPrefix};
use once_cell::sync::Lazy;
use serde::{Deserialize, Serialize};
use serde_json::Value as JsonValue;
use std::io::Write;
use std::ops::Deref;
use std::sync::Arc;
use tokio::sync::RwLock;
use vector_common::sensitive_string::SensitiveString;
use vector_config::configurable_component;
use vector_core::schema;
use vrl::value::Kind;

use crate::sinks::util::Compression;
use crate::{
    codecs::Transformer,
    config::{log_schema, AcknowledgementsConfig, Input, SinkConfig, SinkContext},
    event::{Event, Value},
    http::HttpClient,
    sinks::{
        util::{
            http::{BatchedHttpSink, HttpEventEncoder, HttpSink},
            BatchConfig, BoxedRawValue, JsonArrayBuffer, RealtimeSizeBasedDefaultBatchSettings,
            TowerRequestConfig,
        },
        Healthcheck, VectorSink,
    },
    tls::{TlsConfig, TlsSettings},
};

/// Configuration for the `azure_sentinel_logs` sink.
#[configurable_component(sink("azure_sentinel_logs"))]
#[derive(Clone, Debug)]
#[serde(deny_unknown_fields)]
pub struct AzureSentinelLogsConfig {
    /// The [unique identifier][Directory (tenant) ID] for an Entra Application.
    /// The tenant value in the path of the request can be used to control who can sign into the application.
    /// Valid values are common, organizations, consumers, and tenant identifiers.
    ///
    /// [tenant_id]: https://learn.microsoft.com/en-us/entra/identity-platform/v2-oauth2-auth-code-flow#redeem-a-code-for-an-access-token
    #[configurable(metadata(docs::examples = "97ce69d9-b4be-4241-8dbd-d265edcf06c4"))]
    pub tenant_id: String,

    /// The [unique identifier][Application (client) ID] for an Entra Application.
    /// The Application (client) ID that the Microsoft Entra admin center – App registrations
    ///
    /// [client_id]: https://learn.microsoft.com/en-us/entra/identity-platform/v2-oauth2-auth-code-flow#redeem-a-code-for-an-access-token
    #[configurable(metadata(docs::examples = "5ce893d9-2c32-4b6c-91a9-b0887c2de2d6"))]
    pub client_id: String,

    /// The [Client secrets] is the application secret that you created in the app registration portal for your app.
    ///
    /// [client_secret]: https://learn.microsoft.com/en-us/entra/identity-platform/v2-oauth2-auth-code-flow#redeem-a-code-for-an-access-token
    pub client_secret: SensitiveString,

    /// The [Azure authority host] for identity
    /// [authority_host]: https://github.com/Azure/azure-sdk-for-rust/blob/main/sdk/core/src/constants.rs#L29
    /// Default value https://login.microsoftonline.com
    #[configurable(metadata(docs::examples = "https://login.microsoftonline.com"))]
    #[configurable(validation(pattern = "^(http://|https://)"))]
    pub authority_host: Option<String>,

    /// The [Data collection endpoint (DCE)] provides an endpoint for the application to send to. A single DCE can support multiple DCRs,
    /// so you can use an existing DCE if you already have one in the same region as your Log Analytics workspace.
    ///
    /// [dce_url]: https://learn.microsoft.com/en-us/azure/azure-monitor/logs/logs-ingestion-api-overview
    #[configurable(metadata(docs::examples = "https://mydce-eus-pu8.eastus-1.ingest.monitor.azure.com"))]
    #[configurable(validation(pattern = "^(http://|https://)"))]
    pub dce_url: String,

    /// The [Data Collection Rule (DCR)] immutable ID
    ///
    /// [dcr_im_id]: https://learn.microsoft.com/en-us/azure/azure-monitor/logs/tutorial-logs-ingestion-portal#collect-information-from-the-dcr
    #[configurable(metadata(docs::examples = "dcr-abcdefghij0123456789"))]
    pub dcr_im_id: String,

    #[configurable(derived)]
    #[serde(default)]
    pub compression: Compression,

    /// The [record type][record_type] of the data that is being submitted.
    ///
    /// Can only contain letters, numbers, and underscores (_), and may not exceed 100 characters.
    ///
    /// [record_type]: https://docs.microsoft.com/en-us/azure/azure-monitor/platform/data-collector-api#request-headers
    #[configurable(validation(pattern = "[a-zA-Z0-9_]{1,100}"))]
    #[configurable(metadata(docs::examples = "MyTableName"))]
    #[configurable(metadata(docs::examples = "MyRecordType"))]
    pub log_type: String,

    #[configurable(derived)]
    #[serde(
        default,
        skip_serializing_if = "crate::serde::skip_serializing_if_default"
    )]
    pub encoding: Transformer,

    #[configurable(derived)]
    #[serde(default)]
    pub batch: BatchConfig<RealtimeSizeBasedDefaultBatchSettings>,

    #[configurable(derived)]
    #[serde(default)]
    pub request: TowerRequestConfig,

    /// Use this option to customize the log field used as [`TimeGenerated`][1] in Azure.
    ///
    /// The setting of `log_schema.timestamp_key`, usually `timestamp`, is used here by default.
    /// This field should be used in rare cases where `TimeGenerated` should point to a specific log
    /// field. For example, use this field to set the log field `source_timestamp` as holding the
    /// value that should be used as `TimeGenerated` on the Azure side.
    ///
    /// [1]: https://learn.microsoft.com/en-us/azure/azure-monitor/logs/log-standard-columns#timegenerated
    #[configurable(metadata(docs::examples = "time_generated"))]
    pub time_generated_key: Option<OptionalValuePath>,

    #[configurable(derived)]
    pub tls: Option<TlsConfig>,

    #[configurable(derived)]
    #[serde(
        default,
        deserialize_with = "crate::serde::bool_or_struct",
        skip_serializing_if = "crate::serde::skip_serializing_if_default"
    )]
    acknowledgements: AcknowledgementsConfig,
}

impl Default for AzureSentinelLogsConfig {
    fn default() -> Self {
        Self {
            tenant_id: "my-tenant-id".to_string(),
            client_id: Default::default(),
            client_secret: Default::default(),
            authority_host: Some(AZURE_DEFAULT_AUTHORITY_HOST.to_string()),
            dce_url: Default::default(),
            dcr_im_id: Default::default(),
            compression: Default::default(),
            log_type: "MyLogType".to_string(),
            encoding: Default::default(),
            batch: Default::default(),
            request: Default::default(),
            time_generated_key: None,
            tls: None,
            acknowledgements: Default::default(),
        }
    }
}

#[derive(Deserialize, Serialize, Debug, Eq, PartialEq, Clone, Derivative)]
#[serde(rename_all = "snake_case")]
#[derivative(Default)]
pub enum Encoding {
    #[derivative(Default)]
    Default,
}

/*
https://learn.microsoft.com/en-us/azure/azure-monitor/service-limits#logs-ingestion-api
Logs Ingestion API
Limit	Value	Comments
Maximum size of API call	1 MB	Both compressed and uncompressed data.
Maximum size for field values	64 KB	Fields longer than 64 KB are truncated.
Maximum data/minute per DCR	2 GB	Both compressed and uncompressed data. Retry after the duration listed in the Retry-After header in the response.
Maximum requests/minute per DCR	12,000	Retry after the duration listed in the Retry-After header in the response.
 */

static CONTENT_TYPE_VALUE: Lazy<HeaderValue> = Lazy::new(|| HeaderValue::from_static(CONTENT_TYPE));

impl_generate_config_from_default!(AzureSentinelLogsConfig);

/// Max number of bytes in request body
/// Limitation of Log Ingestion API - https://learn.microsoft.com/en-us/azure/azure-monitor/service-limits#logs-ingestion-api
const MAX_BATCH_SIZE: usize = 1 * 1024 * 1024;

/// JSON content type of logs
const CONTENT_TYPE: &str = "application/json";
const API_VERSION: &str = "2023-01-01";

const AZURE_SENTINEL_RESOURCE: &str = "https://monitor.azure.com";

const AZURE_DEFAULT_AUTHORITY_HOST: &str = "https://login.microsoftonline.com";

#[async_trait::async_trait]
impl SinkConfig for AzureSentinelLogsConfig {
    async fn build(&self, cx: SinkContext) -> crate::Result<(VectorSink, Healthcheck)> {
        let batch_settings = self
            .batch
            .validate()?
            .limit_max_bytes(MAX_BATCH_SIZE)?
            .into_batch_settings()?;

        let time_generated_key = self.time_generated_key.clone().and_then(|k| k.path);

        let tls_settings = TlsSettings::from_options(&self.tls)?;
        let client = HttpClient::new(Some(tls_settings), &cx.proxy)?;

        let sink = AzureSentinelLogsSink::new(self, time_generated_key)?;
        let request_settings = self.request.unwrap_with(&TowerRequestConfig::default());

        let healthcheck = healthcheck(sink.clone(), client.clone()).boxed();

        let sink = BatchedHttpSink::new(
            sink,
            JsonArrayBuffer::new(batch_settings.size),
            request_settings,
            batch_settings.timeout,
            client,
        )
        .sink_map_err(|error| error!(message = "Fatal azure_sentinel_logs sink error.", %error));

        Ok((VectorSink::from_event_sink(sink), healthcheck))
    }

    fn input(&self) -> Input {
        let requirements =
            schema::Requirement::empty().optional_meaning("timestamp", Kind::timestamp());

        Input::log().with_schema_requirement(requirements)
    }

    fn acknowledgements(&self) -> &AcknowledgementsConfig {
        &self.acknowledgements
    }
}

#[derive(Clone)]
struct TokenProvider {
    tenant_id: String,
    client_id: String,
    client_secret: SensitiveString,
    authority_host: String,
    token_provider: Arc<RwLock<AutoRefreshingTokenCredential>>,
}

impl TokenProvider {
    fn new(
        tenant_id: String,
        client_id: String,
        client_secret: SensitiveString,
        authority_host: String,
    ) -> Self {
        let credential_provider = TokenProvider::create_credential_provider(
            tenant_id.clone(),
            client_id.clone(),
            client_secret.clone(),
            authority_host.clone(),
        );

        debug!(message = format!("TokenProvider {:p} created.", &credential_provider), internal_log_rate_limit=true);

        TokenProvider {
            tenant_id,
            client_id,
            client_secret,
            authority_host,
            token_provider: Arc::new(RwLock::new(credential_provider)),
        }
    }

    fn create_credential_provider(
        tenant_id: String,
        client_id: String,
        client_secret: SensitiveString,
        authority_host: String,
    ) -> AutoRefreshingTokenCredential {
        debug!(message = "Creating credential provider", %client_id, internal_log_rate_limit=true);
        let creds = Arc::new(ClientSecretCredential::new(
            azure_core::new_http_client(),
            tenant_id.into(),
            client_id.into(),
            client_secret.into(),
            TokenCredentialOptions::new(authority_host.into()),
        ));

        let credential_provider = AutoRefreshingTokenCredential::new(creds.clone());
        credential_provider
    }

    async fn get_token(&self) -> Result<String, String> {
        // Try to get the token using the existing credential provider
        {
            let read_only_token_provider = self.token_provider.read().await;
            match read_only_token_provider.get_token(AZURE_SENTINEL_RESOURCE).await {
                Ok(token_response) => {
                    debug!(message = format!("Got a token from the sentinel service using TokenProvider {:p}.", read_only_token_provider.deref())
                    , internal_log_rate_limit=true);
                    return Ok(token_response.token.secret().to_string());
                }
                Err(error) => {
                    warn!(message = format!("Failed to get bearer token. Recreating TokenProvider {:p}", read_only_token_provider.deref())
                    , %error, internal_log_rate_limit=true);
                    // Drop the read lock before acquiring the write lock
                }
            }
        }

        // Acquire a write lock to replace the credential provider
        debug!(message = "Acquiring write lock.", internal_log_rate_limit=true);
        let mut token_provider = self.token_provider.write().await;
        debug!(message = "Acquired write lock.", internal_log_rate_limit=true);

        // Use `create_credential_provider()` to replace the old token provider with a new one
        let new_provider = TokenProvider::create_credential_provider(
            self.tenant_id.clone(),
            self.client_id.clone(),
            self.client_secret.clone(),
            self.authority_host.clone(),
        );

        debug!(message = format!("New TokenProvider {:p} created.", &new_provider)
        , internal_log_rate_limit=true);

        *token_provider = new_provider;

        // Return the error message after replacement
        // When error is returned, HTTP retry will be triggered
        Err("Failed to get bearer token. Recreated token provider.".to_string())
    }
}


#[derive(Clone)]
struct AzureSentinelLogsSink {
    uri: Uri,
    time_generated_key: Option<OwnedValuePath>,
    transformer: Transformer,
    token_provider: TokenProvider,
    default_headers: HeaderMap,
    compression: Compression,
}

struct AzureSentinelLogsEventEncoder {
    transformer: Transformer,
    time_generated_key: Option<OwnedValuePath>,
}

impl HttpEventEncoder<serde_json::Value> for AzureSentinelLogsEventEncoder {
    fn encode_event(&mut self, mut event: Event) -> Option<serde_json::Value> {
        self.transformer.transform(&mut event);

        // it seems like Azure Monitor doesn't support full 9-digit nanosecond precision
        // adjust the timestamp format accordingly, keeping only milliseconds
        let mut log = event.into_log();

        // `.remove_timestamp()` will return the `timestamp` value regardless of location in Event or
        // Metadata, the following `insert()` ensures it's encoded in the request.
        let timestamp = if let Some(Value::Timestamp(ts)) = log.remove_timestamp() {
            ts
        } else {
            chrono::Utc::now()
        };

        if let Some(timestamp_key) = &self.time_generated_key {
            log.insert(
                (PathPrefix::Event, timestamp_key),
                JsonValue::String(timestamp.to_rfc3339_opts(chrono::SecondsFormat::Millis, true)),
            );
        }

        let entry = serde_json::json!(&log);

        Some(entry)
    }
}

#[async_trait::async_trait]
impl HttpSink for AzureSentinelLogsSink {
    type Input = serde_json::Value;
    type Output = Vec<BoxedRawValue>;
    type Encoder = AzureSentinelLogsEventEncoder;

    fn build_encoder(&self) -> Self::Encoder {
        AzureSentinelLogsEventEncoder {
            transformer: self.transformer.clone(),
            time_generated_key: self.time_generated_key.clone(),
        }
    }

    async fn build_request(&self, events: Self::Output) -> crate::Result<Request<Bytes>> {
        self.build_request_sync(events).await
    }
}

impl AzureSentinelLogsSink {
    fn new(
        config: &AzureSentinelLogsConfig,
        time_generated_key: Option<OwnedValuePath>,
    ) -> crate::Result<AzureSentinelLogsSink> {
        let url = format!(
            "{}/dataCollectionRules/{}/streams/{}?api-version={}",
            config.dce_url, config.dcr_im_id, config.log_type, API_VERSION
        );
        let uri: Uri = url.parse()?;

        if config.client_secret.inner().is_empty() {
            return Err("client_secret can't be an empty string".into());
        }

        let time_generated_key =
            time_generated_key.or_else(|| log_schema().timestamp_key().cloned());

        let mut default_headers = HeaderMap::with_capacity(3);

        default_headers.insert(header::CONTENT_TYPE, CONTENT_TYPE_VALUE.clone());
        let authority_host = config.authority_host.clone()
            .or(Some(AZURE_DEFAULT_AUTHORITY_HOST.to_string())).unwrap();

        let token_provider = TokenProvider::new(
            config.tenant_id.clone(),
            config.client_id.clone(),
            config.client_secret.clone(),
            authority_host,
        );
        Ok(AzureSentinelLogsSink {
            uri,
            transformer: config.encoding.clone(),
            token_provider,
            default_headers,
            time_generated_key,
            compression: config.compression,
        })
    }

    async fn build_request_sync(&self, events: Vec<BoxedRawValue>) -> crate::Result<Request<Bytes>> {
        let mut builder = Request::post(self.uri.clone());

        let mut body = crate::serde::json::to_bytes(&events)?;
        match self.compression {
            // Azure supports on gzip
            Compression::Gzip(level) => {
                builder = builder.header("Content-Encoding", "gzip");

                let buffer = BytesMut::new();
                let mut w = GzEncoder::new(buffer.writer(), level.as_flate2());
                w.write_all(&body).expect("Writing compressed gzip to Vec can't fail");
                body = w.finish().expect("Writing compressed gzip to Vec can't fail").into_inner();
            }
            Compression::Zlib(level) => {
                builder = builder.header("Content-Encoding", "deflate");

                let buffer = BytesMut::new();
                let mut w = ZlibEncoder::new(buffer.writer(), level.as_flate2());
                w.write_all(&body).expect("Writing compressed zlib to Vec can't fail");
                body = w.finish().expect("Writing compressed zlib to Vec can't fail").into_inner();
            }
            Compression::None => {}
        }

        let authorization = self.build_authorization_header_value()
            .await
            .map_err(|error| format!("Auth Bearer not found.: {}", error))?;

        builder = builder.header(header::AUTHORIZATION, authorization);

        let headers = builder
            .headers_mut()
            .expect("Failed to access headers in http::Request builder- builder has errors.");
        for (header, value) in self.default_headers.iter() {
            headers.insert(header, value.clone());
        }

        let request = builder.body(body.freeze()).unwrap();

        Ok(request)
    }

    async fn build_authorization_header_value(&self) -> crate::Result<String> {
        let bearer_token = self.token_provider.get_token().await?;

        let auth_header = format!(
            "Bearer {}",
            bearer_token
        );
        Ok(auth_header)
    }
}

async fn healthcheck(sink: AzureSentinelLogsSink, client: HttpClient) -> crate::Result<()> {
    let request = sink.build_request(vec![]).await?.map(Body::from);

    let res = client.send(request).await?;

    if res.status().is_server_error() {
        return Err("Server returned a server error".into());
    }

    if res.status() == StatusCode::FORBIDDEN {
        return Err("The service failed to authenticate the request. Verify that the workspace ID and connection key are valid".into());
    }

    if res.status() == StatusCode::NOT_FOUND {
        return Err("Either the URL provided is incorrect, or the request is too large".into());
    }

    if res.status() == StatusCode::BAD_REQUEST {
        return Err("The workspace has been closed or the request was invalid".into());
    }

    Ok(())
}
