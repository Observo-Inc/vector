use std::{
    fmt::Debug,
    net::SocketAddr,
    num::NonZeroU64,
    task::{Context, Poll},
    time::Duration,
};
use vector_config_macros::configurable_component;

use http::StatusCode;
use snafu::{ResultExt, Snafu};
use tokio::{net::TcpStream, time};
use tokio_tungstenite::{
    client_async_with_config,
    tungstenite::{
        client::{uri_mode, IntoClientRequest},
        error::{Error as TungsteniteError, ProtocolError, UrlError},
        handshake::client::Request,
        protocol::WebSocketConfig,
        stream::Mode as UriMode,
    },
    WebSocketStream,
};

use tracing::info;

use crate::{
    common::backoff::ExponentialBackoff,
    dns,
    http::Auth,
    internal_events::{WebSocketConnectionEstablished, WebSocketConnectionFailedError},
    tls::{MaybeTlsSettings, MaybeTlsStream, TlsEnableableConfig, TlsError},
};

#[allow(unreachable_pub)]
#[derive(Debug, Snafu)]
#[snafu(visibility(pub))]
pub enum WebSocketError {
    #[snafu(display("Creating WebSocket client failed: {}", source))]
    CreateFailed { source: TungsteniteError },
    #[snafu(display("Connect error: {}", source))]
    ConnectError { source: TlsError },
    #[snafu(display("Unable to resolve DNS: {}", source))]
    DnsError { source: dns::DnsError },
    #[snafu(display("No addresses returned."))]
    NoAddresses,
}

#[derive(Clone)]
pub(crate) struct WebSocketConnector {
    uri: String,
    host: String,
    port: u16,
    tls: MaybeTlsSettings,
    auth: Option<Auth>,
    retriable_status_codes: Vec<u16>,
}

impl WebSocketConnector {
    pub(crate) fn new(
        uri: String,
        tls: MaybeTlsSettings,
        auth: Option<Auth>,
        retriable_status_codes: Vec<u16>,
    ) -> Result<Self, WebSocketError> {
        let request = (&uri).into_client_request().context(CreateFailedSnafu)?;
        let (host, port) = Self::extract_host_and_port(&request).context(CreateFailedSnafu)?;

        Ok(Self {
            uri,
            host,
            port,
            tls,
            auth,
            retriable_status_codes,
        })
    }

    fn extract_host_and_port(request: &Request) -> Result<(String, u16), TungsteniteError> {
        let host = request
            .uri()
            .host()
            .ok_or(TungsteniteError::Url(UrlError::NoHostName))?
            .to_string();
        let mode = uri_mode(request.uri())?;
        let port = request.uri().port_u16().unwrap_or(match mode {
            UriMode::Tls => 443,
            UriMode::Plain => 80,
        });

        Ok((host, port))
    }

    const fn fresh_backoff() -> ExponentialBackoff {
        ExponentialBackoff::from_millis(2)
            .factor(250)
            .max_delay(Duration::from_secs(60))
    }

    // Check if an error is a retriable HTTP error based on configured status codes.
    fn is_retriable_http_error(&self, error: &WebSocketError) -> Option<StatusCode> {
        if let WebSocketError::CreateFailed {
            source: TungsteniteError::Http(response),
        } = error
        {
            let status = response.status();
            if self.retriable_status_codes.contains(&status.as_u16()) {
                return Some(status);
            }
        }
        None
    }

    async fn tls_connect(&self) -> Result<MaybeTlsStream<TcpStream>, WebSocketError> {
        let ip = dns::Resolver
            .lookup_ip(self.host.clone())
            .await
            .context(DnsSnafu)?
            .next()
            .ok_or(WebSocketError::NoAddresses)?;

        let addr = SocketAddr::new(ip, self.port);
        self.tls
            .connect(&self.host, &addr)
            .await
            .context(ConnectSnafu)
    }

    async fn connect(&self) -> Result<WebSocketStream<MaybeTlsStream<TcpStream>>, WebSocketError> {
        let mut request = (&self.uri)
            .into_client_request()
            .context(CreateFailedSnafu)?;

        if let Some(auth) = &self.auth {
            auth.apply(&mut request);
        }

        let maybe_tls = self.tls_connect().await?;

        let ws_config = WebSocketConfig::default();

        let (ws_stream, _response) = client_async_with_config(request, maybe_tls, Some(ws_config))
            .await
            .context(CreateFailedSnafu)?;

        Ok(ws_stream)
    }

    fn timeout_error() -> WebSocketError {
        WebSocketError::CreateFailed {
            source: TungsteniteError::Io(std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                "Connection attempt timed out",
            )),
        }
    }

    fn handle_connect_error(&self, error: WebSocketError) {
        if let Some(status) = self.is_retriable_http_error(&error) {
            // Retriable errors are logged at INFO to avoid unnecessary alarm.
            info!(
                message = "WebSocket connection failed with retriable HTTP status, will retry with backoff.",
                status_code = %status.as_u16(),
                status = %status,
                internal_log_rate_limit = true,
            );
        } else {
            emit!(WebSocketConnectionFailedError {
                error: Box::new(error)
            });
        }
    }

    pub(crate) async fn connect_backoff(
        &self,
        timeout_per_attempt: Duration,
    ) -> WebSocketStream<MaybeTlsStream<TcpStream>> {
        let mut backoff = Self::fresh_backoff();
        loop {
            // Apply timeout to individual connection attempts, not the entire loop.
            let result = time::timeout(timeout_per_attempt, self.connect()).await;

            match result {
                Ok(Ok(ws_stream)) => {
                    emit!(WebSocketConnectionEstablished {});
                    return ws_stream;
                }
                Ok(Err(error)) => {
                    self.handle_connect_error(error);
                    time::sleep(backoff.next().unwrap()).await;
                }
                Err(_) => {
                    self.handle_connect_error(Self::timeout_error());
                    time::sleep(backoff.next().unwrap()).await;
                }
            }
        }
    }

    #[cfg(feature = "sinks-websocket")]
    pub(crate) async fn healthcheck(&self) -> crate::Result<()> {
        self.connect().await.map(|_| ()).map_err(Into::into)
    }
}

pub(crate) const fn is_closed(error: &TungsteniteError) -> bool {
    matches!(
        error,
        TungsteniteError::ConnectionClosed
            | TungsteniteError::AlreadyClosed
            | TungsteniteError::Protocol(ProtocolError::ResetWithoutClosingHandshake)
    )
}

pub(crate) struct PingInterval {
    interval: Option<time::Interval>,
}

impl PingInterval {
    pub(crate) fn new(period: Option<u64>) -> Self {
        Self {
            interval: period.map(|period| time::interval(Duration::from_secs(period))),
        }
    }

    pub(crate) fn poll_tick(&mut self, cx: &mut Context<'_>) -> Poll<time::Instant> {
        match self.interval.as_mut() {
            Some(interval) => interval.poll_tick(cx),
            None => Poll::Pending,
        }
    }

    pub(crate) async fn tick(&mut self) -> time::Instant {
        std::future::poll_fn(|cx| self.poll_tick(cx)).await
    }
}

/// Shared websocket configuration for sources and sinks.
#[configurable_component]
#[derive(Clone, Debug)]
#[serde(deny_unknown_fields)]
pub struct WebSocketCommonConfig {
    /// The WebSocket URI to connect to.
    ///
    /// This should include the protocol and host, but can also include the port, path, and any other valid part of a URI.
    ///  **Note**: Using the `wss://` protocol requires enabling `tls`.
    #[configurable(metadata(docs::examples = "ws://localhost:8080"))]
    #[configurable(metadata(docs::examples = "wss://example.com/socket"))]
    pub uri: String,

    /// The interval, in seconds, between sending [Ping][ping]s to the remote peer.
    ///
    /// If this option is not configured, pings are not sent on an interval.
    ///
    /// If the `ping_timeout` is not set, pings are still sent but there is no expectation of pong
    /// response times.
    ///
    /// [ping]: https://www.rfc-editor.org/rfc/rfc6455#section-5.5.2
    #[configurable(metadata(docs::type_unit = "seconds"))]
    #[configurable(metadata(docs::advanced))]
    #[configurable(metadata(docs::examples = 30))]
    pub ping_interval: Option<NonZeroU64>,

    /// The number of seconds to wait for a [Pong][pong] response from the remote peer.
    ///
    /// If a response is not received within this time, the connection is re-established.
    ///
    /// [pong]: https://www.rfc-editor.org/rfc/rfc6455#section-5.5.3
    // NOTE: this option is not relevant if the `ping_interval` is not configured.
    #[configurable(metadata(docs::type_unit = "seconds"))]
    #[configurable(metadata(docs::advanced))]
    #[configurable(metadata(docs::examples = 5))]
    pub ping_timeout: Option<NonZeroU64>,

    /// HTTP status codes that should trigger a retry with exponential backoff.
    ///
    /// When the WebSocket handshake fails with one of these HTTP status codes,
    /// the connection will be retried using exponential backoff instead of failing immediately.
    /// This is useful for handling temporary server-side conditions like 409 Conflict or 429 Too Many Requests.
    #[configurable(metadata(docs::advanced))]
    #[configurable(metadata(docs::examples = 409))]
    #[configurable(metadata(docs::examples = 429))]
    #[serde(default = "default_retriable_status_codes")]
    pub retriable_status_codes: Vec<u16>,

    /// TLS configuration.
    #[configurable(derived)]
    pub tls: Option<TlsEnableableConfig>,

    /// HTTP Authentication.
    #[configurable(derived)]
    pub auth: Option<Auth>,
}

fn default_retriable_status_codes() -> Vec<u16> {
    vec![409, 429]
}

impl Default for WebSocketCommonConfig {
    fn default() -> Self {
        Self {
            uri: "ws://127.0.0.1:8080".to_owned(),
            ping_interval: None,
            ping_timeout: None,
            retriable_status_codes: default_retriable_status_codes(),
            tls: None,
            auth: None,
        }
    }
}
