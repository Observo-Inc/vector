use std::sync::Arc;
use std::task::{Context, Poll};

use futures::{future::BoxFuture, TryFutureExt};
use http::Uri;
use hyper::client::HttpConnector;
use hyper_openssl::HttpsConnector;
use hyper_proxy::ProxyConnector;
use prost::Message;
use tonic::metadata::MetadataValue;
use tonic::{body::BoxBody, IntoRequest};
use tower::Service;
use vector_lib::request_metadata::{GroupedCountByteSize, MetaDescriptive, RequestMetadata};
use vector_lib::stream::DriverResponse;

use super::{config::VectorSinkAuthConfig, VectorSinkError};
use crate::{
    event::{EventFinalizers, EventStatus, Finalizable},
    internal_events::EndpointBytesSent,
    proto::vector as proto_vector,
    sinks::util::uri,
    Error,
};

/// Pre-parsed auth state built once at `VectorService` construction time.
///
/// `site_id` and, for inline tokens, the `Authorization` header value are parsed
/// into `MetadataValue` up front so the hot `call()` path pays no allocation or
/// parse cost for those fields.
#[derive(Debug)]
struct AuthState {
    site_id: MetadataValue<tonic::metadata::Ascii>,
    token: AuthToken,
}

#[derive(Debug)]
enum AuthToken {
    /// Fully-formatted `"Bearer <value>"` ready to insert into gRPC metadata.
    Static(MetadataValue<tonic::metadata::Ascii>),
    /// Path to a file re-read on every request (K8s secret rotation).
    File(String),
}

#[derive(Clone, Debug)]
pub struct VectorService {
    pub client: proto_vector::Client<HyperSvc>,
    pub protocol: String,
    pub endpoint: String,
    auth: Option<Arc<AuthState>>,
}

pub struct VectorResponse {
    events_byte_size: GroupedCountByteSize,
}

impl DriverResponse for VectorResponse {
    fn event_status(&self) -> EventStatus {
        EventStatus::Delivered
    }

    fn events_sent(&self) -> &GroupedCountByteSize {
        &self.events_byte_size
    }
}

#[derive(Clone, Default)]
pub struct VectorRequest {
    pub finalizers: EventFinalizers,
    pub metadata: RequestMetadata,
    pub request: proto_vector::PushEventsRequest,
}

impl Finalizable for VectorRequest {
    fn take_finalizers(&mut self) -> EventFinalizers {
        self.finalizers.take_finalizers()
    }
}

impl MetaDescriptive for VectorRequest {
    fn get_metadata(&self) -> &RequestMetadata {
        &self.metadata
    }

    fn metadata_mut(&mut self) -> &mut RequestMetadata {
        &mut self.metadata
    }
}

impl VectorService {
    pub fn new(
        hyper_client: hyper::Client<ProxyConnector<HttpsConnector<HttpConnector>>, BoxBody>,
        uri: Uri,
        compression: bool,
        auth: Option<VectorSinkAuthConfig>,
    ) -> crate::Result<Self> {
        let (protocol, endpoint) = uri::protocol_endpoint(uri.clone());
        let mut proto_client = proto_vector::Client::new(HyperSvc {
            uri,
            client: hyper_client,
        });

        if compression {
            proto_client = proto_client.send_compressed(tonic::codec::CompressionEncoding::Gzip);
        }

        let auth = auth.map(|cfg| {
            let site_id: MetadataValue<tonic::metadata::Ascii> = cfg
                .site_id
                .parse()
                .map_err(|_| "site_id contains characters invalid for gRPC metadata")?;

            let token = match cfg.jwt_token {
                super::config::JwtTokenSource::Inline { value } => {
                    let header: MetadataValue<tonic::metadata::Ascii> =
                        format!("Bearer {value}").parse().map_err(|_| {
                            "JWT token (inline) contains characters invalid for gRPC metadata"
                        })?;
                    AuthToken::Static(header)
                }
                super::config::JwtTokenSource::File { path } => AuthToken::File(path),
            };

            Ok::<_, &'static str>(Arc::new(AuthState { site_id, token }))
        });

        let auth = auth.transpose().map_err(|e| -> Error { e.into() })?;

        Ok(Self {
            client: proto_client,
            protocol,
            endpoint,
            auth,
        })
    }
}

impl Service<VectorRequest> for VectorService {
    type Response = VectorResponse;
    type Error = Error;
    type Future = BoxFuture<'static, Result<Self::Response, Self::Error>>;

    fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, mut list: VectorRequest) -> Self::Future {
        let mut service = self.clone();
        let byte_size = list.request.encoded_len();
        let metadata = std::mem::take(list.metadata_mut());
        let events_byte_size = metadata.into_events_estimated_json_encoded_byte_size();

        let future = async move {
            let mut request = list.request.into_request();

            if let Some(auth) = &service.auth {
                let bearer = match &auth.token {
                    AuthToken::Static(value) => Some(value.clone()),
                    AuthToken::File(path) => match std::fs::read_to_string(path) {
                        Ok(raw) => {
                            let token = raw.trim();
                            match format!("Bearer {token}").parse::<MetadataValue<_>>() {
                                Ok(value) => Some(value),
                                Err(err) => {
                                    return Err(VectorSinkError::JwtTokenUnavailable {
                                        message: format!("token file contains invalid characters: {err}"),
                                    }
                                    .into())
                                }
                            }
                        }
                        Err(err) => {
                            return Err(VectorSinkError::JwtTokenUnavailable {
                                message: format!("failed to read token file '{}': {err}", path),
                            }
                            .into())
                        }
                    },
                };

                if let Some(value) = bearer {
                    request.metadata_mut().insert("authorization", value);
                }
                request
                    .metadata_mut()
                    .insert("x-site-id", auth.site_id.clone());
            }

            service
                .client
                .push_events(request)
                .map_ok(|_response| {
                    emit!(EndpointBytesSent {
                        byte_size,
                        protocol: &service.protocol,
                        endpoint: &service.endpoint,
                    });

                    VectorResponse { events_byte_size }
                })
                .map_err(|source| VectorSinkError::Request { source }.into())
                .await
        };

        Box::pin(future)
    }
}

#[derive(Clone, Debug)]
pub struct HyperSvc {
    uri: Uri,
    client: hyper::Client<ProxyConnector<HttpsConnector<HttpConnector>>, BoxBody>,
}

impl Service<hyper::Request<BoxBody>> for HyperSvc {
    type Response = hyper::Response<hyper::Body>;
    type Error = hyper::Error;
    type Future = BoxFuture<'static, Result<Self::Response, Self::Error>>;

    fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, mut req: hyper::Request<BoxBody>) -> Self::Future {
        let uri = Uri::builder()
            .scheme(self.uri.scheme().unwrap().clone())
            .authority(self.uri.authority().unwrap().clone())
            .path_and_query(req.uri().path_and_query().unwrap().clone())
            .build()
            .unwrap();

        *req.uri_mut() = uri;

        Box::pin(self.client.request(req))
    }
}
