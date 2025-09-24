use std::{
    sync::Arc,
    task::{Context, Poll},
};

use std::format;
use bytes::Bytes;
use futures::future::BoxFuture;
use http::{Response, Uri};
use hyper::{service::Service, Body, Request};
use tower::ServiceExt;
use vector_lib::stream::DriverResponse;
use vector_lib::ByteSizeOf;
use metrics::Counter;
use vector_lib::{
    json_size::JsonSize,
    request_metadata::{GroupedCountByteSize, MetaDescriptive, RequestMetadata},
};

use super::{ElasticsearchCommon, ElasticsearchConfig, RejectionReport};
use crate::{
    event::{EventFinalizers, EventStatus, Finalizable},
    http::HttpClient,
    sinks::util::{
        auth::Auth,
        http::{HttpBatchService, RequestConfig},
        Compression, ElementCount, Decompressor,
    },
};

#[derive(Clone, Debug)]
pub struct ElasticsearchRequest {
    pub payload: Bytes,
    pub finalizers: EventFinalizers,
    pub batch_size: usize,
    pub events_byte_size: JsonSize,
    pub metadata: RequestMetadata,
}

impl ByteSizeOf for ElasticsearchRequest {
    fn allocated_bytes(&self) -> usize {
        self.payload.allocated_bytes() + self.finalizers.allocated_bytes()
    }
}

impl ElementCount for ElasticsearchRequest {
    fn element_count(&self) -> usize {
        self.batch_size
    }
}

impl Finalizable for ElasticsearchRequest {
    fn take_finalizers(&mut self) -> EventFinalizers {
        std::mem::take(&mut self.finalizers)
    }
}

impl MetaDescriptive for ElasticsearchRequest {
    fn get_metadata(&self) -> &RequestMetadata {
        &self.metadata
    }

    fn metadata_mut(&mut self) -> &mut RequestMetadata {
        &mut self.metadata
    }
}

#[derive(Clone)]
pub struct Telemetry {
    // #OBSERVO_STYLE_TELEMETRY# (diverges from upstream convention)
    // The usual way (using emit!(...)) to emit metrics has high overhead. It dereferences global-state and requires
    // more than 8 method calls to pull the labels out for every `emit!` invocation.
    // We can't fix it for all of vector (for fear of merge-conflicts during upgrade) but we use a more efficient
    // approach here.
    // Config::build does that hard-work once and then we hold on to the counter and continue incrementing it.
    pub rejected: Counter,
    pub indexed: Counter,
}

#[derive(Clone)]
pub struct ElasticsearchService {
    // TODO: `HttpBatchService` has been deprecated for direct use in sinks.
    //       This sink should undergo a refactor to utilize the `HttpService`
    //       instead, which extracts much of the boilerplate code for `Service`.
    batch_service: HttpBatchService<
        BoxFuture<'static, Result<http::Request<Bytes>, crate::Error>>,
        ElasticsearchRequest,
    >,
    rej_rpt: RejectionReport,
    compression: Compression,
    telemetry: Telemetry,
}

impl ElasticsearchService {
    pub fn new(
        http_client: HttpClient<Body>,
        http_request_builder: HttpRequestBuilder,
        rej_rpt: RejectionReport,
        compression: Compression,
        telemetry: Telemetry,
    ) -> ElasticsearchService {
        let http_request_builder = Arc::new(http_request_builder);
        let batch_service = HttpBatchService::new(http_client, move |req| {
            let request_builder = Arc::clone(&http_request_builder);
            let future: BoxFuture<'static, Result<http::Request<Bytes>, crate::Error>> =
                Box::pin(async move { request_builder.build_request(req).await });
            future
        });
        ElasticsearchService { batch_service, rej_rpt, compression, telemetry }
    }
}

pub struct HttpRequestBuilder {
    pub bulk_uri: Uri,
    pub auth: Option<Auth>,
    pub service_type: crate::sinks::elasticsearch::OpenSearchServiceType,
    pub compression: Compression,
    pub http_request_config: RequestConfig,
}

impl HttpRequestBuilder {
    pub fn new(common: &ElasticsearchCommon, config: &ElasticsearchConfig) -> HttpRequestBuilder {
        HttpRequestBuilder {
            bulk_uri: common.bulk_uri.clone(),
            auth: common.auth.clone(),
            service_type: common.service_type.clone(),
            compression: config.compression,
            http_request_config: config.request.clone(),
        }
    }

    pub async fn build_request(
        &self,
        es_req: ElasticsearchRequest,
    ) -> Result<Request<Bytes>, crate::Error> {
        let mut builder = Request::post(&self.bulk_uri);

        builder = builder.header("Content-Type", "application/x-ndjson");

        if let Some(ce) = self.compression.content_encoding() {
            builder = builder.header("Content-Encoding", ce);
        }

        if let Some(ae) = self.compression.accept_encoding() {
            builder = builder.header("Accept-Encoding", ae);
        }

        for (header, value) in &self.http_request_config.headers {
            builder = builder.header(&header[..], &value[..]);
        }

        let mut request = builder
            .body(es_req.payload)
            .expect("Invalid http request value used");

        if let Some(auth) = &self.auth {
            match auth {
                Auth::Basic(auth) => {
                    auth.apply(&mut request);
                }
                #[cfg(feature = "aws-core")]
                Auth::Aws {
                    credentials_provider: provider,
                    region,
                } => {
                    crate::sinks::elasticsearch::sign_request(
                        &self.service_type,
                        &mut request,
                        provider,
                        Some(region),
                    )
                    .await?;
                }
            }
        }

        Ok(request)
    }
}

pub struct ElasticsearchResponse {
    pub http_response: Response<Bytes>,
    pub event_status: EventStatus,
    pub events_byte_size: GroupedCountByteSize,
}

impl DriverResponse for ElasticsearchResponse {
    fn event_status(&self) -> EventStatus {
        self.event_status
    }

    fn events_sent(&self) -> &GroupedCountByteSize {
        &self.events_byte_size
    }
}

impl Service<ElasticsearchRequest> for ElasticsearchService {
    type Response = ElasticsearchResponse;
    type Error = crate::Error;
    type Future = BoxFuture<'static, Result<Self::Response, Self::Error>>;

    // Emission of an internal event in case of errors is handled upstream by the caller.
    fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    // Emission of internal events for errors and dropped events is handled upstream by the caller.
    fn call(&mut self, mut req: ElasticsearchRequest) -> Self::Future {
        let mut http_service = self.batch_service.clone();
        let rej_rpt = self.rej_rpt.clone();
        let req_for_rpt = if rej_rpt.needs_request() {
            Some((req.clone(), self.compression.clone()))
        } else {
            None
        };
        let telemetry = self.telemetry.clone();
        Box::pin(async move {
            http_service.ready().await?;
            let events_byte_size =
                std::mem::take(req.metadata_mut()).into_events_estimated_json_encoded_byte_size();
            let http_response = http_service.call(req).await?;

            let event_status = get_event_status(&http_response, req_for_rpt, rej_rpt, telemetry);
            Ok(ElasticsearchResponse {
                event_status,
                http_response,
                events_byte_size,
            })
        })
    }
}

const ES_REJ_RPT: &str = "es_rej_rpt";

fn response_frag(key: &str, val_prefix: &str) -> String {
    format!("\"{key}\":{val_prefix}")
}

#[derive(Debug, PartialEq)]
struct ErrSummary {
    error_code: String,
    msg: String,
    indexed: u64,
    rejected: u64,
}

fn err_summary(response: &Response<Bytes>) -> ErrSummary {
    let body = String::from_utf8_lossy(response.body());
    let i =
        body
            .match_indices(response_frag("status", "201").as_str())
            .count()
            .try_into()
            .unwrap();
    let r =
        body
            .match_indices(response_frag("status", "400").as_str())
            .count()
            .try_into()
            .unwrap();
    ErrSummary {
        error_code: format!("http_response_{}", response.status().as_u16()),
        msg: format!("Request contained errors (indexed: {i}, rejected: {r})."),
        indexed: i,
        rejected: r
    }
}

fn emit_bad_response_error(
    response: &Response<Bytes>,
    request: Option<(ElasticsearchRequest, Compression)>,
    rej_rpt: RejectionReport,
    telemetry: Telemetry,
) {
    let err_summary = err_summary(response);
    telemetry.indexed.increment(err_summary.indexed);
    telemetry.rejected.increment(err_summary.rejected);

    match (rej_rpt, request) {
        (RejectionReport::RequestResponse, Some((req, comp))) => {
            let decomp = Decompressor::from(comp);
            let req_data = match decomp.decompress(req.payload) {
                Ok(data) => data,
                Err(err) => format!("- decompression failed({comp}): '{err}' -").into()
            };

            error!(
                category = ES_REJ_RPT,
                message = err_summary.msg,
                error_code = err_summary.error_code,
                response = ?response,
                request = %String::from_utf8_lossy(&req_data),
            );
        }
        (RejectionReport::Stats, _) => {
            error!(
                category = ES_REJ_RPT,
                message = err_summary.msg,
                error_code = err_summary.error_code,
            );
        }
        _ => {
            error!(
                category = ES_REJ_RPT,
                message = err_summary.msg,
                error_code = err_summary.error_code,
                response = ?response,
            );
        }
    };
}

fn get_event_status(
    response: &Response<Bytes>,
    request: Option<(ElasticsearchRequest, Compression)>,
    rej_rpt: RejectionReport,
    telemetry: Telemetry,
) -> EventStatus {
    let status = response.status();
    if status.is_success() {
        let body = String::from_utf8_lossy(response.body());
        if body.contains(response_frag("errors", "true").as_str()) {
            emit_bad_response_error(response, request, rej_rpt, telemetry);
            EventStatus::Rejected
        } else {
            EventStatus::Delivered
        }
    } else if status.is_server_error() {
        let rej_rpt = if rej_rpt == RejectionReport::RequestResponse {
            RejectionReport::Response
        } else {
            rej_rpt
        };
        emit_bad_response_error(response, None, rej_rpt, telemetry);
        EventStatus::Errored
    } else {
        emit_bad_response_error(response, request, rej_rpt, telemetry);
        EventStatus::Rejected
    }
}


#[cfg(test)]
mod tests {
    use std::{fs::File, io::Read};
    use super::*;

    fn contents(path: &str) -> Bytes {
        let mut file = File::open(path).expect("Unable to open file");
        let mut contents = Vec::new();
        file.read_to_end(&mut contents).expect("Unable to read file");
        Bytes::from(contents)
    }

    #[test]
    fn test_error_summary() {
        let res = Response::new(
            contents("tests/data/elasticsearch_bulk.response.body.json"));

        // <json file> | jq -c '.items | map(.index.status | "\(.)") | histo'
        // {"201":259,"400":5}

        let body = String::from_utf8_lossy(res.body());

        // assert we detect error
        assert!(body.contains(response_frag("errors", "true").as_str()));

        assert_eq!(
            err_summary(&res),
            ErrSummary {
                error_code: "http_response_200".into(),
                msg: "Request contained errors (indexed: 259, rejected: 5).".to_string(),
                indexed: 259,
                rejected: 5})
    }
}