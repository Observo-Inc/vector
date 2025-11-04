use std::{fmt, sync::Arc};

use super::request_builder::HecLogsRequestBuilder;
use crate::{
    internal_events::SplunkEventTimestampInvalidType,
    internal_events::SplunkEventTimestampMissing,
    sinks::{
        prelude::*,
        splunk_hec::common::{
            render_template_string, request::HecRequest, EndpointTarget, INDEX_FIELD,
            SOURCETYPE_FIELD, SOURCE_FIELD,
        },
        util::processed_event::ProcessedEvent,
    },
};
use vector_lib::{
    config::{log_schema, LogNamespace},
    lookup::{event_path, lookup_v2::OptionalTargetPath, OwnedValuePath, PathPrefix},
    schema::meaning,
};
use vrl::path::OwnedTargetPath;
use crate::sinks::splunk_hec::logs::config::TimestampConfiguration;
use chrono::{DateTime, Utc, NaiveDateTime, TimeZone};

// NOTE: The `OptionalTargetPath`s are wrapped in an `Option` in order to distinguish between a true
//       `None` type and an empty string. This is necessary because `OptionalTargetPath` deserializes an
//       empty string to a `None` path internally.
pub struct HecLogsSink<S> {
    pub service: S,
    pub request_builder: HecLogsRequestBuilder,
    pub batch_settings: BatcherSettings,
    pub sourcetype: Option<Template>,
    pub source: Option<Template>,
    pub index: Option<Template>,
    pub indexed_fields: Vec<OwnedValuePath>,
    pub host_key: Option<OptionalTargetPath>,
    pub timestamp_nanos_key: Option<String>,
    pub endpoint_target: EndpointTarget,
    pub auto_extract_timestamp: bool,
    pub timestamp_configuration: Option<TimestampConfiguration>,
}

pub struct HecLogData<'a> {
    pub sourcetype: Option<&'a Template>,
    pub source: Option<&'a Template>,
    pub index: Option<&'a Template>,
    pub indexed_fields: &'a [OwnedValuePath],
    pub host_key: Option<OptionalTargetPath>,
    pub timestamp_nanos_key: Option<&'a String>,
    pub endpoint_target: EndpointTarget,
    pub auto_extract_timestamp: bool,
    pub timestamp_configuration: Option<TimestampConfiguration>,
}

impl<S> HecLogsSink<S>
where
    S: Service<HecRequest> + Send + 'static,
    S::Future: Send + 'static,
    S::Response: DriverResponse + Send + 'static,
    S::Error: fmt::Debug + Into<crate::Error> + Send,
{
    async fn run_inner(self: Box<Self>, input: BoxStream<'_, Event>) -> Result<(), ()> {
        let data = HecLogData {
            sourcetype: self.sourcetype.as_ref(),
            source: self.source.as_ref(),
            index: self.index.as_ref(),
            indexed_fields: self.indexed_fields.as_slice(),
            host_key: self.host_key.clone(),
            timestamp_nanos_key: self.timestamp_nanos_key.as_ref(),
            endpoint_target: self.endpoint_target,
            auto_extract_timestamp: self.auto_extract_timestamp,
            timestamp_configuration: self.timestamp_configuration.clone(),
        };
        let batch_settings = self.batch_settings;

        input
            .map(move |event| process_log(event, &data))
            .batched_partitioned(
                if self.endpoint_target == EndpointTarget::Raw {
                    // We only need to partition by the metadata fields for the raw endpoint since those fields
                    // are sent via query parameters in the request.
                    EventPartitioner::new(
                        self.sourcetype.clone(),
                        self.source.clone(),
                        self.index.clone(),
                        self.host_key.clone(),
                    )
                } else {
                    EventPartitioner::new(None, None, None, None)
                },
                || batch_settings.as_byte_size_config(),
            )
            .request_builder(
                default_request_builder_concurrency_limit(),
                self.request_builder,
            )
            .filter_map(|request| async move {
                match request {
                    Err(e) => {
                        error!("Failed to build HEC Logs request: {:?}.", e);
                        None
                    }
                    Ok(req) => Some(req),
                }
            })
            .into_driver(self.service)
            .run()
            .await
    }
}

#[async_trait]
impl<S> StreamSink<Event> for HecLogsSink<S>
where
    S: Service<HecRequest> + Send + 'static,
    S::Future: Send + 'static,
    S::Response: DriverResponse + Send + 'static,
    S::Error: fmt::Debug + Into<crate::Error> + Send,
{
    async fn run(self: Box<Self>, input: BoxStream<'_, Event>) -> Result<(), ()> {
        self.run_inner(input).await
    }
}

#[derive(Clone, Debug, PartialEq, Hash, Eq)]
pub(super) struct Partitioned {
    pub(super) token: Option<Arc<str>>,
    pub(super) source: Option<String>,
    pub(super) sourcetype: Option<String>,
    pub(super) index: Option<String>,
    pub(super) host: Option<String>,
}

#[derive(Default)]
struct EventPartitioner {
    pub sourcetype: Option<Template>,
    pub source: Option<Template>,
    pub index: Option<Template>,
    pub host_key: Option<OptionalTargetPath>,
}

impl EventPartitioner {
    const fn new(
        sourcetype: Option<Template>,
        source: Option<Template>,
        index: Option<Template>,
        host_key: Option<OptionalTargetPath>,
    ) -> Self {
        Self {
            sourcetype,
            source,
            index,
            host_key,
        }
    }
}

impl Partitioner for EventPartitioner {
    type Item = HecProcessedEvent;
    type Key = Option<Partitioned>;

    fn partition(&self, item: &Self::Item) -> Self::Key {
        let emit_err = |error, field| {
            emit!(TemplateRenderingError {
                error,
                field: Some(field),
                drop_event: false,
            })
        };

        let source = self.source.as_ref().and_then(|source| {
            source
                .render_string(&item.event)
                .map_err(|error| emit_err(error, SOURCE_FIELD))
                .ok()
        });

        let sourcetype = self.sourcetype.as_ref().and_then(|sourcetype| {
            sourcetype
                .render_string(&item.event)
                .map_err(|error| emit_err(error, SOURCETYPE_FIELD))
                .ok()
        });

        let index = self.index.as_ref().and_then(|index| {
            index
                .render_string(&item.event)
                .map_err(|error| emit_err(error, INDEX_FIELD))
                .ok()
        });

        let host = user_or_namespaced_path(
            &item.event,
            self.host_key.as_ref(),
            meaning::HOST,
            log_schema().host_key_target_path(),
        )
        .and_then(|path| item.event.get(&path))
        .and_then(|value| value.as_str().map(|s| s.to_string()));

        Some(Partitioned {
            token: item.event.metadata().splunk_hec_token(),
            source,
            sourcetype,
            index,
            host,
        })
    }
}

#[derive(PartialEq, Default, Clone, Debug)]
pub struct HecLogsProcessedEventMetadata {
    pub sourcetype: Option<String>,
    pub source: Option<String>,
    pub index: Option<String>,
    pub host: Option<Value>,
    pub timestamp: Option<f64>,
    pub fields: LogEvent,
    pub endpoint_target: EndpointTarget,
}

impl ByteSizeOf for HecLogsProcessedEventMetadata {
    fn allocated_bytes(&self) -> usize {
        self.sourcetype.allocated_bytes()
            + self.source.allocated_bytes()
            + self.index.allocated_bytes()
            + self.host.allocated_bytes()
            + self.fields.allocated_bytes()
    }
}

pub type HecProcessedEvent = ProcessedEvent<LogEvent, HecLogsProcessedEventMetadata>;

// determine the path for a field from one of the following use cases:
// 1. user provided a path in the config settings
//     a. If the path provided was an empty string, None is returned
// 2. namespaced path ("default")
//     a. if Legacy namespace, use the provided path from the global log schema
//     b. if Vector namespace, use the semantically defined path
fn user_or_namespaced_path(
    log: &LogEvent,
    user_key: Option<&OptionalTargetPath>,
    semantic: &str,
    legacy_path: Option<&OwnedTargetPath>,
) -> Option<OwnedTargetPath> {
    match user_key {
        Some(maybe_key) => maybe_key.path.clone(),
        None => match log.namespace() {
            LogNamespace::Vector => log.find_key_by_meaning(semantic).cloned(),
            LogNamespace::Legacy => legacy_path.cloned(),
        },
    }
}

pub fn process_log(event: Event, data: &HecLogData) -> HecProcessedEvent {
    let mut log = event.into_log();

    let sourcetype = data
        .sourcetype
        .and_then(|sourcetype| render_template_string(sourcetype, &log, SOURCETYPE_FIELD));

    let source = data
        .source
        .and_then(|source| render_template_string(source, &log, SOURCE_FIELD));

    let index = data
        .index
        .and_then(|index| render_template_string(index, &log, INDEX_FIELD));

    let host = user_or_namespaced_path(
        &log,
        data.host_key.as_ref(),
        meaning::HOST,
        log_schema().host_key_target_path(),
    )
    .and_then(|path| log.get(&path))
    .cloned();

    // only extract the timestamp if this is the Event endpoint, and if the setting
    // `auto_extract_timestamp` is false (because that indicates that we should leave
    // the timestamp in the event as-is, and let Splunk do the extraction).
    let timestamp = if EndpointTarget::Event == data.endpoint_target && !data.auto_extract_timestamp
    {

        let timestamp_configuration = data.timestamp_configuration.as_ref();
        let timestamp_key = timestamp_configuration
            .and_then(|config| config.timestamp_key.as_ref());
        let remove_from_event = timestamp_configuration
            .map(|config| config.remove_from_event)
            .unwrap_or(true);


        let timestamp_format = timestamp_configuration.map(|config| config.format.clone());

        // determine the actual path first
        let timestamp_path_opt = user_or_namespaced_path(
            &log,
            timestamp_key,
            meaning::TIMESTAMP,
            log_schema().timestamp_key_target_path(),
        );


        let ts = timestamp_path_opt.as_ref().and_then(|timestamp_path| {
            let value_opt = log.get(timestamp_path).cloned();
            match (value_opt, timestamp_format) {

                (None, _) => {
                    emit!(SplunkEventTimestampMissing {});
                    None
                }
                (Some(Value::Timestamp(ts)), _) => {
                        if let Some(key) = data.timestamp_nanos_key {
                            log.try_insert(event_path!(key), ts.timestamp_subsec_nanos() % 1_000_000);
                        }
                        Some((ts.timestamp_millis() as f64) / 1000f64)
                }

                (Some(Value::Integer(i)), Some(crate::sinks::splunk_hec::logs::config::TimestampFormat::Seconds)) => {
                    // convert
                    if let Some(key) = data.timestamp_nanos_key {
                        log.try_insert(event_path!(key), 0);
                    }
                    Some(i as f64)
                }

                (Some(Value::Integer(i)), Some(crate::sinks::splunk_hec::logs::config::TimestampFormat::MilliSeconds)) => {
                    // convert
                    if let Some(key) = data.timestamp_nanos_key {
                        log.try_insert(event_path!(key), ((i % 1000) * 1_000_000) as u32);
                    }
                    Some((i as f64) / 1000f64)
                }

                (Some(Value::Integer(i)), Some(crate::sinks::splunk_hec::logs::config::TimestampFormat::Nanos)) => {
                    // convert
                    if let Some(key) = data.timestamp_nanos_key {
                        log.try_insert(event_path!(key), (i % 1_000_000_000) as u32);
                    }
                    Some((i as f64) / 1_000_000_000f64)
                }

                (Some(Value::Bytes(b)), Some(crate::sinks::splunk_hec::logs::config::TimestampFormat::Regex(fmt))) => {
                    let s = match std::str::from_utf8(&b) {
                        Ok(s) => s,
                        Err(_) => {
                            emit!(SplunkEventTimestampInvalidType { r#type: "bytes" });
                            return None;
                        }
                    };

                    let date_time_result = parse_with_format(s, &fmt);
                    match date_time_result {
                        Ok(utc) => {
                            if let Some(key) = data.timestamp_nanos_key {
                                log.try_insert(event_path!(key), utc.timestamp_subsec_nanos() % 1_000_000);
                            }
                            Some((utc.timestamp_millis() as f64) / 1000f64)
                        }
                        Err(err) => {
                            error!("Failed to parse timestamp from regex for Splunk HEC event: {}", err);
                            emit!(SplunkEventTimestampInvalidType { r#type: "string" });
                            None
                        }
                    }
                }

                (Some(value),_) => {
                    emit!(SplunkEventTimestampInvalidType {
                        r#type: value.kind_str()
                    });
                    None
                }
            }
        });
        if remove_from_event && timestamp_path_opt.is_some(){
            let _ = log.remove(timestamp_path_opt.as_ref().unwrap());
        }
        ts
    } else {
        None
    };

    let fields = data
        .indexed_fields
        .iter()
        .filter_map(|field| {
            log.get((PathPrefix::Event, field))
                .map(|value| (field.to_string(), value.clone()))
        })
        .collect::<LogEvent>();

    let metadata = HecLogsProcessedEventMetadata {
        sourcetype,
        source,
        index,
        host,
        timestamp,
        fields,
        endpoint_target: data.endpoint_target,
    };

    ProcessedEvent {
        event: log,
        metadata,
    }
}

fn parse_with_format(s: &str, fmt: &str) -> Result<DateTime<Utc>, chrono::ParseError> {
    // RFC3339 (recommended for inputs like "2024-06-15T12:34:56.789Z")
    if fmt.is_empty() || fmt.eq_ignore_ascii_case("rfc3339") {
        let dt = DateTime::parse_from_rfc3339(s)?;
        return Ok(dt.with_timezone(&Utc));
    }

    // If the user format contains a literal 'Z' (UTC) strip it and parse NaiveDateTime
    if fmt.contains('Z') {
        let s_trim = s.strip_suffix('Z').unwrap_or(s);
        let fmt_trim = fmt.trim_end_matches('Z');
        let naive = NaiveDateTime::parse_from_str(s_trim, fmt_trim)?;
        return Ok(Utc.from_utc_datetime(&naive));
    }


    // Try parsing as NaiveDateTime first (no offset in input), then fall back to DateTime parse
    if let Ok(naive) = NaiveDateTime::parse_from_str(s, fmt) {
        return Ok(Utc.from_utc_datetime(&naive));
    }

    // Otherwise expect the format to include an offset specifier like %z or %:z
    let dt = DateTime::parse_from_str(s, fmt)?;
    Ok(dt.with_timezone(&Utc))
}

impl EventCount for HecProcessedEvent {
    fn event_count(&self) -> usize {
        // A HecProcessedEvent is mapped one-to-one with an event.
        1
    }
}
