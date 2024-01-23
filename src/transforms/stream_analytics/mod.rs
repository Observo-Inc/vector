mod top_n;
mod cardinality;
mod size_quantiles;

use std::{
    collections::{HashMap},
    pin::Pin,
    time::{Duration},
};

use async_stream::stream;
use futures::{stream, Stream, StreamExt};
use indexmap::IndexMap;
use serde_with::serde_as;
use vector_config::configurable_component;
use std::cmp::{min, max};

use crate::config::OutputId;
use crate::{
    config::{DataType, Input, TransformConfig, TransformContext, TransformOutput},
    event::{Event, LogEvent},
    schema,
    transforms::{TaskTransform, Transform},
    internal_events:: {
        StreamAnalyticsFlushed, StreamAnalyticsResets,
        StreamAnalyticsFieldProcessError, StreamAnalyticsPublishError, StreamAnalyticsResetPerEventError
    }
};

use crate::event::Value;
use vector_core::config::LogNamespace;
use std::borrow::{BorrowMut, Cow};
use std::collections::BTreeMap;
use std::fmt::Formatter;
use std::time::Instant;
use regex::Regex;
use vector_common::byte_size_of::ByteSizeOf;
use vector_core::EstimatedJsonEncodedSizeOf;
use vector_core::event::discriminant::Discriminant;
use crate::internal_events::{StreamAnalyticsFieldProcessedTotal, StreamAnalyticsResetError};
use crate::transforms::stream_analytics::cardinality::Cardinality;
use crate::transforms::stream_analytics::size_quantiles::SizeQuantile;
use crate::transforms::stream_analytics::top_n::TopN;

/// StreamAnalytics Calculators
#[serde_as]
#[configurable_component]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum Calculator {
    /// Top N for keys
    /// returns for each key top n values and their cardinality
    TopN,

    /// Cardinality for keys
    /// returns for each key, estimated cardinality
    Cardinality,

    /// SizeQuantile for keys
    /// returns for each key, estimated size quantiles
    SizeQuantile,
}


/// Configuration for the `stream_analytics` transform.
#[serde_as]
#[configurable_component(transform(
    "stream_analytics",
    "Generates analytic statistics for the stream of logs coming in.",
))]
#[derive(Clone, Debug, Derivative)]
#[derivative(Default)]
#[serde(deny_unknown_fields)]
pub struct StreamAnalyticsConfig {
    /// The interval to flush stats calculated, in milliseconds.
    #[serde(default = "default_flush_period_ms")]
    #[serde_as(as = "serde_with::DurationMilliSeconds<u64>")]
    #[derivative(Default(value = "default_flush_period_ms()"))]
    #[configurable(metadata(
    docs::additional_props_description = "The interval to flush stats calculated, in milliseconds. \
    Default 5 minutes."
    ))]
    pub flush_period_ms: Duration,

    /// The maximum number events processed after which flush stats.
    #[serde(default = "default_max_events")]
    #[derivative(Default(value = "default_max_events()"))]
    #[configurable(metadata(
    docs::additional_props_description = "The maximum number events processed after which flush stats. \
    Default 1M."
    ))]
    pub max_events: u64,

    /// The maximum size in bytes that will be processed for key or value.
    /// Max supported value is 255 bytes.
    #[serde(default = "default_processing_limit")]
    #[derivative(Default(value = "default_processing_limit()"))]
    #[configurable(metadata(
    docs::additional_props_description = "The maximum size in bytes that will be processed for key or value.\
    Max supported value is 1024 bytes. Default 256 bytes."
    ))]
    pub max_processing_limit: u16,

    /// The maximum number of internal states that can be buffered.
    #[serde(default = "default_max_internal_state_buffer")]
    #[derivative(Default(value = "default_max_internal_state_buffer()"))]
    #[configurable(metadata(
    docs::additional_props_description = "The maximum number of internal states that can be buffered."
    ))]
    pub max_internal_state_buffer: u16,

    /// The maximum number of labels to consider for TopN.
    /// Max 64 labels are supported
    #[serde(default = "default_max_top_n_labels")]
    #[derivative(Default(value = "default_max_top_n_labels()"))]
    #[configurable(metadata(
    docs::additional_props_description = "The maximum number of labels to consider for TopN. \
    Used only by top_n calculator. \
    Max 1024 labels are supported. Default 16 labels."
    ))]
    pub max_top_n_labels: u16,

    /// The TopN values to consider per Key.
    /// Max 16 values are supported
    #[serde(default = "default_max_top_n_values")]
    #[derivative(Default(value = "default_max_top_n_values()"))]
    #[configurable(metadata(
    docs::additional_props_description = "The maximum number TopN values to consider per Key. \
    Used only by top_n calculator. \
    Max 32 labels are supported. Default 5 values"
    ))]
    pub max_top_n_values: u8,

    /// The error rate for probabilistic calculations.
    #[serde(default = "default_error_rate")]
    #[derivative(Default(value = "default_error_rate()"))]
    #[configurable(metadata(
    docs::additional_props_description = "The error rate for probabilistic calculations. \
    Used only by cardinality calculator. \
    Default 0.005"
    ))]
    pub error_rate: f64,

    /// The probability for estimation calculations.
    #[serde(default = "default_probability")]
    #[derivative(Default(value = "default_probability()"))]
    #[configurable(metadata(
    docs::additional_props_description = "The probability for estimation calculations. \
    Used only by top_n calculator. \
    Default 0.95"
    ))]
    pub probability: f64,

    /// The max size of internal structure to use when performing quantiles estimations.
    #[serde(default = "default_quantile_estimation_size")]
    #[derivative(Default(value = "default_quantile_estimation_size()"))]
    #[configurable(metadata(
    docs::additional_props_description = "The max size of internal structure to use when performing quantiles estimations. \
    Used only by size_quantiles calculator. \
    Default 100"
    ))]
    quantile_estimation_size: u16,

    /// The quantiles to be estimated for size_quantiles calculator.
    /// Used only by size_quantiles calculator.
    #[serde(default)]
    #[configurable(metadata(
    docs::additional_props_description = "The quantiles to be estimated for size_quantiles calculator.\
    Used only by size_quantiles calculator. \
    Default [0.5, 0.75, 0.9, 0.95, 0.99]"
    ))]
    quantiles: Option<Vec<f64>>,

    /// A list of logical name of field that won't be considered for stats calculation
    ///
    #[serde(default)]
    #[configurable(metadata(
    docs::additional_props_description = "A list of logical name of field that won't be considered for stats calculation. \
    Default [\"time\", \"timestamp\", \"date\", \"datetime\"]"
    ))]
    pub skip_fields: Option<Vec<String>>,

    /// A map of logical name of field and a list of log field names.
    ///
    /// For each list of log field names all the statistics are generate along with the default ones
    ///
    #[serde(default)]
    #[configurable(metadata(
        docs::additional_props_description = "A map of logical name of field and a list of log field names. \
        For each list of log field names all the statistics are generate along with the default ones. \
        Field are combined only if their values are not Object or Array types or null. \
        Example: \
        combine_by_fields: \
            \"container_name_and_id\": [ \"kubernetes.container_name\", \"kubernetes.container_id\" ] "
    ))]
    pub combine_by_fields: IndexMap<String, Vec<String>>,

    /// An ordered list of fields by which to group events.
    ///
    /// Each group with matching values for the specified keys is calculated independently, allowing
    /// you to keep independent event streams separate. When no fields are specified, all events
    /// are combined in a single group.
    ///
    /// For example, if `group_by = ["host", "region"]`, then all incoming events that have the same
    /// host and region are grouped together before being calculated.
    #[serde(default)]
    #[configurable(metadata(
    docs::examples = "request_id",
    docs::examples = "user_id",
    docs::examples = "transaction_id",
    ))]
    pub group_by: Vec<String>,

    /// The list of Stream Analytics calculators to use.
    ///
    /// Defaults to all calculators.
    #[configurable(metadata(docs::examples = "example_calculators()"))]
    #[derivative(Default(value = "default_calculators()"))]
    #[serde(default = "default_calculators")]
    pub calculators: Option<Vec<Calculator>>,
}

const fn default_max_events() -> u64 {
    1_000_000 // 1M
}

const fn default_max_internal_state_buffer() -> u16 {
    2048
}

const fn default_max_top_n_labels() -> u16 {
    16
}

const fn default_max_top_n_values() -> u8 {
    5
}

const fn default_error_rate() -> f64 {
    0.005
}

const fn default_probability() -> f64 {
    0.95
}

const fn default_quantile_estimation_size() -> u16 {
    100
}

fn default_quantiles() -> Option<Vec<f64>> {
    Some(vec![0.5, 0.75, 0.9, 0.95, 0.99])
}

fn default_skip_fields() -> Option<Vec<String>> {
    Some(vec![
        "time".to_string(),
        "timestamp".to_string(),
        "date".to_string(),
        "datetime".to_string()
    ])
}

const fn default_processing_limit() -> u16 {
    256
}

const fn default_flush_period_ms() -> Duration {
    Duration::from_millis(300000) // 5 mins
}

const fn example_calculators() -> [&'static str; 3] {
    [
        "top_n",
        "cardinality",
        "size_quantile",
    ]
}

fn default_calculators() -> Option<Vec<Calculator>> {
    Some(vec![
        Calculator::TopN,
        Calculator::Cardinality,
        Calculator::SizeQuantile,
    ])
}

fn get_calculators(config: &StreamAnalyticsSanitisedConfig) -> Vec<Box<dyn StreamAnalyticsCalculator>> {
    let mut calculators: Vec<Box<dyn StreamAnalyticsCalculator>> = Vec::new();
    for calculator in config.calculators.as_ref().expect("Default calculators should always be present.") {
        match calculator {
            Calculator::TopN => {
                calculators.push(Box::new(TopN::new(config)))
            }
            Calculator::Cardinality => {
                calculators.push(Box::new(Cardinality::new(config)))
            }
            Calculator::SizeQuantile => {
                calculators.push(Box::new(SizeQuantile::new(config)))
            }
        }
    }
    calculators
}

impl_generate_config_from_default!(StreamAnalyticsConfig);

#[async_trait::async_trait]
#[typetag::serde(name = "stream_analytics")]
impl TransformConfig for StreamAnalyticsConfig {
    async fn build(&self, _context: &TransformContext) -> crate::Result<Transform> {
        StreamAnalytics::new(self).map(Transform::event_task)
    }

    fn input(&self) -> Input {
        Input::log()
    }

    fn outputs(
        &self,
        _: enrichment::TableRegistry,
        _: &[(OutputId, schema::Definition)],
        _: LogNamespace,
    ) -> Vec<TransformOutput> {
        // let mut output_definitions = HashMap::new();
        // output_definitions.insert("top_n",  BTreeMap<String, Value>);
        vec![TransformOutput::new(DataType::Log, HashMap::new())]
    }
}

pub trait StreamAnalyticsCalculator: std::fmt::Debug + Send + Sync {

    fn name(&self) -> String;
    fn process(&mut self, event_state: &StreamAnalyticsPerEventState, field_name: &String, value: &Value) -> Result<(), String>;
    fn publish_stat(&mut self, log: &mut LogEvent) -> Result<(), String>;
    fn reset(&mut self) -> Result<(), String>;
    fn reset_per_event_state(&mut self) -> Result<(), String>;

}

#[derive(Debug, Derivative)]
pub struct StreamAnalyticsPerEventState {
    event_size: usize,
}


#[derive(Debug, Derivative)]
pub struct StreamAnalyticsState {
    current_events_count: u64,
    last_flush: Instant,
    events_processed: HashMap<Discriminant, u64>,
}

impl StreamAnalyticsState {

    fn inc_event_metric(&mut self, key: &Discriminant) {
        let counter = self.events_processed
            .entry(key.clone())
            .or_insert(0);
        *counter += 1;
    }

    fn get_event_metric(&self, key: &Discriminant) -> u64 {
        let counter = self.events_processed.get(key);
        *(counter.or_else(|| Some(&0u64)).unwrap())
    }


    fn should_flush(&mut self, max_events: u64, duration: Duration) -> bool {
        if (Instant::now() - self.last_flush) >= duration {
            return true;
        }
        self.current_events_count += 1;
        if self.current_events_count > max_events {
            self.current_events_count = max_events; // So we return correct processed event count.
            return true;
        }

        false
    }

    fn flushed(&mut self) {
        self.current_events_count = 0;
        self.last_flush = Instant::now();
        self.events_processed.drain();
    }
}

#[derive(Debug, Derivative)]
pub struct StreamAnalyticsSanitisedConfig {
    flush_period: Duration,
    max_events: u64,
    max_internal_state_buffer: usize,
    max_top_n_labels: u16,
    max_top_n_values: u8,
    max_processing_limit: usize,
    error_rate: f64,
    probability: f64,
    quantile_estimation_size: usize,
    quantiles: Vec<f64>,
    skip_fields: Vec<String>,
    combine_by_fields: IndexMap<String, Vec<String>>,
    group_by: Vec<String>,
    calculators: Option<Vec<Calculator>>,
}

impl std::fmt::Display for StreamAnalyticsSanitisedConfig {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "flush_period = {}, max_events= {}, max_top_n_labels = {}, max_top_n_values = {}, max_processing_limit={}"
               , self.flush_period.as_millis(), self.max_events, self.max_top_n_labels, self.max_top_n_values
               , self.max_processing_limit)
    }
}

impl StreamAnalyticsSanitisedConfig {
    fn new(
        config: &StreamAnalyticsConfig,
    ) -> crate::Result<Self>  {
        Ok( StreamAnalyticsSanitisedConfig {
            flush_period: config.flush_period_ms,
            max_events: config.max_events,
            max_internal_state_buffer: config.max_internal_state_buffer as usize,
            max_top_n_labels: {
                if config.max_top_n_labels > 1024 {
                    warn!(message = "max_top_n_labels value will be set to max allowed value = 1024", IgnoredConfig = %config.max_top_n_labels, internal_log_rate_limit=true);
                }
                min(config.max_top_n_labels, 1024)
            },
            max_top_n_values: {
                if config.max_top_n_values > 32 {
                    warn!(message = "max_top_n_values value will be set to max allowed value = 32", IgnoredConfig = %config.max_top_n_values, internal_log_rate_limit=true);
                }
                min(config.max_top_n_values, 32)
            },
            max_processing_limit: {
                if config.max_processing_limit > 1024 {
                    warn!(message = "max_processing_limit value will be set to max allowed value = 1024", IgnoredConfig = %config.max_processing_limit, internal_log_rate_limit=true);
                }
                min(config.max_processing_limit, 1024) as usize
            }, // keep it usize as that type is used to compare
            error_rate: config.error_rate,
            probability: config.probability,
            quantile_estimation_size: config.quantile_estimation_size as usize,
            quantiles: config.quantiles.clone().or(default_quantiles())
                .expect("Default quantiles not set."),
            skip_fields: config.skip_fields.clone().or(default_skip_fields())
                .expect("Default Skip fields not set."),
            combine_by_fields: config.combine_by_fields.clone(),
            group_by: config.group_by.clone(),
            calculators: config.calculators.clone(),
        })
    }
}

#[derive(Debug, Derivative)]
pub struct StreamAnalytics {
    sanitised_config: StreamAnalyticsSanitisedConfig,
    grouped_calculators: HashMap<Discriminant, (Value, Vec<Box<dyn StreamAnalyticsCalculator>>)>,
    stream_analytics_state: StreamAnalyticsState,
    field_regex: Regex,
}

impl StreamAnalytics {
    pub fn new(
        config: &StreamAnalyticsConfig,
    ) -> crate::Result<Self> {
        let sanitised_conf = StreamAnalyticsSanitisedConfig::new(config)
            .expect("Sanitised StreamAnalytics config creation failed.");
        debug!(message = "Sanitised StreamAnalytics config.", Config = %sanitised_conf, internal_log_rate_limit=true);
        Ok(StreamAnalytics {
            grouped_calculators: HashMap::new(),
            sanitised_config: sanitised_conf,
            stream_analytics_state: StreamAnalyticsState {
                current_events_count: 0,
                last_flush: Instant::now(),
                events_processed: HashMap::new(),
            },
            field_regex: Regex::new(r"\[\d+\]").expect("Failed to compile field regex")
        })
    }

    fn insert_calculators(&mut self, discriminant: &Discriminant, log_event: &LogEvent) {
        if !self.grouped_calculators.contains_key(&discriminant) {
            let mut grp_map: BTreeMap<String, Value> = BTreeMap::new();
            (&self.sanitised_config.group_by).iter().for_each(|group_by_field_name| {
                grp_map.insert(group_by_field_name.to_string()
                               , log_event.get(group_by_field_name.as_str()).cloned()
                                   .or_else(|| Some(Value::Null)).unwrap());
            });
            self.grouped_calculators
                .insert(discriminant.clone(), (Value::from(grp_map), get_calculators(&self.sanitised_config)));
        }
    }

    fn sanitise_field(&self, field_name: String) -> String {
        if field_name.contains("[") {
            return self.field_regex.replace_all(field_name.as_str(), "").to_string();
        }
        field_name
    }

    fn is_valid_value_type(&self, value: &Value) -> bool {
        match value {
            Value::Object(_) => { false }
            Value::Array(_) => { false }
            Value::Null => { false }
            _ => { true }
        }
    }

    fn is_valid_value(&self, value: &Value) -> bool {
        if value.estimated_json_encoded_size_of() > self.sanitised_config.max_processing_limit {
            trace!( message =  "Value size large", Value = %&value.to_string_lossy().to_string()[0..20], ValueSize = %value.allocated_bytes(), internal_log_rate_limit=true);
            return true;
        }
        true
    }

    fn is_valid_field(&self, field_name: &String, skip_fields: &Vec<String>) -> bool {
        if field_name.len() > self.sanitised_config.max_processing_limit {
            trace!( message = "Field size large {} {}", FieldName = %field_name, FieldSize = %field_name.len(), internal_log_rate_limit=true);
            return false;
        }

        let field_name = field_name.to_lowercase();

        if skip_fields.contains(&field_name) {
            return false;
        }

        let split_filed = field_name.rsplit_once('.');
        let match_field = if split_filed.is_some() {
            split_filed.unwrap().1
        } else {
            &field_name
        };

        if skip_fields.contains(&match_field.to_string()) {
            return false;
        }

        return true;
    }

    fn iterate_on_event(&mut self, event: Event) {
        match event {
            Event::Metric(_) => { return; }
            Event::Log(log_event) => {
                let event_state = StreamAnalyticsPerEventState {event_size: log_event.estimated_json_encoded_size_of()};


                let discriminant = Discriminant::from_log_event(&log_event, &self.sanitised_config.group_by);
                self.insert_calculators(&discriminant, &log_event);
                self.stream_analytics_state.inc_event_metric(&discriminant);

                // reset for event
                self.reset_per_event(&discriminant);

                let combined_values = self.get_combined_field_values(&log_event);

                let mut fields_processed: u64 = 0;
                for (field_name, value) in combined_values.iter() {
                    fields_processed += 1;
                    trace!(message = "Group_by Field name being processed.", FieldName = %field_name, internal_log_rate_limit=true);
                    self.process_field(&event_state, &discriminant, field_name.clone(), &Value::from(Cow::from(value)));
                }

                // Process all fields by default
                for (field_name, value) in log_event.all_fields().unwrap() {
                    fields_processed += 1;
                    trace!(message = "Field name being processed.", FieldName = %field_name, internal_log_rate_limit=true);
                    self.process_field(&event_state, &discriminant, field_name, value);
                }

                let (_, calculators) = self.grouped_calculators
                    .get_mut(&discriminant).expect("grouped_calculator can't be empty");
                for stream_analytics_calculator in calculators.iter_mut() {
                    emit!(StreamAnalyticsFieldProcessedTotal {
                            calculator: stream_analytics_calculator.name(),
                            total_fields_processed: fields_processed,
                    });
                }
            }
            Event::Trace(_) => { return; }
        }
    }

    fn reset_per_event(&mut self, discriminant: &Discriminant) {
        let (_, calculators) = self.grouped_calculators
            .get_mut(discriminant).expect("grouped_calculator can't be empty");
        for stream_analytics_calculator in calculators.iter_mut() {
            if let Err(error) = stream_analytics_calculator.reset_per_event_state() {
                warn!(message = "Failed to reset calculator per event.", %error, calculator = %stream_analytics_calculator.name(), internal_log_rate_limit=true);
                emit!(StreamAnalyticsResetPerEventError{
                    error: error,
                    calculator: stream_analytics_calculator.name()})
            }
        }
    }

    fn get_combined_field_values(&mut self, log_event: &LogEvent) -> Vec<(String, String)> {
        let mut combined_values: Vec<(String, String)> = Vec::new();
        'combine_loop: for (field_name, combined_by) in &self.sanitised_config.combine_by_fields {
            let mut combined_value: Vec<String> = Vec::new();
            for combine_by_field in combined_by {
                let Some(val) = log_event.get(combine_by_field.as_str()) else {
                    continue 'combine_loop
                };
                if self.is_valid_value_type(val) {
                    combined_value.push(val.to_string_lossy().to_string());
                } else {
                    continue 'combine_loop;
                }
            }
            combined_values.push((field_name.to_string(), combined_value.join("#~#")));
        }
        combined_values
    }

    fn process_field(&mut self,
                     event_state: &StreamAnalyticsPerEventState,
                     discriminant: &Discriminant,
                     field_name: String,
                     value: &Value
    ) {
        if self.is_valid_field(&field_name, self.sanitised_config.skip_fields.as_ref())
            && self.is_valid_value(value) {
            // self.stream_analytics_state.inc_metric(grouped_by_keys);
            let key = self.sanitise_field(field_name);
            let (_, stream_analytics_calculators) = self.grouped_calculators
                        .get_mut(discriminant).expect("grouped_calculator can't be empty");
            for stream_analytics_calculator in stream_analytics_calculators {
                if let Err(error) = stream_analytics_calculator.process(&event_state, &key, value) {
                    warn!(message = "Failed to process field.", %error, field_name = %key, internal_log_rate_limit=true);
                    emit!(StreamAnalyticsFieldProcessError {error: error, calculator: stream_analytics_calculator.name()})
                }
            }
        }
    }

    fn flush(&mut self) -> Vec<Event> {
        let mut sa_events: Vec<Event> = Vec::new();
        self.grouped_calculators.drain()
            .for_each(|(discriminant, (grouped_by, ref mut calculators))| {

                let mut log = LogEvent::default();
                let mut stats_summary = BTreeMap::new();
                stats_summary.insert("events_processed".to_string(), Value::from(self.stream_analytics_state.get_event_metric(&discriminant)));
                log.insert("stats_summary", Value::Object(stats_summary));
                log.insert("group_by", grouped_by.clone());

                for stream_analytics_calculator in calculators.iter_mut() {
                    match stream_analytics_calculator.publish_stat(log.borrow_mut()) {
                        Ok(_) => {emit!(StreamAnalyticsFlushed{calculator: stream_analytics_calculator.name()})}
                        Err(error) => {
                            warn!(message = "Failed to flush calculator.", %error, calculator = %stream_analytics_calculator.name(), internal_log_rate_limit=true);
                            emit!(StreamAnalyticsPublishError {error: error, calculator: stream_analytics_calculator.name()})
                        }
                    }

                    match stream_analytics_calculator.reset(){
                        Ok(_) => {emit!(StreamAnalyticsResets{calculator: stream_analytics_calculator.name()})}
                        Err(error) => {
                            warn!(message = "Failed to reset calculator.", %error, calculator = %stream_analytics_calculator.name(), internal_log_rate_limit=true);
                            emit!(StreamAnalyticsResetError {error: error, calculator: stream_analytics_calculator.name().clone()})
                        }
                    }
                }

                sa_events.push(Event::Log(log));
            });

        self.stream_analytics_state.flushed();
        sa_events
    }

    fn flush_into(&mut self, output: &mut Vec<Event>) {
        if self.stream_analytics_state.should_flush(self.sanitised_config.max_events, self.sanitised_config.flush_period) {
            output.extend(self.flush());
        }
    }

    fn flush_all_into(&mut self, output: &mut Vec<Event>) {
        output.extend(self.flush());
    }

    fn transform_one(&mut self, output: &mut Vec<Event>, event: Event) {
        self.iterate_on_event(event);
        self.flush_into(output);
    }
}

impl TaskTransform<Event> for StreamAnalytics {
    fn transform(
        self: Box<Self>,
        mut input_rx: Pin<Box<dyn Stream<Item = Event> + Send>>,
    ) -> Pin<Box<dyn Stream<Item = Event> + Send>>
    where
        Self: 'static,
    {
        let mut me = self;

        let poll_period = Duration::from_millis(
            max(me.sanitised_config.flush_period.as_millis()/3, 5000)
                as u64);

        let mut flush_stream = tokio::time::interval(poll_period);

        Box::pin(
            stream! {
              loop {
                let mut output = Vec::new();
                let done = tokio::select! {
                    _ = flush_stream.tick() => {
                      me.flush_into(&mut output);
                      false
                    }
                    maybe_event = input_rx.next() => {
                      match maybe_event {
                        None => {
                          me.flush_all_into(&mut output);
                          true
                        }
                        Some(event) => {
                          me.transform_one(&mut output, event);
                          false
                        }
                      }
                    }
                };
                yield stream::iter(output.into_iter());
                if done { break }
              }
            }
            .flatten(),
        )
    }
}


#[cfg(test)]
mod test {
    use async_graphql::InputType;
    // use serde_json::json;
    use tokio::sync::mpsc;
    use tokio_stream::wrappers::ReceiverStream;
    // use vrl::value::Kind;

    use super::*;
    use crate::event::{LogEvent};
    use crate::test_util::components::assert_transform_compliance;
    use crate::transforms::test::create_topology;
    // use lookup::owned_value_path;

    #[test]
    fn generate_config() {
        crate::test_util::test_generate_config::<StreamAnalyticsConfig>();
    }

        #[tokio::test]
    async fn config_defaults() {
        let config = toml::from_str::<StreamAnalyticsConfig>(
            r#"

            "#,
        );

        match config {
            Ok(conf) => {
                assert_eq!(conf.max_events, default_max_events());
                assert_eq!(conf.calculators.unwrap().len(), 3);
                assert_eq!(conf.error_rate, 0.005);

            },
            Err(_err) => unreachable!("Should not fail."),
        }
    }

    // fn default_ssa_message(size_quantiles: bool) -> LogEvent {
    //     let mut e_1 = LogEvent::default();
    //     e_1.insert("group_by", Value::from(BTreeMap::new()));
    //     e_1.insert("cardinality", Value::from(BTreeMap::new()));
    //     let mut summary = BTreeMap::new();
    //     summary.insert("events_processed".to_string(), Value::from(0));
    //     e_1.insert("stats_summary", Value::from(summary));
    //     if size_quantiles {
    //         e_1.insert("size_quantiles", Value::from(BTreeMap::new()));
    //     }
    //     e_1.insert("top_n", Value::from(BTreeMap::new()));
    //     e_1
    // }

    #[tokio::test]
    async fn ssa_for_default_fields() {
        let config = toml::from_str::<StreamAnalyticsConfig>(
            r#"
max_events = 5
quantiles = [0.99]
"#,
        )
            .unwrap();

        assert_transform_compliance(async move {
            let (tx, rx) = mpsc::channel(1);
            let (topology, mut out) = create_topology(ReceiverStream::new(rx), config).await;

            let mut e_1 = LogEvent::from("test message 1");
            e_1.insert("field_1", 1);
            e_1.insert("time", "good times");
            e_1.insert("field_2", "1");

            let mut e_2 = LogEvent::from("test message 2");
            e_2.insert("field_1", 2);
            e_2.insert("field_2", "2");
            e_1.insert("date", "good dates");

            let mut e_3 = LogEvent::from("test message 3");
            e_3.insert("field_1", 3);
            e_3.insert("field_2", "1");

            let mut e_4 = LogEvent::from("test message 4");
            e_4.insert("field_1", 4);
            e_4.insert("field_2", "1");
            e_4.insert("field_3", "yep");

            let mut e_5 = LogEvent::from("test message 5");
            e_5.insert("field_1", 5);
            e_5.insert("field_2", "2");
            e_5.insert("field_4", "value1");

            for event in vec![e_1.into(), e_2.into(), e_3.into(), e_4.into(), e_5.into()] {
                tx.send(event).await.unwrap();
            };

            let output_1 = out.recv().await.unwrap().into_log();

            assert_eq!(output_1.get(".size_quantiles").is_some(), true);
            assert_eq!(output_1.get(".top_n").is_some(), true);
            assert_eq!(output_1.get(".cardinality").is_some(), true);
            assert_eq!(output_1.get(".stats_summary").is_some(), true);

            assert_eq!(output_1.get("cardinality.time"), None);
            assert_eq!(output_1.get("cardinality.date"), None);
            assert_eq!(output_1.get("top_n.time"), None);
            assert_eq!(output_1.get("top_n.date"), None);
            assert_eq!(output_1.get("stats_summary.events_processed").unwrap().to_string_lossy(), "5");

            // println!("cardinality = {:?}", output_1.get("cardinality").unwrap().to_string_lossy().to_string());

            assert!(output_1["cardinality.field_1"].as_float().unwrap().as_ref() - 5.0 <= 0.005);
            assert!(output_1["cardinality.field_2"].as_float().unwrap().as_ref() - 2.0 <= 0.005);
            assert!(output_1["cardinality.field_3"].as_float().unwrap().as_ref() - 1.0 <= 0.005);
            assert!(output_1["cardinality.field_4"].as_float().unwrap().as_ref() - 1.0 <= 0.005);

            // println!("top_n = {:?}", output_1.get("top_n").unwrap().to_string_lossy().to_string());
            assert_eq!(output_1.get("top_n.field_1").unwrap().to_string_lossy(), "{\"1\":1,\"2\":1,\"3\":1,\"4\":1,\"5\":1}");
            assert_eq!(output_1.get("top_n.field_2").is_some(), true);
            assert_eq!(output_1.get("top_n.field_3").unwrap().to_string_lossy(), "{\"yep\":1}");
            assert_eq!(output_1.get("top_n.field_4").is_some(), true);

            // println!("size_quantiles = {:?}", output_1.get("size_quantiles").unwrap().to_string_lossy().to_string());
            assert_eq!(output_1.get("size_quantiles.field_1").is_some(), true);
            assert!(output_1.get("size_quantiles.field_2.percent_size_quantiles[0]").unwrap().as_float().expect("Need float").as_ref() - 2.0 <= 0.9999);
            assert!(output_1.get("size_quantiles.field_2.raw_size_quantiles[0]").unwrap().as_float().expect("Need float").as_ref() - 3.0 <= 0.9);

            assert_eq!(output_1.get("size_quantiles.field_3").is_some(), true);
            assert!(output_1.get("size_quantiles.field_4.percent_size_quantiles[0]").unwrap().as_float().expect("Need float").as_ref() - 6.0 <= 0.9999);
            assert!(output_1.get("size_quantiles.field_4.raw_size_quantiles[0]").unwrap().as_float().expect("Need float").as_ref() - 8.0 <= 0.9);

            drop(tx);
            topology.stop().await;
            // assert_eq!(out.recv().await.unwrap().into_log(), default_ssa_message(true));
            assert_eq!(out.recv().await, None);

        })
            .await;
    }

    #[tokio::test]
    async fn ssa_no_size_quantiles() {
        let config = toml::from_str::<StreamAnalyticsConfig>(
            r#"
max_events = 5
quantiles = [0.99]
calculators = [ "top_n", "cardinality"]
"#,
        )
            .unwrap();

        assert_transform_compliance(async move {
            let (tx, rx) = mpsc::channel(1);
            let (topology, mut out) = create_topology(ReceiverStream::new(rx), config).await;

            let mut e_1 = LogEvent::from("test message 1");
            e_1.insert("field_1", 1);
            e_1.insert("time", "good times");
            e_1.insert("field_2", "1");

            let mut e_2 = LogEvent::from("test message 2");
            e_2.insert("field_1", 2);
            e_2.insert("field_2", "2");
            e_1.insert("date", "good dates");

            let mut e_3 = LogEvent::from("test message 3");
            e_3.insert("field_1", 3);
            e_3.insert("field_2", "1");

            let mut e_4 = LogEvent::from("test message 4");
            e_4.insert("field_1", 4);
            e_4.insert("field_2", "1");
            e_4.insert("field_3", "yep");

            let mut e_5 = LogEvent::from("test message 5");
            e_5.insert("field_1", 5);
            e_5.insert("field_2", "2");
            e_5.insert("field_4", "value1");

            for event in vec![e_1.into(), e_2.into(), e_3.into(), e_4.into(), e_5.into()] {
                tx.send(event).await.unwrap();
            };

            let output_1 = out.recv().await.unwrap().into_log();

            assert_eq!(output_1.get(".size_quantiles").is_some(), false);
            assert_eq!(output_1.get(".top_n").is_some(), true);
            assert_eq!(output_1.get(".cardinality").is_some(), true);
            assert_eq!(output_1.get(".stats_summary").is_some(), true);

            assert_eq!(output_1.get("cardinality.time"), None);
            assert_eq!(output_1.get("cardinality.date"), None);
            assert_eq!(output_1.get("top_n.time"), None);
            assert_eq!(output_1.get("top_n.date"), None);
            assert_eq!(output_1.get("stats_summary.events_processed").unwrap().to_string_lossy(), "5");

            // println!("cardinality = {:?}", output_1.get("cardinality").unwrap().to_string_lossy().to_string());

            assert!(output_1["cardinality.field_1"].as_float().unwrap().as_ref() - 5.0 <= 0.005);
            assert!(output_1["cardinality.field_2"].as_float().unwrap().as_ref() - 2.0 <= 0.005);
            assert!(output_1["cardinality.field_3"].as_float().unwrap().as_ref() - 1.0 <= 0.005);
            assert!(output_1["cardinality.field_4"].as_float().unwrap().as_ref() - 1.0 <= 0.005);

            // println!("top_n = {:?}", output_1.get("top_n").unwrap().to_string_lossy().to_string());
            assert_eq!(output_1.get("top_n.field_1").unwrap().to_string_lossy(), "{\"1\":1,\"2\":1,\"3\":1,\"4\":1,\"5\":1}");
            assert_eq!(output_1.get("top_n.field_2").is_some(), true);
            assert_eq!(output_1.get("top_n.field_3").unwrap().to_string_lossy(), "{\"yep\":1}");
            assert_eq!(output_1.get("top_n.field_4").is_some(), true);

            drop(tx);
            topology.stop().await;
            // assert_eq!(out.recv().await.unwrap().into_log(), default_ssa_message(false));
            assert_eq!(out.recv().await, None);

        })
            .await;
    }

    #[tokio::test]
    async fn ssa_combine_fields() {
        let config = toml::from_str::<StreamAnalyticsConfig>(
            r#"
max_events = 6
quantiles = [0.99]
max_top_n_values = 8
calculators = [ "top_n", "cardinality"]
combine_by_fields = {"combined_field" = ["field_1", "field_2"], "combined_field2" = ["field_1", "field_2.inside.leaf"] }
"#,
        )
            .unwrap();

        assert_transform_compliance(async move {
            let (tx, rx) = mpsc::channel(1);
            let (topology, mut out) = create_topology(ReceiverStream::new(rx), config).await;

            let mut e_1 = LogEvent::from("test message 1");
            e_1.insert("field_1", 1);
            e_1.insert("time", "good times");
            e_1.insert("field_2", "1");
            e_1.insert("field_2.inside.leaf", "1");

            let mut e_2 = LogEvent::from("test message 2");
            e_2.insert("field_1", 2);
            e_2.insert("field_2", "2");
            e_2.insert("field_2.inside.leaf", "2");
            e_1.insert("date", "good dates");

            let mut e_3 = LogEvent::from("test message 3");
            e_3.insert("field_1", 3);
            e_3.insert("field_2", "1");

            let mut e_4 = LogEvent::from("test message 4");
            e_4.insert("field_1", 4);
            e_4.insert("field_2", "1");
            e_4.insert("field_2.inside.leaf", "1");
            e_4.insert("field_3", "yep");

            let mut e_5 = LogEvent::from("test message 5");
            e_5.insert("field_1", 5);
            e_5.insert("field_2", "2");

            e_5.insert("field_4", "value1");

            let mut e_6 = LogEvent::from("test message 6");
            e_6.insert("field_1", 6);
            e_6.insert("field_2", "2");
            e_6.insert("field_2.inside.leaf", "2");

            e_6.insert("field_4", "value1");

            for event in vec![e_1.into(), e_2.into(), e_3.into(), e_4.into(), e_5.into(), e_6.into()] {
                tx.send(event).await.unwrap();
            };

            let output_1 = out.recv().await.unwrap().into_log();
            println!("output_1 = {}", output_1.as_map().unwrap().to_value().into_json().unwrap());

            assert_eq!(output_1.get(".size_quantiles").is_some(), false);
            assert_eq!(output_1.get(".top_n").is_some(), true);
            assert_eq!(output_1.get(".cardinality").is_some(), true);
            assert_eq!(output_1.get(".stats_summary").is_some(), true);

            assert_eq!(output_1.get("cardinality.time"), None);
            assert_eq!(output_1.get("cardinality.date"), None);
            assert_eq!(output_1.get("top_n.time"), None);
            assert_eq!(output_1.get("top_n.date"), None);
            assert_eq!(output_1.get("stats_summary.events_processed").unwrap().to_string_lossy(), "6");

            // println!("cardinality = {:?}", output_1.get("cardinality").unwrap().to_string_lossy().to_string());

            assert!(output_1["cardinality.field_1"].as_float().unwrap().as_ref() - 6.0 <= 0.005);
            assert!(output_1["cardinality.field_2"].as_float().unwrap().as_ref() - 2.0 <= 0.005);
            assert!(output_1["cardinality.field_3"].as_float().unwrap().as_ref() - 1.0 <= 0.005);
            assert!(output_1["cardinality.field_4"].as_float().unwrap().as_ref() - 1.0 <= 0.005);
            assert!(output_1["cardinality.combined_field"].as_float().unwrap().as_ref() - 2.0 <= 0.005);
            assert!(output_1["cardinality.combined_field2"].as_float().unwrap().as_ref() - 4.0 <= 0.005);

            // println!("top_n = {:?}", output_1.get("top_n").unwrap().to_string_lossy().to_string());
            assert_eq!(output_1.get("top_n.field_1").unwrap().to_string_lossy(), "{\"1\":1,\"2\":1,\"3\":1,\"4\":1,\"5\":1,\"6\":1}");
            assert_eq!(output_1.get("top_n.field_2").is_some(), true);
            assert_eq!(output_1.get("top_n.field_3").unwrap().to_string_lossy(), "{\"yep\":1}");
            assert_eq!(output_1.get("top_n.field_4").is_some(), true);
            assert_eq!(output_1.get("top_n.\"field_2.inside.leaf\"").unwrap().to_string_lossy(), "{\"1\":2,\"2\":2}");
            assert_eq!(output_1.get("top_n.combined_field").unwrap().to_string_lossy(), "{\"3#~#1\":1,\"5#~#2\":1}");
            assert_eq!(output_1.get("top_n.combined_field2").unwrap().to_string_lossy(), "{\"1#~#1\":1,\"2#~#2\":1,\"4#~#1\":1,\"6#~#2\":1}");


            drop(tx);
            topology.stop().await;
            // assert_eq!(out.recv().await.unwrap().into_log(), default_ssa_message(false));
            assert_eq!(out.recv().await, None);
        })
            .await;
    }

    #[tokio::test]
    async fn ssa_group_by_fields() {
        let config = toml::from_str::<StreamAnalyticsConfig>(
            r#"
max_events = 3
flush_period_ms = 1000
quantiles = [0.99]
max_top_n_values = 8
calculators = [ "top_n", "cardinality"]
group_by = ["field_3", "field_4"]
skip_fields = ["_ob", "time", "date"]
combine_by_fields = {"combined_field" = ["field_1", "field_2"], "combined_field2" = ["field_1", "field_2.inside.leaf"] }
"#,
        )
            .unwrap();

        assert_transform_compliance(async move {
            let (tx, rx) = mpsc::channel(1);
            let (topology, mut out) = create_topology(ReceiverStream::new(rx), config).await;

            let mut e_1 = LogEvent::from("test message 1");
            e_1.insert("field_1", 1);
            e_1.insert("_ob", 1);
            e_1.insert("time", "good times");
            e_1.insert("field_2", "1");
            e_1.insert("field_2.inside.leaf", "1");

            let mut e_2 = LogEvent::from("test message 2");
            e_2.insert("field_1", 2);
            e_2.insert("field_2", "2");
            e_2.insert("field_2.inside.leaf", "2");
            e_1.insert("date", "good dates");

            let mut e_3 = LogEvent::from("test message 3");
            e_3.insert("field_1", 3);
            e_3.insert("field_9._ob.source", 3);
            e_3.insert("field_2", "1");

            let mut e_4 = LogEvent::from("test message 4");
            e_4.insert("field_1", 4);
            e_4.insert("field_2", "1");
            e_4.insert("field_2.inside.leaf", "1");
            e_4.insert("field_3", "yep");

            let mut e_5 = LogEvent::from("test message 5");
            e_5.insert("field_1", 5);
            e_5.insert("field_2", "2");

            e_5.insert("field_4", "value1");

            let mut e_6 = LogEvent::from("test message 6");
            e_6.insert("field_1", 6);
            e_6.insert("field_2", "2");
            e_6.insert("field_2.inside.leaf", "2");
            e_6.insert("field_3", "yep");

            e_6.insert("field_4", "value1");

            for event in vec![e_1.into(), e_2.into(), e_3.into()] {
                tx.send(event).await.unwrap();
            };

            let output_1 = out.recv().await.unwrap().into_log();
            println!("output_1 = {}", output_1.as_map().unwrap().to_value().into_json().unwrap());

            assert_eq!(output_1.get(".size_quantiles").is_some(), false);
            assert_eq!(output_1.get(".top_n").is_some(), true);
            assert_eq!(output_1.get(".cardinality").is_some(), true);
            assert_eq!(output_1.get(".stats_summary").is_some(), true);

            assert_eq!(output_1.get("cardinality.time"), None);
            assert_eq!(output_1.contains("cardinality.\"field_9._ob.source\""), true);
            assert_eq!(output_1.get("cardinality.date"), None);
            assert_eq!(output_1.get("top_n.time"), None);
            assert_eq!(output_1.get("top_n.date"), None);
            assert_eq!(output_1.get("stats_summary.events_processed").unwrap().to_string_lossy(), "3");

            assert!(output_1["cardinality.field_1"].as_float().unwrap().as_ref() - 3.0 <= 0.005);
            assert!(output_1["cardinality.field_2"].as_float().unwrap().as_ref() - 1.0 <= 0.005);
            assert_eq!(output_1.get("cardinality.field_3"), None);
            assert_eq!(output_1.get("cardinality.field_4"), None);
            assert!(output_1["cardinality.combined_field"].as_float().unwrap().as_ref() - 1.0 <= 0.005);
            assert!(output_1["cardinality.combined_field2"].as_float().unwrap().as_ref() - 2.0 <= 0.005);

            // println!("top_n = {:?}", output_1.get("top_n").unwrap().to_string_lossy().to_string());
            assert_eq!(output_1.get("top_n.field_1").unwrap().to_string_lossy(), "{\"1\":1,\"2\":1,\"3\":1}");
            assert_eq!(output_1.get("top_n.field_2").is_some(), true);
            assert_eq!(output_1.get("top_n.field_3"), None);
            assert_eq!(output_1.get("top_n.field_4"), None);
            assert_eq!(output_1.get("top_n.\"field_2.inside.leaf\"").unwrap().to_string_lossy(), "{\"1\":1,\"2\":1}");
            assert_eq!(output_1.get("top_n.combined_field").unwrap().to_string_lossy(), "{\"3#~#1\":1}");
            assert_eq!(output_1.get("top_n.combined_field2").unwrap().to_string_lossy(), "{\"1#~#1\":1,\"2#~#2\":1}");

            assert_eq!(output_1.get("group_by").is_some(), true);
            assert_eq!(output_1.get("group_by.field_3").unwrap().to_string_lossy(), "<null>");
            assert_eq!(output_1.get("group_by.field_4").unwrap().to_string_lossy(), "<null>");

            tx.send(e_4.into()).await.unwrap();
            let output_2 = out.recv().await.unwrap().into_log();
            println!("output_2 = {}", output_2.as_map().unwrap().to_value().into_json().unwrap());

            assert_eq!(output_2.get(".size_quantiles").is_some(), false);
            assert_eq!(output_2.get(".top_n").is_some(), true);
            assert_eq!(output_2.get(".cardinality").is_some(), true);
            assert_eq!(output_2.get(".stats_summary").is_some(), true);

            assert_eq!(output_2.get("cardinality.time"), None);
            assert_eq!(output_2.get("cardinality.date"), None);
            assert_eq!(output_2.get("top_n.time"), None);
            assert_eq!(output_2.get("top_n.date"), None);
            assert_eq!(output_2.get("stats_summary.events_processed").unwrap().to_string_lossy(), "1");

            assert!(output_2["cardinality.field_1"].as_float().unwrap().as_ref() - 1.0 <= 0.005);
            assert!(output_2["cardinality.\"field_2.inside.leaf\""].as_float().unwrap().as_ref() - 1.0 <= 0.005);
            assert!(output_2["cardinality.field_3"].as_float().unwrap().as_ref() - 1.0 <= 0.005);

            assert_eq!(output_2.get("cardinality.field_4"), None);
            assert_eq!(output_2.get("cardinality.combined_field"), None);
            assert!(output_2["cardinality.combined_field2"].as_float().unwrap().as_ref() - 1.0 <= 0.005);

            // println!("top_n = {:?}", output_1.get("top_n").unwrap().to_string_lossy().to_string());
            assert_eq!(output_2.get("top_n.field_1").unwrap().to_string_lossy(), "{\"4\":1}");
            assert_eq!(output_2.get("top_n.field_2").is_some(), false);
            assert_eq!(output_2.get("top_n.field_3").unwrap().to_string_lossy(), "{\"yep\":1}");
            assert_eq!(output_2.get("top_n.field_4"), None);
            assert_eq!(output_2.get("top_n.\"field_2.inside.leaf\"").unwrap().to_string_lossy(), "{\"1\":1}");
            assert_eq!(output_2.get("top_n.combined_field"), None);
            assert_eq!(output_2.get("top_n.combined_field2").unwrap().to_string_lossy(), "{\"4#~#1\":1}");

            assert_eq!(output_2.get("group_by").is_some(), true);
            assert_eq!(output_2.get("group_by.field_3").unwrap().to_string_lossy(), "yep");
            assert_eq!(output_2.get("group_by.field_4").unwrap().to_string_lossy(), "<null>");


            tx.send(e_5.into()).await.unwrap();
            let output_3 = out.recv().await.unwrap().into_log();
            println!("output_3 = {}", output_3.as_map().unwrap().to_value().into_json().unwrap());

            assert_eq!(output_3.get(".size_quantiles").is_some(), false);
            assert_eq!(output_3.get(".top_n").is_some(), true);
            assert_eq!(output_3.get(".cardinality").is_some(), true);
            assert_eq!(output_3.get(".stats_summary").is_some(), true);

            assert_eq!(output_3.get("cardinality.time"), None);
            assert_eq!(output_3.get("cardinality.date"), None);
            assert_eq!(output_3.get("top_n.time"), None);
            assert_eq!(output_3.get("top_n.date"), None);
            assert_eq!(output_3.get("stats_summary.events_processed").unwrap().to_string_lossy(), "1");

            assert!(output_3["cardinality.field_1"].as_float().unwrap().as_ref() - 1.0 <= 0.005);
            assert!(output_3["cardinality.field_2"].as_float().unwrap().as_ref() - 1.0 <= 0.005);
            assert!(output_3["cardinality.field_4"].as_float().unwrap().as_ref() - 1.0 <= 0.005);

            assert_eq!(output_3.get("cardinality.field_3"), None);
            assert_eq!(output_3.get("cardinality.combined_field2"), None);
            assert!(output_3["cardinality.combined_field"].as_float().unwrap().as_ref() - 1.0 <= 0.005);

            // println!("top_n = {:?}", output_1.get("top_n").unwrap().to_string_lossy().to_string());
            assert_eq!(output_3.get("top_n.field_1").unwrap().to_string_lossy(), "{\"5\":1}");
            assert_eq!(output_3.get("top_n.field_2").is_some(), true);
            assert_eq!(output_3.get("top_n.field_4").unwrap().to_string_lossy(), "{\"value1\":1}");
            assert_eq!(output_3.get("top_n.field_3"), None);
            assert_eq!(output_3.get("top_n.\"field_2.inside.leaf\""), None);
            assert_eq!(output_3.get("top_n.combined_field2"), None);
            assert_eq!(output_3.get("top_n.combined_field").unwrap().to_string_lossy(), "{\"5#~#2\":1}");

            assert_eq!(output_3.get("group_by").is_some(), true);
            assert_eq!(output_3.get("group_by.field_4").unwrap().to_string_lossy(), "value1");
            assert_eq!(output_3.get("group_by.field_3").unwrap().to_string_lossy(), "<null>");

            tx.send(e_6.into()).await.unwrap();
            let output_4 = out.recv().await.unwrap().into_log();
            println!("output_4 = {}", output_4.as_map().unwrap().to_value().into_json().unwrap());

            assert_eq!(output_4.get(".size_quantiles").is_some(), false);
            assert_eq!(output_4.get(".top_n").is_some(), true);
            assert_eq!(output_4.get(".cardinality").is_some(), true);
            assert_eq!(output_4.get(".stats_summary").is_some(), true);

            assert_eq!(output_4.get("cardinality.time"), None);
            assert_eq!(output_4.get("cardinality.date"), None);
            assert_eq!(output_4.get("top_n.time"), None);
            assert_eq!(output_4.get("top_n.date"), None);
            assert_eq!(output_4.get("stats_summary.events_processed").unwrap().to_string_lossy(), "1");

            assert!(output_4["cardinality.field_1"].as_float().unwrap().as_ref() - 1.0 <= 0.005);
            assert_eq!(output_4.get("cardinality.field_2"), None);
            assert!(output_4["cardinality.field_3"].as_float().unwrap().as_ref() - 1.0 <= 0.005);
            assert!(output_4["cardinality.field_4"].as_float().unwrap().as_ref() - 1.0 <= 0.005);
            assert_eq!(output_4.get("cardinality.combined_field"), None);
            assert!(output_4["cardinality.combined_field2"].as_float().unwrap().as_ref() - 1.0 <= 0.005);

            // println!("top_n = {:?}", output_1.get("top_n").unwrap().to_string_lossy().to_string());
            assert_eq!(output_4.get("top_n.field_1").unwrap().to_string_lossy(), "{\"6\":1}");
            assert_eq!(output_4.get("top_n.field_2").is_some(), false);
            assert_eq!(output_4.get("top_n.field_3").unwrap().to_string_lossy(), "{\"yep\":1}");
            assert_eq!(output_4.get("top_n.field_4").unwrap().to_string_lossy(), "{\"value1\":1}");
            assert_eq!(output_4.get("top_n.\"field_2.inside.leaf\"").unwrap().to_string_lossy(), "{\"2\":1}");
            assert_eq!(output_4.get("top_n.combined_field"), None);
            assert_eq!(output_4.get("top_n.combined_field2").unwrap().to_string_lossy(), "{\"6#~#2\":1}");

            assert_eq!(output_4.get("group_by").is_some(), true);
            assert_eq!(output_4.get("group_by.field_3").unwrap().to_string_lossy(), "yep");
            assert_eq!(output_4.get("group_by.field_4").unwrap().to_string_lossy(), "value1");

            drop(tx);
            topology.stop().await;
            // assert_eq!(out.recv().await.unwrap().into_log(), default_ssa_message(false));
            assert_eq!(out.recv().await, None);
        })
            .await;
    }

    #[tokio::test]
    async fn ssa_default_sanitised_config() {
        let config = toml::from_str::<StreamAnalyticsConfig>(
            r#"
max_events = 5
"#,
        )
            .unwrap();

        let sanitised_config = StreamAnalyticsSanitisedConfig::new(&config)
            .expect("Can't fail in sanitised config creation.");
        assert_eq!(sanitised_config.calculators.unwrap()
                   , vec![ Calculator::TopN, Calculator::Cardinality, Calculator::SizeQuantile ]);
        assert_eq!(sanitised_config.skip_fields
                   , vec!["time".to_string(), "timestamp".to_string(), "date".to_string(), "datetime".to_string()]);
        assert_eq!(sanitised_config.max_events, 5);
        assert_eq!(sanitised_config.flush_period, Duration::from_millis(300000));
        assert_eq!(sanitised_config.quantiles, vec![0.5, 0.75, 0.9, 0.95, 0.99]);
        assert_eq!(sanitised_config.max_processing_limit, 256);
        assert_eq!(sanitised_config.max_top_n_labels, 16);
        assert_eq!(sanitised_config.max_top_n_values, 5);

    }

    #[tokio::test]
    async fn ssa_check_limits_sanitised_config() {
        let config = toml::from_str::<StreamAnalyticsConfig>(
            r#"
max_events = 5
max_top_n_labels = 3280
max_processing_limit = 2000
max_top_n_values = 33
"#,
        )
            .unwrap();

        let sanitised_config = StreamAnalyticsSanitisedConfig::new(&config)
            .expect("Can't fail in sanitised config creation.");
        assert_eq!(sanitised_config.calculators.unwrap()
                   , vec![ Calculator::TopN, Calculator::Cardinality, Calculator::SizeQuantile ]);
        assert_eq!(sanitised_config.skip_fields
                   , vec!["time".to_string(), "timestamp".to_string(), "date".to_string(), "datetime".to_string()]);
        assert_eq!(sanitised_config.max_events, 5);
        assert_eq!(sanitised_config.flush_period, Duration::from_millis(300000));
        assert_eq!(sanitised_config.quantiles, vec![0.5, 0.75, 0.9, 0.95, 0.99]);
        assert_eq!(sanitised_config.max_processing_limit, 1024);
        assert_eq!(sanitised_config.max_top_n_labels, 1024);
        assert_eq!(sanitised_config.max_top_n_values, 32);

    }

}
