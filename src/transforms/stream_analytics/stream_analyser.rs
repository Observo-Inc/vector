use std::borrow::Cow;
use std::collections::{BTreeMap, HashMap, HashSet};
use std::default::Default;
use std::fmt::Debug;

use indexmap::IndexMap;

use vector_common::byte_size_of::ByteSizeOf;
use vector_core::EstimatedJsonEncodedSizeOf;
use vector_core::event::{
    Event,
    LogEvent,
    Value};
use vector_core::event::discriminant::Discriminant;
use vector_core::event::metric::TagValueSet;

use crate::internal_events::{StreamAnalyticsError, StreamAnalyticsFieldProcessedTotal, StreamAnalyticsFieldProcessError, StreamAnalyticsFlushed, StreamAnalyticsPublishError, StreamAnalyticsResetError, StreamAnalyticsResetPerEventError, StreamAnalyticsResets};
use crate::transforms::stream_analytics::{Calculator, get_calculators, StreamAnalyticsCalculator, StreamAnalyticsPerEventState};
use crate::transforms::stream_analytics::config::StreamAnalyticsSanitisedConfig;
use crate::transforms::stream_analytics::log_stream_analyser::LogStreamAnalyser;
use crate::transforms::stream_analytics::metric_stream_analyser::MetricStreamAnalyser;

#[derive(Debug, Derivative)]
pub(crate) enum EventStreamAnalysers {
    LogAnalyser(StreamAnalyser<Discriminant>),
    MetricAnalyser(StreamAnalyser<Vec<TagValueSet>>),
}

impl EventStreamAnalysers {
    pub(crate) fn get_log_stream_analyser(
        sanitised_config: StreamAnalyticsSanitisedConfig,
    ) -> EventStreamAnalysers {
        EventStreamAnalysers::LogAnalyser(
            StreamAnalyser {
                sanitised_config,
                grouped_calculators: HashMap::new(),
                stream_analyser_state: StreamAnalyserState { events_processed: HashMap::new() },
                event_stream_analyser: Box::new(LogStreamAnalyser::new()),
            }
        )
    }

    pub(crate) fn get_metric_stream_analyser(
        sanitised_config: StreamAnalyticsSanitisedConfig,
    ) -> EventStreamAnalysers {
        EventStreamAnalysers::MetricAnalyser(
            StreamAnalyser {
                event_stream_analyser: Box::new(MetricStreamAnalyser::new(sanitised_config.max_top_metrics, sanitised_config.probability)),
                sanitised_config,
                grouped_calculators: HashMap::new(),
                stream_analyser_state: StreamAnalyserState { events_processed: HashMap::new() },
            }
        )
    }

    pub(crate) fn try_into_log_stream_analyser(&mut self) -> Option<&mut StreamAnalyser<Discriminant>> {
        match self {
            EventStreamAnalysers::LogAnalyser(stream_analyser) => {
                Some(stream_analyser)
            }
            _ => None
        }
    }

    pub(crate) fn try_into_metric_stream_analyser(&mut self) -> Option<&mut StreamAnalyser<Vec<TagValueSet>>> {
        match self {
            EventStreamAnalysers::MetricAnalyser(stream_analyser) => {
                Some(stream_analyser)
            }
            _ => None
        }
    }
}

#[derive(Debug, Derivative)]
struct StreamAnalyserState<K: std::hash::Hash + Eq + Clone> {
    events_processed: HashMap<K, u64>,
}

impl<K: std::hash::Hash + Eq + Clone> StreamAnalyserState<K> {
    fn inc_event_metric(&mut self, key: &K) {
        let counter = self.events_processed
            .entry(key.clone())
            .or_insert(0);
        *counter += 1;
    }

    fn get_event_metric(&self, key: &K) -> u64 {
        let counter = self.events_processed.get(key);
        *(counter.or_else(|| Some(&0u64)).unwrap())
    }

    fn flush(&mut self) {
        self.events_processed.drain();
    }
}


pub(crate) trait EventStreamAnalyser<K: std::hash::Hash + Eq + Clone>: Debug + Send + Sync {
    fn get_event_type(&self) -> String;
    fn get_supported_calculators(&self) -> HashSet<Calculator>;
    fn should_process(&mut self, event: &Event) -> bool;
    fn get_group_by_key(&self, event: &Event, group_by: &Vec<String>) -> K;
    fn get_group_by_value(&self, event: &Event, group_by: &Vec<String>) -> Value;
    fn get_combined_field_values(&self, event: &Event,
                                 combine_by_fields: &IndexMap<String, Vec<String>>,
                                 filter: fn(&Value) -> bool) -> Option<Vec<(String, String)>>;
    fn get_per_event_state(&self, event: &Event) -> StreamAnalyticsPerEventState;

    fn flush(&mut self);
}

#[derive(Debug, Derivative)]
pub(crate) struct StreamAnalyser<K: std::hash::Hash + Eq + Clone> {
    sanitised_config: StreamAnalyticsSanitisedConfig,
    grouped_calculators: HashMap<K, (Value, Vec<Box<dyn StreamAnalyticsCalculator>>)>,
    stream_analyser_state: StreamAnalyserState<K>,
    event_stream_analyser: Box<dyn EventStreamAnalyser<K>>,
}

impl<K: std::hash::Hash + Eq + Clone> StreamAnalyser<K> {
    fn insert_calculators(&mut self, supported_calculators: &HashSet<Calculator>, key_ref: &K, event: &Event) {
        if !self.grouped_calculators.contains_key(&key_ref) {
            let value = self.event_stream_analyser.get_group_by_value(&event, &self.sanitised_config.group_by);
            self.grouped_calculators
                .insert(key_ref.clone(), (value, get_calculators(&self.sanitised_config, supported_calculators)));
        }
    }

    fn reset_per_event(&mut self, key_ref: &K) {
        let (_, calculators) = self.grouped_calculators
            .get_mut(key_ref).expect("grouped_calculator can't be empty");
        for stream_analytics_calculator in calculators.iter_mut() {
            if let Err(error) = stream_analytics_calculator.reset_per_event_state() {
                warn!(message = "Failed to reset calculator per event.", %error, calculator = %stream_analytics_calculator.name(), internal_log_rate_limit=true);
                emit!(StreamAnalyticsResetPerEventError{
                    error,
                    calculator: stream_analytics_calculator.name()})
            }
        }
    }
    fn process_field(&mut self,
                     event_state: &StreamAnalyticsPerEventState,
                     key_ref: &K,
                     field_name: String,
                     value: &Value,
    ) {
        if self.is_valid_field(&field_name, &self.sanitised_config)
            && self.is_valid_value(value, &self.sanitised_config) {
            let key = self.sanitise_field(field_name, &self.sanitised_config);
            let (_, stream_analytics_calculators) = self.grouped_calculators
                .get_mut(key_ref).expect("grouped_calculator can't be empty");
            for stream_analytics_calculator in stream_analytics_calculators {
                if let Err(error) = stream_analytics_calculator.process(&event_state, &key, value) {
                    warn!(message = "Failed to process field.", %error, field_name = %key, internal_log_rate_limit=true);
                    emit!(StreamAnalyticsFieldProcessError {error, calculator: stream_analytics_calculator.name()})
                }
            }
        }
    }

    pub(crate) fn iterate_on_event(&mut self, event: Event) {
        if !self.event_stream_analyser.should_process(&event) {
            return;
        }
        let supported_calculators = self.event_stream_analyser.get_supported_calculators();
        let key_ref = self.event_stream_analyser.get_group_by_key(&event, &self.sanitised_config.group_by);
        self.insert_calculators(&supported_calculators, &key_ref, &event);

        self.stream_analyser_state.inc_event_metric(&key_ref);

        // reset for event
        self.reset_per_event(&key_ref);

        let combined_values = self.event_stream_analyser
            .get_combined_field_values(
                &event,
                &self.sanitised_config.combine_by_fields,
                StreamAnalyser::<K>::is_valid_value_type,
            );

        let event_state = self.event_stream_analyser.get_per_event_state(&event);

        let mut fields_processed: u64 = 0;
        if let Some(combined_values) = combined_values {
            for (field_name, value) in combined_values.iter() {
                fields_processed += 1;
                trace!(message = "Group_by Field name being processed.", FieldName = %field_name, internal_log_rate_limit=true);
                self.process_field(&event_state, &key_ref, field_name.clone(), &Value::from(Cow::from(value)));
            }
        }

        // Process all fields by default
        match event {
            Event::Log(_) => {
                let field_iterator = LogStreamAnalyser::log_iterator(&event);
                for (field_name, value) in field_iterator {
                    fields_processed += 1;
                    trace!(message = "Field name being processed.", FieldName = %field_name, internal_log_rate_limit=true);
                    self.process_field(&event_state, &key_ref, field_name, value);
                }
            }
            Event::Metric(_) => {
                let field_iterator = MetricStreamAnalyser::metric_iterator(&event);
                for (field_name, value) in field_iterator {
                    fields_processed += 1;
                    trace!(message = "Field name being processed.", FieldName = %field_name, internal_log_rate_limit=true);
                    self.process_field(&event_state, &key_ref, field_name, &value);
                }
            }
            _ => {
                warn!(message = "Unhandled StreamAnalyser.", internal_log_rate_limit=true);
                emit!(StreamAnalyticsError {error: "Unhandled StreamAnalyser.".to_string()
                    , reason: "Unhandled StreamAnalyser, can't create iterator.".to_string()});
                return;
            }
        };

        let (_, calculators) = self.grouped_calculators
            .get_mut(&key_ref).expect("grouped_calculator can't be empty");
        for stream_analytics_calculator in calculators.iter_mut() {
            emit!(StreamAnalyticsFieldProcessedTotal {
                            calculator: stream_analytics_calculator.name(),
                            total_fields_processed: fields_processed,
                    });
        }
    }

    pub(crate) fn flush(&mut self) -> Vec<Event> {
        let mut sa_events: Vec<Event> = Vec::new();
        self.grouped_calculators.drain()
            .for_each(|(key_ref, (grouped_by, ref mut calculators))| {
                let mut log = LogEvent::default();
                let mut stats_summary = BTreeMap::new();
                let event_count = self.stream_analyser_state.get_event_metric(&key_ref);
                stats_summary.insert("events_processed".to_string(), Value::from(event_count));
                log.insert("stats_summary", Value::Object(stats_summary));
                log.insert("group_by", grouped_by.clone());
                log.insert("event_type", self.event_stream_analyser.get_event_type());

                for stream_analytics_calculator in calculators.iter_mut() {
                    match stream_analytics_calculator.publish_stat(&mut log) {
                        Ok(_) => { emit!(StreamAnalyticsFlushed{calculator: stream_analytics_calculator.name()}) }
                        Err(error) => {
                            warn!(message = "Failed to flush calculator.", %error, calculator = %stream_analytics_calculator.name(), internal_log_rate_limit=true);
                            emit!(StreamAnalyticsPublishError {error, calculator: stream_analytics_calculator.name()})
                        }
                    }

                    match stream_analytics_calculator.reset() {
                        Ok(_) => { emit!(StreamAnalyticsResets{calculator: stream_analytics_calculator.name()}) }
                        Err(error) => {
                            warn!(message = "Failed to reset calculator.", %error, calculator = %stream_analytics_calculator.name(), internal_log_rate_limit=true);
                            emit!(StreamAnalyticsResetError {error, calculator: stream_analytics_calculator.name().clone()})
                        }
                    }
                }

                sa_events.push(Event::Log(log));
            });

        self.stream_analyser_state.flush();
        self.event_stream_analyser.flush();
        return sa_events;
    }

    // Default impl of helper method
    fn sanitise_field(&self, field_name: String, config: &StreamAnalyticsSanitisedConfig) -> String {
        if field_name.contains("[") {
            return config.field_regex.replace_all(field_name.as_str(), "").to_string();
        }
        field_name
    }

    fn is_valid_value_type(value: &Value) -> bool {
        match value {
            Value::Object(_) => { false }
            Value::Array(_) => { false }
            Value::Null => { false }
            _ => { true }
        }
    }

    fn is_valid_value(&self, value: &Value, config: &StreamAnalyticsSanitisedConfig) -> bool {
        if value.estimated_json_encoded_size_of() > config.max_processing_limit {
            trace!( message =  "Value size large", Value = %&value.to_string_lossy().to_string()[0..20], ValueSize = %value.allocated_bytes(), internal_log_rate_limit=true);
            return true;
        }
        true
    }

    fn is_valid_field(&self, field_name: &String, config: &StreamAnalyticsSanitisedConfig) -> bool {
        if field_name.len() > config.max_processing_limit {
            trace!( message = "Field size large {} {}", FieldName = %field_name, FieldSize = %field_name.len(), internal_log_rate_limit=true);
            return false;
        }

        let field_name = field_name.to_lowercase();

        if config.skip_fields.contains(&field_name) {
            return false;
        }

        let split_filed = field_name.rsplit_once('.');
        let match_field = if split_filed.is_some() {
            split_filed.unwrap().1
        } else {
            &field_name
        };

        if config.skip_fields.contains(&match_field.to_string()) {
            return false;
        }

        return true;
    }
}