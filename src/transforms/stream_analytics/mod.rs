use std::{
    collections::HashMap,
    pin::Pin,
    time::Duration,
};
use std::cmp::max;
use std::collections::HashSet;
use std::fmt::Debug;
use std::time::Instant;

use async_stream::stream;
use futures::{stream, Stream, StreamExt};
use serde_with::serde_as;

use vector_config::configurable_component;

use crate::{
    config::DataType,
    event::{Event, LogEvent},
    transforms::TaskTransform,
};
use crate::event::Value;
use crate::internal_events::StreamAnalyticsError;
use crate::transforms::stream_analytics::cardinality::Cardinality;
use crate::transforms::stream_analytics::config::{StreamAnalyticsConfig, StreamAnalyticsSanitisedConfig};
use crate::transforms::stream_analytics::size_quantiles::SizeQuantile;
use crate::transforms::stream_analytics::stream_analyser::*;
use crate::transforms::stream_analytics::top_n::TopN;

mod top_n;
mod cardinality;
mod size_quantiles;
mod tests;
mod log_stream_analyser;
mod metric_stream_analyser;
mod config;
mod stream_analyser;

/// StreamAnalytics Calculators
#[serde_as]
#[configurable_component]
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
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

pub trait StreamAnalyticsCalculator: Debug + Send + Sync {

    fn name(&self) -> String;
    fn process(&mut self, event_state: &StreamAnalyticsPerEventState, field_name: &String, value: &Value) -> Result<(), String>;
    fn publish_stat(&mut self, log: &mut LogEvent) -> Result<(), String>;
    fn reset(&mut self) -> Result<(), String>;
    fn reset_per_event_state(&mut self) -> Result<(), String>;

}


fn get_calculators(config: &StreamAnalyticsSanitisedConfig, supported_calculators: &HashSet<Calculator>) -> Vec<Box<dyn StreamAnalyticsCalculator>> {
    let mut calculators: Vec<Box<dyn StreamAnalyticsCalculator>> = Vec::new();
    for calculator in config.calculators.as_ref().expect("Default calculators should always be present.") {
        if supported_calculators.contains(calculator) {
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
    }
    calculators
}


#[derive(Debug, Derivative)]
pub struct StreamAnalyticsPerEventState {
    event_size: usize,
}


#[derive(Debug, Derivative)]
pub struct StreamAnalyticsState {
    max_events: u64,
    flush_period: Duration,
    current_events_count: u64,
    last_flush: Instant,
}

impl StreamAnalyticsState {
    fn should_flush(&mut self) -> bool {
        if (Instant::now() - self.last_flush) >= self.flush_period {
            return true;
        }
        self.current_events_count += 1;
        if self.current_events_count > self.max_events {
            return true;
        }

        false
    }

    fn flushed(&mut self) {
        self.current_events_count = 0;
        self.last_flush = Instant::now();
    }
}

#[derive(Debug, Derivative)]
pub struct StreamAnalytics {
    sanitised_conf: StreamAnalyticsSanitisedConfig,
    stream_analytics_state: StreamAnalyticsState,
    stream_analysers: HashMap<DataType, EventStreamAnalysers>,
}

impl StreamAnalytics {
    pub fn new(
        config: &StreamAnalyticsConfig,
    ) -> crate::Result<Self> {
        let sanitised_conf = StreamAnalyticsSanitisedConfig::new(config)
            .expect("Sanitised StreamAnalytics config creation failed.");
        debug!(message = "Sanitised StreamAnalytics config.", Config = %sanitised_conf, internal_log_rate_limit=true);
        Ok(StreamAnalytics {
            sanitised_conf: sanitised_conf.clone(),
            stream_analytics_state: StreamAnalyticsState {
                max_events: sanitised_conf.max_events,
                flush_period: sanitised_conf.flush_period,
                current_events_count: 0,
                last_flush: Instant::now(),
            },
            stream_analysers: HashMap::new(),
        })
    }

    fn iterate_on_event(&mut self, event: Event) {
        match event {
            Event::Metric(_) => {
                let stream_analyser = self.stream_analysers
                    .entry(DataType::Metric)
                    .or_insert(EventStreamAnalysers::get_metric_stream_analyser(self.sanitised_conf.clone()));

                if let Some(metric_stream_analyser) = stream_analyser.try_into_metric_stream_analyser() {
                    metric_stream_analyser.iterate_on_event(event);
                } else {
                    let error = "Failed to get metric stream analyser.".to_string();
                    let reason = "Metric stream analyser not found in state map.".to_string();
                    warn!(message = %error, %reason, internal_log_rate_limit=true);
                    emit!(StreamAnalyticsError {error, reason});
                }
            }
            Event::Log(_) => {
                let stream_analyser = self.stream_analysers
                    .entry(DataType::Log)
                    .or_insert(EventStreamAnalysers::get_log_stream_analyser(self.sanitised_conf.clone()));

                if let Some(log_stream_analyser) = stream_analyser.try_into_log_stream_analyser() {
                    log_stream_analyser.iterate_on_event(event);
                } else {
                    let error = "Failed to get log stream analyser.".to_string();
                    let reason = "Log stream analyser not found in state map.".to_string();
                    warn!(message = %error, %reason, internal_log_rate_limit=true);
                    emit!(StreamAnalyticsError {error, reason});
                }
            }
            Event::Trace(_) => { return; }
        }
    }

    fn flush(&mut self) -> Vec<Event> {
        let mut sa_events: Vec<Event> = Vec::new();

        // append
        self.stream_analysers.iter_mut().for_each(|(_, stream_analyser)| {
            let mut ssa = match stream_analyser {
                EventStreamAnalysers::LogAnalyser(log_stream_analyser) => log_stream_analyser.flush(),
                EventStreamAnalysers::MetricAnalyser(metric_stream_analyser) => metric_stream_analyser.flush(),
            };

            sa_events.append(ssa.as_mut());
        });

        self.stream_analytics_state.flushed();
        sa_events
    }

    fn flush_into(&mut self, output: &mut Vec<Event>) {
        if self.stream_analytics_state.should_flush() {
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
            max(me.stream_analytics_state.flush_period.as_millis()/3, 5000)
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
