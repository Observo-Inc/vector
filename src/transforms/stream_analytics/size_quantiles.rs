use std::collections::{BTreeMap, HashMap};

use ordered_float::NotNan;
use tdigest::TDigest;

use vector_core::EstimatedJsonEncodedSizeOf;
use vector_core::event::{LogEvent, Value};

use crate::transforms::stream_analytics::{StreamAnalyticsCalculator, StreamAnalyticsPerEventState, StreamAnalyticsSanitisedConfig};

#[derive(Clone, Debug)]
pub struct SizeQuantile {
    quantile_estimation_size: usize,
    quantiles: Vec<f64>,
    max_internal_state_buffer: usize,
    estimator_map: HashMap<String, Estimator>,
}

#[derive(Clone, Debug)]
pub struct Estimator {
    raw_size_estimator: TDigest,
    percentage_size_estimator: TDigest,
    max_internal_state_buffer: usize,
    raw_size_buffer: Vec<f64>,
    percentage_size_buffer: Vec<f64>,
}

impl Estimator {
    fn ingest(&mut self, value_size: usize, event_size: usize) -> Result<(), String> {
        let value_size= value_size as f64;
        let percent = (value_size / event_size as f64) * 100.0;
        self.raw_size_buffer.push(value_size);
        self.percentage_size_buffer.push(percent);
        if self.raw_size_buffer.len() >= self.max_internal_state_buffer
            || self.percentage_size_buffer.len() >= self.max_internal_state_buffer {
            return self.ingest_buffers();
        }
        Ok(())
    }

    fn ingest_buffers(&mut self) -> Result<(), String> {
        self.raw_size_estimator = self.raw_size_estimator.merge_unsorted(self.raw_size_buffer.drain(..).collect());
        self.percentage_size_estimator = self.percentage_size_estimator.merge_sorted(self.percentage_size_buffer.drain(..).collect());
        Ok(())
    }
}

impl SizeQuantile {
    pub fn new(config: &StreamAnalyticsSanitisedConfig) -> Self {
        SizeQuantile {
            quantile_estimation_size: config.quantile_estimation_size,
            quantiles: config.quantiles.clone(),
            max_internal_state_buffer: config.max_internal_state_buffer,
            estimator_map: HashMap::new(),
        }
    }
}

impl StreamAnalyticsCalculator for SizeQuantile {
    fn name(&self) -> String {
        "size_quantiles".to_string()
    }

    fn process(&mut self, event_state: &StreamAnalyticsPerEventState, field_name: &String, value: &Value) -> Result<(), String> {
        if !self.estimator_map.contains_key(field_name) {
            self.estimator_map.insert(field_name.to_string(), Estimator{
                raw_size_estimator: TDigest::new_with_size(self.quantile_estimation_size),
                percentage_size_estimator: TDigest::new_with_size(self.quantile_estimation_size),
                raw_size_buffer: Vec::with_capacity(self.max_internal_state_buffer),
                percentage_size_buffer: Vec::with_capacity(self.max_internal_state_buffer),
                max_internal_state_buffer: self.max_internal_state_buffer,
            });
        }

        self.estimator_map.get_mut(field_name).expect("Can't be empty here.")
            .ingest(value.estimated_json_encoded_size_of(), event_state.event_size)
    }

    fn publish_stat(&mut self, log: &mut LogEvent) -> Result<(), String> {
        let mut keyed_size_quat_stream = BTreeMap::new();

        for (key, mut value) in self.estimator_map.drain() {
            if let Err(error) = value.ingest_buffers() {
                return Err(error);
            }
            let mut estimator_stream = BTreeMap::new();

            //estimate
            let mut size_quants :Vec<Value> = Vec::new();
            let mut percent_quants :Vec<Value> = Vec::new();
            for quantile in self.quantiles.iter() {
                size_quants.push(Value::Float(
                    NotNan::new(value.raw_size_estimator.estimate_quantile(*quantile))
                        .or::<NotNan<f64>>(Ok(NotNan::from(0)))
                        .expect("Raw size estimator can't be NaN.")));

                percent_quants.push(Value::Float(
                    NotNan::new(value.percentage_size_estimator.estimate_quantile(*quantile))
                        .or::<NotNan<f64>>(Ok(NotNan::from(0)))
                        .expect("Percentage size estimator can't be NaN.")));
            }

            estimator_stream.insert("raw_size_quantiles".to_string(), Value::Array(size_quants));
            estimator_stream.insert("percent_size_quantiles".to_string(), Value::Array(percent_quants));

            keyed_size_quat_stream.insert(key.to_string(), Value::Object(estimator_stream));
        }
        log.insert("size_quantiles", Value::Object(keyed_size_quat_stream));
        Ok(())
    }

    fn reset(&mut self) -> Result<(), String> {
        self.estimator_map.drain();
        Ok(())
    }

    fn reset_per_event_state(&mut self) -> Result<(), String> {
       Ok(())
    }
}