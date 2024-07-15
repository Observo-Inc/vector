use std::collections::{BTreeMap, HashMap};

use ordered_float::NotNan;
use streaming_algorithms::HyperLogLog;

use vector_core::event::{LogEvent, Value};

use crate::transforms::stream_analytics::{StreamAnalyticsCalculator, StreamAnalyticsPerEventState, StreamAnalyticsSanitisedConfig};

#[derive(Clone, Debug)]
pub struct Cardinality {
    error_rate: f64,
    cardinality: HashMap<String, HyperLogLog<str>>,
}

impl Cardinality {
    pub fn new(config: &StreamAnalyticsSanitisedConfig) -> Self {
        Cardinality {
            error_rate: config.error_rate,
            cardinality: HashMap::new(),
        }
    }
}

impl StreamAnalyticsCalculator for Cardinality {
    fn name(&self) -> String {
        "cardinality".to_string()
    }

    fn process(&mut self, _: &StreamAnalyticsPerEventState, field_name: &String, value: &Value) -> Result<(), String> {
        if !self.cardinality.contains_key(field_name) {
            self.cardinality.insert(field_name.to_string(), HyperLogLog::new(self.error_rate));
        }

        self.cardinality.get_mut(field_name).expect("Can't be empty here.")
            .push(value.to_string_lossy().as_ref());
        Ok(())
    }

    fn publish_stat(&mut self, log: &mut LogEvent) -> Result<(), String> {
        let mut keyed_topn_stream = BTreeMap::new();
        for (key, value) in self.cardinality.drain() {
            keyed_topn_stream.insert(key.to_string(),
                                     Value::Float(NotNan::new(value.len())
                                         .or::<NotNan<f64>>(Ok(NotNan::from(0)))
                                         .expect("Cardinality can't be a NAN.")));
        }
        log.insert("cardinality", Value::Object(keyed_topn_stream));
        Ok(())
    }

    fn reset(&mut self) -> Result<(), String> {
        self.cardinality.drain();
        Ok(())
    }

    fn reset_per_event_state(&mut self) -> Result<(), String> {
        Ok(())
    }
}