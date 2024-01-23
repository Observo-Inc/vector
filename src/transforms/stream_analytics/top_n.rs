use std::cmp::{min};
use std::collections::{BTreeMap, HashMap};
// use std::time::Instant;
use streaming_algorithms::Top;
use vector_core::event::{LogEvent, Value};
use crate::transforms::stream_analytics::{StreamAnalyticsCalculator, StreamAnalyticsPerEventState, StreamAnalyticsSanitisedConfig};

#[derive(Clone, Debug)]
pub struct TopN {
    max_top_n_labels: u16,
    max_top_n_values: u8,
    current_label_count: u16,
    probability: f64,
    top_n: HashMap<String, Top<String, u32>>,
}

impl TopN {
    pub fn new(config: &StreamAnalyticsSanitisedConfig) -> Self {
        TopN {
            max_top_n_labels: config.max_top_n_labels,
            max_top_n_values: config.max_top_n_values,
            current_label_count: 0,
            probability: config.probability,
            top_n: HashMap::new(),
        }
    }
}

impl StreamAnalyticsCalculator for TopN {

    fn name(&self) -> String {
        "TopN".to_string()
    }

    fn process(&mut self, _: &StreamAnalyticsPerEventState, field_name: &String, value: &Value) -> Result<(), String> {
        // println!("process called");
        if self.current_label_count >= self.max_top_n_labels {
            return Ok(());
        }
        self.current_label_count = min(self.current_label_count + 1, self.max_top_n_labels);

        if !self.top_n.contains_key(field_name) {
            self.top_n.insert(field_name.to_string(), Top::new(self.max_top_n_values as usize, self.probability, 2.0 / 1000.0, ()));
        }
        self.top_n.get_mut(field_name).expect("Can't be empty here.")
            .push(value.to_string_lossy().to_string(), &1u32);

        // Err("Hello err".to_string())

        Ok(())
    }

    fn publish_stat(&mut self, log: &mut LogEvent) -> Result<(), String> {
        let mut keyed_topn_stream = BTreeMap::new();

        for (key, value) in self.top_n.drain() {
            let mut topn_stream = BTreeMap::new();
            for (key, value) in value.iter() {
                topn_stream.insert(key.to_string(), Value::Integer(*value as i64));
            }
            keyed_topn_stream.insert(key.to_string(), Value::Object(topn_stream));
        }
        log.insert("top_n", Value::Object(keyed_topn_stream));
        Ok(())
    }

    fn reset(&mut self) -> Result<(), String> {
        // println!("Reset called");
        self.top_n.drain();
        // Err("Hello err".to_string())
        Ok(())
    }

    fn reset_per_event_state(&mut self) -> Result<(), String> {
        self.current_label_count = 0;
        Ok(())
    }
}