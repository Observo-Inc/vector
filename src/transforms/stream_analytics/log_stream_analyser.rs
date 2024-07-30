use std::collections::{BTreeMap, HashSet};

use indexmap::IndexMap;

use vector_core::EstimatedJsonEncodedSizeOf;
use vector_core::event::{Event, Value};
use vector_core::event::discriminant::Discriminant;

use crate::transforms::stream_analytics::{Calculator, StreamAnalyticsPerEventState};
use crate::transforms::stream_analytics::stream_analyser::EventStreamAnalyser;

#[derive(Debug, Derivative)]
pub(crate) struct LogStreamAnalyser {
    supported_calculators: HashSet<Calculator>,
}

impl LogStreamAnalyser {
    pub(crate) fn new() -> Self {
        LogStreamAnalyser {
            supported_calculators: HashSet::from([Calculator::TopN, Calculator::Cardinality, Calculator::SizeQuantile]),
        }
    }
    pub(crate) fn log_iterator<'a>(event: &'a Event) -> Box<dyn Iterator<Item=(String, &'a Value)> + 'a> {
        let log_event = event.as_log();
        Box::new(log_event.all_fields().expect("Log can't be null"))
    }
}

impl EventStreamAnalyser<Discriminant> for LogStreamAnalyser {
    fn get_event_type(&self) -> String {
        "LOG".to_string()
    }

    fn get_supported_calculators(&self) -> HashSet<Calculator> {
        self.supported_calculators.clone()
    }

    fn should_process(&mut self, _event: &Event) -> bool {
        true
    }

    fn get_group_by_key(&self, event: &Event, group_by: &Vec<String>) -> Discriminant {
        let log_event = event.as_log();
        Discriminant::from_log_event(&log_event, group_by)
    }

    fn get_group_by_value(&self, event: &Event, group_by: &Vec<String>) -> Value {
        let log_event = event.as_log();
        let mut grp_map: BTreeMap<String, Value> = BTreeMap::new();
        let _ = group_by.iter().for_each(|group_by_field_name| {
            grp_map.insert(group_by_field_name.to_string()
                           , log_event.get(group_by_field_name.as_str()).cloned()
                               .or_else(|| Some(Value::Null)).unwrap());
        });
        Value::from(grp_map)
    }

    fn get_combined_field_values(&self,
                                 event: &Event,
                                 combine_by_fields: &IndexMap<String, Vec<String>>,
                                 filter: fn(&Value) -> bool,
    ) -> Option<Vec<(String, String)>> {
        let log_event = event.as_log();
        let mut combined_values: Vec<(String, String)> = Vec::new();
        'combine_loop: for (field_name, combined_by) in combine_by_fields {
            let mut combined_value: Vec<String> = Vec::new();
            for combine_by_field in combined_by.iter() {
                let Some(val) = log_event.get(combine_by_field.as_str()) else {
                    continue 'combine_loop
                };
                if filter(val) {
                    combined_value.push(val.to_string_lossy().to_string());
                } else {
                    continue 'combine_loop;
                }
            }
            combined_values.push((field_name.to_string(), combined_value.join("#~#")));
        }
        Some(combined_values)
    }

    fn get_per_event_state(&self, event: &Event) -> StreamAnalyticsPerEventState {
        let log_event = event.as_log();
        StreamAnalyticsPerEventState { event_size: log_event.estimated_json_encoded_size_of() }
    }

    fn flush(&mut self) {
        // Nothing to do, no internal state
    }
}

