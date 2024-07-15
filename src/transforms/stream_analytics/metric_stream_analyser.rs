use std::collections::{BTreeMap, HashSet};

use indexmap::IndexMap;
use streaming_algorithms::Top;

use vector_core::event::{Event, Value};
use vector_core::event::metric::{TagValue, TagValueSet};

use crate::transforms::stream_analytics::{Calculator, StreamAnalyticsPerEventState};
use crate::transforms::stream_analytics::stream_analyser::EventStreamAnalyser;

#[derive(Debug, Derivative)]
pub(crate) struct MetricStreamAnalyser {
    supported_calculators: HashSet<Calculator>,
    allowed_metrics: HashSet<String>,
    top_heavy_metrics: Top<String, u32>,
}

impl MetricStreamAnalyser {
    pub(crate) fn new(top_n_values: u16, probability: f64) -> Self {
        MetricStreamAnalyser {
            supported_calculators: HashSet::from([Calculator::TopN, Calculator::Cardinality]),
            allowed_metrics: HashSet::new(),
            top_heavy_metrics: Top::new(top_n_values as usize, probability, 2.0 / 1000.0, ()),
        }
    }
    pub(crate) fn metric_iterator<'a>(event: &'a Event) -> Box<dyn Iterator<Item=(String, Value)> + 'a> {
        let metric = event.as_metric();
        let tags_k_v = metric
            .tags().unwrap()
            .iter_all()
            .map(|(tag_key, tag_value)| {
                (tag_key.to_string(), Value::from(tag_value.unwrap()))
            });
        Box::new(tags_k_v)
    }
}

impl EventStreamAnalyser<Vec<TagValueSet>> for MetricStreamAnalyser {
    fn get_supported_calculators(&self) -> HashSet<Calculator> {
        self.supported_calculators.clone()
    }

    fn should_process(&mut self, event: &Event) -> bool {
        let metric = event.as_metric().name();
        self.top_heavy_metrics.push(metric.to_string(), &1u32);
        self.allowed_metrics.contains(metric)
    }

    fn get_group_by_key(&self, event: &Event, group_by: &Vec<String>) -> Vec<TagValueSet> {
        let metric = event.as_metric();
        let mut key: Vec<TagValueSet> = Vec::new();
        key.push(TagValueSet::Single(TagValue::from("metric_name".to_string() + "__" + metric.name())));
        metric.tags().unwrap().iter_sets()
            .filter(|(tag_key, _tag_value_set)| group_by.contains(&tag_key.to_string()))
            .for_each(|(_tag_key, tag_value_set)| {
                key.push(tag_value_set.clone());
            });
        key
    }

    fn get_group_by_value(&self, event: &Event, group_by: &Vec<String>) -> Value {
        let metric = event.as_metric();
        let mut grp_map: BTreeMap<String, Value> = BTreeMap::new();
        grp_map.insert("metric_name".to_string(), Value::from(metric.name()));
        metric.tags().unwrap().iter_all()
            .filter(|(tag_key, _tag_value_set)| group_by.contains(&tag_key.to_string()))
            .for_each(|(tag_key, tag_value_set)| {
                let key = tag_key.to_string();
                if !grp_map.contains_key(&key) {
                    grp_map.insert(key.clone(), Value::from(Vec::<String>::new()));
                }
                grp_map.get_mut(&key).expect("Tag key can't be missing.")
                    .as_array_mut().expect("Tag value can't be Null.")
                    .push(Value::from(tag_value_set.unwrap().to_string()))
            });

        Value::from(grp_map)
    }

    fn get_combined_field_values(&self, _event: &Event, _combine_by_fields: &IndexMap<String, Vec<String>>, _filter: fn(&Value) -> bool) -> Option<Vec<(String, String)>> {
        None
    }

    fn get_per_event_state(&self, _event: &Event) -> StreamAnalyticsPerEventState {
        StreamAnalyticsPerEventState { event_size: 0 }
    }

    fn flush(&mut self) {
        self.allowed_metrics.clear();
        self.top_heavy_metrics.iter().for_each(|(metric_name, occurrences)| {
            trace!(message = "Top heavy metrics for metric SSA", MetricName = %metric_name, Occurrences = %occurrences, internal_log_rate_limit=true);
            self.allowed_metrics.insert(metric_name.clone());
        });
        self.top_heavy_metrics.clear();
    }
}