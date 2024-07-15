use std::cmp::min;
use std::collections::HashMap;
use std::fmt::Formatter;
use std::time::Duration;

use indexmap::IndexMap;
use regex::Regex;
use serde_with::serde_as;

use vector_config_macros::configurable_component;
use vector_core::config::{DataType, Input, LogNamespace, OutputId, TransformOutput};
use vector_core::schema;
use vector_core::transform::Transform;

use crate::config::{TransformConfig, TransformContext};
use crate::transforms::stream_analytics::{Calculator, StreamAnalytics};

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

    /// The maximum number of top metrics to consider for metrics analytics.
    /// Default 128 and Max 1024 labels are supported
    #[serde(default = "default_max_top_metrics")]
    #[derivative(Default(value = "default_max_top_metrics()"))]
    #[configurable(metadata(
        docs::additional_props_description = "The maximum number of top occuring metrics to consider for Metric insights. \
    Used only by metrics analytics. \
    Max 1024 labels are supported. Default 128 labels."
    ))]
    pub max_top_metrics: u16,

    /// The maximum number of labels to consider for TopN.
    /// Max 1024 labels are supported
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

const fn default_max_top_metrics() -> u16 {
    128
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
        "datetime".to_string(),
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


impl_generate_config_from_default!(StreamAnalyticsConfig);

#[async_trait::async_trait]
#[typetag::serde(name = "stream_analytics")]
impl TransformConfig for StreamAnalyticsConfig {
    async fn build(&self, _context: &TransformContext) -> crate::Result<Transform> {
        StreamAnalytics::new(self).map(Transform::event_task)
    }

    fn input(&self) -> Input {
        Input::all()
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

#[derive(Debug, Derivative, Clone)]
pub struct StreamAnalyticsSanitisedConfig {
    pub(crate) flush_period: Duration,
    pub(crate) max_events: u64,
    pub(crate) max_internal_state_buffer: usize,
    pub(crate) max_top_metrics: u16,
    pub(crate) max_top_n_labels: u16,
    pub(crate) max_top_n_values: u8,
    pub(crate) max_processing_limit: usize,
    pub(crate) error_rate: f64,
    pub(crate) probability: f64,
    pub(crate) quantile_estimation_size: usize,
    pub(crate) quantiles: Vec<f64>,
    pub(crate) skip_fields: Vec<String>,
    pub(crate) combine_by_fields: IndexMap<String, Vec<String>>,
    pub(crate) group_by: Vec<String>,
    pub(crate) calculators: Option<Vec<Calculator>>,
    pub(crate) field_regex: Regex,
}

impl std::fmt::Display for StreamAnalyticsSanitisedConfig {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "flush_period = {}, max_events= {}, max_top_n_labels = {}, max_top_n_values = {}, max_processing_limit={}"
               , self.flush_period.as_millis(), self.max_events, self.max_top_n_labels, self.max_top_n_values
               , self.max_processing_limit)
    }
}

impl StreamAnalyticsSanitisedConfig {
    pub(crate) fn new(
        config: &StreamAnalyticsConfig,
    ) -> crate::Result<Self> {
        Ok(StreamAnalyticsSanitisedConfig {
            flush_period: config.flush_period_ms,
            max_events: config.max_events,
            max_internal_state_buffer: config.max_internal_state_buffer as usize,
            max_top_metrics: {
                if config.max_top_metrics > 1024 {
                    warn!(message = "max_top_metrics value will be set to max allowed value = 1024", IgnoredConfig = %config.max_top_metrics, internal_log_rate_limit=true);
                }
                min(config.max_top_metrics, 1024)
            },
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
            field_regex: Regex::new(r"\[\d+\]").expect("Failed to compile field regex"),
        })
    }
}