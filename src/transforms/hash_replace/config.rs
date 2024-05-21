use std::collections::HashMap;
use std::fmt;
use std::fmt::Formatter;
use std::time::Duration;
use serde_with::serde_as;
use vector_config_macros::configurable_component;
use vector_core::config::{DataType, Input, LogNamespace, OutputId, TransformOutput};
use vector_core::schema;
use vector_core::transform::Transform;
use crate::config::{TransformConfig, TransformContext};
use crate::transforms::hash_replace::HashReplace;

/// Configuration for the `hash_replace` transform.
#[serde_as]
#[configurable_component(transform(
"hash_replace",
"Replaces the given keys with Hash",
))]
#[derive(Clone, Debug, Derivative)]
#[derivative(Default)]
#[serde(deny_unknown_fields)]
pub struct HashReplaceConfig {
    /// The interval to flush the internal state, in milliseconds.
    #[serde(default = "default_flush_period_ms")]
    #[serde_as(as = "serde_with::DurationMilliSeconds<u64>")]
    #[derivative(Default(value = "default_flush_period_ms()"))]
    #[configurable(metadata(
        docs::additional_props_description = "The interval to flush the internal state, in milliseconds. \
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

    /// New Hash key name to be added to the message.
    /// All the replace_keys hashes will be added under this key name
    /// For example, if `hash_key_name = "hashes"`
    #[serde(default)]
    #[configurable(metadata(
        docs::additional_props_description = "New Hash key name to be added to the message. \
    All the replace_keys hashes will be added under this key name \
    Default `hash_key_name = hashes` "
    ))]
    #[configurable(metadata(
        docs::examples = "hashes",
        docs::examples = "myhashkey",
    ))]
    pub hash_key_name: Option<String>,

    /// Sample rate
    /// The rate at which events are forwarded, expressed as `1/N`.
    /// For example, `rate = 10` means 1 out of every 10 events are forwarded and the rest are
    /// dropped.
    #[serde(default = "default_sample_rate")]
    #[derivative(Default(value = "default_sample_rate()"))]
    #[configurable(metadata(
        docs::additional_props_description = "At least 1/sample_rate messages will have both the original fields \
        and the value of hashes for those fields.\
        For rest of the message, original fields will be removed and only hashes will be added.\
        Default 100"
    ))]
    pub sample_rate: u64,

    /// An ordered list of fields for replacing with hash.
    /// For each field a hash is calculated added in the original message
    ///
    /// For example, if `replace_keys = ["host", "region"]`, then all incoming events that have the keys
    /// host and region will have hashes added and for sample_percent we will have original fields
    /// and for rest of the events they keys will be removed.
    #[serde(default)]
    #[configurable(metadata(
        docs::additional_props_description = "For example, if `replace_keys = [\"host\", \"region\", \"user.id\"]`\
        , then all incoming events that have the keys \
        host and region will have hashes added and for sample_percent we will have original fields \
        and for rest of the events they keys will be removed."
    ))]
    #[configurable(metadata(
        docs::examples = "request_id",
        docs::examples = "user.id",
        docs::examples = "transaction_id",
    ))]
    pub replace_keys: Vec<String>,

    /// The Capacity of AMQ filter (Approximate Membership Query Filter).
    #[serde(default = "default_amq_filter_capacity")]
    #[derivative(Default(value = "default_amq_filter_capacity()"))]
    #[configurable(metadata(
        docs::additional_props_description = "The Capacity of AMQ filter. \
    Default (1 << 20) - 1"
    ))]
    pub amq_filter_capacity: usize,
}

const fn default_max_events() -> u64 {
    1_000_000 // 1M
}
const fn default_amq_filter_capacity() -> usize {
    (1 << 20) - 1
}

const fn default_sample_rate() -> u64 {
    100
}

const fn default_flush_period_ms() -> Duration {
    Duration::from_millis(300000) // 5 mins
}

impl_generate_config_from_default!(HashReplaceConfig);

#[async_trait::async_trait]
#[typetag::serde(name = "hash_replace")]
impl TransformConfig for HashReplaceConfig {
    async fn build(&self, _context: &TransformContext) -> crate::Result<Transform> {
        HashReplace::new(self).map(Transform::event_task)
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


impl fmt::Display for HashReplaceConfig {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "replace_keys = {}, hash_key_name= {}, sample_rate = {}, \
                    flush_period_ms = {}, max_events={} \
                    amq_filter_capacity = {} ."
               , self.replace_keys.clone().join(", "), self.get_hash_key_name(), self.sample_rate
               , self.flush_period_ms.as_millis(), self.max_events
               , self.amq_filter_capacity)
    }
}

impl HashReplaceConfig {
    pub(crate) fn get_hash_key_name(&self) -> String {
        match self.hash_key_name.clone() {
            None => {
                trace!( message =  "No value for hash_key_name, returning default", internal_log_rate_limit=true);
                "hashes".to_string()
            }
            Some(hash_key_name) => {
                hash_key_name.clone()
            }
        }
    }
}
