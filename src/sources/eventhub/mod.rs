/**
This file is NOT part of the open-source components licensed under the Mozilla Public License, v. 2.0 (MPL-2.0).
Proprietary and Confidential – © 2026 Observo Inc.
Unauthorized copying, modification, distribution, or disclosure of this file, via any medium, is strictly prohibited.
This file is distributed separately and is not subject to the terms of the MPL-2.0.
**/

use std::collections::BTreeSet;
use futures::FutureExt;

use vector_lib::{
    config::{DataType, LogNamespace, SourceOutput},
    schema::Definition,
    source::Source,
    Result,
};
use vector_config::{configurable_component, impl_generate_config_from_default};

use crate::config::{Resource, SourceConfig, SourceContext};
use eventhub::EventHubSourceConfig;

use tracing::error;

/// Configuration for the `eventhub` source.
#[configurable_component(source("eventhub"))]
#[derive(Clone, Debug)]
#[serde(deny_unknown_fields)]
pub struct Config {
    /// Core Event Hub source configuration
    #[configurable(derived)]
    #[serde(flatten)]
    pub eventhub_config: EventHubSourceConfig,

    /// Log namespace configuration
    #[serde(default)]
    pub log_namespace: Option<bool>,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            eventhub_config: EventHubSourceConfig::default(),
            log_namespace: None,
        }
    }
}

impl_generate_config_from_default!(Config);

#[async_trait::async_trait]
#[typetag::serde(name = "eventhub")]
impl SourceConfig for Config {
    async fn build(&self, cx: SourceContext) -> Result<Source> {
        let log_namespace = cx.log_namespace(self.log_namespace);

        let src = eventhub::run_eventhub_source(
            self.eventhub_config.clone(),
            cx.out,
            cx.shutdown.map(|_token| ()),
            log_namespace,
        )
        .map(|r| match r {
            Ok(_) => Ok(()),
            Err(e) => {
                error!("Event Hub source terminated: {}", e);
                Err(())
            }
        });

        Ok(Box::pin(src))
    }

    fn outputs(&self, global_log_namespace: LogNamespace) -> Vec<SourceOutput> {
        let log_namespace = global_log_namespace.merge(self.log_namespace);
        let lns_set = BTreeSet::from([log_namespace]);

        let schema_definition =
            Definition::default_for_namespace(&lns_set).with_standard_vector_source_metadata();

        vec![SourceOutput::new_maybe_logs(
            DataType::Log,
            schema_definition,
        )]
    }

    fn resources(&self) -> Vec<Resource> {
        vec![]
    }

    fn can_acknowledge(&self) -> bool {
        false
    }
}
