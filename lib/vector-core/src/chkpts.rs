use std::path::PathBuf;

use async_trait::async_trait;
use serde_with::serde_as;
use vector_config::{configurable_component, NamedComponent};

use vector_common::id::ComponentKey;

pub use vector_common::chkpts::*;

#[cfg(feature = "observo")]
use chkpts::{StoreConfig as ObCfg, Store as ObStore};

/// Checkpoint store config.
#[serde_as]
#[configurable_component]
#[derive(Clone, Debug, Eq, PartialEq, Default)]
#[serde(untagged)]
pub enum StoreConfig {
    #[cfg(feature = "observo")]
    Observo(ObCfg),
    #[default]
    None
}

#[async_trait]
pub trait Store : Send + Sync + 'static {
    fn accessor(&self, key: ComponentKey) -> Box<dyn Accessor>;
    async fn reload( &mut self, config: StoreConfig, default_data_dir: Option<PathBuf>) -> crate::Result<()>;
}

#[cfg(feature = "observo")]
#[async_trait]
impl Store for ObStore {
    fn accessor(&self, key: ComponentKey) -> Box<dyn Accessor> {
        Box::new(self.accessor(key))
    }

    async fn reload(&mut self, config: StoreConfig, default_data_dir: Option<PathBuf>) -> crate::Result<()> {
        match config {
            #[cfg(feature = "observo")]
            StoreConfig::Observo(cfg) => {
                *self = cfg.build(default_data_dir).await?;
            },
            StoreConfig::None => {
                tracing::warn!("Checkpoint store config has been dropped but unload is not supported. Restart process to unload (if necessary).");
            },
        }
        Ok(())
    }
}

impl StoreConfig {
    #[allow(unused)]
    pub async fn build(self, data_dir: Option<PathBuf>) -> crate::Result<Option<Box<dyn Store + Send + Sync>>> {
        match self {
            #[cfg(feature = "observo")]
            StoreConfig::Observo(cfg) => Ok(Some(Box::new(cfg.build(data_dir).await?))),
            StoreConfig::None => Ok(None),
        }
    }

    pub fn merge(&self, other: &Self) -> Result<Self, String> {
        match (self, other) {
            #[cfg(feature = "observo")]
            (StoreConfig::Observo(l), StoreConfig::Observo(r)) => {
                l.merge(r).map(StoreConfig::Observo).map_err(|e| e.to_string())
            },
            #[cfg(feature = "observo")]
            (l, StoreConfig::None) => Ok(l.clone()),
            (&StoreConfig::None, r) => Ok(r.clone()),
        }
    }
}

impl NamedComponent for StoreConfig {
    fn get_component_name(&self) -> &'static str {
        match self {
            #[cfg(feature = "observo")]
            StoreConfig::Observo(config) => config.get_component_name(),
            StoreConfig::None => "none",
        }
    }
}
