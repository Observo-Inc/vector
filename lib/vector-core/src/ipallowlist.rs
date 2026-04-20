use serde::{Deserialize, Serialize};
use std::net::IpAddr;
use std::str::FromStr;
use std::cell::RefCell;
use vector_config::GenerateError;

use ipnet::IpNet;
use vector_config::{configurable_component, Configurable, Metadata, ToValue};
use vector_config_common::schema::{InstanceType, SchemaGenerator, SchemaObject};

/// List of allowed origin IP networks. Entries may be in CIDR notation (e.g. `192.168.0.0/16`) or bare IP addresses (e.g. `127.0.0.1`, treated as `/32` or `/128`).
#[configurable_component]
#[derive(Clone, Debug, PartialEq, Eq)]
#[serde(deny_unknown_fields, transparent)]
#[configurable(metadata(docs::human_name = "Allowed IP network origins"))]
#[configurable(metadata(docs::examples = "ip_allow_list_example()"))]
pub struct IpAllowlistConfig(pub Vec<IpNetConfig>);

const fn ip_allow_list_example() -> [&'static str; 4] {
    [
        "192.168.0.0/16",
        "127.0.0.1/32",
        "::1/128",
        "9876:9ca3:99ab::23/128",
    ]
}

/// IP network
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(transparent)]
pub struct IpNetConfig(pub IpNet);

impl FromStr for IpNetConfig {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        // Try CIDR notation first (e.g. "10.0.0.1/32")
        if let Ok(net) = s.parse::<IpNet>() {
            return Ok(IpNetConfig(net));
        }
        // Fall back to bare IP address — treat as a host network (/32 or /128)
        s.parse::<IpAddr>()
            .map(|addr| IpNetConfig(IpNet::from(addr)))
            .map_err(|_| format!("invalid IP address or network: {s}"))
    }
}

impl<'de> Deserialize<'de> for IpNetConfig {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        s.parse().map_err(serde::de::Error::custom)
    }
}

impl ToValue for IpNetConfig {
    fn to_value(&self) -> serde_json::Value {
        serde_json::Value::String(self.0.to_string())
    }
}

impl Configurable for IpNetConfig {
    fn generate_schema(
        _: &RefCell<SchemaGenerator>,
    ) -> std::result::Result<SchemaObject, GenerateError> {
        Ok(SchemaObject {
            instance_type: Some(InstanceType::String.into()),
            ..Default::default()
        })
    }

    fn metadata() -> Metadata {
        Metadata::with_description("IP network")
    }
}

impl From<IpAllowlistConfig> for Vec<IpNet> {
    fn from(value: IpAllowlistConfig) -> Self {
        value.0.iter().map(|net| net.0).collect()
    }
}
