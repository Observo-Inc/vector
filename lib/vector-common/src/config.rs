use std::{
    cmp::{Ord, Ordering, PartialOrd},
    fmt,
};
use std::collections::{HashMap, HashSet};
use std::fmt::{Display, Formatter};
use std::hash::Hash;
use std::net::SocketAddr;
use vector_config::{configurable_component, ConfigurableString};

/// Component identifier.
#[configurable_component(no_deser, no_ser)]
#[derive(::serde::Deserialize, ::serde::Serialize)]
#[serde(from = "String", into = "String")]
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct ComponentKey {
    /// Component ID.
    id: String,
}

impl ComponentKey {
    #[must_use]
    pub fn id(&self) -> &str {
        &self.id
    }

    #[must_use]
    pub fn join<D: fmt::Display>(&self, name: D) -> Self {
        Self {
            // ports and inner component use the same naming convention
            id: self.port(name),
        }
    }

    pub fn port<D: fmt::Display>(&self, name: D) -> String {
        format!("{}.{name}", self.id)
    }

    #[must_use]
    pub fn into_id(self) -> String {
        self.id
    }
}

impl From<String> for ComponentKey {
    fn from(id: String) -> Self {
        Self { id }
    }
}

impl From<&str> for ComponentKey {
    fn from(value: &str) -> Self {
        Self::from(value.to_owned())
    }
}

impl From<ComponentKey> for String {
    fn from(key: ComponentKey) -> Self {
        key.into_id()
    }
}

impl fmt::Display for ComponentKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.id.fmt(f)
    }
}

impl Ord for ComponentKey {
    fn cmp(&self, other: &Self) -> Ordering {
        self.id.cmp(&other.id)
    }
}

impl PartialOrd for ComponentKey {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl ConfigurableString for ComponentKey {}

/// Unique thing, like port, of which only one owner can be.
#[derive(Clone, Debug, Eq, PartialEq, Hash, Ord, PartialOrd)]
pub enum Resource { // TODO(akshay): move to a better place (outside `net`)
    Port(SocketAddr, Protocol),
    SystemFdOffset(usize),
    Fd(u32),
    DiskBuffer(String),
}

#[derive(Clone, Debug, Eq, PartialEq, Hash, Ord, PartialOrd, Copy)]
pub enum Protocol {
    Tcp,
    Udp,
}

impl Display for Protocol {
    fn fmt(&self, fmt: &mut Formatter<'_>) -> Result<(), fmt::Error> {
        match self {
            Protocol::Udp => write!(fmt, "udp"),
            Protocol::Tcp => write!(fmt, "tcp"),
        }
    }
}

impl Display for Resource {
    fn fmt(&self, fmt: &mut Formatter<'_>) -> Result<(), fmt::Error> {
        match self {
            Resource::Port(address, protocol) => write!(fmt, "{} {}", protocol, address),
            Resource::SystemFdOffset(offset) => write!(fmt, "systemd {}th socket", offset + 1),
            Resource::Fd(fd) => write!(fmt, "file descriptor: {}", fd),
            Resource::DiskBuffer(name) => write!(fmt, "disk buffer {:?}", name),
        }
    }
}


impl Resource {
    pub const fn tcp(addr: SocketAddr) -> Self {
        Self::Port(addr, Protocol::Tcp)
    }

    pub const fn udp(addr: SocketAddr) -> Self {
        Self::Port(addr, Protocol::Udp)
    }

    /// From given components returns all that have a resource conflict with any other component.
    pub fn conflicts<K: Eq + Hash + Clone>(
        components: impl IntoIterator<Item = (K, Vec<Resource>)>,
    ) -> HashMap<Resource, HashSet<K>> {
        let mut resource_map = HashMap::<Resource, HashSet<K>>::new();
        let mut unspecified = Vec::new();

        // Find equality based conflicts
        for (key, resources) in components {
            for resource in resources {
                if let Resource::Port(address, protocol) = &resource {
                    if address.ip().is_unspecified() {
                        unspecified.push((key.clone(), *address, *protocol));
                    }
                }

                resource_map
                    .entry(resource)
                    .or_default()
                    .insert(key.clone());
            }
        }

        // Port with unspecified address will bind to all network interfaces
        // so we have to check for all Port resources if they share the same
        // port.
        for (key, address0, protocol0) in unspecified {
            for (resource, components) in resource_map.iter_mut() {
                if let Resource::Port(address, protocol) = resource {
                    // IP addresses can either be v4 or v6.
                    // Therefore we check if the ip version matches, the port matches and if the protocol (TCP/UDP) matches
                    // when checking for equality.
                    if &address0 == address && &protocol0 == protocol {
                        components.insert(key.clone());
                    }
                }
            }
        }

        resource_map.retain(|_, components| components.len() > 1);

        resource_map
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deserialize_string() {
        let result: ComponentKey = serde_json::from_str("\"foo\"").unwrap();
        assert_eq!(result.id(), "foo");
    }

    #[test]
    fn serialize_string() {
        let item = ComponentKey::from("foo");
        let result = serde_json::to_string(&item).unwrap();
        assert_eq!(result, "\"foo\"");
    }

    #[test]
    #[allow(clippy::similar_names)]
    fn ordering() {
        let global_baz = ComponentKey::from("baz");
        let yolo_bar = ComponentKey::from("yolo.bar");
        let foo_bar = ComponentKey::from("foo.bar");
        let foo_baz = ComponentKey::from("foo.baz");
        let mut list = vec![&foo_baz, &yolo_bar, &global_baz, &foo_bar];
        list.sort();
        assert_eq!(list, vec![&global_baz, &foo_bar, &foo_baz, &yolo_bar]);
    }
}
