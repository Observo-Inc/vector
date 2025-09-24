use std::{error::Error, fmt::Display};

use crate::id::ComponentKey;
use chrono::{DateTime, Utc};

#[derive(Debug, PartialEq, Eq, Hash)]
pub struct ChkptId {
    pub key: ComponentKey,
    pub id: String,
}

impl ChkptId {
    pub fn new(key: ComponentKey, id: String) -> Self {
        Self { key, id }
    }
}

#[derive(Debug, PartialEq, Eq)]
pub struct Value {
    pub chkpt: ChkptId,
    pub value: String,
    pub context: String,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug)]
pub enum ChkptErr {
    NotFound(ChkptId),
    RaceLost(Value),
    TooBig(Value),
    Unknown(crate::Error)
}

impl Display for ChkptErr {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{self:?}")
    }
}

impl Error for ChkptErr {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Unknown(e) => Some(e.as_ref()),
            _ => None,
        }
    }
}

pub trait Accessor: Send + dyn_clone::DynClone + Sync {
    fn get(&self, id: String) -> Result<Value, ChkptErr>;
    fn set(&self, id: String, value: String, ctx: String) -> Result<(), ChkptErr>;
}

dyn_clone::clone_trait_object!(Accessor);