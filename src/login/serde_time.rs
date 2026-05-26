//! Serde helpers for serializing `SystemTime` as Unix seconds (`u64`).
//!
//! Session timestamps are stored as `SystemTime` in the domain types but
//! serialized as integer seconds for compact, portable wire/storage formats.

use std::time::{Duration, SystemTime};

use serde::{Deserialize, Deserializer, Serialize, Serializer};

fn to_unix(t: SystemTime) -> u64 {
    t.duration_since(SystemTime::UNIX_EPOCH)
        .unwrap_or(Duration::ZERO)
        .as_secs()
}

fn from_unix(secs: u64) -> SystemTime {
    SystemTime::UNIX_EPOCH + Duration::from_secs(secs)
}

pub(crate) mod unix_secs {
    use super::*;

    pub fn serialize<S: Serializer>(time: &SystemTime, ser: S) -> Result<S::Ok, S::Error> {
        to_unix(*time).serialize(ser)
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(de: D) -> Result<SystemTime, D::Error> {
        u64::deserialize(de).map(from_unix)
    }
}

pub(crate) mod option_unix_secs {
    use super::*;

    pub fn serialize<S: Serializer>(time: &Option<SystemTime>, ser: S) -> Result<S::Ok, S::Error> {
        time.map(to_unix).serialize(ser)
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(de: D) -> Result<Option<SystemTime>, D::Error> {
        Option::<u64>::deserialize(de).map(|opt| opt.map(from_unix))
    }
}
