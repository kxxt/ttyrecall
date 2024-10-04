use std::{collections::HashSet, fmt::Display};

use serde::Deserialize;
use ttyrecall_common::{RECALL_CONFIG_MODE_ALLOWLIST, RECALL_CONFIG_MODE_BLOCKLIST};

#[derive(Debug, Deserialize)]
pub struct DaemonConfig {
    /// A list of users.
    pub users: HashSet<String>,
    /// A list of uids
    pub uids: HashSet<u32>,
    /// Mode that determines the meaning of users/uids
    pub mode: Mode,
    /// The root dir for storing recordings.
    pub root: String,
    /// Compression
    pub compress: Compress,
}

#[derive(Debug)]
pub enum Compress {
    None,
    Zstd(Option<i32>),
}

#[derive(Debug, Clone, Copy, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Mode {
    /// Don't capture ptys from block listed user/uids
    BlockList = RECALL_CONFIG_MODE_BLOCKLIST as isize,
    /// Only capture ptys from allow listed user/uids
    AllowList = RECALL_CONFIG_MODE_ALLOWLIST as isize,
}

impl Display for Compress {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Compress::None => f.write_str("none"),
            Compress::Zstd(level) => {
                if let Some(level) = level {
                    write!(f, "zstd:{level}")
                } else {
                    f.write_str("zstd")
                }
            }
        }
    }
}

impl<'de> Deserialize<'de> for Compress {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        let s = s.as_str();
        Ok(match s {
            "none" => Compress::None,
            "zstd" => Compress::Zstd(None),
            s => {
                let Some(("zstd", level)) = s.split_once(':') else {
                    return Err(serde::de::Error::invalid_value(
                        serde::de::Unexpected::Str(s),
                        &"none or zstd or zstd:$level",
                    ));
                };
                match level.parse::<i32>() {
                    Ok(i) if (1..=22).contains(&i) => Compress::Zstd(Some(i)),
                    _ => {
                        return Err(serde::de::Error::invalid_value(
                            serde::de::Unexpected::Str(level),
                            &"A valid zstd compression level (1..=22)",
                        ))
                    }
                }
            }
        })
    }
}
