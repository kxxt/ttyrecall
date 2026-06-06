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
    /// Excluded comms
    pub excluded_comms: HashSet<Comm>,
    /// Soft budget
    pub soft_budget: usize,
}

#[derive(Debug, Deserialize, Default)]
pub(crate) struct DaemonConfigFile {
    /// A list of users.
    pub users: Option<HashSet<String>>,
    /// A list of uids
    pub uids: Option<HashSet<u32>>,
    /// Mode that determines the meaning of users/uids
    pub mode: Option<Mode>,
    /// Compression
    pub compress: Option<Compress>,
    /// Excluded comms
    pub excluded_comms: Option<HashSet<Comm>>,
    /// Soft budget
    pub soft_budget: Option<usize>,
}

impl DaemonConfigFile {
    pub(crate) fn merge(self, override_config: Self) -> Self {
        Self {
            users: override_config.users.or(self.users),
            uids: override_config.uids.or(self.uids),
            mode: override_config.mode.or(self.mode),
            compress: override_config.compress.or(self.compress),
            excluded_comms: override_config.excluded_comms.or(self.excluded_comms),
            soft_budget: override_config.soft_budget.or(self.soft_budget),
        }
    }
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

impl DaemonConfig {
    pub(crate) fn from_file(root: String, config: Option<DaemonConfigFile>) -> Self {
        let config = config.unwrap_or_default();
        Self {
            users: config.users.unwrap_or_default(),
            uids: config.uids.unwrap_or_else(default_uids),
            mode: config.mode.unwrap_or(Mode::BlockList),
            root,
            compress: config.compress.unwrap_or(Compress::Zstd(None)),
            excluded_comms: config.excluded_comms.unwrap_or_else(default_excluded_comms),
            soft_budget: config.soft_budget.unwrap_or(52_428_800),
        }
    }
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

#[derive(Debug, PartialEq, Eq, Hash)]
pub struct Comm(pub [u8; 16]);

impl<'de> Deserialize<'de> for Comm {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        Self::from_name(&s).map_err(|_| {
            serde::de::Error::invalid_value(
                serde::de::Unexpected::Str(&s),
                &"A valid comm string (byte length is less than 16)",
            )
        })
    }
}

impl Comm {
    pub(crate) fn from_name(name: &str) -> Result<Self, ()> {
        let bytes = name.as_bytes();
        if name.len() > 15 {
            return Err(());
        }
        let mut comm = [0; 16];
        comm[..bytes.len()].copy_from_slice(bytes);
        Ok(Self(comm))
    }
}

fn default_uids() -> HashSet<u32> {
    HashSet::from([0])
}

fn default_excluded_comms() -> HashSet<Comm> {
    HashSet::from([
        Comm::from_name("sudo").expect("static comm is valid"),
        Comm::from_name("asciinema").expect("static comm is valid"),
    ])
}
