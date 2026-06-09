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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn daemon_config_from_file_uses_defaults_and_overrides() {
        let config = DaemonConfig::from_file("/var/lib/ttyrecall".to_string(), None);

        assert_eq!(config.root, "/var/lib/ttyrecall");
        assert_eq!(config.uids, HashSet::from([0]));
        assert!(matches!(config.mode, Mode::BlockList));
        assert!(matches!(config.compress, Compress::Zstd(None)));
        assert_eq!(config.soft_budget, 52_428_800);
        assert!(config
            .excluded_comms
            .contains(&Comm::from_name("sudo").unwrap()));

        let override_config = DaemonConfigFile {
            users: Some(HashSet::from(["alice".to_string()])),
            uids: Some(HashSet::from([1000])),
            mode: Some(Mode::AllowList),
            compress: Some(Compress::None),
            excluded_comms: Some(HashSet::from([Comm::from_name("bash").unwrap()])),
            soft_budget: Some(42),
        };
        let config = DaemonConfig::from_file("/tmp/ttyrecall".to_string(), Some(override_config));

        assert_eq!(config.users, HashSet::from(["alice".to_string()]));
        assert_eq!(config.uids, HashSet::from([1000]));
        assert!(matches!(config.mode, Mode::AllowList));
        assert!(matches!(config.compress, Compress::None));
        assert_eq!(
            config.excluded_comms,
            HashSet::from([Comm::from_name("bash").unwrap()])
        );
        assert_eq!(config.soft_budget, 42);
    }

    #[test]
    fn daemon_config_file_merge_preserves_base_when_override_missing() {
        let base = DaemonConfigFile {
            users: Some(HashSet::from(["alice".to_string()])),
            uids: Some(HashSet::from([1000])),
            mode: Some(Mode::BlockList),
            compress: Some(Compress::Zstd(Some(3))),
            excluded_comms: Some(HashSet::from([Comm::from_name("sudo").unwrap()])),
            soft_budget: Some(100),
        };
        let override_config = DaemonConfigFile {
            users: None,
            uids: Some(HashSet::from([2000])),
            mode: Some(Mode::AllowList),
            compress: None,
            excluded_comms: None,
            soft_budget: Some(200),
        };

        let merged = base.merge(override_config);

        assert_eq!(merged.users.unwrap(), HashSet::from(["alice".to_string()]));
        assert_eq!(merged.uids.unwrap(), HashSet::from([2000]));
        assert!(matches!(merged.mode.unwrap(), Mode::AllowList));
        assert!(matches!(merged.compress.unwrap(), Compress::Zstd(Some(3))));
        assert_eq!(
            merged.excluded_comms.unwrap(),
            HashSet::from([Comm::from_name("sudo").unwrap()])
        );
        assert_eq!(merged.soft_budget, Some(200));
    }

    #[test]
    fn compress_display_and_deserialize_accept_valid_values() {
        #[derive(Deserialize)]
        struct Wrapper {
            compress: Compress,
        }

        assert_eq!(Compress::None.to_string(), "none");
        assert_eq!(Compress::Zstd(None).to_string(), "zstd");
        assert_eq!(Compress::Zstd(Some(9)).to_string(), "zstd:9");

        assert!(matches!(
            toml::from_str::<Wrapper>(r#"compress = "none""#)
                .unwrap()
                .compress,
            Compress::None
        ));
        assert!(matches!(
            toml::from_str::<Wrapper>(r#"compress = "zstd""#)
                .unwrap()
                .compress,
            Compress::Zstd(None)
        ));
        assert!(matches!(
            toml::from_str::<Wrapper>(r#"compress = "zstd:22""#)
                .unwrap()
                .compress,
            Compress::Zstd(Some(22))
        ));
    }

    #[test]
    fn compress_deserialize_rejects_invalid_values() {
        #[derive(Deserialize)]
        struct Wrapper {
            #[allow(dead_code)]
            compress: Compress,
        }

        assert!(toml::from_str::<Wrapper>(r#"compress = "gzip""#).is_err());
        assert!(toml::from_str::<Wrapper>(r#"compress = "zstd:0""#).is_err());
        assert!(toml::from_str::<Wrapper>(r#"compress = "zstd:23""#).is_err());
        assert!(toml::from_str::<Wrapper>(r#"compress = "zstd:fast""#).is_err());
    }

    #[test]
    fn comm_from_name_pads_and_rejects_long_names() {
        let comm = Comm::from_name("bash").unwrap();

        assert_eq!(&comm.0[..4], b"bash");
        assert!(comm.0[4..].iter().all(|byte| *byte == 0));
        assert!(Comm::from_name("123456789012345").is_ok());
        assert!(Comm::from_name("1234567890123456").is_err());
    }
}
