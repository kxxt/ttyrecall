use std::path::PathBuf;

use serde::Deserialize;

use crate::daemon::{DaemonConfig, DaemonConfigFile};
use crate::indexer::{IndexerConfig, IndexerConfigFile};

pub(crate) const DEFAULT_CONFIG_PATH: &str = "/etc/ttyrecall/config.toml";

#[derive(Debug)]
pub(crate) struct AppConfig {
    pub(crate) root: String,
    pub(crate) daemon: DaemonConfig,
    pub(crate) web: WebConfigFile,
    pub(crate) indexer: IndexerConfig,
}

#[derive(Debug, Deserialize, Default)]
struct AppConfigFile {
    root: Option<String>,
    daemon: Option<DaemonConfigFile>,
    web: Option<WebConfigFile>,
    indexer: Option<IndexerConfigFile>,
    #[allow(dead_code)]
    tui: Option<TuiConfigFile>,
}

#[derive(Debug, Deserialize, Default, Clone)]
pub(crate) struct WebConfigFile {
    pub(crate) bind: Option<String>,
    pub(crate) pam_service: Option<String>,
    pub(crate) session_ttl_minutes: Option<u64>,
    pub(crate) frontend_root: Option<String>,
    pub(crate) single_user_token: Option<String>,
    pub(crate) single_user_uid: Option<u32>,
    pub(crate) single_user_username: Option<String>,
}

#[derive(Debug, Deserialize, Default)]
struct TuiConfigFile {}

impl AppConfigFile {
    fn merge(self, override_config: Self) -> Self {
        Self {
            root: override_config.root.or(self.root),
            daemon: merge_option(self.daemon, override_config.daemon, DaemonConfigFile::merge),
            web: merge_option(self.web, override_config.web, WebConfigFile::merge),
            indexer: merge_option(
                self.indexer,
                override_config.indexer,
                IndexerConfigFile::merge,
            ),
            tui: merge_option(self.tui, override_config.tui, TuiConfigFile::merge),
        }
    }
}

impl WebConfigFile {
    fn merge(self, override_config: Self) -> Self {
        Self {
            bind: override_config.bind.or(self.bind),
            pam_service: override_config.pam_service.or(self.pam_service),
            session_ttl_minutes: override_config
                .session_ttl_minutes
                .or(self.session_ttl_minutes),
            frontend_root: override_config.frontend_root.or(self.frontend_root),
            single_user_token: override_config.single_user_token.or(self.single_user_token),
            single_user_uid: override_config.single_user_uid.or(self.single_user_uid),
            single_user_username: override_config
                .single_user_username
                .or(self.single_user_username),
        }
    }
}

impl TuiConfigFile {
    fn merge(self, _override_config: Self) -> Self {
        Self {}
    }
}

pub(crate) fn load_system(path: Option<PathBuf>) -> color_eyre::Result<AppConfig> {
    let path = path.unwrap_or_else(system_config_path);
    Ok(from_file_config(load_optional_file(path)?))
}

pub(crate) fn load_system_with_user_override(
    path: Option<PathBuf>,
) -> color_eyre::Result<AppConfig> {
    if let Some(path) = path {
        return Ok(from_file_config(load_optional_file(path)?));
    }

    let system_config = load_optional_file(system_config_path())?;
    let user_config = load_optional_file(user_config_path())?;
    Ok(from_file_config(system_config.merge(user_config)))
}

pub(crate) fn load_required(path: Option<PathBuf>) -> color_eyre::Result<AppConfig> {
    let path = path.unwrap_or_else(system_config_path);
    let file_config = load_required_file(path)?;
    Ok(from_file_config(file_config))
}

fn load_optional_file(path: PathBuf) -> color_eyre::Result<AppConfigFile> {
    if !path.exists() {
        return Ok(AppConfigFile::default());
    }
    load_required_file(path)
}

fn load_required_file(path: PathBuf) -> color_eyre::Result<AppConfigFile> {
    let content = std::fs::read_to_string(&path)?;
    Ok(toml::from_str::<AppConfigFile>(&content)?)
}

fn system_config_path() -> PathBuf {
    PathBuf::from(DEFAULT_CONFIG_PATH)
}

fn user_config_path() -> PathBuf {
    if let Some(path) = std::env::var_os("XDG_CONFIG_HOME") {
        return PathBuf::from(path).join("ttyrecall/config.toml");
    }
    if let Some(path) = std::env::var_os("HOME") {
        return PathBuf::from(path).join(".config/ttyrecall/config.toml");
    }
    PathBuf::from("./config.toml")
}

fn merge_option<T>(
    base: Option<T>,
    override_value: Option<T>,
    merge: impl FnOnce(T, T) -> T,
) -> Option<T> {
    match (base, override_value) {
        (Some(base), Some(override_value)) => Some(merge(base, override_value)),
        (None, Some(override_value)) => Some(override_value),
        (Some(base), None) => Some(base),
        (None, None) => None,
    }
}

fn from_file_config(file_config: AppConfigFile) -> AppConfig {
    let root = file_config
        .root
        .unwrap_or_else(|| "/var/lib/ttyrecall".to_string());

    AppConfig {
        root: root.clone(),
        daemon: DaemonConfig::from_file(root.clone(), file_config.daemon),
        web: file_config.web.unwrap_or_default(),
        indexer: IndexerConfig::from_file(root, file_config.indexer),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::daemon::{Compress, Mode};

    #[test]
    fn minimal_common_config_uses_section_defaults() {
        let config = toml::from_str::<AppConfigFile>(
            r#"
root = "/tmp/ttyrecall"

[daemon]
compress = "zstd"

[web]

[tui]
"#,
        )
        .unwrap();
        let root = config.root.unwrap();
        let daemon = DaemonConfig::from_file(root, config.daemon);

        assert_eq!(daemon.root, "/tmp/ttyrecall");
        assert!(matches!(daemon.compress, Compress::Zstd(None)));
        assert!(matches!(daemon.mode, Mode::BlockList));
        assert_eq!(daemon.uids, std::collections::HashSet::from([0]));
        assert_eq!(daemon.soft_budget, 52_428_800);
    }

    #[test]
    fn sample_common_config_parses() {
        let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../etc/config.toml");
        let content = std::fs::read_to_string(path).unwrap();
        let config = from_file_config(toml::from_str::<AppConfigFile>(&content).unwrap());

        assert_eq!(config.root, "/var/lib/ttyrecall");
        assert_eq!(config.web.bind.as_deref(), Some("127.0.0.1:8450"));
        assert!(!config.indexer.enabled);
        assert_eq!(config.indexer.meilisearch_url, "http://127.0.0.1:7700");
    }

    #[test]
    fn user_config_overrides_system_values_field_by_field() {
        let system = toml::from_str::<AppConfigFile>(
            r#"
root = "/var/lib/ttyrecall"

[daemon]
compress = "zstd"
soft_budget = 10

[web]
bind = "127.0.0.1:8450"
pam_service = "login"
session_ttl_minutes = 60
"#,
        )
        .unwrap();
        let user = toml::from_str::<AppConfigFile>(
            r#"
root = "/tmp/ttyrecall"

[web]
bind = "127.0.0.1:9000"
session_ttl_minutes = 5
"#,
        )
        .unwrap();

        let config = from_file_config(system.merge(user));

        assert_eq!(config.root, "/tmp/ttyrecall");
        assert_eq!(config.web.bind.as_deref(), Some("127.0.0.1:9000"));
        assert_eq!(config.web.pam_service.as_deref(), Some("login"));
        assert_eq!(config.web.session_ttl_minutes, Some(5));
        assert_eq!(config.daemon.soft_budget, 10);
    }

    #[test]
    fn indexer_config_merges_field_by_field() {
        let system = toml::from_str::<AppConfigFile>(
            r#"
[indexer]
enabled = true
meilisearch_url = "http://127.0.0.1:7700"
api_key = "secret"
index_name = "ttyrecall"
batch_size = 80
"#,
        )
        .unwrap();
        let user = toml::from_str::<AppConfigFile>(
            r#"
[indexer]
api_key = "override"
batch_size = 10
"#,
        )
        .unwrap();

        let config = from_file_config(system.merge(user));

        assert!(config.indexer.enabled);
        assert_eq!(config.indexer.api_key.as_deref(), Some("override"));
        assert_eq!(config.indexer.index_name, "ttyrecall");
        assert_eq!(config.indexer.batch_size, 10);
    }
}
