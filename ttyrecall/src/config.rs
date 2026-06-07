use std::path::PathBuf;

use color_eyre::eyre::WrapErr;
use serde::Deserialize;

use crate::daemon::{DaemonConfig, DaemonConfigFile};

pub(crate) const DEFAULT_CONFIG_PATH: &str = "/etc/ttyrecall/config.toml";

#[derive(Debug)]
pub(crate) struct AppConfig {
    pub(crate) root: String,
    pub(crate) daemon: DaemonConfig,
    pub(crate) web: WebConfigFile,
    pub(crate) search: SearchConfig,
}

#[derive(Debug, Deserialize, Default)]
struct AppConfigFile {
    root: Option<String>,
    daemon: Option<DaemonConfigFile>,
    web: Option<WebConfigFile>,
    search: Option<SearchConfigFile>,
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

#[derive(Debug, Deserialize, Default, Clone)]
pub(crate) struct SearchConfigFile {
    pub(crate) enabled: Option<bool>,
    pub(crate) ripgrep_path: Option<String>,
    pub(crate) max_results: Option<usize>,
}

#[derive(Debug, Clone)]
pub(crate) struct SearchConfig {
    pub(crate) enabled: bool,
    pub(crate) ripgrep_path: String,
    pub(crate) max_results: usize,
}

#[derive(Debug, Deserialize, Default)]
struct TuiConfigFile {}

impl AppConfigFile {
    fn merge(self, override_config: Self) -> Self {
        Self {
            root: override_config.root.or(self.root),
            daemon: merge_option(self.daemon, override_config.daemon, DaemonConfigFile::merge),
            web: merge_option(self.web, override_config.web, WebConfigFile::merge),
            search: merge_option(self.search, override_config.search, SearchConfigFile::merge),
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

impl SearchConfigFile {
    fn merge(self, override_config: Self) -> Self {
        Self {
            enabled: override_config.enabled.or(self.enabled),
            ripgrep_path: override_config.ripgrep_path.or(self.ripgrep_path),
            max_results: override_config.max_results.or(self.max_results),
        }
    }
}

impl SearchConfig {
    pub(crate) fn from_file(config: Option<SearchConfigFile>) -> Self {
        let config = config.unwrap_or_default();
        Self {
            enabled: config.enabled.unwrap_or(false),
            ripgrep_path: config.ripgrep_path.unwrap_or_else(|| "rg".to_string()),
            max_results: config.max_results.unwrap_or(50),
        }
    }
}

impl TuiConfigFile {
    fn merge(self, _override_config: Self) -> Self {
        Self {}
    }
}

pub(crate) fn load_system(path: Option<PathBuf>) -> color_eyre::Result<AppConfig> {
    let file_config = match path {
        Some(path) => load_required_file(path)?,
        None => load_optional_file(system_config_path())?,
    };
    Ok(from_file_config(file_config))
}

pub(crate) fn load_system_with_user_override(
    path: Option<PathBuf>,
) -> color_eyre::Result<AppConfig> {
    if let Some(path) = path {
        return Ok(from_file_config(load_required_file(path)?));
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
    let content = std::fs::read_to_string(&path)
        .wrap_err_with(|| format!("failed to read config file {}", path.display()))?;
    toml::from_str::<AppConfigFile>(&content)
        .wrap_err_with(|| format!("failed to parse config file {}", path.display()))
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
        search: SearchConfig::from_file(file_config.search),
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

[search]
"#,
        )
        .unwrap();
        let app_config = from_file_config(config);
        let daemon = app_config.daemon;

        assert_eq!(daemon.root, "/tmp/ttyrecall");
        assert!(matches!(daemon.compress, Compress::Zstd(None)));
        assert!(matches!(daemon.mode, Mode::BlockList));
        assert_eq!(daemon.uids, std::collections::HashSet::from([0]));
        assert_eq!(daemon.soft_budget, 52_428_800);
        assert!(!app_config.search.enabled);
        assert_eq!(app_config.search.ripgrep_path, "rg");
        assert_eq!(app_config.search.max_results, 50);
    }

    #[test]
    fn sample_common_config_parses() {
        let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../etc/config.toml");
        let content = std::fs::read_to_string(path).unwrap();
        let config = from_file_config(toml::from_str::<AppConfigFile>(&content).unwrap());

        assert_eq!(config.root, "/var/lib/ttyrecall");
        assert_eq!(config.web.bind.as_deref(), Some("127.0.0.1:8450"));
        assert_eq!(config.search.ripgrep_path, "rg");
        assert_eq!(config.search.max_results, 50);
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

[search]
enabled = false
ripgrep_path = "/usr/bin/rg"
max_results = 25
"#,
        )
        .unwrap();
        let user = toml::from_str::<AppConfigFile>(
            r#"
root = "/tmp/ttyrecall"

[web]
bind = "127.0.0.1:9000"
session_ttl_minutes = 5

[search]
enabled = true
max_results = 5
"#,
        )
        .unwrap();

        let config = from_file_config(system.merge(user));

        assert_eq!(config.root, "/tmp/ttyrecall");
        assert_eq!(config.web.bind.as_deref(), Some("127.0.0.1:9000"));
        assert_eq!(config.web.pam_service.as_deref(), Some("login"));
        assert_eq!(config.web.session_ttl_minutes, Some(5));
        assert_eq!(config.daemon.soft_budget, 10);
        assert!(config.search.enabled);
        assert_eq!(config.search.ripgrep_path, "/usr/bin/rg");
        assert_eq!(config.search.max_results, 5);
    }

    #[test]
    fn explicit_system_config_path_must_exist() {
        let missing = missing_test_config_path("system");

        let error = load_system(Some(missing.clone())).unwrap_err();

        assert!(error
            .to_string()
            .contains(&format!("failed to read config file {}", missing.display())));
    }

    #[test]
    fn explicit_user_override_config_path_must_exist() {
        let missing = missing_test_config_path("user-override");

        let error = load_system_with_user_override(Some(missing.clone())).unwrap_err();

        assert!(error
            .to_string()
            .contains(&format!("failed to read config file {}", missing.display())));
    }

    #[test]
    fn optional_missing_config_file_still_uses_defaults() {
        let missing = missing_test_config_path("optional");

        let config = load_optional_file(missing).unwrap();
        let app_config = from_file_config(config);

        assert_eq!(app_config.root, "/var/lib/ttyrecall");
        assert!(!app_config.search.enabled);
    }

    fn missing_test_config_path(name: &str) -> PathBuf {
        let path = std::env::temp_dir().join(format!(
            "ttyrecall-missing-config-{}-{name}.toml",
            std::process::id()
        ));
        let _ = std::fs::remove_file(&path);
        path
    }
}
