use std::{path::PathBuf, time::Duration};

use nix::unistd::{Uid, User};

use crate::config as common_config;
use crate::indexer::IndexerConfig;

use super::session::new_session_token;

#[derive(Clone, Debug)]
pub enum WebMode {
    Service,
    SingleUser { uid: u32, username: String },
}

#[derive(Debug, Clone)]
pub(super) struct WebConfig {
    pub(super) bind: String,
    pub(crate) root: PathBuf,
    pub(super) pam_service: String,
    pub(super) session_ttl: Duration,
    pub(super) frontend_root: PathBuf,
    pub(super) single_user_token: Option<String>,
    pub(super) single_user_uid: Option<u32>,
    pub(super) single_user_username: Option<String>,
    pub(super) indexer: IndexerConfig,
}

#[derive(Debug, Clone)]
pub(super) struct SingleUser {
    pub(super) uid: u32,
    pub(super) username: String,
}

pub(crate) fn load_config(mode: &WebMode, path: Option<PathBuf>) -> color_eyre::Result<WebConfig> {
    let default_bind = "127.0.0.1:8450".to_string();
    let default_pam = "login".to_string();
    let default_ttl = Duration::from_secs(60 * 60);

    let app_config = match mode {
        WebMode::Service => common_config::load_system(path)?,
        WebMode::SingleUser { .. } => common_config::load_system_with_user_override(path)?,
    };
    let file_config = app_config.web;

    Ok(WebConfig {
        bind: file_config.bind.unwrap_or(default_bind),
        root: PathBuf::from(app_config.root),
        pam_service: file_config.pam_service.unwrap_or(default_pam),
        session_ttl: Duration::from_secs(
            file_config
                .session_ttl_minutes
                .unwrap_or(default_ttl.as_secs() / 60)
                * 60,
        ),
        frontend_root: file_config
            .frontend_root
            .map(PathBuf::from)
            .unwrap_or_else(default_frontend_root),
        single_user_token: file_config.single_user_token,
        single_user_uid: file_config.single_user_uid,
        single_user_username: file_config.single_user_username,
        indexer: app_config.indexer,
    })
}

pub(crate) fn resolve_single_user(
    mode: &WebMode,
    config: &WebConfig,
) -> color_eyre::Result<Option<SingleUser>> {
    let mut single_user = match mode {
        WebMode::Service => None,
        WebMode::SingleUser { uid, username } => Some(SingleUser {
            uid: *uid,
            username: username.clone(),
        }),
    };

    if let Some(single_user) = single_user.as_mut() {
        if let Some(username) = config.single_user_username.clone() {
            single_user.username = username;
        }
        if let Some(uid) = config.single_user_uid {
            single_user.uid = uid;
        }
        if config.single_user_uid.is_some() && config.single_user_username.is_none() {
            if let Ok(Some(user)) = User::from_uid(Uid::from_raw(single_user.uid)) {
                single_user.username = user.name;
            }
        }
        if config.single_user_username.is_some() && config.single_user_uid.is_none() {
            if let Ok(Some(user)) = User::from_name(&single_user.username) {
                single_user.uid = user.uid.as_raw();
            }
        }
    }

    Ok(single_user)
}

pub(super) fn prepare_single_user_token(mode: &WebMode, config: &WebConfig) -> Option<String> {
    match mode {
        WebMode::Service => None,
        WebMode::SingleUser { .. } => {
            let token = config
                .single_user_token
                .clone()
                .unwrap_or_else(new_session_token);
            let display_bind = display_bind(&config.bind);
            println!("Single user token: {token}");
            println!(
                "Single user login URL: http://{}/?token={}",
                display_bind, token
            );
            Some(token)
        }
    }
}

pub fn current_user_mode() -> color_eyre::Result<WebMode> {
    let mut uid = Uid::current().as_raw();
    let mut username = User::from_uid(Uid::current())?
        .map(|user| user.name)
        .unwrap_or_else(|| uid.to_string());

    if uid == 0 {
        if let Ok(sudo_uid) = std::env::var("SUDO_UID") {
            if let Ok(parsed) = sudo_uid.parse::<u32>() {
                uid = parsed;
            }
        }
        if let Ok(sudo_user) = std::env::var("SUDO_USER") {
            username = sudo_user;
        }
        if username == "root" && uid != 0 {
            if let Ok(Some(user)) = User::from_uid(Uid::from_raw(uid)) {
                username = user.name;
            }
        }
    }

    Ok(WebMode::SingleUser { uid, username })
}

fn default_frontend_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("frontend")
        .join("dist")
}

fn display_bind(bind: &str) -> String {
    if let Some(port) = bind.rsplit_once(':').map(|(_, port)| port) {
        if bind.starts_with("0.0.0.0:") || bind.starts_with("[::]:") {
            return format!("127.0.0.1:{port}");
        }
    }
    bind.to_string()
}
