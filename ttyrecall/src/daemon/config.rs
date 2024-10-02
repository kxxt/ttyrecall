use std::collections::HashSet;

use serde::Deserialize;

#[derive(Debug, Deserialize)]
pub struct DaemonConfig {
    /// A list of users that should be excluded.
    pub exclude_users: HashSet<String>,
    /// The root dir for storing recordings.
    pub root: String,
}
