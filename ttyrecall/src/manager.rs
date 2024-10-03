use std::{
    borrow::Cow,
    fs::{create_dir, set_permissions, File, Permissions},
    io::{self, ErrorKind},
    os::{linux::fs::MetadataExt, unix::fs::PermissionsExt},
    path::PathBuf,
};

use chrono::{DateTime, Datelike, Local, Timelike};
use color_eyre::{eyre::bail, Section};
use log::warn;
use nix::{
    sys::stat::{umask, Mode},
    unistd::{chown, Gid, Group, Uid},
};

use crate::daemon::Compress;

/// A manager for on-disk recordings
#[derive(Debug)]
pub struct Manager {
    root: PathBuf,
    group: Option<Group>,
    pub compress: Compress,
}

impl Manager {
    /// Create a new manager,
    /// It could be opened in exclusive mode to ensure two daemons won't step
    /// on each other's toes.
    pub fn new(dir: String, exclusive: bool, compress: Compress) -> color_eyre::Result<Self> {
        let root = PathBuf::from(dir);
        let meta = root
            .metadata()
            .with_note(|| format!("Does the storage root {root:?} exist?"))?;
        if !meta.is_dir() {
            bail!("Storage root dir {root:?} does not exist or inaccessible.");
        }
        // Check ownership. It should be owned by root:ttyrecall
        let uid = Uid::from_raw(meta.st_uid());
        if !uid.is_root() {
            warn!("Storage root dir {root:?} is not owned by root user!");
        }
        let group = Group::from_name("ttyrecall")?;
        if let Some(group) = group.as_ref() {
            let gid = Gid::from_raw(meta.st_gid());
            if gid != group.gid {
                warn!("Storage root dir {root:?} is not owned by ttyrecall group!")
            }
        } else {
            warn!("Group ttyrecall does not exist!");
        }
        // Set umask to 007
        umask(Mode::S_IXOTH | Mode::S_IROTH | Mode::S_IWOTH);
        // TODO: Maybe check permissions
        Ok(Self {
            root,
            group,
            compress,
        })
    }

    pub fn create_recording_file(
        &self,
        uid: Uid,
        pty_id: u32,
        comm: &str,
    ) -> color_eyre::Result<File> {
        let now = chrono::Local::now();

        let path_for_recording = |counter: usize| {
            self.root.join(format!(
                "{uid}/{year}/{month:02}/{day:02}/{comm}-pty{pty_id}-{hour:02}:{minte:02}{dash}{cnt}.cast{compress}",
                year = now.year(),
                month = now.month(),
                day = now.day(),
                hour = now.hour(),
                minte = now.minute(),
                dash = if counter > 0 { "-" } else { "" },
                cnt = if counter > 0 { Cow::Owned(counter.to_string()) } else { Cow::Borrowed("") },
                compress = if let Compress::Zstd(_) = self.compress { ".zst" } else { "" }
            ))
        };
        for counter in 0..32768 {
            let path = path_for_recording(counter);
            match File::create_new(&path) {
                Ok(f) => {
                    chown(&path, Some(uid), self.group.as_ref().map(|g| g.gid))?;
                    return Ok(f);
                }
                Err(e) => match e.kind() {
                    ErrorKind::AlreadyExists => continue,
                    ErrorKind::NotFound => {
                        self.create_dir_for_date(uid, now)?;
                        continue;
                    }
                    _ => return Err(e.into()),
                },
            }
        }
        bail!("Failed to create recording file for pty {pty_id}");
    }

    fn create_dir_for_date(&self, uid: Uid, date: DateTime<Local>) -> color_eyre::Result<PathBuf> {
        let mut dir = self.root.join(format!("{}", uid.as_raw()));
        if !dir.is_dir() {
            self.add_user(uid)?;
        }
        dir.push(date.year().to_string());
        self.create_dir_helper(&dir, uid)?;
        dir.push(format!("{:02}", date.month()));
        self.create_dir_helper(&dir, uid)?;
        dir.push(format!("{:02}", date.day()));
        self.create_dir_helper(&dir, uid)?;
        Ok(dir)
    }

    fn add_user(&self, uid: Uid) -> color_eyre::Result<()> {
        // Create user's directory
        let dir = self.root.join(format!("{}", uid.as_raw()));
        self.create_dir_helper(&dir, uid)?;
        // Changing Permission to rwxrwx---
        set_permissions(&dir, Permissions::from_mode(0o770))?;
        Ok(())
    }

    /// Creates the directory and set owner to user:ttyrecall
    fn create_dir_helper(&self, dir: &PathBuf, uid: Uid) -> color_eyre::Result<()> {
        match create_dir(dir) {
            Ok(_) => (),
            Err(e) if e.kind() == io::ErrorKind::AlreadyExists => (),
            r => r?,
        }
        // Changing ownership to user:ttyrecall
        chown(dir, Some(uid), self.group.as_ref().map(|g| g.gid))?;
        Ok(())
    }
}
