use std::{
    borrow::Cow,
    fs::File,
    os::{
        fd::{AsRawFd, FromRawFd, RawFd},
        linux::fs::MetadataExt,
    },
    path::{Path, PathBuf},
};

use chrono::{DateTime, Datelike, Local, Timelike};
use color_eyre::{
    eyre::{bail, eyre},
    Section,
};
use log::warn;
use nix::{
    errno::Errno,
    fcntl::{open, openat, AtFlags, OFlag},
    sys::stat::{fchmod, fstatat, mkdirat, umask, Mode},
    unistd::{fchown, Gid, Group, Uid},
};

use crate::daemon::Compress;

pub(crate) const RECORDING_UNFINISHED_SUFFIX: &str = ".unfinished";

/// A manager for on-disk recordings
#[derive(Debug)]
pub struct Manager {
    root: PathBuf,
    group: Option<Group>,
    directory_owner: Uid,
    pub compress: Compress,
}

#[derive(Debug)]
pub(crate) struct PendingRecordingFile {
    pub(crate) file: File,
    pub(crate) unfinished_path: PathBuf,
    pub(crate) final_path: PathBuf,
}

impl Manager {
    /// Create a new manager,
    /// It could be opened in exclusive mode to ensure two daemons won't step
    /// on each other's toes.
    pub fn new(dir: String, _exclusive: bool, compress: Compress) -> color_eyre::Result<Self> {
        let root = PathBuf::from(dir);
        let meta = root
            .symlink_metadata()
            .with_note(|| format!("Does the storage root {root:?} exist?"))?;
        if meta.file_type().is_symlink() {
            bail!("Storage root dir {root:?} must not be a symlink.");
        }
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
            directory_owner: Uid::from_raw(0),
            compress,
        })
    }

    pub(crate) fn create_recording_file(
        &self,
        uid: Uid,
        pty_id: u32,
        comm: &str,
    ) -> color_eyre::Result<PendingRecordingFile> {
        let now = chrono::Local::now();

        let (date_dir, date_dir_fd) = self.create_dir_for_date(uid, now)?;
        for counter in 0..32768 {
            let file_name = self.recording_file_name(now, pty_id, comm, counter);
            let final_path = date_dir.join(&file_name);
            if entry_exists_at(date_dir_fd.as_raw_fd(), &file_name)? {
                continue;
            }

            let unfinished_path = unfinished_path_for(&final_path);
            let unfinished_name = unfinished_path
                .file_name()
                .and_then(|name| name.to_str())
                .ok_or_else(|| eyre!("invalid recording filename"))?;

            match self.create_file_at(date_dir_fd.as_raw_fd(), unfinished_name, uid) {
                Ok(file) => {
                    return Ok(PendingRecordingFile {
                        file,
                        unfinished_path,
                        final_path,
                    });
                }
                Err(Errno::EEXIST) => continue,
                Err(err) => {
                    return Err(eyre!(
                        "failed to create recording {}: {err}",
                        unfinished_path.display()
                    ));
                }
            }
        }
        bail!("Failed to create recording file for pty {pty_id}");
    }

    fn create_dir_for_date(
        &self,
        uid: Uid,
        date: DateTime<Local>,
    ) -> color_eyre::Result<(PathBuf, File)> {
        let root = self.open_root_dir()?;
        let uid_name = uid.as_raw().to_string();
        let year = date.year().to_string();
        let month = format!("{:02}", date.month());
        let day = format!("{:02}", date.day());

        let uid_dir = self.ensure_child_dir(root.as_raw_fd(), &uid_name)?;
        let year_dir = self.ensure_child_dir(uid_dir.as_raw_fd(), &year)?;
        let month_dir = self.ensure_child_dir(year_dir.as_raw_fd(), &month)?;
        let day_dir = self.ensure_child_dir(month_dir.as_raw_fd(), &day)?;

        Ok((
            self.root.join(uid_name).join(year).join(month).join(day),
            day_dir,
        ))
    }

    fn recording_file_name(
        &self,
        date: DateTime<Local>,
        pty_id: u32,
        comm: &str,
        counter: usize,
    ) -> String {
        format!(
            "{comm}-pty{pty_id}-{hour:02}:{minute:02}:{second:02}{dash}{cnt}.cast{compress}",
            hour = date.hour(),
            minute = date.minute(),
            second = date.second(),
            dash = if counter > 0 { "-" } else { "" },
            cnt = if counter > 0 {
                Cow::Owned(counter.to_string())
            } else {
                Cow::Borrowed("")
            },
            compress = if let Compress::Zstd(_) = self.compress {
                ".zst"
            } else {
                ""
            }
        )
    }

    fn open_root_dir(&self) -> color_eyre::Result<File> {
        let fd = open(
            self.root.as_path(),
            OFlag::O_RDONLY | OFlag::O_DIRECTORY | OFlag::O_CLOEXEC | OFlag::O_NOFOLLOW,
            Mode::empty(),
        )?;
        Ok(unsafe { File::from_raw_fd(fd) })
    }

    fn ensure_child_dir(&self, parent_fd: RawFd, name: &str) -> color_eyre::Result<File> {
        match mkdirat(Some(parent_fd), name, dir_mode()) {
            Ok(()) | Err(Errno::EEXIST) => {}
            Err(err) => return Err(err.into()),
        }

        let fd = openat(
            Some(parent_fd),
            name,
            OFlag::O_RDONLY | OFlag::O_DIRECTORY | OFlag::O_CLOEXEC | OFlag::O_NOFOLLOW,
            Mode::empty(),
        )?;
        let dir = unsafe { File::from_raw_fd(fd) };
        fchown(
            dir.as_raw_fd(),
            Some(self.directory_owner),
            self.group.as_ref().map(|g| g.gid),
        )?;
        fchmod(dir.as_raw_fd(), dir_mode())?;
        Ok(dir)
    }

    fn create_file_at(&self, parent_fd: RawFd, name: &str, uid: Uid) -> Result<File, Errno> {
        let fd = openat(
            Some(parent_fd),
            name,
            OFlag::O_WRONLY | OFlag::O_CREAT | OFlag::O_EXCL | OFlag::O_CLOEXEC | OFlag::O_NOFOLLOW,
            file_mode(),
        )?;
        let file = unsafe { File::from_raw_fd(fd) };
        fchown(
            file.as_raw_fd(),
            Some(uid),
            self.group.as_ref().map(|g| g.gid),
        )?;
        fchmod(file.as_raw_fd(), file_mode())?;
        Ok(file)
    }

    #[cfg(test)]
    pub(crate) fn for_test(root: PathBuf, compress: Compress) -> Self {
        Self {
            root,
            group: None,
            directory_owner: Uid::current(),
            compress,
        }
    }
}

fn entry_exists_at(parent_fd: RawFd, name: &str) -> Result<bool, Errno> {
    match fstatat(Some(parent_fd), name, AtFlags::AT_SYMLINK_NOFOLLOW) {
        Ok(_) => Ok(true),
        Err(Errno::ENOENT) => Ok(false),
        Err(err) => Err(err),
    }
}

fn dir_mode() -> Mode {
    Mode::from_bits_truncate(0o770)
}

fn file_mode() -> Mode {
    Mode::from_bits_truncate(0o660)
}

pub(crate) fn unfinished_path_for(path: &Path) -> PathBuf {
    let mut unfinished = path.as_os_str().to_os_string();
    unfinished.push(RECORDING_UNFINISHED_SUFFIX);
    PathBuf::from(unfinished)
}

#[cfg(test)]
mod tests {
    use std::{fs, os::unix::fs::symlink};

    use nix::unistd::Uid;

    use super::*;

    fn temp_root(name: &str) -> PathBuf {
        let root =
            std::env::temp_dir().join(format!("ttyrecall-manager-{name}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&root);
        fs::create_dir_all(&root).unwrap();
        root
    }

    #[test]
    fn rejects_symlinked_user_directory() {
        let root = temp_root("symlink-root");
        let outside = temp_root("symlink-outside");
        let uid = Uid::current();
        symlink(&outside, root.join(uid.as_raw().to_string())).unwrap();

        let manager = Manager::for_test(root.clone(), Compress::None);
        assert!(manager.create_recording_file(uid, 1, "bash").is_err());
        assert!(fs::read_dir(&outside).unwrap().next().is_none());

        let _ = fs::remove_dir_all(root);
        let _ = fs::remove_dir_all(outside);
    }
}
