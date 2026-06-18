use std::{
    borrow::Cow,
    fs::{File, Permissions},
    os::{linux::fs::MetadataExt, unix::fs::PermissionsExt},
    path::{Path, PathBuf},
};

use chrono::{DateTime, Datelike, Local, Timelike};
use color_eyre::{
    eyre::{bail, eyre},
    Section,
};
use log::warn;
use nix::{
    sys::stat::{umask, Mode},
    unistd::{Gid, Group, Uid},
};
use pathrs::{
    error::ErrorKind as PathrsErrorKind,
    flags::{OpenFlags, ResolverFlags},
    Root,
};
use rustix::{
    fs::{fchmod, fchown as rustix_fchown, Mode as RustixMode},
    process::{Gid as RustixGid, Uid as RustixUid},
};

use crate::daemon::{AsciicastVersion, Compress};

pub(crate) const RECORDING_UNFINISHED_SUFFIX: &str = ".unfinished";

/// A manager for on-disk recordings
#[derive(Debug)]
pub struct Manager {
    root: PathBuf,
    root_handle: Root,
    group: Option<Group>,
    pub compress: Compress,
    pub asciicast_version: AsciicastVersion,
}

#[derive(Debug)]
pub(crate) struct PendingRecordingFile {
    pub(crate) file: File,
    pub(crate) root: Root,
    pub(crate) unfinished_path: PathBuf,
    pub(crate) final_path: PathBuf,
    pub(crate) unfinished_rel_path: PathBuf,
    pub(crate) final_rel_path: PathBuf,
}

impl Manager {
    /// Create a new manager,
    /// It could be opened in exclusive mode to ensure two daemons won't step
    /// on each other's toes.
    pub fn new(
        dir: String,
        _exclusive: bool,
        compress: Compress,
        asciicast_version: AsciicastVersion,
    ) -> color_eyre::Result<Self> {
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
        // Check ownership. The storage root should be owned by root:ttyrecall.
        // It also needs o+x so unprivileged users can traverse into their own
        // uid-owned recording subtree without being able to list the root.
        let uid = Uid::from_raw(meta.st_uid());
        if !uid.is_root() {
            warn!("Storage root dir {root:?} is not owned by root user!");
        }
        let mode = meta.permissions().mode() & 0o777;
        if mode & 0o001 == 0 {
            warn!(
                "Storage root dir {root:?} is not searchable by unprivileged users; ttyrecall browse may not be able to access per-user recordings"
            );
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
        let root_handle = Root::open(&root)?.with_resolver_flags(ResolverFlags::NO_SYMLINKS);
        // Set umask to 007
        umask(Mode::S_IXOTH | Mode::S_IROTH | Mode::S_IWOTH);
        // TODO: Maybe check permissions
        Ok(Self {
            root,
            root_handle,
            group,
            compress,
            asciicast_version,
        })
    }

    pub(crate) fn create_recording_file(
        &self,
        uid: Uid,
        pty_id: u32,
        comm: &str,
    ) -> color_eyre::Result<PendingRecordingFile> {
        let now = chrono::Local::now();

        let (date_dir, date_dir_rel) = self.create_dir_for_date(uid, now)?;
        for counter in 0..32768 {
            let file_name = self.recording_file_name(now, pty_id, comm, counter);
            let final_rel_path = date_dir_rel.join(&file_name);
            let final_path = date_dir.join(&file_name);
            if self.entry_exists(&final_rel_path)? {
                continue;
            }

            let unfinished_path = unfinished_path_for(&final_path);
            let unfinished_rel_path = unfinished_path_for(&final_rel_path);

            let file = match self.root_handle.create_file(
                &unfinished_rel_path,
                OpenFlags::O_WRONLY
                    | OpenFlags::O_EXCL
                    | OpenFlags::O_CLOEXEC
                    | OpenFlags::O_NOFOLLOW,
                &file_permissions(),
            ) {
                Ok(file) => {
                    self.set_file_owner_mode(&file, uid)?;
                    file
                }
                Err(err) if is_pathrs_errno(&err, libc::EEXIST) => continue,
                Err(err) => {
                    return Err(eyre!(
                        "failed to create recording {}: {err}",
                        unfinished_path.display()
                    ));
                }
            };

            return Ok(PendingRecordingFile {
                file,
                root: self.root_handle.try_clone()?,
                unfinished_path,
                final_path,
                unfinished_rel_path,
                final_rel_path,
            });
        }
        bail!("Failed to create recording file for pty {pty_id}");
    }

    fn create_dir_for_date(
        &self,
        uid: Uid,
        date: DateTime<Local>,
    ) -> color_eyre::Result<(PathBuf, PathBuf)> {
        let uid_name = uid.as_raw().to_string();
        let year = date.year().to_string();
        let month = format!("{:02}", date.month());
        let day = format!("{:02}", date.day());
        let date_dir_rel = PathBuf::from(&uid_name).join(&year).join(&month).join(&day);

        self.root_handle
            .mkdir_all(&date_dir_rel, &dir_permissions())?;
        for rel_path in date_dir_components(&uid_name, &year, &month, &day) {
            self.set_dir_owner_mode(&rel_path, uid)?;
        }

        Ok((self.root.join(&date_dir_rel), date_dir_rel))
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

    fn set_dir_owner_mode(&self, rel_path: &Path, uid: Uid) -> color_eyre::Result<()> {
        let dir = self.root_handle.open_subpath(
            rel_path,
            OpenFlags::O_RDONLY | OpenFlags::O_DIRECTORY | OpenFlags::O_CLOEXEC,
        )?;
        rustix_fchown(
            &dir,
            Some(rustix_uid(uid)),
            self.group.as_ref().map(|g| g.gid).map(rustix_gid),
        )?;
        fchmod(&dir, dir_mode())?;
        Ok(())
    }

    fn set_file_owner_mode(&self, file: &File, uid: Uid) -> color_eyre::Result<()> {
        rustix_fchown(
            file,
            Some(rustix_uid(uid)),
            self.group.as_ref().map(|g| g.gid).map(rustix_gid),
        )?;
        fchmod(file, file_mode())?;
        Ok(())
    }

    fn entry_exists(&self, rel_path: &Path) -> color_eyre::Result<bool> {
        match self.root_handle.resolve_nofollow(rel_path) {
            Ok(_) => Ok(true),
            Err(err) if is_pathrs_errno(&err, libc::ENOENT) => Ok(false),
            Err(err) => Err(err.into()),
        }
    }

    #[cfg(test)]
    pub(crate) fn for_test(root: PathBuf, compress: Compress) -> Self {
        Self::for_test_with_version(root, compress, AsciicastVersion::V2)
    }

    #[cfg(test)]
    pub(crate) fn for_test_with_version(
        root: PathBuf,
        compress: Compress,
        asciicast_version: AsciicastVersion,
    ) -> Self {
        let root_handle = Root::open(&root)
            .expect("test storage root must exist")
            .with_resolver_flags(ResolverFlags::NO_SYMLINKS);
        Self {
            root,
            root_handle,
            group: None,
            compress,
            asciicast_version,
        }
    }
}

fn dir_mode() -> RustixMode {
    RustixMode::from_raw_mode(0o770)
}

fn file_mode() -> RustixMode {
    RustixMode::from_raw_mode(0o660)
}

fn dir_permissions() -> Permissions {
    Permissions::from_mode(0o770)
}

fn file_permissions() -> Permissions {
    Permissions::from_mode(0o660)
}

fn date_dir_components(uid: &str, year: &str, month: &str, day: &str) -> [PathBuf; 4] {
    [
        PathBuf::from(uid),
        PathBuf::from(uid).join(year),
        PathBuf::from(uid).join(year).join(month),
        PathBuf::from(uid).join(year).join(month).join(day),
    ]
}

fn is_pathrs_errno(err: &pathrs::error::Error, errno: i32) -> bool {
    matches!(err.kind(), PathrsErrorKind::OsError(Some(value)) if value == errno)
}

fn rustix_uid(uid: Uid) -> RustixUid {
    RustixUid::from_raw(uid.as_raw())
}

fn rustix_gid(gid: Gid) -> RustixGid {
    RustixGid::from_raw(gid.as_raw())
}

pub(crate) fn unfinished_path_for(path: &Path) -> PathBuf {
    let mut unfinished = path.as_os_str().to_os_string();
    unfinished.push(RECORDING_UNFINISHED_SUFFIX);
    PathBuf::from(unfinished)
}

#[cfg(test)]
mod tests {
    use std::{
        fs,
        os::unix::fs::{symlink, MetadataExt, PermissionsExt},
    };

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

    #[test]
    fn rejects_symlink_inside_user_directory() {
        let root = temp_root("symlink-year");
        let outside = temp_root("symlink-year-outside");
        let uid = Uid::current();
        let year = Local::now().year().to_string();
        fs::create_dir_all(root.join(uid.as_raw().to_string())).unwrap();
        symlink(&outside, root.join(uid.as_raw().to_string()).join(year)).unwrap();

        let manager = Manager::for_test(root.clone(), Compress::None);
        assert!(manager.create_recording_file(uid, 1, "bash").is_err());
        assert!(fs::read_dir(&outside).unwrap().next().is_none());

        let _ = fs::remove_dir_all(root);
        let _ = fs::remove_dir_all(outside);
    }

    #[test]
    fn creates_user_owned_recording_subtree() {
        let root = temp_root("user-owned");
        let uid = Uid::current();
        let manager = Manager::for_test(root.clone(), Compress::None);

        let pending = manager.create_recording_file(uid, 1, "bash").unwrap();
        drop(pending.file);

        let mut path = root.clone();
        for component in pending.final_rel_path.parent().unwrap().components() {
            path.push(component.as_os_str());
            let metadata = fs::metadata(&path).unwrap();
            assert_eq!(metadata.uid(), uid.as_raw());
            assert_eq!(metadata.permissions().mode() & 0o777, 0o770);
        }

        let metadata = fs::metadata(&pending.unfinished_path).unwrap();
        assert_eq!(metadata.uid(), uid.as_raw());
        assert_eq!(metadata.permissions().mode() & 0o777, 0o660);

        let _ = fs::remove_dir_all(root);
    }
}
