use std::{
    collections::HashMap,
    path::{Path, PathBuf},
};

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use chrono::NaiveDate;
use serde::Serialize;

#[derive(Debug, Clone, Serialize)]
pub(crate) struct RecordingInfo {
    pub(crate) id: String,
    pub(crate) name: String,
    pub(crate) display: String,
    pub(crate) date: String,
    pub(crate) size: u64,
    pub(crate) compressed: bool,
}

#[derive(Debug, Clone, Serialize)]
pub(crate) struct HeatmapDay {
    pub(crate) date: String,
    pub(crate) count: usize,
}

#[derive(Debug, Default)]
pub(crate) struct RecordingIndex {
    by_user: HashMap<u32, HashMap<PathBuf, RecordingInfo>>,
}

impl RecordingIndex {
    pub(crate) fn clear(&mut self) {
        self.by_user.clear();
    }

    pub(crate) fn upsert_path(&mut self, storage_root: &Path, path: &Path) {
        let Some((uid, rel_path, info)) = indexed_recording(storage_root, path) else {
            return;
        };

        self.by_user.entry(uid).or_default().insert(rel_path, info);
    }

    pub(crate) fn remove_path(&mut self, storage_root: &Path, path: &Path) {
        let Some((uid, rel_path)) = storage_rel_path(storage_root, path) else {
            return;
        };

        if let Some(recordings) = self.by_user.get_mut(&uid) {
            recordings.remove(&rel_path);
            if recordings.is_empty() {
                self.by_user.remove(&uid);
            }
        }
    }

    pub(crate) fn remove_tree(&mut self, storage_root: &Path, path: &Path) {
        let Some((uid, rel_prefix)) = storage_rel_path(storage_root, path) else {
            return;
        };

        if let Some(recordings) = self.by_user.get_mut(&uid) {
            recordings.retain(|rel_path, _| !rel_path.starts_with(&rel_prefix));
            if recordings.is_empty() {
                self.by_user.remove(&uid);
            }
        }
    }

    pub(crate) fn list_for_user(&self, uid: u32) -> Vec<RecordingInfo> {
        let Some(recordings) = self.by_user.get(&uid) else {
            return Vec::new();
        };

        let mut recordings: Vec<_> = recordings.values().cloned().collect();
        recordings.sort_by(|a, b| b.display.cmp(&a.display));
        recordings
    }

    pub(crate) fn list_for_user_page(
        &self,
        uid: u32,
        date: Option<&str>,
        offset: usize,
        limit: usize,
    ) -> (Vec<RecordingInfo>, usize) {
        let Some(recordings) = self.by_user.get(&uid) else {
            return (Vec::new(), 0);
        };

        let mut recordings: Vec<_> = recordings
            .values()
            .filter(|recording| match date {
                Some(date) => recording.date == date,
                None => true,
            })
            .collect();
        recordings.sort_by(|a, b| b.display.cmp(&a.display));

        let total = recordings.len();
        let page = recordings
            .into_iter()
            .skip(offset)
            .take(limit)
            .cloned()
            .collect();
        (page, total)
    }

    pub(crate) fn heatmap_for_user(&self, uid: u32) -> Vec<HeatmapDay> {
        let Some(recordings) = self.by_user.get(&uid) else {
            return Vec::new();
        };

        let mut counts: HashMap<String, usize> = HashMap::new();
        for recording in recordings.values() {
            if recording.date.is_empty() {
                continue;
            }
            *counts.entry(recording.date.clone()).or_insert(0) += 1;
        }

        let mut days: Vec<_> = counts
            .into_iter()
            .map(|(date, count)| HeatmapDay { date, count })
            .collect();
        days.sort_by(|a, b| a.date.cmp(&b.date));
        days
    }
}

pub(crate) fn indexed_recording(
    storage_root: &Path,
    path: &Path,
) -> Option<(u32, PathBuf, RecordingInfo)> {
    let (uid, rel_path) = storage_rel_path(storage_root, path)?;
    let user_root = storage_root.join(uid.to_string());
    let info = recording_info(&user_root, path)?;
    Some((uid, rel_path, info))
}

pub(crate) fn storage_rel_path(storage_root: &Path, path: &Path) -> Option<(u32, PathBuf)> {
    let rel = path.strip_prefix(storage_root).ok()?;
    let mut components = rel.components();
    let uid: u32 = components
        .next()?
        .as_os_str()
        .to_string_lossy()
        .parse()
        .ok()?;
    let remainder = components.as_path();
    if remainder.as_os_str().is_empty() {
        return None;
    }
    Some((uid, remainder.to_path_buf()))
}

pub(crate) fn resolve_recording_path(storage_root: &Path, uid: u32, id: &str) -> Option<PathBuf> {
    let decoded = URL_SAFE_NO_PAD.decode(id).ok()?;
    let rel = String::from_utf8(decoded).ok()?;
    let rel_path = PathBuf::from(rel);
    if rel_path.is_absolute() {
        return None;
    }
    for component in rel_path.components() {
        if matches!(component, std::path::Component::ParentDir) {
            return None;
        }
    }

    let user_root = storage_root.join(uid.to_string());
    let full = user_root.join(rel_path);
    let canonical = full.canonicalize().ok()?;
    if !canonical.starts_with(&user_root) {
        return None;
    }
    Some(canonical)
}

pub(crate) fn read_cast_bytes(path: &Path) -> Result<Vec<u8>, std::io::Error> {
    let bytes = std::fs::read(path)?;
    if path.extension().and_then(|s| s.to_str()) == Some("zst") {
        let decoded = zstd::stream::decode_all(bytes.as_slice())
            .map_err(|err| std::io::Error::new(std::io::ErrorKind::InvalidData, err))?;
        Ok(decoded)
    } else {
        Ok(bytes)
    }
}

fn recording_info(user_root: &Path, path: &Path) -> Option<RecordingInfo> {
    let file_name = path.file_name()?.to_string_lossy().to_string();
    if !is_recording_file_name(&file_name) {
        return None;
    }

    let rel = path.strip_prefix(user_root).ok()?;
    let id = URL_SAFE_NO_PAD.encode(rel.to_string_lossy().as_bytes());

    let compressed = file_name.ends_with(".zst");
    let display = format_display(rel).unwrap_or_else(|| file_name.clone());
    let date = date_from_path(user_root, path)
        .map(|value| value.format("%Y-%m-%d").to_string())
        .unwrap_or_default();
    let size = path.metadata().ok()?.len();

    Some(RecordingInfo {
        id,
        name: file_name,
        display,
        date,
        size,
        compressed,
    })
}

fn is_recording_file_name(file_name: &str) -> bool {
    file_name.ends_with(".cast") || file_name.ends_with(".cast.zst")
}

fn format_display(rel: &Path) -> Option<String> {
    let components: Vec<_> = rel.components().collect();
    if components.len() < 4 {
        return None;
    }
    let year = components[0].as_os_str().to_string_lossy();
    let month = components[1].as_os_str().to_string_lossy();
    let day = components[2].as_os_str().to_string_lossy();
    let file = components.last()?.as_os_str().to_string_lossy();

    let base = file.trim_end_matches(".zst").trim_end_matches(".cast");

    let time = base.rsplit_once("-pty")?.1;
    let time = time.split('-').nth(1)?;
    Some(format!("{}-{}-{} {}", year, month, day, time))
}

fn date_from_path(user_root: &Path, path: &Path) -> Option<NaiveDate> {
    let rel = path.strip_prefix(user_root).ok()?;
    let components: Vec<_> = rel.components().collect();
    if components.len() < 4 {
        return None;
    }
    let year: i32 = components[0].as_os_str().to_string_lossy().parse().ok()?;
    let month: u32 = components[1].as_os_str().to_string_lossy().parse().ok()?;
    let day: u32 = components[2].as_os_str().to_string_lossy().parse().ok()?;
    NaiveDate::from_ymd_opt(year, month, day)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_root(name: &str) -> PathBuf {
        let root =
            std::env::temp_dir().join(format!("ttyrecall-catalog-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        root
    }

    fn write_file(path: &Path, content: &str) {
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(path, content).unwrap();
    }

    #[test]
    fn index_filters_sorts_and_builds_heatmap() {
        let root = temp_root("index");
        let first = root.join("1000/2026/06/05/zsh-pty1-09:15.cast.zst");
        let second = root.join("1000/2026/06/06/bash-pty2-10:30.cast");
        let ignored = root.join("1000/2026/06/06/not-a-recording.txt");
        write_file(&first, "{}");
        write_file(&second, "{}");
        write_file(&ignored, "{}");

        let mut index = RecordingIndex::default();
        index.upsert_path(&root, &first);
        index.upsert_path(&root, &second);
        index.upsert_path(&root, &ignored);

        let recordings = index.list_for_user(1000);
        assert_eq!(recordings.len(), 2);
        assert_eq!(recordings[0].display, "2026-06-06 10:30");
        assert_eq!(recordings[1].display, "2026-06-05 09:15");
        assert!(recordings[1].compressed);

        let heatmap = index.heatmap_for_user(1000);
        assert_eq!(heatmap.len(), 2);
        assert_eq!(heatmap[0].date, "2026-06-05");
        assert_eq!(heatmap[0].count, 1);
        assert_eq!(heatmap[1].date, "2026-06-06");
        assert_eq!(heatmap[1].count, 1);

        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn resolve_recording_path_rejects_traversal() {
        let root = temp_root("resolve");
        let recording = root.join("1000/2026/06/06/bash-pty2-10:30.cast");
        write_file(&recording, "{}");

        let valid_id = URL_SAFE_NO_PAD.encode("2026/06/06/bash-pty2-10:30.cast");
        assert_eq!(
            resolve_recording_path(&root, 1000, &valid_id).unwrap(),
            recording.canonicalize().unwrap()
        );

        let traversal_id = URL_SAFE_NO_PAD.encode("../1001/2026/06/06/other.cast");
        assert!(resolve_recording_path(&root, 1000, &traversal_id).is_none());

        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn remove_tree_prunes_nested_recordings() {
        let root = temp_root("remove-tree");
        let first = root.join("1000/2026/06/05/zsh-pty1-09:15.cast");
        let second = root.join("1000/2026/06/06/bash-pty2-10:30.cast");
        write_file(&first, "{}");
        write_file(&second, "{}");

        let mut index = RecordingIndex::default();
        index.upsert_path(&root, &first);
        index.upsert_path(&root, &second);
        index.remove_tree(&root, &root.join("1000/2026/06/05"));

        let recordings = index.list_for_user(1000);
        assert_eq!(recordings.len(), 1);
        assert_eq!(recordings[0].display, "2026-06-06 10:30");

        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn list_for_user_page_filters_and_slices() {
        let root = temp_root("page");
        let first = root.join("1000/2026/06/04/fish-pty1-08:00.cast");
        let second = root.join("1000/2026/06/05/zsh-pty1-09:15.cast");
        let third = root.join("1000/2026/06/06/bash-pty2-10:30.cast");
        write_file(&first, "{}");
        write_file(&second, "{}");
        write_file(&third, "{}");

        let mut index = RecordingIndex::default();
        index.upsert_path(&root, &first);
        index.upsert_path(&root, &second);
        index.upsert_path(&root, &third);

        let (recordings, total) = index.list_for_user_page(1000, None, 1, 1);
        assert_eq!(total, 3);
        assert_eq!(recordings.len(), 1);
        assert_eq!(recordings[0].display, "2026-06-05 09:15");

        let (recordings, total) = index.list_for_user_page(1000, Some("2026-06-06"), 0, 10);
        assert_eq!(total, 1);
        assert_eq!(recordings[0].display, "2026-06-06 10:30");

        let _ = std::fs::remove_dir_all(root);
    }
}
