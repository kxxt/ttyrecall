use std::{
    path::PathBuf,
    sync::{Arc, RwLock as StdRwLock},
    time::Instant,
};

use crate::catalog::{self, HeatmapDay, RecordingIndex, RecordingInfo};
use crate::search::{search_recordings, RipgrepSearchConfig, SearchResult};

use super::{playback::Playback, REFRESH_INTERVAL};

pub(super) const HEATMAP_TOTAL_WEEKS: usize = 26;
pub(super) const HEATMAP_TOTAL_ROWS: usize = 8;

pub(super) struct App {
    storage_root: PathBuf,
    uid: u32,
    pub(super) username: String,
    recording_index: Arc<StdRwLock<RecordingIndex>>,
    all_recordings: Vec<RecordingInfo>,
    pub(super) recordings: Vec<RecordingInfo>,
    pub(super) heatmap: Vec<HeatmapDay>,
    pub(super) selected: usize,
    pub(super) list_offset: usize,
    pub(super) main_split_percent: u16,
    pub(super) heatmap_rows: u16,
    pub(super) heatmap_week_scroll: usize,
    pub(super) heatmap_row_offset: usize,
    pub(super) date_filter: Option<String>,
    selected_id: Option<String>,
    pub(super) last_refresh: Instant,
    pub(super) playback: Playback,
    pub(super) status: String,
    pub(super) delete_confirmation: Option<DeleteConfirmation>,
    confirm_deletes: bool,
    pub(super) search_enabled: bool,
    pub(super) search_config: RipgrepSearchConfig,
    pub(super) search_mode: SearchMode,
    pub(super) search_query: String,
    search_results: Vec<SearchResult>,
}

#[derive(Debug, Clone)]
pub(super) struct DeleteConfirmation {
    pub(super) recording: RecordingInfo,
    pub(super) dont_ask_again: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum SearchMode {
    Inactive,
    Editing,
    Results,
}

impl App {
    pub(super) fn new(
        storage_root: PathBuf,
        uid: u32,
        username: String,
        recording_index: Arc<StdRwLock<RecordingIndex>>,
        search_enabled: bool,
        search_config: RipgrepSearchConfig,
    ) -> Self {
        Self {
            storage_root,
            uid,
            username,
            recording_index,
            all_recordings: Vec::new(),
            recordings: Vec::new(),
            heatmap: Vec::new(),
            selected: 0,
            list_offset: 0,
            main_split_percent: 42,
            heatmap_rows: 10,
            heatmap_week_scroll: 0,
            heatmap_row_offset: 0,
            date_filter: None,
            selected_id: None,
            last_refresh: Instant::now() - REFRESH_INTERVAL,
            playback: Playback::empty(),
            status: String::new(),
            delete_confirmation: None,
            confirm_deletes: true,
            search_enabled,
            search_config,
            search_mode: SearchMode::Inactive,
            search_query: String::new(),
            search_results: Vec::new(),
        }
    }

    pub(super) fn refresh(&mut self) {
        let index = self.recording_index.read().unwrap();
        self.all_recordings = index.list_for_user(self.uid);
        self.heatmap = index.heatmap_for_user(self.uid);
        drop(index);

        if self.search_mode != SearchMode::Inactive {
            self.last_refresh = Instant::now();
            self.load_selected_if_needed();
            return;
        }

        self.apply_filter();
        self.clamp_selection();
        self.last_refresh = Instant::now();
        self.load_selected_if_needed();
    }

    pub(super) fn select_next(&mut self) {
        if self.recordings.is_empty() {
            return;
        }
        self.selected = (self.selected + 1).min(self.recordings.len() - 1);
        self.load_selected_if_needed();
    }

    pub(super) fn select_prev(&mut self) {
        self.selected = self.selected.saturating_sub(1);
        self.load_selected_if_needed();
    }

    pub(super) fn select_first(&mut self) {
        self.selected = 0;
        self.load_selected_if_needed();
    }

    pub(super) fn select_last(&mut self) {
        if !self.recordings.is_empty() {
            self.selected = self.recordings.len() - 1;
            self.load_selected_if_needed();
        }
    }

    pub(super) fn select_index(&mut self, index: usize) {
        if index >= self.recordings.len() {
            return;
        }
        self.selected = index;
        self.load_selected_if_needed();
    }

    pub(super) fn set_date_filter(&mut self, date: String) {
        self.date_filter = Some(date.clone());
        self.selected = 0;
        self.list_offset = 0;
        self.selected_id = None;
        self.apply_filter();
        self.clamp_selection();
        self.status = format!("Showing recordings from {date}");
        self.load_selected_if_needed();
    }

    pub(super) fn clear_date_filter(&mut self) {
        if self.date_filter.is_none() {
            return;
        }
        self.date_filter = None;
        self.selected = 0;
        self.list_offset = 0;
        self.selected_id = None;
        self.apply_filter();
        self.clamp_selection();
        self.status = "Showing all recordings".to_string();
        self.load_selected_if_needed();
    }

    pub(super) fn start_search(&mut self) {
        if !self.search_enabled {
            self.status = "Search is disabled".to_string();
            return;
        }
        self.search_mode = SearchMode::Editing;
        self.search_query.clear();
        self.status = "Search recordings".to_string();
    }

    pub(super) fn cancel_search(&mut self) {
        if self.search_mode == SearchMode::Inactive {
            return;
        }
        self.search_mode = SearchMode::Inactive;
        self.search_query.clear();
        self.search_results.clear();
        self.selected = 0;
        self.list_offset = 0;
        self.selected_id = None;
        self.apply_filter();
        self.clamp_selection();
        self.status = "Search cleared".to_string();
        self.load_selected_if_needed();
    }

    pub(super) fn push_search_char(&mut self, ch: char) {
        if self.search_mode == SearchMode::Editing && !ch.is_control() {
            self.search_query.push(ch);
        }
    }

    pub(super) fn pop_search_char(&mut self) {
        if self.search_mode == SearchMode::Editing {
            self.search_query.pop();
        }
    }

    pub(super) fn run_search(&mut self) {
        if !self.search_enabled || self.search_mode != SearchMode::Editing {
            return;
        }
        let query = self.search_query.trim().to_string();
        if query.is_empty() {
            self.status = "Search query is empty".to_string();
            return;
        }

        match search_recordings(&self.storage_root, self.uid, &query, &self.search_config) {
            Ok(results) => {
                self.search_results = results;
                self.recordings = self
                    .search_results
                    .iter()
                    .map(|result| RecordingInfo {
                        id: result.recording_id.clone(),
                        name: result.name.clone(),
                        display: result.display.clone(),
                        date: result.date.clone(),
                        size: result.size,
                        compressed: result.compressed,
                    })
                    .collect();
                self.search_mode = SearchMode::Results;
                self.selected = 0;
                self.list_offset = 0;
                self.selected_id = None;
                self.clamp_selection();
                self.status = format!(
                    "{} search match{} for {query}",
                    self.recordings.len(),
                    if self.recordings.len() == 1 { "" } else { "es" }
                );
                self.load_selected_if_needed();
            }
            Err(err) => {
                self.status = format!("Search failed: {err}");
            }
        }
    }

    pub(super) fn reload_selected(&mut self) {
        self.selected_id = None;
        self.load_selected_if_needed();
    }

    pub(super) fn request_delete_selected(&mut self) {
        let Some(recording) = self.selected_recording().cloned() else {
            self.status = "No recording selected".to_string();
            return;
        };

        if self.confirm_deletes {
            self.delete_confirmation = Some(DeleteConfirmation {
                recording,
                dont_ask_again: false,
            });
        } else {
            self.delete_recording(recording);
        }
    }

    pub(super) fn confirm_delete(&mut self) {
        let Some(confirmation) = self.delete_confirmation.take() else {
            return;
        };
        if confirmation.dont_ask_again {
            self.confirm_deletes = false;
        }
        self.delete_recording(confirmation.recording);
    }

    pub(super) fn cancel_delete(&mut self) {
        if let Some(confirmation) = self.delete_confirmation.take() {
            self.status = format!("Kept {}", confirmation.recording.name);
        }
    }

    pub(super) fn toggle_delete_dont_ask_again(&mut self) {
        if let Some(confirmation) = &mut self.delete_confirmation {
            confirmation.dont_ask_again = !confirmation.dont_ask_again;
        }
    }

    pub(super) fn has_pending_delete_confirmation(&self) -> bool {
        self.delete_confirmation.is_some()
    }

    pub(super) fn resize_main_split(&mut self, delta: i16) {
        self.main_split_percent = add_clamped(self.main_split_percent, delta, 20, 80);
    }

    pub(super) fn set_main_split_percent(&mut self, percent: u16) {
        self.main_split_percent = percent.clamp(20, 80);
    }

    pub(super) fn resize_heatmap_rows(&mut self, delta: i16) {
        self.heatmap_rows = add_clamped(self.heatmap_rows, delta, 3, 30);
    }

    pub(super) fn set_heatmap_rows(&mut self, rows: u16) {
        self.heatmap_rows = rows.clamp(3, 30);
    }

    pub(super) fn scroll_heatmap_weeks(&mut self, delta: i16) {
        self.heatmap_week_scroll = add_clamped_usize(
            self.heatmap_week_scroll,
            delta,
            0,
            HEATMAP_TOTAL_WEEKS.saturating_sub(1),
        );
    }

    pub(super) fn scroll_heatmap_rows(&mut self, delta: i16) {
        self.heatmap_row_offset = add_clamped_usize(
            self.heatmap_row_offset,
            delta,
            0,
            HEATMAP_TOTAL_ROWS.saturating_sub(1),
        );
    }

    pub(super) fn clamp_heatmap_scroll(&mut self, visible_rows: usize, visible_weeks: usize) {
        let max_week_scroll = HEATMAP_TOTAL_WEEKS.saturating_sub(visible_weeks.max(1));
        let max_row_offset = HEATMAP_TOTAL_ROWS.saturating_sub(visible_rows.max(1));
        self.heatmap_week_scroll = self.heatmap_week_scroll.min(max_week_scroll);
        self.heatmap_row_offset = self.heatmap_row_offset.min(max_row_offset);
    }

    pub(super) fn ensure_selected_visible(&mut self, visible_rows: usize) {
        if visible_rows == 0 || self.recordings.is_empty() {
            self.list_offset = 0;
            return;
        }
        if self.selected < self.list_offset {
            self.list_offset = self.selected;
        } else if self.selected >= self.list_offset + visible_rows {
            self.list_offset = self.selected + 1 - visible_rows;
        }
    }

    pub(super) fn visible_recordings(&self, visible_rows: usize) -> &[RecordingInfo] {
        let end = (self.list_offset + visible_rows).min(self.recordings.len());
        &self.recordings[self.list_offset..end]
    }

    fn selected_recording(&self) -> Option<&RecordingInfo> {
        self.recordings.get(self.selected)
    }

    fn apply_filter(&mut self) {
        self.recordings = match self.date_filter.as_deref() {
            Some(date) => self
                .all_recordings
                .iter()
                .filter(|recording| recording.date == date)
                .cloned()
                .collect(),
            None => self.all_recordings.clone(),
        };
    }

    fn clamp_selection(&mut self) {
        if self.selected >= self.recordings.len() {
            self.selected = self.recordings.len().saturating_sub(1);
        }
        if self.list_offset > self.selected {
            self.list_offset = self.selected;
        }
    }

    fn load_selected_if_needed(&mut self) {
        let Some(recording) = self.selected_recording().cloned() else {
            self.selected_id = None;
            self.playback = Playback::empty();
            self.status = match self.date_filter.as_deref() {
                Some(date) => format!("No recordings found for {date}"),
                None => "No recordings found".to_string(),
            };
            return;
        };

        let start_at = self
            .search_results
            .get(self.selected)
            .filter(|_| self.search_mode == SearchMode::Results)
            .map(|result| result.timestamp)
            .unwrap_or(0.0);
        let selection_key = if self.search_mode == SearchMode::Results {
            format!("{}@{:.3}", recording.id, start_at)
        } else {
            recording.id.clone()
        };

        if self.selected_id.as_deref() == Some(selection_key.as_str()) {
            return;
        }
        self.selected_id = Some(selection_key);

        let Some(recording_file) =
            catalog::open_recording_file(&self.storage_root, self.uid, &recording.id)
        else {
            self.playback = Playback::error(
                recording.display.clone(),
                "recording path no longer exists".to_string(),
            );
            self.status = format!("Missing {}", recording.display);
            return;
        };

        match Playback::load_recording(recording_file, recording.display.clone(), start_at) {
            Ok(playback) => {
                self.playback = playback;
                if start_at > 0.0 {
                    self.status = format!("Playing {} at {:.2}s", recording.display, start_at);
                } else {
                    self.status = format!("Playing {}", recording.display);
                }
            }
            Err(err) => {
                self.playback = Playback::error(recording.display.clone(), err.to_string());
                self.status = format!("Failed to load {}", recording.display);
            }
        }
    }

    pub(super) fn search_result_at(&self, index: usize) -> Option<&SearchResult> {
        if self.search_mode == SearchMode::Results {
            self.search_results.get(index)
        } else {
            None
        }
    }

    fn delete_recording(&mut self, recording: RecordingInfo) {
        let Some(path) =
            catalog::remove_recording_file(&self.storage_root, self.uid, &recording.id)
        else {
            self.status = format!("Missing {}", recording.name);
            self.refresh_after_delete();
            return;
        };

        self.recording_index
            .write()
            .unwrap()
            .remove_path(&self.storage_root, &path);
        self.status = format!("Deleted {}", recording.name);
        self.refresh_after_delete();
    }

    fn refresh_after_delete(&mut self) {
        let previous_status = self.status.clone();
        self.selected_id = None;
        self.refresh();
        if !previous_status.is_empty() {
            self.status = previous_status;
        }
    }
}

fn add_clamped(value: u16, delta: i16, min: u16, max: u16) -> u16 {
    let value = value as i16 + delta;
    value.clamp(min as i16, max as i16) as u16
}

fn add_clamped_usize(value: usize, delta: i16, min: usize, max: usize) -> usize {
    if delta < 0 {
        value.saturating_sub(delta.unsigned_abs() as usize).max(min)
    } else {
        value.saturating_add(delta as usize).min(max)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn recording(id: &str, date: &str) -> RecordingInfo {
        RecordingInfo {
            id: id.to_string(),
            name: format!("{id}.cast"),
            display: id.to_string(),
            date: date.to_string(),
            size: 10,
            compressed: false,
        }
    }

    fn app_with_recordings(recordings: Vec<RecordingInfo>) -> App {
        let mut app = App::new(
            PathBuf::from("/tmp/ttyrecall-test"),
            1000,
            "user".to_string(),
            Arc::new(StdRwLock::new(RecordingIndex::default())),
            false,
            RipgrepSearchConfig {
                ripgrep_path: "rg".to_string(),
                max_results: 50,
            },
        );
        app.all_recordings = recordings;
        app.apply_filter();
        app
    }

    fn temp_root(name: &str) -> PathBuf {
        let root =
            std::env::temp_dir().join(format!("ttyrecall-tui-app-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        root
    }

    fn write_file(path: &std::path::Path, content: &str) {
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(path, content).unwrap();
    }

    #[test]
    fn date_filter_limits_visible_recordings() {
        let mut app = app_with_recordings(vec![
            recording("first", "2026-06-05"),
            recording("second", "2026-06-06"),
        ]);

        app.set_date_filter("2026-06-06".to_string());

        assert_eq!(app.recordings.len(), 1);
        assert_eq!(app.recordings[0].id, "second");
        assert_eq!(app.date_filter.as_deref(), Some("2026-06-06"));
    }

    #[test]
    fn clear_date_filter_restores_all_recordings() {
        let mut app = app_with_recordings(vec![
            recording("first", "2026-06-05"),
            recording("second", "2026-06-06"),
        ]);

        app.set_date_filter("2026-06-06".to_string());
        app.clear_date_filter();

        assert_eq!(app.recordings.len(), 2);
        assert!(app.date_filter.is_none());
    }

    #[test]
    fn ensure_selected_visible_adjusts_offset() {
        let mut app = app_with_recordings(vec![
            recording("first", "2026-06-05"),
            recording("second", "2026-06-06"),
            recording("third", "2026-06-07"),
        ]);

        app.select_index(2);
        app.ensure_selected_visible(2);

        assert_eq!(app.list_offset, 1);
        assert_eq!(app.visible_recordings(2)[0].id, "second");
    }

    #[test]
    fn resizing_clamps_layout_state() {
        let mut app = app_with_recordings(Vec::new());

        app.resize_main_split(-100);
        app.resize_heatmap_rows(100);

        assert_eq!(app.main_split_percent, 20);
        assert_eq!(app.heatmap_rows, 30);
    }

    #[test]
    fn heatmap_scroll_clamps_to_visible_window() {
        let mut app = app_with_recordings(Vec::new());

        app.scroll_heatmap_weeks(100);
        app.scroll_heatmap_rows(100);
        app.clamp_heatmap_scroll(4, 10);

        assert_eq!(app.heatmap_week_scroll, HEATMAP_TOTAL_WEEKS - 10);
        assert_eq!(app.heatmap_row_offset, HEATMAP_TOTAL_ROWS - 4);
    }

    #[test]
    fn delete_selected_waits_for_confirmation_then_removes_file() {
        let root = temp_root("delete-confirmed");
        let recording = root.join("1000/2026/06/06/bash-pty2-10:30.cast");
        write_file(
            &recording,
            r#"{"version":2,"width":80,"height":24}
[0.0,"o","hello"]
"#,
        );
        let mut index = RecordingIndex::default();
        index.upsert_path(&root, &recording);
        let index = Arc::new(StdRwLock::new(index));
        let mut app = App::new(
            root.clone(),
            1000,
            "user".to_string(),
            index.clone(),
            false,
            RipgrepSearchConfig {
                ripgrep_path: "rg".to_string(),
                max_results: 50,
            },
        );
        app.refresh();

        app.request_delete_selected();

        assert!(recording.exists());
        assert!(app.has_pending_delete_confirmation());

        app.confirm_delete();

        assert!(!recording.exists());
        assert!(app.recordings.is_empty());
        assert!(index.read().unwrap().list_for_user(1000).is_empty());
        assert!(app.status.contains("Deleted"));

        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn delete_dont_ask_again_deletes_future_selection_immediately() {
        let root = temp_root("delete-skip-confirmation");
        let first = root.join("1000/2026/06/06/bash-pty2-10:30.cast");
        let second = root.join("1000/2026/06/05/zsh-pty1-09:15.cast");
        write_file(&first, r#"{"version":2}"#);
        write_file(&second, r#"{"version":2}"#);
        let mut index = RecordingIndex::default();
        index.upsert_path(&root, &first);
        index.upsert_path(&root, &second);
        let mut app = App::new(
            root.clone(),
            1000,
            "user".to_string(),
            Arc::new(StdRwLock::new(index)),
            false,
            RipgrepSearchConfig {
                ripgrep_path: "rg".to_string(),
                max_results: 50,
            },
        );
        app.refresh();

        app.request_delete_selected();
        app.toggle_delete_dont_ask_again();
        app.confirm_delete();

        assert!(!first.exists());
        assert!(second.exists());

        app.request_delete_selected();

        assert!(!second.exists());
        assert!(!app.has_pending_delete_confirmation());

        let _ = std::fs::remove_dir_all(root);
    }
}
