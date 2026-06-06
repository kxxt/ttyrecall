use std::{
    path::PathBuf,
    sync::{Arc, RwLock as StdRwLock},
    time::Instant,
};

use crate::catalog::{self, HeatmapDay, RecordingIndex, RecordingInfo};

use super::{playback::Playback, REFRESH_INTERVAL};

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
    pub(super) date_filter: Option<String>,
    selected_id: Option<String>,
    pub(super) last_refresh: Instant,
    pub(super) playback: Playback,
    pub(super) status: String,
}

impl App {
    pub(super) fn new(
        storage_root: PathBuf,
        uid: u32,
        username: String,
        recording_index: Arc<StdRwLock<RecordingIndex>>,
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
            date_filter: None,
            selected_id: None,
            last_refresh: Instant::now() - REFRESH_INTERVAL,
            playback: Playback::empty(),
            status: String::new(),
        }
    }

    pub(super) fn refresh(&mut self) {
        let index = self.recording_index.read().unwrap();
        self.all_recordings = index.list_for_user(self.uid);
        self.heatmap = index.heatmap_for_user(self.uid);
        drop(index);

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

    pub(super) fn reload_selected(&mut self) {
        self.selected_id = None;
        self.load_selected_if_needed();
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

        if self.selected_id.as_deref() == Some(recording.id.as_str()) {
            return;
        }
        self.selected_id = Some(recording.id.clone());

        let Some(path) =
            catalog::resolve_recording_path(&self.storage_root, self.uid, &recording.id)
        else {
            self.playback = Playback::error(
                recording.display.clone(),
                "recording path no longer exists".to_string(),
            );
            self.status = format!("Missing {}", recording.display);
            return;
        };

        match Playback::load(path, recording.display.clone()) {
            Ok(playback) => {
                self.playback = playback;
                self.status = format!("Playing {}", recording.display);
            }
            Err(err) => {
                self.playback = Playback::error(recording.display.clone(), err.to_string());
                self.status = format!("Failed to load {}", recording.display);
            }
        }
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
        );
        app.all_recordings = recordings;
        app.apply_filter();
        app
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
}
