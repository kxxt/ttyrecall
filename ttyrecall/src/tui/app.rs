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
    pub(super) recordings: Vec<RecordingInfo>,
    pub(super) heatmap: Vec<HeatmapDay>,
    pub(super) selected: usize,
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
            recordings: Vec::new(),
            heatmap: Vec::new(),
            selected: 0,
            selected_id: None,
            last_refresh: Instant::now() - REFRESH_INTERVAL,
            playback: Playback::empty(),
            status: String::new(),
        }
    }

    pub(super) fn refresh(&mut self) {
        let index = self.recording_index.read().unwrap();
        self.recordings = index.list_for_user(self.uid);
        self.heatmap = index.heatmap_for_user(self.uid);
        drop(index);

        if self.selected >= self.recordings.len() {
            self.selected = self.recordings.len().saturating_sub(1);
        }
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

    pub(super) fn reload_selected(&mut self) {
        self.selected_id = None;
        self.load_selected_if_needed();
    }

    fn selected_recording(&self) -> Option<&RecordingInfo> {
        self.recordings.get(self.selected)
    }

    fn load_selected_if_needed(&mut self) {
        let Some(recording) = self.selected_recording().cloned() else {
            self.selected_id = None;
            self.playback = Playback::empty();
            self.status = "No recordings found".to_string();
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
