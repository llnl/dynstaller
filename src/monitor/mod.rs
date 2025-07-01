use std::{collections::BTreeMap, path::PathBuf};

use anyhow::Result;
use async_trait::async_trait;
use serde::Serialize;

use crate::options::{MonitorMethod, MonitorOptions, TrackOptions};

pub mod procmon;
pub mod usn;
pub mod winapi;

#[async_trait]
pub trait Monitor {
    fn new(options: MonitorOptions, track_options: TrackOptions) -> Result<Self>
    where
        Self: Sized;

    async fn start(&mut self) -> Result<()>;
    async fn stop(&mut self) -> Result<()>;
    fn get_changed_files(&self) -> Result<BTreeMap<PathBuf, ItemMetadata>>;
    fn get_changed_registry_keys(&self) -> Option<Result<BTreeMap<PathBuf, ItemMetadata>>> {
        None
    }
}

#[derive(Serialize, Debug, Default, Clone)]
pub struct ItemMetadata {
    pub created: bool,
    pub modified: bool,
    pub deleted: bool,
    pub renamed: bool,
}

impl ItemMetadata {
    pub fn merge(&mut self, other: &Self) {
        self.created |= other.created;
        self.modified |= other.modified;
        self.deleted |= other.deleted;
        self.renamed |= other.renamed;
    }

    pub fn create(mut self, value: bool) -> Self {
        self.created = value;
        self
    }

    pub fn modify(mut self, value: bool) -> Self {
        self.modified = value;
        self
    }

    pub fn delete(mut self, value: bool) -> Self {
        self.deleted = value;
        self
    }

    pub fn rename(mut self, value: bool) -> Self {
        self.renamed = value;
        self
    }

    pub fn is_empty(&self) -> bool {
        !self.created && !self.modified && !self.deleted && !self.renamed
    }
}

pub enum ItemAction {
    Create,
    Modify,
    Delete,
    Rename,
}

impl From<ItemAction> for ItemMetadata {
    fn from(action: ItemAction) -> Self {
        let created = matches!(action, ItemAction::Create);
        let modified = matches!(action, ItemAction::Modify);
        let deleted = matches!(action, ItemAction::Delete);
        let renamed = matches!(action, ItemAction::Rename);
        ItemMetadata {
            created,
            modified,
            deleted,
            renamed,
        }
    }
}

pub fn new_boxed(options: MonitorOptions, track_options: TrackOptions) -> Result<Box<dyn Monitor>> {
    match options.method {
        MonitorMethod::Usn => Ok(Box::new(usn::UsnMonitor::new(options, track_options)?)),
        MonitorMethod::WinApi => Ok(Box::new(winapi::WinApiMonitor::new(
            options,
            track_options,
        )?)),
        MonitorMethod::Procmon => Ok(Box::new(procmon::ProcmonMonitor::new(
            options,
            track_options,
        )?)),
    }
}
