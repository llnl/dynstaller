use std::{
    collections::BTreeMap,
    ffi::{OsStr, OsString},
    os::windows::prelude::OsStringExt,
    path::PathBuf,
    sync::Arc,
};

use anyhow::{Result, bail};
use async_trait::async_trait;
use tokio::task::JoinHandle;
use widestring::U16CString;
use windows::{
    Win32::{
        Foundation::{ERROR_OPERATION_ABORTED, HANDLE},
        Storage::FileSystem::{
            CreateFileW, FILE_ACTION, FILE_ACTION_ADDED, FILE_ACTION_MODIFIED, FILE_ACTION_REMOVED,
            FILE_ACTION_RENAMED_NEW_NAME, FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OVERLAPPED,
            FILE_GENERIC_READ, FILE_NOTIFY_CHANGE, FILE_NOTIFY_CHANGE_CREATION,
            FILE_NOTIFY_CHANGE_DIR_NAME, FILE_NOTIFY_CHANGE_FILE_NAME,
            FILE_NOTIFY_CHANGE_LAST_WRITE, FILE_NOTIFY_CHANGE_SIZE,
            FILE_NOTIFY_EXTENDED_INFORMATION, FILE_SHARE_DELETE, FILE_SHARE_READ, FILE_SHARE_WRITE,
            OPEN_EXISTING, ReadDirectoryChangesExW, ReadDirectoryNotifyExtendedInformation,
        },
    },
    core::{Owned, PCWSTR},
};

use crate::{
    monitor::{ItemMetadata, Monitor, MonitorOptions},
    options::TrackOptions,
    overlapped_future::OverlappedFuture,
};

pub struct WinApi {
    handle: Owned<HANDLE>,
    future: OverlappedFuture,
}

#[derive(Clone)]
pub struct FileNotification {
    pub info: FILE_NOTIFY_EXTENDED_INFORMATION,
    pub filename: OsString,
}

impl WinApi {
    pub fn new(path: &OsStr) -> Result<Self> {
        let path_wide = U16CString::from_os_str(path)?;
        let ret = unsafe {
            Owned::new(CreateFileW(
                PCWSTR(path_wide.as_ptr()),
                FILE_GENERIC_READ.0,
                FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                None,
                OPEN_EXISTING,
                FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OVERLAPPED,
                None,
            )?)
        };
        let future = OverlappedFuture::create_overlapped(*ret)?;

        Ok(Self {
            handle: ret,
            future,
        })
    }

    fn parse_records(mut data: &[u8]) -> Result<Vec<FileNotification>> {
        let mut records = Vec::new();
        while !data.is_empty() {
            if data.len() < std::mem::size_of::<FILE_NOTIFY_EXTENDED_INFORMATION>() {
                bail!("Insufficient data for FILE_NOTIFY_EXTENDED_INFORMATION");
            }
            let info =
                unsafe { std::ptr::read(data.as_ptr().cast::<FILE_NOTIFY_EXTENDED_INFORMATION>()) };

            let (info_data, remaining_data) = if info.NextEntryOffset != 0 {
                if data.len() < info.NextEntryOffset as usize {
                    bail!("NextEntryOffset exceeds available data length");
                }
                data.split_at(info.NextEntryOffset as usize)
            } else {
                (data, &[] as &[u8])
            };

            let filename = if info.FileNameLength > 0 {
                let name_offset = std::mem::offset_of!(FILE_NOTIFY_EXTENDED_INFORMATION, FileName);
                if name_offset as u32 + info.FileNameLength > info_data.len() as u32 {
                    bail!("FileNameLength exceeds available data length");
                }
                if !info.FileNameLength.is_multiple_of(size_of::<u16>() as u32) {
                    bail!("FileNameLength is not a multiple of u16 size");
                }

                let filename_data =
                    &info_data[name_offset..name_offset + info.FileNameLength as usize];
                let filename_u16 = unsafe {
                    std::slice::from_raw_parts(
                        filename_data.as_ptr().cast::<u16>(),
                        info.FileNameLength as usize / size_of::<u16>(),
                    )
                };
                OsString::from_wide(filename_u16)
            } else {
                OsString::new()
            };

            records.push(FileNotification { info, filename });
            data = remaining_data;
        }

        Ok(records)
    }

    pub async fn read_changes(
        &self,
        scratch: &mut [u8],
        filter: FILE_NOTIFY_CHANGE,
    ) -> Result<Vec<FileNotification>> {
        let (_, buffer, _) = unsafe { scratch.align_to_mut::<u32>() };
        let buffer = unsafe {
            std::slice::from_raw_parts_mut(
                buffer.as_mut_ptr().cast::<u8>(),
                std::mem::size_of_val(buffer),
            )
        };

        let buffer_size = buffer.len() as u32;
        self.future.reset()?;
        unsafe {
            ReadDirectoryChangesExW(
                *self.handle,
                buffer.as_mut_ptr().cast(),
                buffer_size as u32,
                true,
                filter,
                None,
                Some(self.future.overlapped().cast_mut()),
                None,
                ReadDirectoryNotifyExtendedInformation,
            )
        }?;

        let bytes_returned = self.future.clone().await?;

        if bytes_returned > buffer_size as u32 {
            bail!("Bytes returned exceed buffer size");
        }

        Self::parse_records(&buffer[..bytes_returned as usize])
    }

    fn cancel(&self) -> Result<()> {
        Ok(self.future.cancel()?)
    }
}

unsafe impl Send for WinApi {}
unsafe impl Sync for WinApi {}

#[derive(Default)]
enum MonitorState {
    #[default]
    NotStarted,
    Running(JoinHandle<Result<BTreeMap<PathBuf, ItemMetadata>>>),
    Stopped(Result<BTreeMap<PathBuf, ItemMetadata>>),
}

pub struct WinApiMonitor {
    api: Arc<WinApi>,
    state: MonitorState,
    options: MonitorOptions,
}

impl WinApiMonitor {
    fn notify_change_mask(&self) -> FILE_NOTIFY_CHANGE {
        let mut mask = FILE_NOTIFY_CHANGE(0);

        if self.options.creation {
            mask |= FILE_NOTIFY_CHANGE_CREATION;
            mask |= FILE_NOTIFY_CHANGE_FILE_NAME;
            mask |= FILE_NOTIFY_CHANGE_DIR_NAME;
        }
        if self.options.deletion {
            mask |= FILE_NOTIFY_CHANGE_FILE_NAME;
            mask |= FILE_NOTIFY_CHANGE_DIR_NAME;
        }
        if self.options.modification {
            mask |= FILE_NOTIFY_CHANGE_LAST_WRITE;
            mask |= FILE_NOTIFY_CHANGE_SIZE;
        }
        if self.options.renaming {
            mask |= FILE_NOTIFY_CHANGE_FILE_NAME;
            mask |= FILE_NOTIFY_CHANGE_DIR_NAME;
        }

        mask
    }

    fn get_meta(options: &MonitorOptions, action: FILE_ACTION) -> ItemMetadata {
        ItemMetadata::default()
            .create(action == FILE_ACTION_ADDED && options.creation)
            .delete(action == FILE_ACTION_REMOVED && options.deletion)
            .modify(action == FILE_ACTION_MODIFIED && options.modification)
            .rename(action == FILE_ACTION_RENAMED_NEW_NAME && options.renaming)
    }
}

#[async_trait]
impl Monitor for WinApiMonitor {
    fn new(options: MonitorOptions, _track_options: TrackOptions) -> Result<Self> {
        Ok(Self {
            api: Arc::new(WinApi::new(options.path.as_os_str())?),
            state: MonitorState::default(),
            options,
        })
    }

    async fn start(&mut self) -> Result<()> {
        let api = self.api.clone();
        let notify_change_mask = self.notify_change_mask();
        let options = self.options.clone();

        self.state = MonitorState::Running(tokio::spawn(async move {
            let mut ret: BTreeMap<PathBuf, ItemMetadata> = BTreeMap::new();
            let mut scratch = vec![0u8; 64 * 1024]; // 64 KB buffer
            loop {
                log::trace!("Waiting for file changes...");
                let changes = api.read_changes(&mut scratch, notify_change_mask).await;
                let changes = match changes {
                    Ok(changes) => changes,
                    Err(e)
                        if e.downcast_ref::<windows::core::Error>()
                            .is_some_and(|e| *e == ERROR_OPERATION_ABORTED.into()) =>
                    {
                        break;
                    }
                    Err(e) => {
                        return Err(e);
                    }
                };
                for change in changes {
                    let meta = Self::get_meta(&options, change.info.Action);
                    if !meta.is_empty() {
                        let filename = options.path.join(&change.filename);
                        log::trace!("File {:?}: {}", change.info.Action, filename.display());
                        ret.entry(filename).or_default().merge(&meta);
                    }
                }
            }
            Ok(ret)
        }));

        Ok(())
    }

    async fn stop(&mut self) -> Result<()> {
        match std::mem::take(&mut self.state) {
            MonitorState::Running(handle) => {
                self.api.cancel()?;
                let result = match handle.await {
                    Ok(res) => res,
                    Err(e) => bail!("Monitor thread panicked: {}", e),
                };
                self.state = MonitorState::Stopped(result);
            }
            v => {
                self.state = v;
            }
        }
        Ok(())
    }

    fn get_changed_files(&self) -> Result<BTreeMap<PathBuf, ItemMetadata>> {
        if let MonitorState::Stopped(changes) = &self.state {
            match changes {
                Ok(changes) => Ok(changes.clone()),
                Err(e) => bail!("Error retrieving changes: {:?}", e),
            }
        } else {
            bail!("Monitor has not been stopped or no changes recorded")
        }
    }
}
