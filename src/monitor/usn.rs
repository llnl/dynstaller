use std::{
    collections::{BTreeMap, HashMap},
    ffi::{OsStr, OsString, c_void},
    ops::Range,
    os::windows::prelude::OsStringExt,
    path::{Component, Path, PathBuf, Prefix},
};

use anyhow::{Result, bail};
use async_trait::async_trait;
use either::Either;
use widestring::U16CString;
use windows::{
    Win32::{
        Foundation::{ERROR_ACCESS_DENIED, ERROR_HANDLE_EOF, HANDLE},
        Storage::FileSystem::{
            ExtendedFileIdType, FILE_ID_128, FILE_ID_DESCRIPTOR, FILE_ID_DESCRIPTOR_0, FileIdType,
            FileNormalizedNameInfo, GetFileInformationByHandleEx, OpenFileById,
        },
        System::{
            IO::DeviceIoControl,
            Ioctl::{
                FSCTL_ENUM_USN_DATA, FSCTL_QUERY_USN_JOURNAL, MFT_ENUM_DATA_V1,
                USN_JOURNAL_DATA_V2, USN_REASON_CLOSE, USN_REASON_DATA_EXTEND,
                USN_REASON_DATA_OVERWRITE, USN_REASON_DATA_TRUNCATION, USN_REASON_FILE_CREATE,
                USN_REASON_FILE_DELETE, USN_REASON_HARD_LINK_CHANGE, USN_REASON_RENAME_NEW_NAME,
                USN_REASON_RENAME_OLD_NAME, USN_REASON_REPARSE_POINT_CHANGE,
                USN_RECORD_COMMON_HEADER, USN_RECORD_EXTENT, USN_RECORD_V2, USN_RECORD_V3,
                USN_RECORD_V4,
            },
        },
    },
    core::Owned,
};
use windows::{
    Win32::{
        Storage::FileSystem::{
            CreateFileW, FILE_FLAGS_AND_ATTRIBUTES, FILE_GENERIC_READ, FILE_SHARE_DELETE,
            FILE_SHARE_READ, FILE_SHARE_WRITE, OPEN_EXISTING,
        },
        System::Ioctl::{FSCTL_READ_USN_JOURNAL, READ_USN_JOURNAL_DATA_V1},
    },
    core::PCWSTR,
};

use crate::{
    monitor::{ItemMetadata, Monitor, MonitorOptions},
    options::TrackOptions,
};

pub struct Usn {
    handle: Owned<HANDLE>,
}

unsafe impl Send for Usn {}
unsafe impl Sync for Usn {}

#[derive(Debug, Clone)]
pub enum UsnRecord {
    V2 {
        record: USN_RECORD_V2,
        filename: OsString,
    },
    V3 {
        record: USN_RECORD_V3,
        filename: OsString,
    },
    V4 {
        record: USN_RECORD_V4,
        extents: Vec<USN_RECORD_EXTENT>,
    },
}

impl Usn {
    pub fn from_letter(letter: char) -> Result<Self> {
        let path = format!("\\\\.\\{letter}:");
        Self::new(&OsString::from(path))
    }

    pub fn from_path(path: &Path) -> Result<Self> {
        let mut c = path.components();
        match (c.next(), c.next(), c.next()) {
            (Some(Component::Prefix(prefix)), Some(Component::RootDir) | None, None) => {
                match prefix.kind() {
                    Prefix::Disk(letter) => Self::from_letter(letter.to_ascii_uppercase() as char),
                    Prefix::UNC(server, share) => Self::new(&OsString::from(format!(
                        "\\\\?\\UNC\\{}\\{}",
                        server.display(),
                        share.display()
                    ))),
                    _ => Self::new(prefix.as_os_str()),
                }
            }
            (Some(Component::RootDir), None, None) => Self::from_letter('C'),
            _ => {
                bail!("Invalid path for USN journal: {}", path.display());
            }
        }
    }

    pub fn new(path: &OsStr) -> Result<Self> {
        let path_wide = U16CString::from_os_str(path)?;
        let ret = unsafe {
            let handle = CreateFileW(
                PCWSTR(path_wide.as_ptr()),
                FILE_GENERIC_READ.0,
                FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                None,
                OPEN_EXISTING,
                FILE_FLAGS_AND_ATTRIBUTES(0),
                None,
            );
            if let Err(e) = &handle
                && e.code() == ERROR_ACCESS_DENIED.into()
            {
                log::error!("Access denied to USN journal at path: {}", path.display());
                log::error!("You may have to run as administrator.");
            }
            Owned::new(handle?)
        };
        Ok(Self { handle: ret })
    }

    pub fn query_journal(&self) -> Result<USN_JOURNAL_DATA_V2> {
        let mut data = USN_JOURNAL_DATA_V2::default();
        let data_size = std::mem::size_of_val(&data) as u32;
        let mut bytes_received = 0u32;
        unsafe {
            DeviceIoControl(
                *self.handle,
                FSCTL_QUERY_USN_JOURNAL,
                None,
                0,
                Some((&raw mut data).cast::<c_void>()),
                data_size,
                Some(&raw mut bytes_received),
                None,
            )
        }?;
        if bytes_received != data_size {
            return Err(anyhow::anyhow!(
                "Invalid data size received from USN journal query"
            ));
        }
        Ok(data)
    }

    fn parse_records(data: &[u8]) -> Result<(i64, Vec<UsnRecord>)> {
        if data.len() < std::mem::size_of::<i64>() {
            return Err(anyhow::anyhow!(
                "Invalid data size received from USN journal read"
            ));
        }
        let cursor_next_usn: i64 = i64::from_le_bytes(data[0..8].try_into().unwrap());
        let mut records = Vec::new();
        let mut offset = 8; // Skip the USN value
        while offset < data.len() {
            if offset + std::mem::size_of::<USN_RECORD_COMMON_HEADER>() > data.len() {
                bail!("USN record size exceeds header length");
            }
            let header = unsafe {
                std::ptr::read(data[offset..].as_ptr().cast::<USN_RECORD_COMMON_HEADER>())
            };
            if offset + header.RecordLength as usize > data.len() {
                bail!("USN record size exceeds record length");
            }
            let record: UsnRecord = match header.MajorVersion {
                2 => {
                    if offset + std::mem::size_of::<USN_RECORD_V2>() > data.len() {
                        bail!("USN record size exceeds data length");
                    }
                    let record =
                        unsafe { std::ptr::read(data[offset..].as_ptr().cast::<USN_RECORD_V2>()) };

                    let filename = if record.FileNameLength > 0 {
                        if record.FileNameOffset as u32 + record.FileNameLength as u32
                            > header.RecordLength
                        {
                            bail!("File name offset and length exceed record length");
                        }
                        if !record
                            .FileNameLength
                            .is_multiple_of(size_of::<u16>() as u16)
                        {
                            bail!("File name length is not a multiple of u16");
                        }
                        let start = offset + record.FileNameOffset as usize;
                        let end = start + record.FileNameLength as usize;
                        let filename_data = &data[start..end];
                        let filename_u16 = unsafe {
                            std::slice::from_raw_parts(
                                filename_data.as_ptr() as *const u16,
                                record.FileNameLength as usize / 2,
                            )
                        };
                        OsString::from_wide(filename_u16)
                    } else {
                        OsString::new()
                    };

                    log::trace!("2 {:#02X} {filename:?}", record.Reason);
                    UsnRecord::V2 { record, filename }
                }
                3 => {
                    if offset + std::mem::size_of::<USN_RECORD_V3>() > data.len() {
                        bail!("USN record size exceeds data length");
                    }
                    let record =
                        unsafe { std::ptr::read(data[offset..].as_ptr().cast::<USN_RECORD_V3>()) };

                    let filename = if record.FileNameLength > 0 {
                        if record.FileNameOffset as u32 + record.FileNameLength as u32
                            > header.RecordLength
                        {
                            bail!("File name offset and length exceed record length");
                        }
                        if !record
                            .FileNameLength
                            .is_multiple_of(size_of::<u16>() as u16)
                        {
                            bail!("File name length is not a multiple of u16");
                        }
                        let start = offset + record.FileNameOffset as usize;
                        let end = start + record.FileNameLength as usize;
                        let filename_data = &data[start..end];
                        let filename_u16 = unsafe {
                            std::slice::from_raw_parts(
                                filename_data.as_ptr().cast::<u16>(),
                                record.FileNameLength as usize / size_of::<u16>(),
                            )
                        };
                        OsString::from_wide(filename_u16)
                    } else {
                        OsString::new()
                    };
                    log::trace!("3 {:#02X} {filename:?}", record.Reason);
                    UsnRecord::V3 { record, filename }
                }
                4 => {
                    if offset + std::mem::size_of::<USN_RECORD_V4>() > data.len() {
                        bail!("USN record size exceeds data length");
                    }
                    let record =
                        unsafe { std::ptr::read(data[offset..].as_ptr().cast::<USN_RECORD_V4>()) };

                    let extents = if record.ExtentSize > 0 {
                        let extents_offset = std::mem::offset_of!(USN_RECORD_V4, Extents) as u16;
                        if extents_offset as u32 + record.ExtentSize as u32 > header.RecordLength {
                            bail!("File name offset and length exceed record length");
                        }
                        if !record
                            .ExtentSize
                            .is_multiple_of(size_of::<USN_RECORD_EXTENT>() as u16)
                        {
                            bail!("Extent size is not a multiple of USN_RECORD_EXTENT");
                        }
                        let start = offset + extents_offset as usize;
                        let end = start + record.ExtentSize as usize;
                        let extents_data = &data[start..end];
                        let extents_slice = unsafe {
                            std::slice::from_raw_parts(
                                extents_data.as_ptr().cast::<USN_RECORD_EXTENT>(),
                                record.ExtentSize as usize / size_of::<USN_RECORD_EXTENT>(),
                            )
                        };
                        extents_slice.to_vec()
                    } else {
                        Vec::new()
                    };
                    log::trace!("4 {:#02X}", record.Reason);
                    UsnRecord::V4 { record, extents }
                }
                _ => bail!("Unsupported USN record version: {}", header.MajorVersion),
            };
            records.push(record);
            offset += header.RecordLength as usize;
        }

        Ok((cursor_next_usn, records))
    }

    pub fn read_journal(
        &self,
        input: READ_USN_JOURNAL_DATA_V1,
        scratch: &mut [u8],
    ) -> Result<(i64, Vec<UsnRecord>)> {
        let input_size = std::mem::size_of_val(&input) as u32;
        if scratch.len() < input.BytesToWaitFor as usize {
            bail!(
                "Scratch buffer is too small: {} bytes required, {} bytes provided",
                input.BytesToWaitFor,
                scratch.len()
            );
        }

        let data = &mut scratch[..input.BytesToWaitFor as usize];
        let data_size = data.len() as u32;
        let mut bytes_received = 0u32;

        unsafe {
            DeviceIoControl(
                *self.handle,
                FSCTL_READ_USN_JOURNAL,
                Some((&raw const input).cast::<c_void>()),
                input_size,
                Some(data.as_mut_ptr().cast::<c_void>()),
                data_size,
                Some(&raw mut bytes_received),
                None,
            )
        }?;

        let data = data
            .get(..bytes_received as usize)
            .ok_or_else(|| anyhow::anyhow!("Received data size is invalid"))?;

        Self::parse_records(data)
    }

    #[deprecated(note = "Use `read_journal` instead")]
    pub fn enum_journal(
        &self,
        input: MFT_ENUM_DATA_V1,
        scratch: &mut [u8],
    ) -> Result<(i64, Vec<UsnRecord>)> {
        let input_size = std::mem::size_of_val(&input) as u32;
        let data = scratch;
        let data_size = data.len() as u32;
        let mut bytes_received = 0u32;

        unsafe {
            DeviceIoControl(
                *self.handle,
                FSCTL_ENUM_USN_DATA,
                Some((&raw const input).cast::<c_void>()),
                input_size,
                Some(data.as_mut_ptr().cast::<c_void>()),
                data_size,
                Some(&raw mut bytes_received),
                None,
            )
        }?;

        let data = data
            .get(..bytes_received as usize)
            .ok_or_else(|| anyhow::anyhow!("Received data size is invalid"))?;

        Self::parse_records(data)
    }

    pub fn read_range(&self, mut range: Range<i64>, reason_mask: u32) -> Result<Vec<UsnRecord>> {
        let query = self.query_journal()?;
        if range.start < query.FirstUsn {
            bail!(
                "USN journal start ({}) is less than the first USN ({})",
                range.start,
                query.FirstUsn
            );
        }
        range.end = range.end.min(query.NextUsn);

        let mut scratch = vec![0u8; 0x10000]; // 64 KiB buffer

        let mut input = READ_USN_JOURNAL_DATA_V1 {
            StartUsn: range.start,
            ReasonMask: reason_mask,
            ReturnOnlyOnClose: 0,
            Timeout: 0,
            BytesToWaitFor: scratch.len() as u64,
            UsnJournalID: query.UsnJournalID,
            MinMajorVersion: 2.max(query.MinSupportedMajorVersion),
            MaxMajorVersion: 4.min(query.MaxSupportedMajorVersion),
        };

        let mut records = Vec::new();
        while input.StartUsn < range.end {
            log::trace!(
                "Reading USN journal from {} to {}",
                input.StartUsn,
                range.end
            );
            let (next_usn, mut cur_records) = self.read_journal(input, &mut scratch)?;
            if next_usn > range.end {
                cur_records.retain(|r| match r {
                    UsnRecord::V2 { record, .. } => record.Usn < range.end,
                    UsnRecord::V3 { record, .. } => record.Usn < range.end,
                    UsnRecord::V4 { record, .. } => record.Usn < range.end,
                });
                records.extend(cur_records);
                break;
            }
            records.extend(cur_records);
            input.StartUsn = next_usn;
        }
        Ok(records)
    }

    #[deprecated(note = "Use `read_range` instead")]
    pub fn enum_range(&self, range: Range<i64>) -> Result<Vec<UsnRecord>> {
        let mut scratch = vec![0u8; 0x10000]; // 64 KiB buffer

        let mut input = MFT_ENUM_DATA_V1 {
            StartFileReferenceNumber: 0,
            LowUsn: range.start,
            HighUsn: range.end,
            MinMajorVersion: 2,
            MaxMajorVersion: 4,
        };

        let mut records = Vec::new();
        loop {
            #[allow(deprecated)]
            let result = self.enum_journal(input, &mut scratch);
            if let Err(ref e) = result
                && let Some(e) = e.downcast_ref::<windows::core::Error>()
                && e.code() == ERROR_HANDLE_EOF.into()
            {
                break;
            }
            let (next_number, cur_records) = result?;
            if cur_records.is_empty() {
                break;
            }
            records.extend(cur_records);
            input.StartFileReferenceNumber = next_number as u64;
        }
        Ok(records)
    }
}

pub struct UsnMonitor {
    usn: Usn,
    initial_usn: Option<i64>,
    end_usn: Option<i64>,
    options: MonitorOptions,
}

impl UsnMonitor {
    fn get_file_path(&self, file_id: Either<i64, FILE_ID_128>) -> Result<PathBuf> {
        let descriptor: FILE_ID_DESCRIPTOR = match file_id {
            Either::Left(id) => FILE_ID_DESCRIPTOR {
                Type: FileIdType,
                Anonymous: FILE_ID_DESCRIPTOR_0 { FileId: id },
                dwSize: std::mem::size_of::<FILE_ID_DESCRIPTOR>() as u32,
            },
            Either::Right(file_id_128) => FILE_ID_DESCRIPTOR {
                Type: ExtendedFileIdType,
                Anonymous: FILE_ID_DESCRIPTOR_0 {
                    ExtendedFileId: file_id_128,
                },
                dwSize: std::mem::size_of::<FILE_ID_DESCRIPTOR>() as u32,
            },
        };

        let handle = unsafe {
            Owned::new(OpenFileById(
                *self.usn.handle,
                &raw const descriptor,
                0,
                FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                None,
                FILE_FLAGS_AND_ATTRIBUTES(0),
            )?)
        };

        let mut info_buffer = [0u8; 1024];
        unsafe {
            GetFileInformationByHandleEx(
                *handle,
                FileNormalizedNameInfo,
                info_buffer.as_mut_ptr().cast::<c_void>(),
                info_buffer.len() as u32,
            )
        }?;

        let file_name_length = u32::from_ne_bytes(info_buffer[0..4].try_into().unwrap()) as usize;
        if 4 + file_name_length > info_buffer.len() {
            bail!("Buffer too small for file name");
        }
        if !file_name_length.is_multiple_of(2) {
            bail!("File name length is not a multiple of u16");
        }
        let file_name_data = &info_buffer[4..(4 + file_name_length)];
        let filename_u16 = unsafe {
            std::slice::from_raw_parts(file_name_data.as_ptr().cast::<u16>(), file_name_length / 2)
        };

        Ok(PathBuf::from(OsString::from_wide(filename_u16)))
    }

    fn get_meta(&self, reason: u32) -> ItemMetadata {
        const CREATION_MASK: u32 = USN_REASON_FILE_CREATE | USN_REASON_HARD_LINK_CHANGE;
        const DELETION_MASK: u32 = USN_REASON_FILE_DELETE | USN_REASON_HARD_LINK_CHANGE;
        const MODIFICATION_MASK: u32 =
            USN_REASON_DATA_EXTEND | USN_REASON_DATA_OVERWRITE | USN_REASON_DATA_TRUNCATION;
        const RENAMING_MASK: u32 = USN_REASON_RENAME_NEW_NAME;

        ItemMetadata::default()
            .create((reason & CREATION_MASK) != 0 && self.options.creation)
            .delete((reason & DELETION_MASK) != 0 && self.options.deletion)
            .modify((reason & MODIFICATION_MASK) != 0 && self.options.modification)
            .rename((reason & RENAMING_MASK) != 0 && self.options.renaming)
    }
}

#[async_trait]
impl Monitor for UsnMonitor {
    fn new(options: MonitorOptions, _track_options: TrackOptions) -> Result<Self> {
        Ok(Self {
            usn: Usn::from_path(&options.path)?,
            initial_usn: None,
            end_usn: None,
            options,
        })
    }

    async fn start(&mut self) -> Result<()> {
        let query = self.usn.query_journal()?;
        self.initial_usn = Some(query.NextUsn);
        self.end_usn = None;
        Ok(())
    }

    async fn stop(&mut self) -> Result<()> {
        if self.initial_usn.is_none() {
            bail!("Monitor has not been started");
        }
        if self.end_usn.is_some() {
            bail!("Monitor has already been stopped");
        }
        let query = self.usn.query_journal()?;
        self.end_usn = Some(query.NextUsn);
        Ok(())
    }

    fn get_changed_files(&self) -> Result<BTreeMap<PathBuf, ItemMetadata>> {
        let Some(start) = self.initial_usn else {
            bail!("Monitor has not been started");
        };
        let Some(end) = self.end_usn else {
            bail!("Monitor has not been stopped");
        };
        let range = start..end;
        //let records = self.usn.enum_range(range)?;
        let records = self.usn.read_range(range.clone(), u32::MAX)?;

        let mut ids: HashMap<Either<i64, u128>, (OsString, ItemMetadata)> = HashMap::new();
        for record in records {
            let (reason, file_id, filename) = match record {
                UsnRecord::V2 { record, filename } => (
                    record.Reason,
                    Either::Left(record.FileReferenceNumber as i64),
                    Some(filename),
                ),
                UsnRecord::V3 { record, filename } => (
                    record.Reason,
                    Either::Right(record.FileReferenceNumber),
                    Some(filename),
                ),
                UsnRecord::V4 { record, .. } => (
                    record.Reason,
                    Either::Right(record.FileReferenceNumber),
                    None,
                ),
            };
            let Some(filename) = filename else { continue };

            let metadata = self.get_meta(reason);
            if metadata.is_empty() {
                continue;
            }

            const EXCLUDE_MASK: u32 =
                USN_REASON_CLOSE | USN_REASON_RENAME_OLD_NAME | USN_REASON_REPARSE_POINT_CHANGE;
            if reason & EXCLUDE_MASK != 0 {
                log::trace!("Skipping change record (excluded): {}", filename.display());
                continue;
            }

            let file_id = file_id.map_right(|id| u128::from_le_bytes(id.Identifier));
            let (entry_name, entry_meta) = ids.entry(file_id).or_default();
            *entry_name = filename;
            entry_meta.merge(&metadata);
        }

        let mut paths = BTreeMap::new();
        for (file_id, (filename, metadata)) in ids {
            let file_id = file_id.map_right(|id| FILE_ID_128 {
                Identifier: id.to_le_bytes(),
            });
            let result = self.get_file_path(file_id);
            let filename = if let Err(ref e) = result {
                if let Some(e) = e.downcast_ref::<windows::core::Error>() {
                    log::warn!("{} => {:?}", filename.display(), e.message());
                    let code: i32 = e.code().0;
                    PathBuf::from(format!("{code:#02X}")).join(filename)
                } else {
                    result?
                }
            } else {
                result?
            };
            paths.insert(filename, metadata);
        }
        Ok(paths)
    }
}
