use std::{
    collections::{BTreeMap, HashMap, HashSet},
    ffi::OsStr,
    fmt::Debug,
    fs::File,
    path::{Path, PathBuf},
    process::{ExitStatus, Stdio},
    sync::LazyLock,
};

use anyhow::{Result, bail};
use async_trait::async_trait;
use hex_literal::hex;
use regex::Regex;
use serde::Deserialize;
use sha1::{Digest, Sha1};
use tokio::{process::Command, task::JoinHandle};
use tokio_util::sync::CancellationToken;
use ureq::{
    config::Config,
    tls::{TlsConfig, TlsProvider},
};
#[cfg(windows)]
use windows::Win32::System::Threading::CREATE_NEW_CONSOLE;

use crate::{
    build,
    monitor::{
        ItemAction, ItemMetadata, Monitor, MonitorOptions,
        procmon::xml::{Event, LogFile, Process},
    },
    options::TrackOptions,
    utils::{DropGuard, create_temp_path},
};

#[derive(Default)]
enum MonitorState {
    #[default]
    NotStarted,
    Running {
        stop_signal: CancellationToken,
        handle: JoinHandle<Result<MonitorResult>>,
    },
    Stopped(MonitorResult),
}

struct MonitorResult {
    pub files: BTreeMap<PathBuf, ItemMetadata>,
    pub registry_keys: BTreeMap<PathBuf, ItemMetadata>,
}

pub struct ProcmonMonitor {
    options: MonitorOptions,
    track_options: TrackOptions,
    state: MonitorState,
}

const HASH: [u8; 20] = hex!("BC18A67AD4057DD36F896A4D411B8FC5B06E5B2F"); // Procmon.exe
const HASH_64: [u8; 20] = hex!("8ED888A02861142E5EB576385568C2BA0DDD8589"); // Procmon64.exe
const VERSION: &str = "4.01";
const URL: &str = "https://live.sysinternals.com/Procmon64.exe";

impl ProcmonMonitor {
    async fn run_cmd(procmon_path: &Path, args: &[&OsStr]) -> std::io::Result<ExitStatus> {
        let mut cmd = Command::new(procmon_path);

        cmd.args(["/Minimized", "/AcceptEula", "/Quiet"]).args(args);

        #[cfg(windows)]
        cmd.creation_flags(CREATE_NEW_CONSOLE.0);
        cmd.stdin(Stdio::null());
        cmd.stdout(Stdio::inherit());
        cmd.stderr(Stdio::inherit());

        log::info!("Running {:?}", cmd.as_std());

        let mut cmd = cmd.spawn()?;
        cmd.wait().await
    }

    async fn run(
        options: MonitorOptions,
        track_options: TrackOptions,
        stop_signal: CancellationToken,
        started_signal: CancellationToken,
    ) -> Result<MonitorResult> {
        let procmon_path = Self::resolve_procmon_path(&options)?;
        log::info!("Using Procmon path: {}", procmon_path.display());

        let pmc_path = create_temp_path(Some("pmc"));
        let _pmc_guard = DropGuard::new({
            let pmc_path = pmc_path.clone();
            move || {
                log::info!("Deleting temporary PMC file: {}", pmc_path.display());
                std::fs::remove_file(pmc_path).unwrap_or_else(|e| {
                    log::warn!("Failed to delete PMC file: {e:?}");
                });
            }
        });
        std::fs::write(&pmc_path, include_bytes!("../../procmon/filter.pmc"))?;

        let pml_path = create_temp_path(Some("pml"));
        let _pml_guard = DropGuard::new({
            let pml_path = pml_path.clone();
            move || {
                log::info!("Deleting temporary PML file: {}", pml_path.display());
                std::fs::remove_file(pml_path).unwrap_or_else(|e| {
                    log::warn!("Failed to delete PML file: {e:?}");
                });
            }
        });

        let run_args = [
            "/BackingFile".as_ref(),
            pml_path.as_os_str(),
            "/LoadConfig".as_ref(),
            pmc_path.as_os_str(),
        ];
        let wait_args = [OsStr::new("/WaitForIdle")];

        let run_end_token = CancellationToken::new();
        let run_future = async {
            let ret = Self::run_cmd(&procmon_path, &run_args).await?;
            run_end_token.cancel();
            if !ret.success() {
                log::warn!("Procmon run command exited with status: {ret}");
            }
            Ok(())
        };
        let wait_future = async {
            let ret = Self::run_cmd(&procmon_path, &wait_args).await?;
            if !ret.success() {
                bail!("Procmon wait command exited with status: {ret}");
            }
            started_signal.cancel();
            Ok(())
        };
        let cancel_future = async {
            stop_signal.cancelled().await;
            if !run_end_token.is_cancelled() {
                let ret = Self::run_cmd(&procmon_path, &[OsStr::new("/Terminate")]).await?;
                if !ret.success() {
                    log::warn!("Procmon terminate command exited with status: {ret}");
                }
            }
            Ok(())
        };
        tokio::try_join!(run_future, wait_future, cancel_future)?;

        let xml_path = create_temp_path(Some("xml"));
        let _xml_guard = DropGuard::new({
            let xml_path = xml_path.clone();
            move || {
                log::info!("Deleting temporary XML file: {}", xml_path.display());
                std::fs::remove_file(xml_path).unwrap_or_else(|e| {
                    log::warn!("Failed to delete XML file: {e:?}");
                });
            }
        });

        Self::run_cmd(
            &procmon_path,
            &[
                "/OpenLog".as_ref(),
                pml_path.as_os_str(),
                "/SaveAs".as_ref(),
                xml_path.as_os_str(),
            ],
        )
        .await?;

        if !xml_path.exists() {
            bail!(
                "Procmon did not create the output XML file at {}",
                xml_path.display()
            );
        }

        log::info!("Procmon output saved to {}", xml_path.display());

        let xml_reader = std::fs::File::open(&xml_path)?;
        let xml_reader = std::io::BufReader::new(xml_reader);

        log::info!("Reading XML file");
        let document: LogFile = serde_xml_rs::from_reader(xml_reader)?;
        log::info!("Parsed XML file");

        let proc_map = if let Some(filter_pid) = track_options.pid {
            let mut processes = BTreeMap::new();
            let mut pid_idx = None;
            for process in document.processes.processes {
                if process.process_id == filter_pid {
                    pid_idx = Some(process.process_index);
                }
                processes.insert(process.process_index, process);
            }
            if let Some(idx) = pid_idx {
                log::debug!("Found target PID {filter_pid} at process index {idx}");
            } else {
                bail!("No process with target PID {filter_pid} found in the log");
            }

            Some(processes)
        } else {
            None
        };

        let mut processes = HashSet::new();
        let mut registry_keys: BTreeMap<PathBuf, ItemMetadata> = BTreeMap::new();
        let mut files: BTreeMap<PathBuf, ItemMetadata> = BTreeMap::new();
        for event in document.events.events {
            if event.result != "SUCCESS" {
                continue;
            }

            if let Some(filter_pid) = track_options.pid
                && !Self::pid_matches(
                    filter_pid,
                    !track_options.no_children,
                    proc_map.as_ref().unwrap(),
                    &event,
                )
            {
                continue;
            }

            if let Some((key, metadata)) = Self::registry_matches(&options, &event) {
                if !metadata.is_empty() {
                    registry_keys.entry(key).or_default().merge(&metadata);
                }
            } else if let Some((file, metadata)) = Self::file_matches(&options, &event)
                && !metadata.is_empty()
            {
                files.entry(file).or_default().merge(&metadata);
                processes.insert(event.process_name.clone());
            }
        }

        log::info!("Processes: {processes:?}");

        Ok(MonitorResult {
            files,
            registry_keys,
        })
    }

    pub fn resolve_procmon_path(options: &MonitorOptions) -> Result<PathBuf> {
        let path = options
            .procmon_path
            .clone()
            .or_else(|| {
                // Check if Procmon64.exe exists in the current directory
                let current_dir = std::env::current_dir().ok()?;
                let procmon_path = current_dir.join("Procmon64.exe");
                if procmon_path.exists() {
                    Some(procmon_path)
                } else {
                    None
                }
            })
            .or_else(|| {
                // Check PATH
                std::env::var_os("PATH").and_then(|path| {
                    std::env::split_paths(&path)
                        .flat_map(|p| [p.join("Procmon64.exe"), p.join("Procmon.exe")])
                        .find(|p| p.exists())
                })
            });

        let path = if let Some(p) = path {
            p
        } else {
            let path = std::env::temp_dir().join("Procmon64.exe");
            if !path.exists() {
                log::info!("Downloading Procmon to {}", path.display());
                Self::download_procmon(&path)?;
            }
            path
        };

        if !path.exists() {
            bail!("Specified Procmon path does not exist: {}", path.display());
        }

        let hash = {
            let mut hasher = Sha1::new();
            std::io::copy(&mut File::open(&path)?, &mut hasher)?;
            hasher.finalize()
        };
        let hash = hash.as_slice();

        if hash == HASH || hash == HASH_64 {
            Ok(path.clone())
        } else {
            bail!(
                "Invalid Procmon executable found at {}. Remember to use Procmon {VERSION}.",
                path.display()
            )
        }
    }

    fn download_procmon(path: &PathBuf) -> Result<()> {
        let agent = Config::builder()
            .tls_config(
                TlsConfig::builder()
                    .provider(TlsProvider::NativeTls)
                    .disable_verification(true)
                    .build(),
            )
            .user_agent(format!(
                "{}/{}+{}",
                build::PROJECT_NAME,
                build::PKG_VERSION,
                build::SHORT_COMMIT
            ))
            .build()
            .new_agent();

        log::info!("Downloading Procmon from {URL}");
        let resp = agent.get(URL).call()?;
        if !resp.status().is_success() {
            bail!("Failed to download Procmon: HTTP {}", resp.status());
        }

        log::info!("Download started, writing to file...");
        let mut file = std::fs::File::create(path)?;
        std::io::copy(&mut resp.into_body().into_reader(), &mut file)?;
        log::info!("Download completed successfully");
        Ok(())
    }

    #[allow(clippy::match_same_arms)]
    fn registry_matches(
        options: &MonitorOptions,
        event: &Event,
    ) -> Option<(PathBuf, ItemMetadata)> {
        if !options.add_registry {
            return None;
        }

        let details = parse_details(&event.detail);
        let ret: &[ItemAction] = match event.operation.as_str() {
            "RegOpenKey" => &[],
            "RegCreateKey" if details.get("Disposition") == Some(&"REG_CREATED_NEW_KEY") => {
                &[ItemAction::Create]
            }
            "RegCreateKey" => &[],
            "RegCloseKey" => &[],
            "RegQueryKey" => &[],
            "RegSetValue" => &[ItemAction::Create, ItemAction::Modify],
            "RegQueryValue" => &[],
            "RegEnumValue" => &[],
            "RegEnumKey" => &[],
            "RegSetInfoKey" => &[],
            "RegDeleteKey" => &[ItemAction::Delete],
            "RegDeleteValue" => &[ItemAction::Delete],
            "RegFlushKey" => &[],
            "RegLoadKey" => &[],
            "RegUnloadKey" => &[],
            "RegRenameKey" => &[ItemAction::Rename],
            "RegQueryMultipleValueKey" => &[],
            "RegSetKeySecurity" => &[ItemAction::Modify],
            "RegQueryKeySecurity" => &[],
            "RegOpenKey2" => &[],
            "RegRestorekey" => &[],
            "RegSaveKey" => &[],
            _ => return None,
        };

        let mut meta = ItemMetadata::default();
        if !ret.is_empty() {
            for action in ret {
                match action {
                    ItemAction::Create => meta.created = options.creation,
                    ItemAction::Modify => meta.modified = options.modification,
                    ItemAction::Delete => meta.deleted = options.deletion,
                    ItemAction::Rename => meta.renamed = options.renaming,
                }
            }
        }

        Some((PathBuf::from(&event.path), meta))
    }

    #[allow(clippy::match_same_arms)]
    fn file_matches(options: &MonitorOptions, event: &Event) -> Option<(PathBuf, ItemMetadata)> {
        let details = parse_details(&event.detail);
        let operation = get_file_operation(event.operation.as_str(), details.get("Type").copied())?;
        let ret: &[ItemAction] = match operation.as_str() {
            "VolumeDismount" => &[],
            "VolumeMount" => &[],
            "FASTIO_MDL_WRITE_COMPLETE" => &[ItemAction::Modify],
            "FASTIO_PREPARE_MDL_WRITE" => &[ItemAction::Modify],
            "FASTIO_MDL_READ_COMPLETE" => &[],
            "FASTIO_MDL_READ" => &[],
            "FASTIO_NETWORK_QUERY_OPEN" => &[],
            "FASTIO_CHECK_IF_POSSIBLE" => &[],
            "IRP_MJ_12" => &[],
            "IRP_MJ_11" => &[],
            "IRP_MJ_10" => &[],
            "IRP_MJ_9" => &[],
            "IRP_MJ_8" => &[],
            "FASTIO_NOTIFY_STREAM_FO_CREATION" => &[],
            "FASTIO_RELEASE_FOR_CC_FLUSH" => &[],
            "FASTIO_ACQUIRE_FOR_CC_FLUSH" => &[],
            "FASTIO_RELEASE_FOR_MOD_WRITE" => &[],
            "FASTIO_ACQUIRE_FOR_MOD_WRITE" => &[],
            "FASTIO_RELEASE_FOR_SECTION_SYNCHRONIZATION" => &[],
            "CreateFileMapping" => &[], // Maybe check if PageProtection contains 'WRITE'?
            "CreateFile" if details.get("OpenResult") == Some(&"Created") => &[ItemAction::Create],
            "CreateFile" if details.get("OpenResult") == Some(&"Superseded") => {
                &[ItemAction::Create, ItemAction::Delete]
            }
            "CreateFile" if details.get("OpenResult") == Some(&"Overwritten") => {
                &[ItemAction::Modify]
            }
            "CreateFile" => &[],
            "CreatePipe" => &[ItemAction::Create],
            "IRP_MJ_CLOSE" => &[],
            "ReadFile" => &[],
            "WriteFile" => &[ItemAction::Modify],
            "QueryInformationFile" => &[],
            "QueryAllInformationFile" => &[],
            "QueryAttributeTagFile" => &[],
            "QueryBasicInformationFile" => &[],
            "QueryCompressionInformationFile" => &[],
            "QueryEaInformationFile" => &[],
            "QueryFileInternalInformationFile" => &[],
            "QueryMoveClusterInformationFile" => &[],
            "QueryNetworkOpenInformationFile" => &[],
            "QueryPositionInformationFile" => &[],
            "QueryStandardInformationFile" => &[],
            "QueryStreamInformationFile" => &[],
            "QueryNameInformationFile" => &[],
            "QueryShortNameInformationFile" => &[],
            "QueryNormalizedNameInformationFile" => &[],
            "QueryNetworkPhysicalNameInformationFile" => &[],
            "QueryIdBothDirectory" => &[],
            "QueryValidDataLength" => &[],
            "QueryIoPiorityHint" => &[],
            "QueryLinks" => &[],
            "QueryId" => &[],
            "QueryEndOfFile" => &[],
            "QueryAttributeTag" => &[],
            "QueryIdGlobalTxDirectoryInformation" => &[],
            "QueryIsRemoteDeviceInformation" => &[],
            "QueryAttributeCacheInformation," => &[],
            "QueryNumaNodeInformation" => &[],
            "QueryStandardLinkInformation" => &[],
            "QueryRemoteProtocolInformation" => &[],
            "QueryRenameInformationBypassAccessCheck" => &[],
            "QueryLinkInformationBypassAccessCheck" => &[],
            "QueryVolumeNameInformation" => &[],
            "QueryIdInformation" => &[],
            "QueryIdExtdDirectoryInformation" => &[],
            "QueryHardLinkFullIdInformation" => &[],
            "QueryIdExtdBothDirectoryInformation" => &[],
            "QueryDesiredStorageClassInformation" => &[],
            "QueryStatInformation" => &[],
            "QueryMemoryPartitionInformation" => &[],
            "QuerySatLxInformation" => &[],
            "QueryCaseSensitiveInformation" => &[],
            "QueryLinkInformationEx" => &[],
            "QueryLinkInfomraitonBypassAccessCheck" => &[],
            "QueryStorageReservedIdInformation" => &[],
            "QueryCaseSensitiveInformationForceAccessCheck" => &[],
            "SetInformationFile" => &[],
            "SetAllocationInformationFile" => &[ItemAction::Modify],
            "SetDispositionInformationFile" => &[ItemAction::Modify],
            "SetEndOfFileInformationFile" => &[ItemAction::Modify],
            "SetLinkInformationFile" => &[ItemAction::Modify],
            "SetPositionInformationFile" => &[ItemAction::Modify],
            "SetRenameInformationFile" => &[ItemAction::Modify],
            "SetValidDataLengthInformationFile" => &[ItemAction::Modify],
            "SetFileStreamInformation" => &[ItemAction::Modify],
            "SetPipeInformation" => &[ItemAction::Modify],
            "SetShortNameInformation" => &[ItemAction::Modify],
            "SetDispositionInformationEx" => &[ItemAction::Modify],
            "SetReplaceCompletionInformation" => &[ItemAction::Modify],
            "SetRenameInformationEx" | "SetRenameInformationExBypassAccessCheck" => {
                if let Some(&path) = details.get("FileName")
                    && !path.is_empty()
                {
                    return Some((
                        PathBuf::from(path),
                        ItemMetadata::default().modify(options.renaming),
                    ));
                }
                &[ItemAction::Rename]
            }
            "SetStorageReservedIdInformation" => &[ItemAction::Modify],
            "QueryEAFile" => &[],
            "SetEAFile" => &[ItemAction::Modify],
            "FlushBuffersFile" => &[],
            "QueryVolumeInformation" => &[],
            "QueryInformationVolume" => &[],
            "QueryLabelInformationVolume" => &[],
            "QuerySizeInformationVolume" => &[],
            "QueryDeviceInformationVolume" => &[],
            "QueryAttributeInformationVolume" => &[],
            "QueryControlInformationVolume" => &[],
            "QueryFullSizeInformationVolume" => &[],
            "QueryObjectIdInformationVolume" => &[],
            "SetVolumeInformation" => &[],
            "DirectoryControl" => &[],
            "QueryDirectory" => &[],
            "NotifyChangeDirectory" => &[],
            "FileSystemControl" => &[],
            "DeviceIoControl" => &[],
            "InternalDeviceIoControl" => &[],
            "Shutdown" => &[],
            "LockUnlockFile" => &[],
            "LockFile" => &[],
            "UnlockFileSingle" => &[],
            "UnlockFileAll" => &[],
            "UnlockFileByKey" => &[],
            "CloseFile" => &[],
            "CreateMailSlot" => &[ItemAction::Create],
            "QuerySecurityFile" => &[],
            "SetSecurityFile" => &[],
            "Power" => &[],
            "SystemControl" => &[],
            "DeviceChange" => &[],
            "QueryFileQuota" => &[],
            "SetFileQuota" => &[],
            "PlugAndPlay" => &[],
            "StartDevice" => &[],
            "QueryRemoveDevice" => &[],
            "RemoveDevice" => &[],
            "CancelRemoveDevice" => &[],
            "StopDevice" => &[],
            "QueryStopDevice" => &[],
            "CancelStopDevice" => &[],
            "QueryDeviceRelations" => &[],
            "QueryInterface" => &[],
            "QueryCapabilities" => &[],
            "QueryResources" => &[],
            "QueryResourceRequirements" => &[],
            "QueryDeviceText" => &[],
            "FilterResourceRequirements" => &[],
            "ReadConfig" => &[],
            "WriteConfig" => &[],
            "Eject" => &[],
            "SetLock" => &[],
            // "QueryId" => &[],
            "QueryPnpDeviceState" => &[],
            "QueryBusInformation" => &[],
            "DeviceUsageNotification" => &[],
            "SurpriseRemoval" => &[],
            "QueryLegacyBusInformation" => &[],
            "IRP_MJ_MAXIMUM_FUNCTION" => &[],
            _ => return None,
        };

        let mut meta = ItemMetadata::default();
        if !ret.is_empty() {
            for action in ret {
                match action {
                    ItemAction::Create => meta.created = options.creation,
                    ItemAction::Modify => meta.modified = options.modification,
                    ItemAction::Delete => meta.deleted = options.deletion,
                    ItemAction::Rename => meta.renamed = options.renaming,
                }
            }
        }

        Some((PathBuf::from(&event.path), meta))
    }

    fn pid_matches(
        filter_pid: u32,
        recurse: bool,
        processes: &BTreeMap<u32, Process>,
        event: &Event,
    ) -> bool {
        let mut process = processes.get(&event.process_index);
        while let Some(p) = process {
            if p.process_id == filter_pid {
                return true;
            }
            if !recurse {
                break;
            }
            if p.parent_process_index == p.process_index {
                // This is a root process, no parent
                break;
            }
            process = processes.get(&p.parent_process_index);
        }
        false
    }
}

#[async_trait]
impl Monitor for ProcmonMonitor {
    fn new(options: MonitorOptions, track_options: TrackOptions) -> Result<Self> {
        Ok(Self {
            options,
            track_options,
            state: MonitorState::NotStarted,
        })
    }

    async fn start(&mut self) -> Result<()> {
        let stop_token = CancellationToken::new();
        let start_token = CancellationToken::new();
        self.state = MonitorState::Running {
            stop_signal: stop_token.clone(),
            handle: tokio::spawn(Self::run(
                self.options.clone(),
                self.track_options.clone(),
                stop_token,
                start_token.clone(),
            )),
        };
        start_token.cancelled_owned().await;
        Ok(())
    }

    async fn stop(&mut self) -> Result<()> {
        match std::mem::take(&mut self.state) {
            MonitorState::Running {
                stop_signal,
                handle,
            } => {
                stop_signal.cancel();
                let result = handle.await??;
                self.state = MonitorState::Stopped(result);
            }
            v => {
                self.state = v;
            }
        }
        Ok(())
    }

    fn get_changed_files(&self) -> Result<BTreeMap<PathBuf, ItemMetadata>> {
        if let MonitorState::Stopped(result) = &self.state {
            Ok(result.files.clone())
        } else {
            bail!("Monitor has not been stopped or no changes recorded")
        }
    }

    fn get_changed_registry_keys(&self) -> Option<Result<BTreeMap<PathBuf, ItemMetadata>>> {
        if let MonitorState::Stopped(result) = &self.state {
            Some(Ok(result.registry_keys.clone()))
        } else {
            None
        }
    }
}

mod xml {
    use serde::Deserialize;

    #[derive(Debug, Deserialize)]
    pub struct LogFile {
        #[serde(rename = "processlist")]
        pub processes: ProcessList,
        #[serde(rename = "eventlist")]
        pub events: EventList,
    }

    #[derive(Debug, Deserialize)]
    pub struct ProcessList {
        #[serde(rename = "process", default)]
        pub processes: Vec<Process>,
    }

    #[derive(Debug, Deserialize)]
    pub struct ModuleList {
        #[serde(rename = "module", default)]
        pub modules: Vec<Module>,
    }

    #[derive(Debug, Deserialize)]
    pub struct EventList {
        #[serde(rename = "event", default)]
        pub events: Vec<Event>,
    }

    #[derive(Debug, Deserialize)]
    #[serde(rename_all = "PascalCase")]
    pub struct Process {
        pub process_index: u32,
        pub process_id: u32,
        pub parent_process_id: u32,
        pub parent_process_index: u32,
        pub authentication_id: String,
        pub create_time: u64,
        pub finish_time: u64,
        pub is_virtualized: u32,
        #[serde(rename = "Is64bit")]
        pub is_64_bit: bool,
        pub integrity: String,
        pub owner: String,
        pub process_name: String,
        pub image_path: String,
        pub command_line: String,
        pub company_name: String,
        pub version: String,
        pub description: String,
        #[serde(rename = "modulelist")]
        pub modules: ModuleList,
    }

    #[derive(Debug, Deserialize)]
    #[serde(rename_all = "PascalCase")]
    pub struct Module {
        pub timestamp: u64,
        pub base_address: String,
        pub size: u64,
        pub path: String,
        pub version: String,
        pub company: String,
        pub description: String,
    }

    #[derive(Debug, Deserialize)]
    #[serde(rename_all = "PascalCase")]
    pub struct Event {
        pub process_index: u32,
        #[serde(rename = "Time_of_Day")]
        pub time_of_day: String,
        #[serde(rename = "Process_Name")]
        pub process_name: String,
        #[serde(rename = "PID")]
        pub pid: u32,
        pub operation: String,
        pub path: String,
        pub result: String,
        pub detail: String,
    }
}

// (?:^|,\s*) — match start-of-string or “, ” but don’t capture it
// ([^:]+):   — capture the key
// \s*        — optional space
// (…value…)  — capture the value (comma-grouped number or non-comma text)
static DETAILS_REGEX: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?:^|,\s*)([^:]+):\s*(\d{1,3}(?:,\d{3})*|[^,]+)").unwrap());

fn parse_details(data: &str) -> HashMap<&str, &str> {
    DETAILS_REGEX
        .captures_iter(data)
        .map(|caps| {
            let key = caps.get(1).unwrap().as_str().trim();
            let val = caps.get(2).unwrap().as_str().trim();
            (key, val)
        })
        .collect()
}

#[derive(Debug, Deserialize)]
struct FilesystemOperation {
    #[serde(default)]
    to: String,
    from: String,
    #[serde(default)]
    additional: Vec<AdditionalFilesystemOperation>,
}

#[derive(Debug, Deserialize)]
struct AdditionalFilesystemOperation {
    id: u32,
    irp: String,
    fastio: String,
    #[serde(default)]
    name: Option<String>,
}

static FILESYSTEM_OPS: LazyLock<Vec<FilesystemOperation>> =
    LazyLock::new(|| serde_json::from_str(include_str!("../../procmon/filesystem.json")).unwrap());

fn get_file_operation(operation: &str, evt_type: Option<&str>) -> Option<String> {
    for op in &*FILESYSTEM_OPS {
        // Check if already converted
        if operation == op.to {
            return Some(op.to.clone());
        }

        for additional in op.additional.as_slice() {
            if let Some(name) = &additional.name {
                // Check if already converted
                if name == operation {
                    return Some(name.clone());
                }

                if let Some(evt_type) = evt_type
                    && (additional.irp == operation || additional.fastio == operation)
                    && name == evt_type
                {
                    return Some(name.clone());
                }
            }
        }

        if operation == op.from {
            return Some(op.to.clone());
        }
    }

    None
}
