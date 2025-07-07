use std::{
    env::consts::EXE_SUFFIX,
    ffi::OsStr,
    path::{Path, PathBuf},
};

use anyhow::{Result, bail};
use base64::{Engine, prelude::BASE64_URL_SAFE_NO_PAD};
use tokio::process::Command;
use windows::Win32::System::Threading::CREATE_NEW_CONSOLE;

use crate::{
    Cli, CommandType,
    monitor::procmon::ProcmonMonitor,
    options::{HostOptions, MonitorMethod, MonitorOptions, PackerOptions},
    utils::{create_temp_name, create_temp_path},
};

pub struct Hoster {
    packer_output: PathBuf,
    host_work_folder: PathBuf,
    wsb_configuration: xml::Configuration,
}

impl Hoster {
    pub fn new(
        mut options: HostOptions,
        mut monitor_options: MonitorOptions,
        packer_options: PackerOptions,
    ) -> Result<Self> {
        let mut configuration = xml::Configuration::default();

        let host_work_folder = create_temp_path(None);
        let sandbox_work_folder = Path::new("C:\\").join(create_temp_name());
        log::debug!("Using host work folder: {}", host_work_folder.display());
        std::fs::create_dir(&host_work_folder)?;
        log::debug!(
            "Mapping to sandbox work folder: {}",
            sandbox_work_folder.display()
        );
        configuration
            .mapped_folders
            .mapped_folders
            .push(xml::MappedFolder {
                host_folder: host_work_folder.to_string_lossy().to_string(),
                sandbox_folder: sandbox_work_folder.to_string_lossy().to_string(),
                read_only: false,
            });

        log::debug!("Copying self to work folder");
        let dynstaller_exe = format!("dynstaller{EXE_SUFFIX}");
        std::fs::copy(
            &std::env::current_exe()?,
            host_work_folder.as_path().join(&dynstaller_exe),
        )?;

        let cert_path = if let Some(cert_path) = &options.cert_path {
            log::debug!(
                "Copying certificate to work folder: {}",
                cert_path.display()
            );
            let ext = cert_path.extension().unwrap_or(OsStr::new("cer"));
            let cert_name = Path::new("cert").with_extension(ext);
            std::fs::copy(cert_path, host_work_folder.as_path().join(&cert_name))?;
            Some(sandbox_work_folder.join(&cert_name))
        } else {
            log::trace!("No certificate path provided, skipping certificate copy.");
            None
        };

        monitor_options.procmon_path = if matches!(monitor_options.method, MonitorMethod::Procmon) {
            log::debug!("Copying Procmon to work folder");
            let procmon_path = ProcmonMonitor::resolve_procmon_path(&monitor_options)?;
            let procmon_name = procmon_path
                .file_name()
                .unwrap_or(OsStr::new("Procmon.exe"));
            std::fs::copy(&procmon_path, host_work_folder.as_path().join(procmon_name))?;
            Some(sandbox_work_folder.join(procmon_name))
        } else {
            log::trace!("Monitor method is not Procmon, skipping Procmon copy.");
            None
        };

        // Canonicalize the process path and get the file name
        // NOTE: This will dereference symlinks, which can affect share_process_folder behavior!
        options.launch_options.process = options.launch_options.process.canonicalize()?;
        let process_name = options.launch_options.process.file_name().ok_or_else(|| {
            anyhow::anyhow!(
                "Failed to get file name of the process: {}",
                options.launch_options.process.display()
            )
        })?;

        // Copy the process to the work folder
        // If share_process_folder is enabled, we will map the parent folder instead
        let sandbox_process: PathBuf = if options.share_process_folder {
            let process_folder = options.launch_options.process.parent().ok_or_else(|| {
                anyhow::anyhow!(
                    "Failed to get parent directory of the process: {}",
                    options.launch_options.process.display()
                )
            })?;
            let sandbox_process_folder = Path::new("C:\\").join(create_temp_name());

            log::debug!("Using process folder: {}", process_folder.display());
            configuration
                .mapped_folders
                .mapped_folders
                .push(xml::MappedFolder {
                    host_folder: process_folder.to_string_lossy().to_string(),
                    sandbox_folder: sandbox_work_folder.to_string_lossy().to_string(),
                    read_only: !options.writable_process_folder,
                });
            sandbox_process_folder.join(process_name)
        } else {
            log::debug!(
                "Copying process to work folder: {}",
                host_work_folder.join(process_name).display()
            );
            std::fs::copy(
                &options.launch_options.process,
                host_work_folder.as_path().join(process_name),
            )?;
            sandbox_work_folder.join(process_name)
        };

        // Setup the launch script
        configuration.logon_command.command = format!(
            "powershell.exe -ExecutionPolicy Bypass -NoProfile -File {}",
            sandbox_work_folder.join("launch.ps1").display()
        );

        log::debug!("Setting up WSB options");
        if options.no_vgpu {
            configuration.vgpu = xml::OptionValue::Disable;
        }
        if options.no_network {
            configuration.networking = xml::OptionValue::Disable;
        }
        if options.isolated {
            configuration.protected_client = xml::OptionValue::Enable;
        }
        if let Some(memory) = options.memory {
            configuration.memory_in_mb = Some(memory);
        }

        options.launch_options.process = sandbox_process;
        options.launch_options.shutdown_on_exit = true;

        let mut launch_packer_options = packer_options.clone();
        launch_packer_options.overwrite = false;
        launch_packer_options.output = sandbox_work_folder.join("output.zip");

        let launch_args = Cli {
            command: CommandType::GuestLaunch(options.launch_options),
            packer_options: launch_packer_options,
            monitor_options,
        };
        let launch_var = BASE64_URL_SAFE_NO_PAD.encode(serde_json::to_vec(&launch_args)?);

        log::debug!("Creating launch script");
        let mut launch_script: Vec<String> = vec![];
        if let Some(cert_path) = cert_path {
            launch_script.extend_from_slice(&[
                format!("$rootCertPath = {cert_path:?}"),
                "$rootCert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2".to_string(),
                "$rootCert.Import($rootCertPath)".to_string(),
                "$certStore = New-Object System.Security.Cryptography.X509Certificates.X509Store(\"Root\", \"LocalMachine\")".to_string(),
                "$certStore.Open(\"ReadWrite\")".to_string(),
                "$certStore.Add($rootCert)".to_string(),
                "$certStore.Close()".to_string()
            ]);
        }
        if options.delay > 0 {
            launch_script.push(format!("Start-Sleep -Seconds {}", options.delay));
        }
        launch_script.push(format!("$env:DYNSTALLER_ARGS = '{launch_var}'"));
        launch_script.push(format!(
            "Start-Process {}",
            sandbox_work_folder.join(&dynstaller_exe).display()
        ));
        std::fs::write(
            host_work_folder.join("launch.ps1"),
            launch_script.join("\n"),
        )?;

        Ok(Self {
            packer_output: packer_options.output,
            host_work_folder,
            wsb_configuration: configuration,
        })
    }

    pub async fn run(&mut self) -> Result<()> {
        let wsb_path = create_temp_path(Some("wsb"));
        let wsb_file = wsb_path.with_extension("wsb");
        let xml_content = serde_xml_rs::to_string(&self.wsb_configuration)?;
        std::fs::write(&wsb_file, xml_content)?;

        log::info!(
            "Creating Windows Sandbox configuration file: {}",
            wsb_file.display()
        );
        let mut cmd = Command::new("C:\\Windows\\System32\\WindowsSandbox.exe");

        cmd.arg(wsb_file);

        cmd.creation_flags(CREATE_NEW_CONSOLE.0);

        log::info!("Starting Windows Sandbox...");

        let mut cmd = cmd.spawn()?;
        let result = cmd.wait().await?;
        if result.success() {
            log::info!("Windows Sandbox completed successfully.");
        } else {
            bail!("Windows Sandbox exited with a non-zero status: {result:?}");
        }

        std::fs::copy(
            self.host_work_folder.join("output.zip"),
            &self.packer_output,
        )?;
        // TODO: Write to log and copy log

        Ok(())
    }
}

mod xml {
    use serde::Serialize;

    #[derive(Debug, Serialize, Default)]
    #[serde(rename_all = "PascalCase")]
    pub struct Configuration {
        pub mapped_folders: MappedFolders,
        pub logon_command: LogonCommand,
        #[serde(rename = "vGPU")]
        #[serde(skip_serializing_if = "OptionValue::is_default")]
        pub vgpu: OptionValue,
        #[serde(skip_serializing_if = "OptionValue::is_default")]
        pub networking: OptionValue,
        #[serde(skip_serializing_if = "OptionValue::is_default")]
        pub audio_input: OptionValue,
        #[serde(skip_serializing_if = "OptionValue::is_default")]
        pub video_input: OptionValue,
        #[serde(skip_serializing_if = "OptionValue::is_default")]
        pub protected_client: OptionValue,
        #[serde(skip_serializing_if = "OptionValue::is_default")]
        pub printer_redirection: OptionValue,
        #[serde(skip_serializing_if = "OptionValue::is_default")]
        pub clipboard_redirection: OptionValue,
        #[serde(rename = "MemoryInMB")]
        #[serde(skip_serializing_if = "Option::is_none")]
        pub memory_in_mb: Option<u64>,
    }

    #[derive(Debug, Serialize, Default)]
    pub struct MappedFolders {
        #[serde(rename = "MappedFolder", default)]
        pub mapped_folders: Vec<MappedFolder>,
    }

    #[derive(Debug, Serialize)]
    #[serde(rename_all = "PascalCase")]
    pub struct MappedFolder {
        pub host_folder: String,
        pub sandbox_folder: String,
        pub read_only: bool,
    }

    #[derive(Debug, Serialize, Default)]
    #[serde(rename_all = "PascalCase")]
    pub struct LogonCommand {
        pub command: String,
    }

    #[derive(Debug, Serialize, Clone, Copy, PartialEq, Eq, Default)]
    #[serde(rename_all = "PascalCase")]
    pub enum OptionValue {
        Enable,
        Disable,
        #[default]
        Default,
    }

    impl OptionValue {
        pub fn is_default(&self) -> bool {
            matches!(self, OptionValue::Default)
        }
    }
}
