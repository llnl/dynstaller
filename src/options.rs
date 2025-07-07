use std::path::PathBuf;

use clap::{Args, ValueEnum};
use serde::{Deserialize, Serialize};

#[derive(Args, Serialize, Deserialize, Debug, Clone)]
pub struct MonitorOptions {
    /// The method to use for monitoring file changes.
    #[arg(value_enum)]
    pub method: MonitorMethod,
    /// The path to monitor for changes.
    /// If using host launch, this is the path on the guest system.
    #[arg(long, short, default_value = "C:\\")]
    pub path: PathBuf,

    /// Tracks creation of files and directories.
    #[arg(long = "create", short = 'c')]
    pub creation: bool,
    /// Tracks deletion of files and directories.
    #[arg(long = "delete", short = 'd')]
    pub deletion: bool,
    /// Tracks modification of files and directories.
    #[arg(long = "modify", short = 'm')]
    pub modification: bool,
    /// Tracks the renaming of files and directories.
    #[arg(long = "rename", short = 'r')]
    pub renaming: bool,
    /// Additionally registry changes based on the previous options.
    /// This option is only supported by the Procmon method.
    #[arg(long = "registry", short = 'R')]
    pub add_registry: bool,

    /// The path to the Procmon executable. If not specified, it will be downloaded automatically.
    /// If not provided, the PATH will be searched for `Procmon64.exe`.
    #[arg(long = "procmon")]
    pub procmon_path: Option<PathBuf>,
}

#[derive(Args, Serialize, Deserialize, Debug, Clone)]
pub struct TrackOptions {
    /// The process ID to filter changes by. If not specified, all processes will be monitored.
    /// This option is only supported by the Procmon method.
    #[arg(long)]
    pub pid: Option<u32>,
    /// Don't track child processes of the specified PID.
    /// This option is only supported by the Procmon method.
    #[arg(long = "children", requires = "pid")]
    pub no_children: bool,
}

#[derive(Args, Serialize, Deserialize, Debug, Clone)]
pub struct LaunchOptions {
    /// The path to the executable to launch.
    pub process: PathBuf,
    /// The arguments to pass to the executable.
    #[arg(trailing_var_arg = true)]
    pub args: Vec<String>,
    /// Don't track child processes of the specified PID.
    /// This option is only supported by the Procmon method.
    #[arg(long = "children")]
    pub no_children: bool,
    #[arg(skip)]
    pub shutdown_on_exit: bool,
}

#[derive(Args, Serialize, Deserialize, Debug, Clone)]
pub struct HostOptions {
    #[command(flatten)]
    pub launch_options: LaunchOptions,
    /// Share the entire folder that contains the executable with the Windows Sandbox VM.
    /// This will allow the VM to access the executable and any possible dependencies it may have.
    #[arg(short)]
    pub share_process_folder: bool,
    /// Allows write access to the folder that contains the executable in the Windows Sandbox VM.
    #[arg(short, requires = "share_process_folder")]
    pub writable_process_folder: bool,
    /// Adds a root certificate to the Windows Sandbox VM.
    /// Supports both PEM and DER formats.
    #[arg(long)]
    pub cert_path: Option<PathBuf>,
    /// The amount of time to delay launching & tracking. This is useful to prevent capturing startup events/cruft.
    /// Defaults to 5 seconds.
    #[arg(long, default_value = "5")]
    pub delay: u64,
    /// Disables the vGPU in the Windows Sandbox VM.
    #[arg(long)]
    pub no_vgpu: bool,
    /// Disables networking in the Windows Sandbox VM.
    #[arg(long)]
    pub no_network: bool,
    /// Runs the VM in Protected Client mode using AppContainer Isolation.
    #[arg(long)]
    pub isolated: bool,
    /// The amount of memory to allocate to the Windows Sandbox VM in MiB.
    #[arg(long)]
    pub memory: Option<u64>,
}

#[derive(ValueEnum, Serialize, Deserialize, Debug, Clone, Copy)]
pub enum MonitorMethod {
    /// Uses the NTFS USN journal to monitor file changes. This method is the most efficient and has the least overhead.
    /// Can only track files in NTFS volumes. This method only tracks actual disk changes, not file system events.
    /// Does not support registry changes or PID filtering.
    Usn,
    /// Uses the Windows API (`ReadDirectoryChangesEx`) to monitor file changes. This is the only method that can be
    /// run without administrator privileges.
    /// Does not support registry changes or PID filtering.
    #[value(name = "winapi")]
    WinApi,
    /// Uses Process Monitor to track changes. This method takes significantly longer to start and process, but it
    /// provides the most comprehensive results.
    /// The only method to support registry changes and PID filtering.
    Procmon,
}

#[derive(Args, Serialize, Deserialize, Debug, Clone)]
pub struct PackerOptions {
    /// The output zip file where the changes will be written.
    pub output: PathBuf,
    /// If the output file already exists, it will be overwritten.
    #[arg(long, short = 'o')]
    pub overwrite: bool,
    /// Changed files greater than this size will not be included (they will still be tracked).
    /// Defaults to 256 MiB.
    #[arg(long, default_value = "268435456")]
    pub size_limit: u64,
}
