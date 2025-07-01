use std::path::PathBuf;

use clap::{Args, ValueEnum};
use serde::Serialize;

#[derive(Args, Serialize, Debug, Clone)]
pub struct MonitorOptions {
    /// The method to use for monitoring file changes.
    #[arg(value_enum)]
    pub method: MonitorMethod,
    /// The path to monitor for changes.
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

    /// The process ID to filter changes by. If not specified, all processes will be monitored.
    /// This option is only supported by the Procmon method.
    #[arg(long)]
    pub pid: Option<u32>,
    /// If true, child processes of the specified PID will also be monitored.
    /// This option is only supported by the Procmon method.
    /// Defaults to true.
    #[arg(long = "children", default_value = "true")]
    pub child_processes: bool,
}

#[derive(ValueEnum, Serialize, Debug, Clone, Copy)]
pub enum MonitorMethod {
    /// Uses the NTFS USN journal to monitor file changes. This method is the most efficient and has the least overhead.
    /// Can only track files in NTFS volumes. This method only tracks actual disk changes, not file system events.
    /// Does not support registry changes or PID filtering.
    Usn,
    /// Uses the Windows API (ReadDirectoryChangesEx) to monitor file changes. This is the only method that can be
    /// run without administrator privileges.
    /// Does not support registry changes or PID filtering.
    #[value(name = "winapi")]
    WinApi,
    /// Uses Process Monitor to track changes. This method takes significantly longer to start and process, but it
    /// provides the most comprehensive results.
    /// The only method to support registry changes and PID filtering.
    Procmon,
}

#[derive(Args, Serialize, Debug, Clone)]
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
