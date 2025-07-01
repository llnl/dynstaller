#![allow(dead_code)]

mod guard;
mod monitor;
mod options;
mod overlapped_future;
mod packer;

use anyhow::{Result, bail};
use clap::{Parser, Subcommand, crate_authors, crate_description, crate_name};
use shadow_rs::shadow;
use tokio::{io::AsyncBufReadExt, process::Command};
use windows::{
    Win32::{
        Foundation::ERROR_NO_MORE_FILES,
        System::{
            Diagnostics::ToolHelp::{
                CreateToolhelp32Snapshot, TH32CS_SNAPTHREAD, THREADENTRY32, Thread32First,
                Thread32Next,
            },
            Threading::{CREATE_SUSPENDED, OpenThread, ResumeThread, THREAD_SUSPEND_RESUME},
        },
    },
    core::Owned,
};

use crate::{
    options::{HostOptions, LaunchOptions, MonitorOptions, PackerOptions, TrackOptions},
    packer::Packer,
};

shadow!(build);

#[derive(Parser)]
#[command(name = crate_name!())]
#[command(version = build::CLAP_LONG_VERSION)]
#[command(author = crate_authors!())]
#[command(about = crate_description!())]
#[command(args_override_self = true)]
struct Cli {
    #[command(subcommand)]
    command: CommandType,
    #[command(flatten)]
    monitor_options: MonitorOptions,
    #[command(flatten)]
    packer_options: PackerOptions,
}

#[derive(Subcommand, Debug, Clone)]
enum CommandType {
    /// Launches the specified executable with optionally provided arguments.
    /// This command is intended to be run on the guest system (i.e. a VM).
    GuestLaunch(#[command(flatten)] LaunchOptions),
    /// Tracks file and registry changes on the host system without launching any executable.
    /// This command is intended to be run on the guest system (i.e. a VM).
    GuestTrack(#[command(flatten)] TrackOptions),
    /// Launches a Windows Sandbox VM and runs the specified executable with optionally provided arguments.
    /// The executable will be launched in a Windows Sandbox VM with the specified options.
    /// This command is intended to be run on the host system.
    HostLaunch(#[command(flatten)] HostOptions),
}

#[tokio::main]
async fn main() -> Result<()> {
    env_logger::init_from_env(env_logger::Env::new().default_filter_or("debug"));

    let cli = Cli::parse();
    match cli.command {
        CommandType::GuestLaunch(launch_options) => {
            log::info!("Launching process: {}", launch_options.process.display());
            let mut cmd = Command::new(&launch_options.process);
            cmd.args(launch_options.args)
                .creation_flags(CREATE_SUSPENDED.0);
            let mut cmd = cmd.spawn()?;

            let pid = cmd.id();
            log::info!("Process launched with PID: {:?}", pid);

            let track_options = TrackOptions {
                pid,
                child_processes: launch_options.child_processes,
            };
            let mut monitor = monitor::new_boxed(cli.monitor_options.clone(), track_options)?;
            monitor.start().await?;
            log::info!("Monitoring started.");

            if let Some(pid) = pid {
                resume_process(pid)?;
                log::info!("Began execution on launched process.");
            }

            log::info!("Press Enter to stop monitoring early...");
            let mut stdin = tokio::io::BufReader::new(tokio::io::stdin()).lines();
            tokio::select! {
                _ = stdin.next_line() => {
                    cmd.start_kill()?;
                    log::info!("Sending SIGKILL.");
                }
                status = cmd.wait() => {
                    log::info!("Process finished with exit status {:?}.", status?);
                }
            }

            log::info!("Stopping monitoring...");
            monitor.stop().await?;

            log::info!("Monitoring stopped.");
            log::info!("Writing results...");
            let packer = Packer::new(cli.monitor_options, cli.packer_options, monitor);
            packer.write_out()?;

            log::info!("Results written successfully.");
            Ok(())
        }
        CommandType::GuestTrack(track_options) => {
            let mut monitor = monitor::new_boxed(cli.monitor_options.clone(), track_options)?;
            monitor.start().await?;

            log::info!("Monitoring started.");
            log::info!("Press Enter to stop monitoring...");
            std::io::stdin().read_line(&mut String::new())?;

            log::info!("Stopping monitoring...");
            monitor.stop().await?;

            log::info!("Monitoring stopped.");
            log::info!("Writing results...");
            let packer = Packer::new(cli.monitor_options, cli.packer_options, monitor);
            packer.write_out()?;

            log::info!("Results written successfully.");
            Ok(())
        }
        CommandType::HostLaunch(_host_options) => {
            todo!()
        }
    }
}

fn resume_process(pid: u32) -> Result<()> {
    let snapshot = unsafe { Owned::new(CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, pid)?) };

    let mut te = THREADENTRY32 {
        dwSize: std::mem::size_of::<THREADENTRY32>() as u32,
        ..Default::default()
    };

    unsafe { Thread32First(*snapshot, &mut te) }?;

    let mut tid = None;
    loop {
        if te.th32OwnerProcessID == pid {
            tid = Some(te.th32ThreadID);
        }
        let result = unsafe { Thread32Next(*snapshot, &mut te) };
        if let Err(e) = result {
            if e.code() == ERROR_NO_MORE_FILES.to_hresult() {
                break;
            }
            bail!(e);
        }
    }

    let tid = match tid {
        Some(tid) => tid,
        None => bail!("No thread found for process ID {}", pid),
    };

    let thread_handle = unsafe { Owned::new(OpenThread(THREAD_SUSPEND_RESUME, false, tid)?) };
    unsafe { ResumeThread(*thread_handle) };

    Ok(())
}
