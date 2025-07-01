#![allow(dead_code)]

mod guard;
mod monitor;
mod options;
mod overlapped_future;
mod packer;
mod process;

use anyhow::Result;
use clap::{Parser, Subcommand, crate_authors, crate_description, crate_name};
use shadow_rs::shadow;
use tokio::process::Command;
use windows::Win32::System::Threading::CREATE_SUSPENDED;

use crate::{
    options::{HostOptions, LaunchOptions, MonitorOptions, PackerOptions, TrackOptions},
    packer::Packer,
    process::resume_process,
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

            let status = cmd.wait().await?;
            log::info!("Process finished with exit status {:?}.", status);

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
