#![allow(dead_code)]

mod guard;
mod monitor;
mod options;
mod overlapped_future;
mod packer;

use anyhow::Result;
use clap::{Parser, ValueEnum, crate_authors, crate_description, crate_name};
use shadow_rs::shadow;

use crate::{
    monitor::{Monitor, procmon::ProcmonMonitor, usn::UsnMonitor, winapi::WinApiMonitor},
    options::{MonitorMethod, MonitorOptions, PackerOptions},
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
    #[arg()]
    command: CommandType,
    #[command(flatten)]
    monitor_options: MonitorOptions,
    #[command(flatten)]
    packer_options: PackerOptions,
}

#[derive(ValueEnum, Debug, Clone, Copy)]
enum CommandType {
    /// Launches the specified executable with optionally provided arguments.
    /// This command is intended to be run on the guest system (i.e. a VM).
    GuestLaunch,
    /// Tracks file and registry changes on the host system without launching any executable.
    /// This command is intended to be run on the guest system (i.e. a VM).
    GuestTrack,
    /// Launches a Windows Sandbox VM and runs the specified executable with optionally provided arguments.
    /// The executable will be launched in a Windows Sandbox VM with the specified options.
    /// This command is intended to be run on the host system.
    HostLaunch,
}

#[tokio::main]
async fn main() -> Result<()> {
    env_logger::init_from_env(env_logger::Env::new().default_filter_or("debug"));

    let cli = Cli::parse();
    match cli.command {
        CommandType::GuestLaunch => {
            todo!()
        }
        CommandType::GuestTrack => {
            let monitor_options = cli.monitor_options.clone();
            let mut monitor: Box<dyn Monitor> = match monitor_options.method {
                MonitorMethod::Usn => Box::new(<UsnMonitor as Monitor>::new(monitor_options)?),
                MonitorMethod::WinApi => {
                    Box::new(<WinApiMonitor as Monitor>::new(monitor_options)?)
                }
                MonitorMethod::Procmon => Box::new(ProcmonMonitor::new(monitor_options)?),
            };
            log::info!("{}", cli.monitor_options.child_processes);

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
        CommandType::HostLaunch => {
            todo!()
        }
    }
}
