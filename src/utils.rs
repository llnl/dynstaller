use std::{iter::repeat_with, path::PathBuf};

use anyhow::Result;
#[cfg(windows)]
use anyhow::bail;
#[cfg(windows)]
use windows::{
    Win32::{
        Foundation::ERROR_NO_MORE_FILES,
        System::{
            Diagnostics::ToolHelp::{
                CreateToolhelp32Snapshot, TH32CS_SNAPTHREAD, THREADENTRY32, Thread32First,
                Thread32Next,
            },
            Threading::{OpenThread, ResumeThread, THREAD_SUSPEND_RESUME},
        },
    },
    core::Owned,
};

#[cfg(windows)]
pub fn resume_process(pid: u32) -> Result<()> {
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

    let Some(tid) = tid else {
        bail!("No thread found for process ID {pid}")
    };

    let thread_handle = unsafe { Owned::new(OpenThread(THREAD_SUSPEND_RESUME, false, tid)?) };
    unsafe { ResumeThread(*thread_handle) };

    Ok(())
}

#[cfg(not(windows))]
pub fn resume_process(_pid: u32) -> Result<()> {
    Ok(())
}

pub fn create_temp_name() -> String {
    repeat_with(fastrand::alphabetic).take(10).collect()
}

pub fn create_temp_path(ext: Option<&str>) -> PathBuf {
    let temp_path = std::env::temp_dir();

    loop {
        let mut output_path = temp_path.join(create_temp_name());
        if let Some(extension) = ext {
            output_path.set_extension(extension);
        }
        if !output_path.exists() {
            return output_path;
        }
    }
}

#[derive(Debug)]
pub struct DropGuard<F: FnOnce()>(Option<F>);

impl<F: FnOnce()> DropGuard<F> {
    pub fn new(f: F) -> Self {
        DropGuard(Some(f))
    }
}

impl<F: FnOnce()> Drop for DropGuard<F> {
    fn drop(&mut self) {
        if let Some(f) = self.0.take() {
            f();
        }
    }
}
