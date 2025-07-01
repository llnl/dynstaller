use anyhow::{Result, bail};
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

    let tid = match tid {
        Some(tid) => tid,
        None => bail!("No thread found for process ID {}", pid),
    };

    let thread_handle = unsafe { Owned::new(OpenThread(THREAD_SUSPEND_RESUME, false, tid)?) };
    unsafe { ResumeThread(*thread_handle) };

    Ok(())
}
