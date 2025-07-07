use std::{
    pin::Pin,
    sync::{Arc, RwLock},
    task::{Context, Poll},
};

use windows::{
    Win32::{
        Foundation::{ERROR_IO_INCOMPLETE, HANDLE, STATUS_PENDING},
        System::{
            IO::{CancelIoEx, GetOverlappedResultEx, OVERLAPPED},
            Threading::{CreateEventW, ResetEvent},
        },
    },
    core::{Error, Owned, Result},
};

#[derive(Debug, Default)]
enum OverlappedStatus {
    #[default]
    Pending,
    Ok {
        bytes_transferred: u32,
    },
    Err {
        error: Error,
        bytes_transferred: u32,
    },
}

#[derive(Clone)]
pub struct OverlappedFuture(Arc<RwLock<OverlappedFutureImpl>>);

struct OverlappedFutureImpl {
    data: Arc<OverlappedData>,
    event: Owned<HANDLE>,
    status: OverlappedStatus,
}

unsafe impl Send for OverlappedFutureImpl {}
unsafe impl Sync for OverlappedFutureImpl {}

struct OverlappedData {
    handle: HANDLE,
    overlapped: Pin<Box<OVERLAPPED>>,
}

unsafe impl Send for OverlappedData {}
unsafe impl Sync for OverlappedData {}

impl OverlappedFuture {
    pub fn new(handle: HANDLE, event: Owned<HANDLE>) -> Self {
        Self(Arc::new(RwLock::new(OverlappedFutureImpl {
            data: Arc::new(OverlappedData::new(handle, &event)),
            event,
            status: OverlappedStatus::Pending,
        })))
    }

    fn create_event() -> Result<Owned<HANDLE>> {
        Ok(unsafe { Owned::new(CreateEventW(None, true, false, None)?) })
    }

    pub fn create_overlapped(handle: HANDLE) -> Result<Self> {
        Ok(Self::new(handle, Self::create_event()?))
    }

    pub fn overlapped(&self) -> *const OVERLAPPED {
        self.0.read().unwrap().data.overlapped()
    }

    pub fn bytes_transferred(&self) -> Option<u32> {
        match self.0.read().unwrap().status {
            OverlappedStatus::Ok { bytes_transferred }
            | OverlappedStatus::Err {
                bytes_transferred, ..
            } => Some(bytes_transferred),
            OverlappedStatus::Pending => None,
        }
    }

    pub fn cancel(&self) -> Result<()> {
        self.0.write().unwrap().data.cancel()
    }

    pub fn reset(&self) -> Result<()> {
        let mut this = self.0.write().unwrap();

        // Cancel any outstanding operation on the old OverlappedData
        let _ = this.data.cancel();

        unsafe { ResetEvent(*this.event) }?;

        this.status = OverlappedStatus::Pending;
        this.data = Arc::new(OverlappedData::new(this.data.handle, &this.event));

        Ok(())
    }
}

impl OverlappedData {
    fn new(handle: HANDLE, event: &Owned<HANDLE>) -> Self {
        Self {
            handle,
            overlapped: Box::pin(OVERLAPPED {
                hEvent: **event,
                ..Default::default()
            }),
        }
    }

    fn overlapped(&self) -> *const OVERLAPPED {
        std::ptr::from_ref(self.overlapped.as_ref().get_ref())
    }

    // https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-hasoverlappediocompleted
    fn is_completed(&self) -> bool {
        self.overlapped
            .Internal
            .try_into()
            .map(|v: i32| v != STATUS_PENDING.0)
            .unwrap_or(true)
    }

    fn get_result(&self) -> (Result<()>, u32) {
        let mut bytes_transferred = 0u32;
        let result = unsafe {
            GetOverlappedResultEx(
                self.handle,
                self.overlapped(),
                &raw mut bytes_transferred,
                0,
                false,
            )
        };
        (result, bytes_transferred)
    }

    fn cancel(&self) -> Result<()> {
        unsafe { CancelIoEx(self.handle, Some(self.overlapped())) }
    }
}

impl Future for OverlappedFuture {
    type Output = Result<u32>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let mut this = self.0.write().unwrap();
        match &this.status {
            OverlappedStatus::Ok { bytes_transferred } => Poll::Ready(Ok(*bytes_transferred)),
            OverlappedStatus::Err { error, .. } => Poll::Ready(Err(error.clone())),
            OverlappedStatus::Pending if !this.data.is_completed() => {
                cx.waker().wake_by_ref();
                Poll::Pending
            }
            OverlappedStatus::Pending => match this.data.get_result() {
                (Ok(()), bytes_transferred) => {
                    this.status = OverlappedStatus::Ok { bytes_transferred };
                    Poll::Ready(Ok(bytes_transferred))
                }
                (Err(e), _) if e.code() == ERROR_IO_INCOMPLETE.into() => {
                    cx.waker().wake_by_ref();
                    Poll::Pending
                }
                (Err(e), bytes_transferred) => {
                    this.status = OverlappedStatus::Err {
                        error: e.clone(),
                        bytes_transferred,
                    };
                    Poll::Ready(Err(e))
                }
            },
        }
    }
}

impl Drop for OverlappedFutureImpl {
    fn drop(&mut self) {
        if !self.data.is_completed() {
            if let Err(e) = self.data.cancel() {
                log::error!("Failed to cancel overlapped operation: {e:?}");
            }
        }
    }
}
