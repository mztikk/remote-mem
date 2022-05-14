use std::ffi::c_void;
use thiserror::Error;
use windows::Win32::{
    Foundation::{CloseHandle, HANDLE},
    System::Diagnostics::Debug::ReadProcessMemory,
};
use winproc::{ModuleEntry, Process};

#[cfg(target_family = "windows")]
pub struct WindowsRemoteMemory {
    pub process: Process,
    pub process_id: u32,
    pub handle: HANDLE,
    pub base_module: ModuleEntry,
}

impl Drop for WindowsRemoteMemory {
    fn drop(&mut self) {
        unsafe {
            CloseHandle(self.handle);
        }
    }
}

#[derive(Debug, Error)]
pub enum WindowsError {
    #[error("{0}")]
    CoreError(String),
    #[error("{0}")]
    OsError(#[from] std::io::Error),
    #[error("{0}")]
    ProcessNotFound(String),
    #[error("{0}")]
    InvalidProcessName(String),
    #[error("Handle to process is invalid")]
    InvalidHandle,
    #[error("Failed to read memory at address {0:X}")]
    ReadMemoryError(usize),
    #[error("Process has no modules loaded")]
    NoModules,
}

impl From<windows::core::Error> for WindowsError {
    fn from(e: windows::core::Error) -> Self {
        WindowsError::CoreError(e.message().to_string())
    }
}

impl From<winproc::Error> for WindowsError {
    fn from(e: winproc::Error) -> Self {
        match e {
            winproc::Error::Os(e) => WindowsError::OsError(e),
            winproc::Error::NoProcess(e) => WindowsError::ProcessNotFound(e),
            winproc::Error::NulError(e) => WindowsError::InvalidProcessName(e.to_string()),
            winproc::Error::NulErrorW { pos, data } => WindowsError::InvalidProcessName(format!(
                "Invalid UTF-16 character at position {}: {:?}",
                pos, data
            )),
        }
    }
}

pub fn get_base_address(process: &Process) -> Result<usize, WindowsError> {
    get_base_module(process).map(|module| module.mod_base_addr as usize)
}

pub fn get_base_module(process: &Process) -> Result<ModuleEntry, WindowsError> {
    let mut modules = process.module_entries()?;
    match modules.next() {
        Some(module) => Ok(module),
        None => Err(WindowsError::NoModules),
    }
}

pub fn read_process_memory(
    handle: HANDLE,
    address: usize,
    buffer: &mut [u8],
) -> Result<(), WindowsError> {
    use windows::Win32::Foundation::BOOL;

    if handle.is_invalid() {
        return Err(WindowsError::InvalidHandle);
    }

    if buffer.is_empty() {
        return Ok(());
    }

    let mut num_bytes_read: usize = 0;
    let buffer_ptr = buffer.as_mut_ptr() as *mut c_void;
    if unsafe {
        ReadProcessMemory(
            handle,
            address as *mut c_void,
            buffer_ptr,
            buffer.len(),
            &mut num_bytes_read,
        )
    } == BOOL(1)
        && buffer.len() == num_bytes_read
    {
        return Ok(());
    }

    Err(WindowsError::ReadMemoryError(buffer_ptr as usize))
}

#[cfg(target_os = "windows")]
impl WindowsRemoteMemory {
    pub fn new(process_id: u32) -> Result<WindowsRemoteMemory, WindowsError> {
        use windows::Win32::System::Threading::{OpenProcess, PROCESS_ACCESS_RIGHTS};
        let process = Process::from_id(process_id)?;

        let handle = unsafe { OpenProcess(PROCESS_ACCESS_RIGHTS(0x1F0FFF), false, process_id)? };
        Ok(WindowsRemoteMemory {
            base_module: get_base_module(&process)?,
            process,
            process_id,
            handle,
        })
    }

    pub fn new_by_name(process_name: &str) -> Result<WindowsRemoteMemory, WindowsError> {
        let process = Process::from_name(process_name)?;
        WindowsRemoteMemory::new(process.id())
    }

    pub fn read_bytes(&self, address: usize, buffer: &mut [u8]) -> Result<(), WindowsError> {
        read_process_memory(self.handle, address, buffer)
    }
}
