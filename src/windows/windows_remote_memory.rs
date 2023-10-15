use std::ffi::c_void;
use thiserror::Error;
use windows::Win32::{
    Foundation::{CloseHandle, HANDLE},
    System::Diagnostics::Debug::{ReadProcessMemory, WriteProcessMemory},
};
use winproc::{ModuleEntry, Process};

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
    #[error("Failed to read {0} bytes from memory at address {1:X}")]
    ReadMemoryError(usize, usize),
    #[error("Failed to write {0} bytes to memory at address {1:X}")]
    WriteMemoryError(usize, usize),
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
    if handle.is_invalid() {
        return Err(WindowsError::InvalidHandle);
    }

    if buffer.is_empty() {
        return Ok(());
    }

    let num_bytes_to_read = buffer.len();

    let num_bytes_read: Option<*mut usize> = None;
    let buffer_ptr = buffer.as_mut_ptr() as *mut c_void;
    match unsafe {
        ReadProcessMemory(
            handle,
            address as *mut c_void,
            buffer_ptr,
            num_bytes_to_read,
            num_bytes_read,
        )
    } {
        Ok(_) if num_bytes_read.is_some_and(|x| unsafe { *x == num_bytes_to_read }) => Ok(()),
        _ => Err(WindowsError::ReadMemoryError(
            num_bytes_to_read,
            buffer_ptr as usize,
        )),
    }
}

pub fn write_process_memory(
    handle: HANDLE,
    address: usize,
    bytes: usize,
    num_bytes_to_write: usize,
) -> Result<(), WindowsError> {
    if handle.is_invalid() {
        return Err(WindowsError::InvalidHandle);
    }

    let num_bytes_written: Option<*mut usize> = None;
    let bytes_ptr = bytes as *const c_void;

    match unsafe {
        WriteProcessMemory(
            handle,
            address as *mut c_void,
            bytes_ptr,
            num_bytes_to_write,
            num_bytes_written,
        )
    } {
        Ok(_) if num_bytes_written.is_some_and(|x| unsafe { *x == num_bytes_to_write }) => Ok(()),
        _ => Err(WindowsError::ReadMemoryError(
            num_bytes_to_write,
            bytes_ptr as usize,
        )),
    }
}

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

    pub fn write_ptr(
        &self,
        address: usize,
        ptr: usize,
        num_bytes_to_write: usize,
    ) -> Result<(), WindowsError> {
        write_process_memory(self.handle, address, ptr, num_bytes_to_write)
    }
}
