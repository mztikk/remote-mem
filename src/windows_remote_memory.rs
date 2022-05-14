use std::ffi::c_void;
use windows::Win32::{
    Foundation::{CloseHandle, HANDLE},
    System::Diagnostics::Debug::ReadProcessMemory,
};
use winproc::{ModuleEntry, Process};

#[cfg(target_family = "windows")]
pub(crate) struct WindowsRemoteMemory {
    process: Process,
    process_id: u32,
    handle: HANDLE,
    pub base_module: ModuleEntry,
}

impl Drop for WindowsRemoteMemory {
    fn drop(&mut self) {
        unsafe {
            CloseHandle(self.handle);
        }
    }
}

#[derive(Debug)]
pub enum WindowsError {
    CoreError(windows::core::Error),
    WinProcError(winproc::Error),
    InvalidHandle,
    ReadByteError(*const c_void),
    NoModules,
}

impl From<windows::core::Error> for WindowsError {
    fn from(e: windows::core::Error) -> Self {
        WindowsError::CoreError(e)
    }
}

impl From<winproc::Error> for WindowsError {
    fn from(e: winproc::Error) -> Self {
        WindowsError::WinProcError(e)
    }
}

#[cfg(target_os = "windows")]
impl WindowsRemoteMemory {
    pub fn new(process_id: u32) -> Result<WindowsRemoteMemory, WindowsError> {
        use windows::Win32::System::Threading::{OpenProcess, PROCESS_ACCESS_RIGHTS};
        let process = Process::from_id(process_id)?;

        let handle = unsafe { OpenProcess(PROCESS_ACCESS_RIGHTS(0x1F0FFF), false, process_id)? };
        Ok(WindowsRemoteMemory {
            base_module: WindowsRemoteMemory::get_base_module(&process)?,
            process,
            process_id,
            handle,
        })

        // let handle =
        //     unsafe { OpenProcess(PROCESS_ACCESS_RIGHTS(0x1F0FFF), false, process_id) }.unwrap();
        // if unsafe { GetLastError() } == WIN32_ERROR(0) {
        //     return Ok(WindowsRemoteMemory { process_id, handle });
        // }

        // Err(std::io::Error::last_os_error())
    }

    pub fn new_by_name(process_name: &str) -> Result<WindowsRemoteMemory, WindowsError> {
        let process = Process::from_name(process_name)?;
        WindowsRemoteMemory::new(process.id())
    }

    fn read_mem(handle: HANDLE, address: usize, buffer: &mut [u8]) -> Result<(), WindowsError> {
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

        Err(WindowsError::ReadByteError(buffer_ptr))
    }

    pub fn read_bytes(&self, address: usize, buffer: &mut [u8]) -> Result<(), WindowsError> {
        WindowsRemoteMemory::read_mem(self.handle, address, buffer)
    }

    fn get_base_address(process: &Process) -> Result<usize, WindowsError> {
        WindowsRemoteMemory::get_base_module(process).map(|module| module.mod_base_addr as usize)
    }

    fn get_base_module(process: &Process) -> Result<ModuleEntry, WindowsError> {
        let mut modules = process.module_entries()?;
        match modules.next() {
            Some(module) => Ok(module),
            None => Err(WindowsError::NoModules),
        }
    }
}
