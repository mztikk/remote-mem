use robs::{scanner, signature::Signature};
use windows_remote_memory::WindowsRemoteMemory;

mod windows_remote_memory;

pub struct RemoteMemory {
    #[cfg(target_family = "windows")]
    windows_remote_memory: WindowsRemoteMemory,
}

#[derive(Debug)]
pub enum RemoteMemoryError {
    WindowsError(windows_remote_memory::WindowsError),
    OsNotSupported,
}

impl From<windows_remote_memory::WindowsError> for RemoteMemoryError {
    fn from(e: windows_remote_memory::WindowsError) -> Self {
        RemoteMemoryError::WindowsError(e)
    }
}

impl RemoteMemory {
    pub fn new(process_id: u32) -> Result<RemoteMemory, RemoteMemoryError> {
        if cfg!(target_family = "windows") {
            Ok(RemoteMemory {
                windows_remote_memory: WindowsRemoteMemory::new(process_id)?,
            })
        } else {
            Err(RemoteMemoryError::OsNotSupported)
        }
    }

    pub fn new_by_name(process_name: &str) -> Result<RemoteMemory, RemoteMemoryError> {
        if cfg!(target_family = "windows") {
            Ok(RemoteMemory {
                windows_remote_memory: WindowsRemoteMemory::new_by_name(process_name)?,
            })
        } else {
            Err(RemoteMemoryError::OsNotSupported)
        }
    }

    pub fn read_bytes(&self, address: usize, buffer: &mut [u8]) -> Result<(), RemoteMemoryError> {
        if cfg!(target_family = "windows") {
            Ok(self.windows_remote_memory.read_bytes(address, buffer)?)
        } else {
            Err(RemoteMemoryError::OsNotSupported)
        }
    }

    pub fn read<T: Sized + Copy>(&self, address: usize) -> Result<T, RemoteMemoryError> {
        let size = std::mem::size_of::<T>();
        let mut buffer: Vec<u8> = vec![0; size];
        self.read_bytes(address, &mut buffer)?;
        Ok(unsafe { (buffer.as_ptr() as *const T).read_unaligned() })
    }

    #[cfg(target_family = "windows")]
    pub fn get_base_address(&self) -> usize {
        self.windows_remote_memory.base_module.mod_base_addr as usize
    }

    #[cfg(target_family = "windows")]
    pub fn get_base_size(&self) -> usize {
        self.windows_remote_memory.base_module.mod_base_size as usize
    }

    pub fn find_signature(&self, signature: &Signature) -> Option<usize> {
        let base_address = self.get_base_address();
        let base_size = self.get_base_size();
        let mut buffer = vec![0; base_size];
        self.read_bytes(base_address, &mut buffer).ok()?;
        scanner::find_signature(&buffer, signature)
    }
}
