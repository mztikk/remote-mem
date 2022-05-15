use robs::{scanner, signature::Signature};
use thiserror::Error;

#[cfg(target_family = "windows")]
pub mod windows;

pub struct RemoteMemory {
    #[cfg(target_family = "windows")]
    windows_remote_memory: windows::windows_remote_memory::WindowsRemoteMemory,
}

#[derive(Debug, Error)]
pub enum RemoteMemoryError {
    #[cfg(target_family = "windows")]
    #[error("{0}")]
    WindowsError(windows::windows_remote_memory::WindowsError),
    #[error("'{0}' OS is not supported")]
    OsNotSupported(String),
}

#[cfg(target_family = "windows")]
impl From<windows::windows_remote_memory::WindowsError> for RemoteMemoryError {
    fn from(e: windows::windows_remote_memory::WindowsError) -> Self {
        RemoteMemoryError::WindowsError(e)
    }
}

#[cfg(target_family = "windows")]
impl RemoteMemory {
    pub fn new(process_id: u32) -> Result<RemoteMemory, RemoteMemoryError> {
        Ok(RemoteMemory {
            windows_remote_memory: windows::windows_remote_memory::WindowsRemoteMemory::new(
                process_id,
            )?,
        })
    }

    pub fn new_by_name(process_name: &str) -> Result<RemoteMemory, RemoteMemoryError> {
        Ok(RemoteMemory {
            windows_remote_memory:
                windows::windows_remote_memory::WindowsRemoteMemory::new_by_name(process_name)?,
        })
    }

    pub fn read_bytes(&self, address: usize, buffer: &mut [u8]) -> Result<(), RemoteMemoryError> {
        Ok(self.windows_remote_memory.read_bytes(address, buffer)?)
    }

    pub fn write_ptr(
        &self,
        address: usize,
        ptr: usize,
        num_bytes_to_write: usize,
    ) -> Result<(), RemoteMemoryError> {
        Ok(self
            .windows_remote_memory
            .write_ptr(address, ptr, num_bytes_to_write)?)
    }

    pub fn get_base_address(&self) -> usize {
        self.windows_remote_memory.base_module.mod_base_addr as usize
    }

    pub fn get_base_size(&self) -> usize {
        self.windows_remote_memory.base_module.mod_base_size as usize
    }
}

impl RemoteMemory {
    pub fn read<T: Sized + Copy>(&self, address: usize) -> Result<T, RemoteMemoryError> {
        let size = std::mem::size_of::<T>();
        let mut buffer: Vec<u8> = vec![0; size];
        self.read_bytes(address, &mut buffer)?;
        Ok(unsafe { (buffer.as_ptr() as *const T).read_unaligned() })
    }

    pub fn write_bytes(&self, address: usize, buffer: &[u8]) -> Result<(), RemoteMemoryError> {
        self.write_ptr(address, buffer.as_ptr() as usize, buffer.len())
    }

    pub fn write<T: Sized + Copy>(
        &self,
        address: usize,
        value: T,
    ) -> Result<(), RemoteMemoryError> {
        let size = std::mem::size_of::<T>();
        self.write_ptr(address, std::ptr::addr_of!(value) as usize, size)
    }

    pub fn find_signature_in(
        &self,
        signature: &Signature,
        start_address: usize,
        size: usize,
    ) -> Option<usize> {
        let mut buffer = vec![0; size];
        self.read_bytes(start_address, &mut buffer).ok()?;
        scanner::find_signature(&buffer, signature)
    }

    pub fn find_signature(&self, signature: &Signature) -> Option<usize> {
        let base_address = self.get_base_address();
        let base_size = self.get_base_size();
        self.find_signature_in(signature, base_address, base_size)
            .map(|address| address + base_address)
    }
}

#[cfg(test)]
mod test {
    #[test]
    fn test_read_bytes() {
        let buffer = vec![0xFF, 0x00, 0x12, 0xCD];
        let buffer_ptr = buffer.as_ptr() as usize;
        let process_id = std::process::id();
        let remote_memory = super::RemoteMemory::new(process_id);
        assert!(remote_memory.is_ok());
        let remote_memory = remote_memory.unwrap();
        let mut read_buffer = vec![0; 4];
        assert!(remote_memory
            .read_bytes(buffer_ptr, &mut read_buffer)
            .is_ok());
        assert_eq!(buffer, read_buffer);
    }

    #[test]
    fn test_read_u32() {
        let value = 12345;
        let value_ptr = std::ptr::addr_of!(value) as usize;
        let process_id = std::process::id();
        let remote_memory = super::RemoteMemory::new(process_id);
        assert!(remote_memory.is_ok());
        let remote_memory = remote_memory.unwrap();
        let read_value = remote_memory.read::<u32>(value_ptr);
        assert!(read_value.is_ok());
        let read_value = read_value.unwrap();
        assert_eq!(read_value, value);
    }

    #[test]
    fn test_write_bytes() {
        let data = vec![0xFF, 0x00, 0x12, 0xCD];
        let buffer = vec![0; 4];
        let buffer_ptr = buffer.as_ptr() as usize;
        let process_id = std::process::id();
        let remote_memory = super::RemoteMemory::new(process_id);
        assert!(remote_memory.is_ok());
        let remote_memory = remote_memory.unwrap();
        assert_ne!(data, buffer);
        assert!(remote_memory.write_bytes(buffer_ptr, &data).is_ok());
        assert_eq!(data, buffer);
    }

    #[test]
    fn test_write_u32() {
        let data: usize = 12345;
        let buffer: usize = 0;
        let buffer_ptr = std::ptr::addr_of!(buffer) as usize;
        let process_id = std::process::id();
        let remote_memory = super::RemoteMemory::new(process_id);
        assert!(remote_memory.is_ok());
        let remote_memory = remote_memory.unwrap();
        assert_ne!(data, buffer);
        assert!(remote_memory.write::<usize>(buffer_ptr, data).is_ok());
        assert_eq!(data, buffer);
    }
}
