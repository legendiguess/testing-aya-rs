#![no_std]

#[derive(Debug, Copy, Clone)]
#[repr(C)]
pub struct TcpInfo {
    pub pid: u32,
    pub tid: u32,
    pub uid: u32
}

#[cfg(feature = "user")]
pub mod user {
    use super::*;

    unsafe impl aya::Pod for TcpInfo {}
}
