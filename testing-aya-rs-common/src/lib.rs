#![no_std]

#[derive(Debug, Copy, Clone)]
#[repr(C)]
pub struct TcpInfo {
    pub pid: u32,
    pub tgid: u32,
    pub uid: u32,
    pub daddr: u32,
    pub padding: u16,
    pub port: u16
}

#[derive(Debug, Copy, Clone)]
#[repr(C)]
pub struct Filter {
    pub pid: Option<u32>,
    pub daddr: Option<u32>
}

#[cfg(feature = "user")]
pub mod user {
    use super::*;

    unsafe impl aya::Pod for TcpInfo {}
    unsafe impl aya::Pod for Filter {}
}

