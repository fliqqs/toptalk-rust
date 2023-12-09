#![no_std]

#[repr(C)]
#[derive(Clone, Copy)]
pub struct PacketFlow {
    pub ipv4_src_address: u32,
    pub ipv4_dst_address: u32,
}

#[cfg(feature = "user")]
unsafe impl aya::Pod for PacketFlow {}