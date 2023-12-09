#![no_std]
#![no_main]

use aya_bpf::{bindings::{xdp_action, iphdr}, macros::xdp, programs::XdpContext, maps::xdp};
use aya_log_ebpf::info;
use aya_bpf::maps::PerfEventArray;
use aya_bpf::macros::map;

use toptalk_rust_common::PacketFlow;

#[map]
static EVENTS: PerfEventArray<PacketFlow> =
    PerfEventArray::with_max_entries(1024, 0);

use core::mem;
use network_types::{
    eth::{EthHdr, EtherType},
    ip::{IpProto, Ipv4Hdr, Ipv6Hdr},
    tcp::TcpHdr,
    udp::UdpHdr,
};


#[xdp]
pub fn toptalk_rust(ctx: XdpContext) -> u32 {
    match try_toptalk_rust(ctx) {
        Ok(ret) => ret,
        Err(_) => xdp_action::XDP_ABORTED,
    }
}

#[inline(always)]
unsafe fn ptr_at<T>(ctx: &XdpContext, offset: usize) -> Result<*const T, ()> {
    let start = ctx.data();
    let end = ctx.data_end();
    let len = mem::size_of::<T>();

    if start + offset + len > end {
        return Err(());
    }

    let ptr = (start + offset) as *const T;
    Ok(&*ptr)
}

fn decode_ipv4(ctx: &XdpContext, ethhdr: *const EthHdr, flow: &mut PacketFlow) -> Result<u32, ()> {
    let offset: usize = mem::size_of::<EthHdr>();

    let iphdr: *const Ipv4Hdr = unsafe { ptr_at(&ctx, offset) }?;


    flow.ipv4_dst_address = unsafe { (*iphdr).dst_addr.into() };
    flow.ipv4_src_address = unsafe { (*iphdr).src_addr.into() };

    //log the flow dst addres
    info!(ctx, "ip decode LOG: SRC{} DST {}", flow.ipv4_src_address, flow.ipv4_dst_address);


    Ok(1)

}


fn try_toptalk_rust(ctx: XdpContext) -> Result<u32, ()> {

    info!(&ctx, "received a packet");

    let ethhdr: *const EthHdr = unsafe { ptr_at(&ctx, 0)? };

    let mut new_flow = PacketFlow{
        ipv4_src_address: 0,
        ipv4_dst_address: 0,
    };

    // check ethertype and decode
    unsafe {
        let etype: EtherType = (*ethhdr).ether_type;
        match etype {
            EtherType::Ipv4 => {
                // Properly handle the result of decode_ipv4
                match decode_ipv4(&ctx, ethhdr, &mut new_flow) {
                    Ok(1) => {
                        // Successfully decoded

                        //log the flow before sending perf array
                        info!(&ctx, "LOG: SRC{} DST {}", new_flow.ipv4_src_address, new_flow.ipv4_dst_address);

                        EVENTS.output(&ctx, &new_flow, 0);
                    }
                    Err(()) => {
                        // Failed to decode IPv4
                        // Handle the failure
                        return Err(());
                    }
                    _ => {}
                }
            }
            _ => (),
        }
    }


    

    Ok(xdp_action::XDP_PASS)
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}
