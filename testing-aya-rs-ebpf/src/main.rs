#![no_std]
#![no_main]

use aya_bpf::{
    helpers::{bpf_get_current_pid_tgid, bpf_probe_read_kernel, bpf_get_current_uid_gid}, macros::{kprobe, kretprobe, map}, programs::ProbeContext,
    maps::{Array, PerfEventArray},
};
use aya_log_ebpf::info;

#[allow(non_upper_case_globals)]
#[allow(non_snake_case)]
#[allow(non_camel_case_types)]
#[allow(dead_code)]
mod binding;

use binding::{sock, sock_common};

use testing_aya_rs_common::{TcpInfo, Filter};

#[map]
pub static DATA: PerfEventArray<TcpInfo> = PerfEventArray::new(0);

#[no_mangle]
static FILTER: Filter = Filter { pid: None, daddr: None };

#[kprobe(name = "kprobetcpv4")]
pub fn kprobe_tcp_v4(ctx: ProbeContext) -> u32 {
    let pid_tgid = bpf_get_current_pid_tgid();
	let tgid = (pid_tgid >> 32) as u32;
    let pid = pid_tgid as u32;
	let uid = bpf_get_current_uid_gid() as u32;

    let filter = unsafe { core::ptr::read_volatile(&FILTER) };

    if let Some(filter_pid) = filter.pid {
        if pid != filter_pid {
            return 0
        }
    }

    let sock: *mut sock = ctx.arg(0).ok_or(1i64).unwrap();
    let sk_common = unsafe {
        bpf_probe_read_kernel(&(*sock).__sk_common as *const sock_common)
            .map_err(|e| e).unwrap()
    };
    let src_addr = u32::from_be(unsafe {
        sk_common.__bindgen_anon_1.__bindgen_anon_1.skc_rcv_saddr
    });
    let dest_addr: u32 = u32::from_be(unsafe {
        sk_common.__bindgen_anon_1.__bindgen_anon_1.skc_daddr
    });

    if let Some(filter_daddr) = filter.daddr {
        info!(&ctx, "filter daddr: {}", filter_daddr);
        if dest_addr != filter_daddr {
            return 0;
        }
    }
    
    DATA.output(&ctx, &TcpInfo { pid: pid, tgid: tgid, uid: uid, daddr: dest_addr}, 0);

    info!(&ctx, "connecting tcpv4");
    0
}

#[kretprobe(name = "kretprobetcpv4")]
pub fn kretprobe_tcp_v4(ctx: ProbeContext) -> u32 {
    info!(&ctx, "end of connection tcpv4");
    0
}

#[kprobe(name = "kprobetcpv6")]
pub fn kprobe_tcp_v6(ctx: ProbeContext) -> u32 {
    info!(&ctx, "connecting tcpv6");
    0
}

#[kretprobe(name = "kretprobetcpv6")]
pub fn kretprobe_tcp_v6(ctx: ProbeContext) -> u32 {
    info!(&ctx, "end of connection tcpv6");
    0
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}

