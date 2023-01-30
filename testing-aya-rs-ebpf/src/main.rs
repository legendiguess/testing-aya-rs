#![no_std]
#![no_main]

use aya_bpf::{
    helpers::{bpf_get_current_pid_tgid, bpf_probe_read_kernel, bpf_get_current_uid_gid}, macros::{kprobe, kretprobe, map}, programs::ProbeContext,
    maps::{Array, PerfEventArray},
};
use aya_log_ebpf::info;

use testing_aya_rs_common::TcpInfo;

#[map]
pub static DATA: PerfEventArray<TcpInfo> = PerfEventArray::new(0);

#[map]
pub static ARGS: Array<u32> = Array::with_max_entries(2, 0);

#[kprobe(name = "kprobetcpv4")]
pub fn kprobe_tcp_v4(ctx: ProbeContext) -> u32 {
	let pid_tgid = bpf_get_current_pid_tgid();
	let pid = (pid_tgid >> 32) as u32;
	let tid = pid_tgid as u32;
	let uid = bpf_get_current_uid_gid() as u32;

    DATA.output(&ctx, &TcpInfo { pid: pid, tid: tid, uid: uid}, 0);

    info!(&ctx, "connecting tcpv4");
    if let Some(result) = ARGS.get(0) {
        info!(&ctx, "{}", result);
    }
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

