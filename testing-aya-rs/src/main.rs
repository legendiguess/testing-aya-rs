use anyhow::Context;
use aya::maps::Array;
use aya::programs::KProbe;
use aya::{include_bytes_aligned, Bpf, BpfLoader, Btf};
use aya::{maps::perf::AsyncPerfEventArray, util::online_cpus};
use aya_log::BpfLogger;
use bytes::BytesMut;
use clap::Parser;
use log::{info, warn};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::{mem, ptr};
use testing_aya_rs_common::{Filter, TcpInfo};
use tokio::signal;

#[derive(Debug, Parser)]
struct Opt {
    #[clap(short, long)]
    daddr: Option<String>,
    #[clap(short, long)]
    pid: Option<String>,
}

#[tokio::main]
async fn main() -> Result<(), anyhow::Error> {
    let opt = Opt::parse();

    env_logger::init();

    let mut bpf = BpfLoader::new();
    // let mut bpf = bpf.btf(Btf::from_sys_fs().ok().as_ref()); todo

    let filter_pid = opt.pid.map(|string| string.parse::<u32>().unwrap());

    let filter_daddr = opt
        .daddr
        .map(|string| u32::from_be_bytes(string.parse::<Ipv4Addr>().unwrap().octets()));

    let filter = Filter {
        pid: filter_pid,
        daddr: filter_daddr,
    };

    let mut bpf = bpf.set_global("FILTER", &filter);

    #[cfg(debug_assertions)]
    let mut bpf = bpf.load(include_bytes_aligned!(
        "../../target/bpfel-unknown-none/debug/testing-aya-rs"
    ))?;
    #[cfg(not(debug_assertions))]
    let mut bpf = bpf.load(include_bytes_aligned!(
        "../../target/bpfel-unknown-none/release/testing-aya-rs"
    ))?;
    if let Err(e) = BpfLogger::init(&mut bpf) {
        // This can happen if you remove all log statements from your eBPF program.
        warn!("failed to initialize eBPF logger: {}", e);
    }

    let kprobetcpv4_program: &mut KProbe = bpf.program_mut("kprobetcpv4").unwrap().try_into()?;
    kprobetcpv4_program.load()?;
    kprobetcpv4_program.attach("tcp_v4_connect", 0)?;

    let kretprobetcpv4_program: &mut KProbe =
        bpf.program_mut("kretprobetcpv4").unwrap().try_into()?;
    kretprobetcpv4_program.load()?;
    kretprobetcpv4_program.attach("tcp_v4_connect", 0)?;

    let cpus = online_cpus()?;
    let num_cpus = cpus.len();
    let mut events = AsyncPerfEventArray::try_from(bpf.map_mut("DATA")?)?;
    for cpu in cpus {
        let mut buf = events.open(cpu, None)?;

        tokio::task::spawn(async move {
            let mut buffers = (0..num_cpus)
                .map(|_| BytesMut::with_capacity(9000))
                .collect::<Vec<_>>();

            loop {
                let events = buf.read_events(&mut buffers).await.unwrap();
                for i in 0..events.read {
                    let buf = &mut buffers[i];

                    let tcp_info = unsafe { ptr::read_unaligned(buf.as_ptr() as *const TcpInfo) };
                    // let pkt_buf = buf.split().freeze().slice(
                    //     mem::size_of::<TcpInfo>()..mem::size_of::<TcpInfo>(),
                    // );
                    info!(
                        "received TcpInfo: pid: {:?}, tgid: {:?}, uid: {:?}, daddr: {:?}",
                        tcp_info.pid,
                        tcp_info.tgid,
                        tcp_info.uid,
                        Ipv4Addr::from(tcp_info.daddr)
                    );
                }
            }
        });
    }

    info!("Waiting for Ctrl-C...");
    signal::ctrl_c().await?;
    info!("Exiting...");

    Ok(())
}
