use anyhow::Context;
use aya::programs::KProbe;
use aya::{include_bytes_aligned, Bpf};
use aya_log::BpfLogger;
use clap::Parser;
use log::{info, warn};
use tokio::signal;
use testing_aya_rs_common::TcpInfo;
use aya::{
    maps::perf::AsyncPerfEventArray,
    util::online_cpus,
};
use std::{mem, ptr};
use bytes::BytesMut;

#[derive(Debug, Parser)]
struct Opt {}


#[tokio::main]
async fn main() -> Result<(), anyhow::Error> {
    let opt = Opt::parse();

    env_logger::init();

    // This will include your eBPF object file as raw bytes at compile-time and load it at
    // runtime. This approach is recommended for most real-world use cases. If you would
    // like to specify the eBPF program at runtime rather than at compile-time, you can
    // reach for `Bpf::load_file` instead.
    #[cfg(debug_assertions)]
    let mut bpf = Bpf::load(include_bytes_aligned!(
        "../../target/bpfel-unknown-none/debug/testing-aya-rs"
    ))?;
    #[cfg(not(debug_assertions))]
    let mut bpf = Bpf::load(include_bytes_aligned!(
        "../../target/bpfel-unknown-none/release/testing-aya-rs"
    ))?;
    if let Err(e) = BpfLogger::init(&mut bpf) {
        // This can happen if you remove all log statements from your eBPF program.
        warn!("failed to initialize eBPF logger: {}", e);
    }


    let kprobetcpv4_program: &mut KProbe = bpf.program_mut("kprobetcpv4").unwrap().try_into()?;
    kprobetcpv4_program.load()?;
    kprobetcpv4_program.attach("tcp_v4_connect", 0)?;

    let kretprobetcpv4_program: &mut KProbe = bpf.program_mut("kretprobetcpv4").unwrap().try_into()?;
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
                    info!("received TcpInfo: pid: {:?}, tid: {:?}, uid: {:?}", tcp_info.pid, tcp_info.tid, tcp_info.uid);
                }
            }
        });
    }


    info!("Waiting for Ctrl-C...");
    signal::ctrl_c().await?;
    info!("Exiting...");

    Ok(())
}
