use aya_tool::generate::InputFile;
use std::{fs::File, io::Write, path::PathBuf};

pub fn generate() -> Result<(), anyhow::Error> {
    let dir = PathBuf::from("testing-aya-rs-ebpf/src");
    dbg!("1");
    let names: Vec<&str> = vec!["sock", "sock_common"];
    dbg!("2");
    let bindings = aya_tool::generate(
        InputFile::Btf(PathBuf::from("/sys/kernel/btf/vmlinux")),
        &names,
        &[],
    )?;
    dbg!("3");
    // Write the bindings to the $OUT_DIR/bindings.rs file.
    let mut out = File::create(dir.join("bindings.rs"))?;
    dbg!("4");
    write!(out, "{}", bindings)?;
    Ok(())
}
