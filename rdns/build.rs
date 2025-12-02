use std::process::Command;

fn main() -> anyhow::Result<()> {
    // 告诉 cargo 在 eBPF 程序变更时重新构建
    println!("cargo:rerun-if-changed=../rdns-ebpf/src");
    
    // 如果设置了 SKIP_EBPF_BUILD 环境变量，跳过 eBPF 构建
    // 这在打包脚本中使用，因为我们会先单独构建 eBPF
    if std::env::var("SKIP_EBPF_BUILD").is_ok() {
        println!("cargo:warning=SKIP_EBPF_BUILD set, skipping eBPF build");
        return Ok(());
    }
    
    // 检查是否有 bpf-linker
    let has_bpf_linker = Command::new("which")
        .arg("bpf-linker")
        .status()
        .map(|s| s.success())
        .unwrap_or(false);
    
    if !has_bpf_linker {
        println!("cargo:warning=bpf-linker not found, skipping eBPF build");
        println!("cargo:warning=Install with: cargo install bpf-linker");
        return Ok(());
    }
    
    // 构建 eBPF 程序 (使用 nightly)
    let status = Command::new("cargo")
        .args([
            "+nightly",
            "build",
            "--package=rdns-ebpf",
            "--release",
            "--target=bpfel-unknown-none",
            "-Z", "build-std=core",
        ])
        .status();
    
    match status {
        Ok(s) if s.success() => Ok(()),
        Ok(_) => {
            println!("cargo:warning=Failed to build eBPF programs");
            println!("cargo:warning=Make sure nightly toolchain is installed: rustup install nightly");
            Ok(())
        }
        Err(e) => {
            println!("cargo:warning=Failed to run cargo: {}", e);
            Ok(())
        }
    }
}
