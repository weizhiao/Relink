use std::env;

fn main() {
    println!("cargo:rerun-if-env-changed=TARGET");
    println!("cargo:rerun-if-env-changed=CARGO_CFG_TARGET_ABI");
    println!("cargo:rerun-if-env-changed=CARGO_CFG_TARGET_ARCH");
    println!("cargo:rustc-check-cfg=cfg(riscv_float_abi, values(\"soft\", \"f\", \"d\", \"q\"))");

    let target_arch = env::var("CARGO_CFG_TARGET_ARCH").unwrap_or_default();
    if target_arch != "riscv32" && target_arch != "riscv64" {
        return;
    }

    let target_abi = env::var("CARGO_CFG_TARGET_ABI").unwrap_or_default();
    let float_abi = float_abi_from_target_abi(&target_abi).or_else(|| {
        env::var("TARGET")
            .ok()
            .and_then(|target| float_abi_from_target(&target))
    });

    if let Some(float_abi) = float_abi {
        println!("cargo:rustc-cfg=riscv_float_abi=\"{float_abi}\"");
    }
}

fn float_abi_from_target_abi(target_abi: &str) -> Option<&'static str> {
    match target_abi {
        "ilp32" | "lp64" => Some("soft"),
        "ilp32f" | "lp64f" => Some("f"),
        "ilp32d" | "lp64d" => Some("d"),
        _ => None,
    }
}

fn float_abi_from_target(target: &str) -> Option<&'static str> {
    let arch = target.split('-').next()?;
    let extensions = arch
        .strip_prefix("riscv32")
        .or_else(|| arch.strip_prefix("riscv64"))?;
    let single_letter_extensions = extensions.split('_').next().unwrap_or(extensions);

    if single_letter_extensions.contains('g') || single_letter_extensions.contains('d') {
        Some("d")
    } else if single_letter_extensions.contains('f') {
        Some("f")
    } else {
        Some("soft")
    }
}
