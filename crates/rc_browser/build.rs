use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

fn main() {
    let target_os = env::var("CARGO_CFG_TARGET_OS").unwrap_or_default();
    if target_os != "windows" {
        return;
    }

    let manifest_dir = PathBuf::from(env::var("CARGO_MANIFEST_DIR").unwrap());
    let ico_path = manifest_dir.join("../../assets/oya_logo.ico");
    println!("cargo:rerun-if-changed={}", ico_path.display());
    println!("cargo:rerun-if-changed=build.rs");

    let Ok(ico_canon) = fs::canonicalize(&ico_path) else {
        println!("cargo:warning=Oya Browser icon not found at {}", ico_path.display());
        return;
    };

    // canonicalize on Windows produces a \\?\ prefix that rc.exe dislikes.
    let ico_str = ico_canon.to_string_lossy();
    let ico_clean = ico_str.strip_prefix(r"\\?\").unwrap_or(&ico_str);
    let ico_escaped = ico_clean.replace('\\', "\\\\");

    let out_dir = PathBuf::from(env::var("OUT_DIR").unwrap());
    let rc_path = out_dir.join("oya_logo.rc");
    let res_path = out_dir.join("oya_logo.res");

    let rc_content = format!("1 ICON \"{ico_escaped}\"\n");
    if let Err(e) = fs::write(&rc_path, rc_content) {
        println!("cargo:warning=Failed to write oya_logo.rc: {e}");
        return;
    }

    let Some(rc_exe) = find_rc_exe() else {
        println!("cargo:warning=Windows SDK rc.exe not found; Task Manager icon will not be embedded");
        return;
    };

    let status = Command::new(&rc_exe)
        .arg("/nologo")
        .arg("/fo")
        .arg(&res_path)
        .arg(&rc_path)
        .status();

    match status {
        Ok(s) if s.success() => {
            println!("cargo:rustc-link-arg-bin=oya_browser={}", res_path.display());
        }
        Ok(s) => {
            println!("cargo:warning=rc.exe exited with {s}; Task Manager icon not embedded");
        }
        Err(e) => {
            println!("cargo:warning=Failed to invoke rc.exe: {e}");
        }
    }
}

fn find_rc_exe() -> Option<PathBuf> {
    if let Ok(path_env) = env::var("PATH") {
        for dir in env::split_paths(&path_env) {
            let candidate = dir.join("rc.exe");
            if candidate.is_file() {
                return Some(candidate);
            }
        }
    }

    let arch = match env::var("CARGO_CFG_TARGET_ARCH").as_deref() {
        Ok("x86_64") => "x64",
        Ok("aarch64") => "arm64",
        _ => "x86",
    };

    let kits_bin = Path::new(r"C:\Program Files (x86)\Windows Kits\10\bin");
    let mut versions: Vec<PathBuf> = fs::read_dir(kits_bin)
        .ok()?
        .filter_map(|e| e.ok().map(|entry| entry.path()))
        .filter(|p| p.is_dir())
        .collect();
    versions.sort();
    versions.reverse();

    for ver in versions {
        let candidate = ver.join(arch).join("rc.exe");
        if candidate.is_file() {
            return Some(candidate);
        }
    }
    None
}
