use serde::{Deserialize, Serialize};
use std::process::Command;
use which::which;

#[derive(Debug, Serialize, Deserialize)]
pub struct ToolchainInfo {
    pub clang_path: String,
    pub version: String,
    pub fuzzer_supported: bool,
    pub asan_supported: bool,
}

#[tauri::command]
pub async fn check_toolchain() -> Result<ToolchainInfo, String> {
    // Find the best clang: prefer one that actually supports libFuzzer.
    // On macOS, `brew install llvm` puts clang++ in a versioned opt path that
    // isn't on PATH by default, so we search known locations explicitly.
    let clang_path = find_best_clang()
        .unwrap_or_default();

    // Get version
    let version = get_clang_version(&clang_path);

    // Test fuzzer support by compiling a minimal test
    let fuzzer_supported = test_sanitizer(&clang_path, "fuzzer");
    let asan_supported = test_sanitizer(&clang_path, "address");

    Ok(ToolchainInfo {
        clang_path,
        version,
        fuzzer_supported,
        asan_supported,
    })
}

/// Check a specific user-supplied clang path without auto-detection.
#[tauri::command]
pub async fn check_toolchain_at(clang_path: String) -> Result<ToolchainInfo, String> {
    if !std::path::Path::new(&clang_path).exists() {
        return Err(format!("Path not found: {clang_path}"));
    }
    let version = get_clang_version(&clang_path);
    let fuzzer_supported = test_sanitizer(&clang_path, "fuzzer");
    let asan_supported = test_sanitizer(&clang_path, "address");
    Ok(ToolchainInfo { clang_path, version, fuzzer_supported, asan_supported })
}

/// Return candidate clang++ paths in preference order:
/// 1. Brew LLVM (Apple Silicon then Intel) — most likely to have libFuzzer
/// 2. Any versioned llvm in /opt/homebrew/opt or /usr/local/opt
/// 3. Whatever `which clang++` / `which clang` finds
fn candidate_clangs() -> Vec<String> {
    let mut candidates: Vec<String> = Vec::new();

    // ── Windows ──────────────────────────────────────────────────────────────
    #[cfg(target_os = "windows")]
    {
        // Standard LLVM installer default locations
        for base in &[
            r"C:\Program Files\LLVM\bin",
            r"C:\Program Files (x86)\LLVM\bin",
        ] {
            candidates.push(format!(r"{base}\clang++.exe"));
            candidates.push(format!(r"{base}\clang.exe"));
        }
        // Scoop: %USERPROFILE%\scoop\apps\llvm\current\bin
        if let Ok(home) = std::env::var("USERPROFILE") {
            candidates.push(format!(r"{home}\scoop\apps\llvm\current\bin\clang++.exe"));
            candidates.push(format!(r"{home}\scoop\apps\llvm\current\bin\clang.exe"));
        }
        // Chocolatey
        candidates.push(r"C:\ProgramData\chocolatey\lib\llvm\tools\bin\clang++.exe".into());
        candidates.push(r"C:\ProgramData\chocolatey\lib\llvm\tools\bin\clang.exe".into());
    }

    // ── macOS (Homebrew) ─────────────────────────────────────────────────────
    #[cfg(target_os = "macos")]
    {
        // Brew LLVM fixed paths (Apple Silicon / Intel)
        for base in &["/opt/homebrew/opt/llvm", "/usr/local/opt/llvm"] {
            candidates.push(format!("{base}/bin/clang++"));
            candidates.push(format!("{base}/bin/clang"));
        }

        // Versioned brew llvm (e.g. llvm@18, llvm@17 …)
        for base in &["/opt/homebrew/opt", "/usr/local/opt"] {
            if let Ok(entries) = std::fs::read_dir(base) {
                let mut versioned: Vec<String> = entries
                    .flatten()
                    .filter_map(|e| {
                        let name = e.file_name().to_string_lossy().to_string();
                        if name.starts_with("llvm@") { Some(name) } else { None }
                    })
                    .collect();
                versioned.sort_by(|a, b| b.cmp(a));
                for v in versioned {
                    candidates.push(format!("{base}/{v}/bin/clang++"));
                    candidates.push(format!("{base}/{v}/bin/clang"));
                }
            }
        }
    }

    // ── Linux (versioned clangs) ─────────────────────────────────────────────
    #[cfg(target_os = "linux")]
    {
        // On Debian/Kali, versioned binaries know their own LLVM runtime dir,
        // so `-fsanitize=fuzzer` works even when the unversioned `clang` does not.
        for ver in (14u32..=21).rev() {
            candidates.push(format!("/usr/bin/clang++-{ver}"));
            candidates.push(format!("/usr/bin/clang-{ver}"));
            candidates.push(format!("/usr/lib/llvm-{ver}/bin/clang++"));
            candidates.push(format!("/usr/lib/llvm-{ver}/bin/clang"));
        }
    }

    // ── PATH fallback (all platforms) ────────────────────────────────────────
    if let Ok(p) = which("clang++") { candidates.push(p.to_string_lossy().to_string()); }
    if let Ok(p) = which("clang")   { candidates.push(p.to_string_lossy().to_string()); }

    candidates
}

/// Pick the first clang that supports -fsanitize=fuzzer; fall back to the
/// first one that exists at all.
pub fn find_best_clang() -> Option<String> {
    let candidates = candidate_clangs();
    let mut first_existing: Option<String> = None;

    for c in &candidates {
        if !std::path::Path::new(c).exists() {
            continue;
        }
        if first_existing.is_none() {
            first_existing = Some(c.clone());
        }
        if test_sanitizer(c, "fuzzer") {
            return Some(c.clone());
        }
    }

    first_existing
}

fn get_clang_version(clang: &str) -> String {
    let output = Command::new(clang)
        .arg("--version")
        .output()
        .unwrap_or_else(|_| std::process::Output {
            status: std::process::ExitStatus::default(),
            stdout: vec![],
            stderr: vec![],
        });

    let stdout = String::from_utf8_lossy(&output.stdout);
    // Extract "clang version X.Y.Z" from the first line
    stdout
        .lines()
        .next()
        .unwrap_or("")
        .to_string()
}

fn test_sanitizer(clang: &str, sanitizer: &str) -> bool {
    use std::io::Write;

    let dir = std::env::temp_dir();
    let src_path = dir.join("guzzle_test.cpp");

    // On Windows the linker produces .exe; name it explicitly so we can clean up.
    #[cfg(target_os = "windows")]
    let out_path = dir.join("guzzle_test_out.exe");
    #[cfg(not(target_os = "windows"))]
    let out_path = dir.join("guzzle_test_out");

    // Write a minimal C++ test. Use extern "C" so lld-link on Windows can
    // resolve LLVMFuzzerTestOneInput without name mangling.
    let mut f = match std::fs::File::create(&src_path) {
        Ok(f) => f,
        Err(_) => return false,
    };
    if sanitizer == "fuzzer" {
        let _ = writeln!(f,
            "#include <stdint.h>\n#include <stddef.h>\n\
             extern \"C\" int LLVMFuzzerTestOneInput(const uint8_t *d, size_t s) {{ return 0; }}"
        );
    } else {
        let _ = writeln!(f, "int main() {{ return 0; }}");
    }
    drop(f);

    let mut cmd = Command::new(clang);
    cmd.arg(format!("-fsanitize={sanitizer}"))
       .arg("-x").arg("c++")
       .arg(src_path.to_str().unwrap_or(""))
       .arg("-o").arg(out_path.to_str().unwrap_or("guzzle_test_out"));

    // Windows fuzzer runtime requires these system libraries to link.
    #[cfg(target_os = "windows")]
    cmd.args(["-ldbghelp", "-lshell32"]);

    let status = cmd.output();

    let _ = std::fs::remove_file(&src_path);
    let _ = std::fs::remove_file(&out_path);

    match status {
        Ok(output) => output.status.success(),
        Err(_) => false,
    }
}
