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
            // Sort descending so higher versions are tried first
            versioned.sort_by(|a, b| b.cmp(a));
            for v in versioned {
                candidates.push(format!("{base}/{v}/bin/clang++"));
                candidates.push(format!("{base}/{v}/bin/clang"));
            }
        }
    }

    // Linux versioned clangs (e.g. clang++-19, clang++-18, … clang++-14)
    // On Debian/Kali, versioned binaries know their own LLVM runtime dir, so
    // `-fsanitize=fuzzer` works even when the unversioned `clang` does not.
    for ver in (14u32..=21).rev() {
        candidates.push(format!("/usr/bin/clang++-{ver}"));
        candidates.push(format!("/usr/bin/clang-{ver}"));
        // Some distros install to /usr/lib/llvm-N/bin/
        candidates.push(format!("/usr/lib/llvm-{ver}/bin/clang++"));
        candidates.push(format!("/usr/lib/llvm-{ver}/bin/clang"));
    }

    // PATH fallback
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
    let src_path = dir.join("guzzle_test.c");
    let out_path = dir.join("guzzle_test_out");

    // Write a minimal C file
    let mut f = match std::fs::File::create(&src_path) {
        Ok(f) => f,
        Err(_) => return false,
    };
    let _ = writeln!(f, "int main() {{ return 0; }}");
    drop(f);

    let status = Command::new(clang)
        .arg(format!("-fsanitize={}", sanitizer))
        .arg("-x")
        .arg("c")
        .arg(src_path.to_str().unwrap_or(""))
        .arg("-o")
        .arg(out_path.to_str().unwrap_or("/dev/null"))
        .output();

    let _ = std::fs::remove_file(&src_path);
    let _ = std::fs::remove_file(&out_path);

    match status {
        Ok(output) => output.status.success(),
        Err(_) => false,
    }
}
