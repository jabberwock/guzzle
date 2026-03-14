use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::io::{BufRead, BufReader};
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::sync::{Arc, Mutex};
use tauri::{AppHandle, Emitter};

#[derive(Debug, Serialize, Deserialize)]
pub struct FuzzerArgs {
    pub binary: String,
    pub corpus_dir: String,
    pub max_total_time: u64,
    pub jobs: u32,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct FuzzerStats {
    pub execs_per_sec: u64,
    pub coverage: u64,
    pub corpus_size: u64,
    pub run_time_secs: u64,
    pub total_execs: u64,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct CrashFile {
    pub path: String,
    pub size: u64,
    pub preview_bytes: Vec<u8>,
    /// Unix timestamp (seconds) of the file's last modification time.
    pub modified_secs: u64,
}

// Resettable per-run child PID so stop_fuzzer can kill it.
static FUZZER_PID: Mutex<Option<u32>> = Mutex::new(None);
// Start time of the current fuzzer run, for computing elapsed time.
static FUZZER_START: Mutex<Option<std::time::Instant>> = Mutex::new(None);

#[tauri::command]
pub async fn start_fuzzer(app: AppHandle, args: FuzzerArgs) -> Result<u32, String> {
    // JS paths use forward slashes; normalize to native separators so that
    // Windows path operations (is_dir, create_dir_all) behave correctly.
    #[cfg(windows)]
    let (corpus_str, binary_str) = (
        args.corpus_dir.replace('/', "\\"),
        args.binary.replace('/', "\\"),
    );
    #[cfg(not(windows))]
    let (corpus_str, binary_str) = (args.corpus_dir.clone(), args.binary.clone());

    let corpus_dir = PathBuf::from(&corpus_str);
    if !corpus_dir.is_dir() {
        std::fs::create_dir_all(&corpus_dir)
            .map_err(|e| format!("Failed to create corpus dir: {e}"))?;
    }

    let crash_dir = corpus_dir
        .parent()
        .map(|p| p.join("crashes"))
        .unwrap_or_else(|| {
            #[cfg(windows)]
            return PathBuf::from(std::env::temp_dir().join("guzzle_crashes"));
            #[cfg(not(windows))]
            return PathBuf::from("/tmp/guzzle_crashes");
        });
    std::fs::create_dir_all(&crash_dir)
        .map_err(|e| format!("Failed to create crash dir: {e}"))?;

    let mut cmd = Command::new(&binary_str);
    cmd.arg(corpus_dir.to_str().unwrap_or("."));
    // Append the platform separator so libFuzzer sees a clean directory prefix
    cmd.arg(format!("-artifact_prefix={}{}", crash_dir.to_string_lossy(), std::path::MAIN_SEPARATOR));


    if args.max_total_time > 0 {
        cmd.arg(format!("-max_total_time={}", args.max_total_time));
    }
    if args.jobs > 1 {
        cmd.arg(format!("-jobs={}", args.jobs));
    }

    cmd.stdout(Stdio::piped());
    cmd.stderr(Stdio::piped());

    // Always run the fuzzer from crash_dir so any relative-path file writes
    // from the harness land there instead of in src-tauri/ (the cargo cwd),
    // which would trigger Tauri's dev file watcher and restart the app.
    cmd.current_dir(&crash_dir);

    // On Windows, ASAN writes its report directly to the console handle,
    // bypassing the stderr pipe. Force it to a log file instead so we can
    // read and display it. We can't use a full path in ASAN_OPTIONS because
    // the drive letter colon (C:\...) is parsed as an option separator — so
    // use a bare filename (resolves relative to crash_dir, set above).
    #[cfg(target_os = "windows")]
    cmd.env("ASAN_OPTIONS", "log_path=asan.log");

    // On Windows the ASAN dynamic runtime DLL lives under the LLVM installation
    // at lib/clang/<version>/lib/windows/. Find it relative to clang.exe and
    // prepend to PATH so fuzzer.exe can load it without requiring a system-wide
    // PATH change.
    #[cfg(target_os = "windows")]
    if let Some(clang) = super::toolchain::find_best_clang() {
        if let Some(rt_dir) = find_clang_rt_dir(&clang) {
            let current_path = std::env::var("PATH").unwrap_or_default();
            cmd.env("PATH", format!("{};{current_path}", rt_dir.display()));
        }
    }

    let mut child = cmd.spawn().map_err(|e| format!("Failed to spawn fuzzer: {e}"))?;
    let pid = child.id();

    // Store PID and start time so stop_fuzzer / stat lines can use them
    *FUZZER_PID.lock().unwrap() = Some(pid);
    *FUZZER_START.lock().unwrap() = Some(std::time::Instant::now());

    // Shared set of already-emitted crash file paths (deduplication)
    let seen_crashes: Arc<Mutex<HashSet<String>>> = Arc::new(Mutex::new(HashSet::new()));

    let app_out = app.clone();
    let app_crash = app.clone();
    let seen_out = seen_crashes.clone();
    let crash_dir_out = crash_dir.clone();

    // libFuzzer writes all output to stderr
    let stderr = child.stderr.take();
    tokio::task::spawn_blocking(move || {
        if let Some(stderr) = stderr {
            let reader = BufReader::new(stderr);
            for line in reader.lines().map_while(Result::ok) {
                if let Some(mut stats) = parse_fuzzer_stats(&line) {
                    stats.run_time_secs = FUZZER_START.lock().unwrap()
                        .map(|t| t.elapsed().as_secs())
                        .unwrap_or(0);
                    let _ = app_out.emit("fuzzer_stats", stats);
                }
                if line.contains("Test unit written to")
                    || line.contains("SUMMARY: AddressSanitizer")
                    || line.contains("SUMMARY: UndefinedBehaviorSanitizer")
                    || line.contains("SUMMARY: libFuzzer")
                {
                    emit_new_crashes(&crash_dir_out, &app_crash, &seen_out);
                }
                let _ = app_out.emit("fuzzer_output", &line);
            }
        }
    });

    // stdout (usually empty for libFuzzer but stream it anyway)
    let stdout = child.stdout.take();
    let app_stdout = app.clone();
    tokio::task::spawn_blocking(move || {
        if let Some(stdout) = stdout {
            let reader = BufReader::new(stdout);
            for line in reader.lines().map_while(Result::ok) {
                let _ = app_stdout.emit("fuzzer_output", &line);
            }
        }
    });

    // Wait for process and emit stopped event
    let app_done = app.clone();
    let seen_done = seen_crashes.clone();
    let crash_dir_done = crash_dir.clone();
    tokio::task::spawn_blocking(move || {
        let _ = child.wait();
        // On Windows, emit ASAN log file contents (ASAN bypasses the stderr pipe)
        #[cfg(target_os = "windows")]
        {
            let log_path = crash_dir_done.join("asan.log");
            // ASAN appends the PID to the filename: asan.log.<pid>
            if let Ok(entries) = std::fs::read_dir(&crash_dir_done) {
                for entry in entries.flatten() {
                    let name = entry.file_name();
                    let name = name.to_string_lossy();
                    if name.starts_with("asan.log") {
                        if let Ok(contents) = std::fs::read_to_string(entry.path()) {
                            for line in contents.lines() {
                                let _ = app_done.emit("fuzzer_output", line);
                            }
                        }
                    }
                }
            }
            // Also try the exact path in case ASAN didn't append PID
            if let Ok(contents) = std::fs::read_to_string(&log_path) {
                for line in contents.lines() {
                    let _ = app_done.emit("fuzzer_output", line);
                }
            }
        }
        // Final crash scan after process exits
        emit_new_crashes(&crash_dir_done, &app_done, &seen_done);
        let _ = app_done.emit("fuzzer_stopped", ());
        *FUZZER_PID.lock().unwrap() = None;
        *FUZZER_START.lock().unwrap() = None;
    });

    Ok(pid)
}

#[tauri::command]
pub async fn stop_fuzzer(pid: u32) -> Result<(), String> {
    let stored = *FUZZER_PID.lock().unwrap();
    let target = stored.unwrap_or(pid);

    #[cfg(unix)]
    libc_kill(target as i32, 15); // SIGTERM

    #[cfg(windows)]
    {
        let _ = Command::new("taskkill")
            .args(["/PID", &target.to_string(), "/F"])
            .output();
    }

    Ok(())
}

#[cfg(unix)]
fn libc_kill(pid: i32, sig: i32) {
    use std::ffi::c_int;
    extern "C" { fn kill(pid: i32, sig: c_int) -> c_int; }
    unsafe { kill(pid, sig); }
}

#[tauri::command]
pub async fn read_crash_files(corpus_dir: String) -> Result<Vec<CrashFile>, String> {
    let dir = PathBuf::from(&corpus_dir);
    if !dir.exists() {
        return Ok(vec![]);
    }

    let mut crashes = Vec::new();
    for entry in std::fs::read_dir(&dir).map_err(|e| format!("Failed to read dir: {e}"))?.flatten() {
        let path = entry.path();
        if !path.is_file() { continue; }
        let name = path.file_name().unwrap_or_default().to_string_lossy().to_string();
        if !is_crash_filename(&name) { continue; }

        let meta = entry.metadata().ok();
        let size = meta.as_ref().map(|m| m.len()).unwrap_or(0);
        let modified_secs = meta
            .and_then(|m| m.modified().ok())
            .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
            .map(|d| d.as_secs())
            .unwrap_or(0);
        let data = std::fs::read(&path).unwrap_or_default();
        crashes.push(CrashFile {
            path: path.to_string_lossy().to_string(),
            size,
            preview_bytes: data.into_iter().take(256).collect(),
            modified_secs,
        });
    }

    // Newest first
    crashes.sort_unstable_by(|a, b| b.modified_secs.cmp(&a.modified_secs));
    Ok(crashes)
}

pub(crate) fn is_crash_filename(name: &str) -> bool {
    name.starts_with("crash-")
        || name.starts_with("oom-")
        || name.starts_with("timeout-")
        || name.starts_with("leak-")
        || name.starts_with("slow-")
}

fn emit_new_crashes(crash_dir: &PathBuf, app: &AppHandle, seen: &Arc<Mutex<HashSet<String>>>) {
    let Ok(entries) = std::fs::read_dir(crash_dir) else { return };
    let mut seen_lock = seen.lock().unwrap();

    for entry in entries.flatten() {
        let path = entry.path();
        if !path.is_file() { continue; }
        let name = path.file_name().unwrap_or_default().to_string_lossy().to_string();
        if !is_crash_filename(&name) { continue; }

        let path_str = path.to_string_lossy().to_string();
        if seen_lock.contains(&path_str) { continue; }
        seen_lock.insert(path_str.clone());

        let meta = entry.metadata().ok();
        let size = meta.as_ref().map(|m| m.len()).unwrap_or(0);
        let modified_secs = meta
            .and_then(|m| m.modified().ok())
            .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
            .map(|d| d.as_secs())
            .unwrap_or(0);
        let data = std::fs::read(&path).unwrap_or_default();
        let _ = app.emit("fuzzer_crash", CrashFile {
            path: path_str,
            size,
            preview_bytes: data.into_iter().take(256).collect(),
            modified_secs,
        });
    }
}

pub(crate) fn parse_fuzzer_stats(line: &str) -> Option<FuzzerStats> {
    if !line.starts_with('#') { return None; }

    let total_execs = parse_field_u64(line, "#")?;
    let coverage = parse_field_u64(line, "cov: ").unwrap_or(0);
    let corpus_size = parse_field_u64(line, "corp: ").unwrap_or(0);
    let execs_per_sec = parse_field_u64(line, "exec/s: ").unwrap_or(0);
    // run_time_secs is filled in by the caller from FUZZER_START
    let run_time_secs = 0;

    Some(FuzzerStats { total_execs, coverage, corpus_size, execs_per_sec, run_time_secs })
}

pub(crate) fn parse_field_u64(line: &str, prefix: &str) -> Option<u64> {
    let start = if prefix == "#" {
        1
    } else {
        line.find(prefix)? + prefix.len()
    };
    line[start..].split_whitespace().next()?.split('/').next()?.parse().ok()
}

/// Find the directory containing clang_rt DLLs by walking up from clang's
/// location and finding lib/clang/<version>/lib/windows/. Used on Windows
/// to inject the runtime DLL directory into PATH before spawning the fuzzer.
#[cfg(target_os = "windows")]
fn find_clang_rt_dir(clang_path: &str) -> Option<PathBuf> {
    // clang.exe is typically at <root>/bin/clang.exe; root is one level up.
    let root = std::path::Path::new(clang_path).parent()?.parent()?;
    let lib_clang = root.join("lib").join("clang");
    // Iterate version subdirectories and return the first that has lib/windows/
    let entries = std::fs::read_dir(&lib_clang).ok()?;
    for entry in entries.flatten() {
        let candidate = entry.path().join("lib").join("windows");
        if candidate.is_dir() {
            return Some(candidate);
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    // --- parse_field_u64 ---

    #[test]
    fn field_u64_hash_prefix() {
        assert_eq!(parse_field_u64("#1234 cov: 567", "#"), Some(1234));
    }

    #[test]
    fn field_u64_cov_prefix() {
        assert_eq!(parse_field_u64("#1234 cov: 567", "cov: "), Some(567));
    }

    #[test]
    fn field_u64_slash_terminated() {
        // exec/s: 1234/5 — should parse 1234 (before the slash)
        assert_eq!(parse_field_u64("exec/s: 1234/5", "exec/s: "), Some(1234));
    }

    #[test]
    fn field_u64_missing_prefix() {
        assert_eq!(parse_field_u64("#1234 cov: 567", "exec/s: "), None);
    }

    #[test]
    fn field_u64_non_numeric() {
        assert_eq!(parse_field_u64("#abc cov: 567", "#"), None);
    }

    // --- parse_fuzzer_stats ---

    #[test]
    fn fuzzer_stats_full_line() {
        let line = "#1234 pulse  cov: 50 corp: 10/200b lim: 4096 exec/s: 500 rss: 42Mb";
        let stats = parse_fuzzer_stats(line).expect("should parse");
        assert_eq!(stats.total_execs, 1234);
        assert_eq!(stats.coverage, 50);
        assert_eq!(stats.corpus_size, 10);
        assert_eq!(stats.execs_per_sec, 500);
        assert_eq!(stats.run_time_secs, 0); // filled in by caller
    }

    #[test]
    fn fuzzer_stats_missing_optional_fields() {
        let stats = parse_fuzzer_stats("#42").expect("should parse");
        assert_eq!(stats.total_execs, 42);
        assert_eq!(stats.coverage, 0);
        assert_eq!(stats.corpus_size, 0);
        assert_eq!(stats.execs_per_sec, 0);
    }

    #[test]
    fn fuzzer_stats_non_stat_line() {
        assert!(parse_fuzzer_stats("INFO: libFuzzer started").is_none());
    }

    // --- is_crash_filename ---

    #[test]
    fn crash_filename_crash() {
        assert!(is_crash_filename("crash-abc123"));
    }

    #[test]
    fn crash_filename_oom() {
        assert!(is_crash_filename("oom-abc"));
    }

    #[test]
    fn crash_filename_timeout() {
        assert!(is_crash_filename("timeout-abc"));
    }

    #[test]
    fn crash_filename_leak() {
        assert!(is_crash_filename("leak-abc"));
    }

    #[test]
    fn crash_filename_slow() {
        assert!(is_crash_filename("slow-abc"));
    }

    #[test]
    fn crash_filename_corpus_item() {
        assert!(!is_crash_filename("corpus_item"));
    }

    #[test]
    fn crash_filename_crash_no_dash() {
        assert!(!is_crash_filename("crash"));
    }

    #[test]
    fn fuzzer_current_dir_is_set_for_all_platforms() {
        // Static guard: the start_fuzzer source must call cmd.current_dir
        // unconditionally (not just inside a #[cfg(windows)] block) so that
        // the fuzzer binary never inherits src-tauri/ as its cwd and can't
        // write temp files there.
        let src = include_str!("fuzzer.rs");
        // Find the spawn_fuzzer section — look for the unconditional current_dir call.
        // It must appear OUTSIDE any cfg(target_os="windows") guard.
        let cd_pos = src.find("cmd.current_dir(&crash_dir)")
            .expect("cmd.current_dir(&crash_dir) must exist in fuzzer.rs");
        // The unconditional call must NOT be preceded by a cfg(target_os="windows") on the same logical block.
        // A simple heuristic: the line containing it should not itself be inside the windows-only block,
        // which ends with the env("ASAN_OPTIONS") line. We verify by checking that there IS a
        // current_dir call before any Windows-cfg block.
        let cfg_win_pos = src.find("#[cfg(target_os = \"windows\")]\n    cmd.env(\"ASAN_OPTIONS\"")
            .unwrap_or(usize::MAX);
        assert!(cd_pos < cfg_win_pos,
            "cmd.current_dir(&crash_dir) must appear before the Windows-only ASAN_OPTIONS block");
    }

    // --- read_crash_files sorting ---

    #[test]
    fn crash_files_sorted_newest_first() {
        let dir = tempfile::tempdir().unwrap();
        // Create two crash files with different mtimes using std::fs::write,
        // then manually set their timestamps via a small sleep.
        let older = dir.path().join("crash-aaa");
        let newer = dir.path().join("crash-bbb");
        std::fs::write(&older, b"old").unwrap();
        std::thread::sleep(std::time::Duration::from_millis(10));
        std::fs::write(&newer, b"new").unwrap();

        let rt = tokio::runtime::Runtime::new().unwrap();
        let result = rt.block_on(read_crash_files(dir.path().to_str().unwrap().to_string())).unwrap();

        assert_eq!(result.len(), 2);
        assert!(result[0].modified_secs >= result[1].modified_secs,
            "crashes should be newest first");
        assert!(result[0].path.contains("crash-bbb"));
    }

    #[test]
    fn crash_file_modified_secs_nonzero() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("crash-abc"), b"data").unwrap();

        let rt = tokio::runtime::Runtime::new().unwrap();
        let result = rt.block_on(read_crash_files(dir.path().to_str().unwrap().to_string())).unwrap();

        assert_eq!(result.len(), 1);
        assert!(result[0].modified_secs > 0);
    }

    // --- find_clang_rt_dir ---

    #[cfg(target_os = "windows")]
    #[test]
    fn clang_rt_dir_found_under_lib_clang_version() {
        let dir = tempfile::tempdir().unwrap();
        // Simulate <root>/bin/clang and <root>/lib/clang/17/lib/windows/
        let bin_dir = dir.path().join("bin");
        let rt_dir = dir.path().join("lib").join("clang").join("17").join("lib").join("windows");
        std::fs::create_dir_all(&bin_dir).unwrap();
        std::fs::create_dir_all(&rt_dir).unwrap();
        let clang_path = bin_dir.join("clang").to_string_lossy().to_string();

        let result = find_clang_rt_dir(&clang_path);
        assert_eq!(result, Some(rt_dir));
    }

    #[cfg(target_os = "windows")]
    #[test]
    fn clang_rt_dir_missing_returns_none() {
        let dir = tempfile::tempdir().unwrap();
        let bin_dir = dir.path().join("bin");
        std::fs::create_dir_all(&bin_dir).unwrap();
        let clang_path = bin_dir.join("clang").to_string_lossy().to_string();

        assert_eq!(find_clang_rt_dir(&clang_path), None);
    }

    #[cfg(target_os = "windows")]
    #[test]
    fn clang_rt_dir_no_parent_returns_none() {
        assert_eq!(find_clang_rt_dir("clang"), None);
    }
}
