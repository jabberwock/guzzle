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
}

// Resettable per-run child PID so stop_fuzzer can kill it.
static FUZZER_PID: Mutex<Option<u32>> = Mutex::new(None);

#[tauri::command]
pub async fn start_fuzzer(app: AppHandle, args: FuzzerArgs) -> Result<u32, String> {
    let corpus_dir = PathBuf::from(&args.corpus_dir);
    std::fs::create_dir_all(&corpus_dir)
        .map_err(|e| format!("Failed to create corpus dir: {e}"))?;

    let crash_dir = corpus_dir
        .parent()
        .map(|p| p.join("crashes"))
        .unwrap_or_else(|| PathBuf::from("/tmp/guzzle_crashes"));
    std::fs::create_dir_all(&crash_dir)
        .map_err(|e| format!("Failed to create crash dir: {e}"))?;

    let mut cmd = Command::new(&args.binary);
    cmd.arg(corpus_dir.to_str().unwrap_or("."));
    cmd.arg(format!("-artifact_prefix={}/", crash_dir.to_string_lossy()));


    if args.max_total_time > 0 {
        cmd.arg(format!("-max_total_time={}", args.max_total_time));
    }
    if args.jobs > 1 {
        cmd.arg(format!("-jobs={}", args.jobs));
    }

    cmd.stdout(Stdio::piped());
    cmd.stderr(Stdio::piped());

    let mut child = cmd.spawn().map_err(|e| format!("Failed to spawn fuzzer: {e}"))?;
    let pid = child.id();

    // Store PID so stop_fuzzer can kill it
    *FUZZER_PID.lock().unwrap() = Some(pid);

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
                if let Some(stats) = parse_fuzzer_stats(&line) {
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
        // Final crash scan after process exits
        emit_new_crashes(&crash_dir_done, &app_done, &seen_done);
        let _ = app_done.emit("fuzzer_stopped", ());
        *FUZZER_PID.lock().unwrap() = None;
    });

    Ok(pid)
}

#[tauri::command]
pub async fn stop_fuzzer(pid: u32) -> Result<(), String> {
    let stored = *FUZZER_PID.lock().unwrap();
    let target = stored.unwrap_or(pid);

    #[cfg(unix)]
    unsafe {
        libc_kill(target as i32, 15); // SIGTERM
    }

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

        let size = entry.metadata().map(|m| m.len()).unwrap_or(0);
        let data = std::fs::read(&path).unwrap_or_default();
        crashes.push(CrashFile {
            path: path.to_string_lossy().to_string(),
            size,
            preview_bytes: data.into_iter().take(256).collect(),
        });
    }

    Ok(crashes)
}

fn is_crash_filename(name: &str) -> bool {
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

        let size = entry.metadata().map(|m| m.len()).unwrap_or(0);
        let data = std::fs::read(&path).unwrap_or_default();
        let _ = app.emit("fuzzer_crash", CrashFile {
            path: path_str,
            size,
            preview_bytes: data.into_iter().take(256).collect(),
        });
    }
}

fn parse_fuzzer_stats(line: &str) -> Option<FuzzerStats> {
    if !line.starts_with('#') { return None; }

    let total_execs = parse_field_u64(line, "#")?;
    let coverage = parse_field_u64(line, "cov: ").unwrap_or(0);
    let corpus_size = parse_field_u64(line, "corp: ").unwrap_or(0);
    let execs_per_sec = parse_field_u64(line, "exec/s: ").unwrap_or(0);
    let run_time_secs = parse_field_u64(line, "ft: ").unwrap_or(0);

    Some(FuzzerStats { total_execs, coverage, corpus_size, execs_per_sec, run_time_secs })
}

fn parse_field_u64(line: &str, prefix: &str) -> Option<u64> {
    let start = if prefix == "#" {
        1
    } else {
        line.find(prefix)? + prefix.len()
    };
    line[start..].split_whitespace().next()?.split('/').next()?.parse().ok()
}
