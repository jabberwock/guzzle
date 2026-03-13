use serde::{Deserialize, Serialize};
use std::io::{BufRead, BufReader};
use std::path::PathBuf;
use std::process::{Command, Stdio};
use tauri::{AppHandle, Emitter};

use super::toolchain::find_best_clang;
use super::parser::get_all_functions;

#[derive(Debug, Serialize, Deserialize)]
pub struct CompileSettings {
    pub sanitizers: Vec<String>,
    pub includes: Vec<String>,
    pub library_files: Vec<String>,
    pub extra_flags: String,
    pub out_path: String,
    /// User-overridden clang path; if None, auto-detect via find_best_clang()
    pub clang_override: Option<String>,
}

/// Injected before the user's harness code.
/// - Renames LLVMFuzzerTestOneInput → __guzzle_fuzz_impl so we can wrap it
/// - Provides exit()/abort() overrides via longjmp so target code can't kill
///   the fuzzer process
const HARNESS_PREAMBLE: &str = r#"/* === Guzzle preamble === */
#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>
#include <setjmp.h>

/* Rename the user's entry point so we can wrap it with setjmp protection */
#define LLVMFuzzerTestOneInput __guzzle_fuzz_impl

/* Override exit() — some targets call exit(0) on bad input which would kill
   the entire fuzzer process. longjmp back to our wrapper instead.
   NOTE: abort() is intentionally NOT overridden — ASan uses it to signal
   crashes to libFuzzer's signal handler. */
jmp_buf __guzzle_exit_buf;
static int __guzzle_jmp_ready = 0;
extern "C" void exit(int code) {
    if (__guzzle_jmp_ready) { longjmp(__guzzle_exit_buf, 1); }
    /* setjmp not called yet (e.g. during startup) — let it propagate */
    __builtin_trap();
}
/* === end preamble === */

"#;

/// Injected after the user's harness. Provides the real LLVMFuzzerTestOneInput
/// that libFuzzer calls, wrapped in setjmp so exit()/abort() in the target
/// returns 0 instead of terminating the process.
const HARNESS_POSTAMBLE: &str = r#"
/* === Guzzle postamble === */
#undef LLVMFuzzerTestOneInput
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    __guzzle_jmp_ready = 1;
    if (setjmp(__guzzle_exit_buf)) { __guzzle_jmp_ready = 0; return 0; }
    int r = __guzzle_fuzz_impl(data, size);
    __guzzle_jmp_ready = 0;
    return r;
}
/* === end postamble === */
"#;

#[tauri::command]
pub async fn compile_harness(
    app: AppHandle,
    harness: String,
    target_files: Vec<String>,
    settings: CompileSettings,
) -> Result<String, String> {
    let temp_dir = std::env::temp_dir().join("guzzle");
    std::fs::create_dir_all(&temp_dir).map_err(|e| format!("Failed to create temp dir: {e}"))?;

    // Strip any #include lines that pull in one of the target files directly
    let harness_clean = strip_target_includes(&harness, &target_files);

    // Build extern "C" forward declarations for C target functions
    let extern_c_block = build_extern_c_block(&target_files);

    let harness_final = format!("{HARNESS_PREAMBLE}{extern_c_block}{harness_clean}{HARNESS_POSTAMBLE}");
    let harness_path = temp_dir.join("harness.cpp");
    std::fs::write(&harness_path, &harness_final)
        .map_err(|e| format!("Failed to write harness: {e}"))?;

    // Output binary path
    let out_path = if settings.out_path.is_empty() {
        let target_dir = target_files
            .first()
            .and_then(|f| PathBuf::from(f).parent().map(|p| p.to_path_buf()))
            .unwrap_or_else(|| PathBuf::from("/tmp"));
        let guzzle_dir = target_dir.join(".guzzle");
        std::fs::create_dir_all(&guzzle_dir)
            .map_err(|e| format!("Failed to create .guzzle dir: {e}"))?;

        // Also save a copy of the harness next to the binary for inspection
        let _ = std::fs::copy(&harness_path, guzzle_dir.join("harness.cpp"));

        guzzle_dir.join("fuzzer").to_string_lossy().to_string()
    } else {
        settings.out_path.clone()
    };

    let clang = settings.clang_override.clone()
        .filter(|p| !p.is_empty())
        .or_else(find_best_clang)
        .ok_or_else(|| "No suitable clang found. Run the toolchain check first.".to_string())?;

    let sanitize_flag = if settings.sanitizers.is_empty() {
        "-fsanitize=fuzzer".to_string()
    } else {
        format!("-fsanitize={}", settings.sanitizers.join(","))
    };

    // Detect if any C target file defines main() — if so, rename it so
    // libFuzzer's own main() takes precedence.
    // NOTE: get_all_functions() skips main() by design (for extern "C" blocks),
    // so we do a direct source scan here instead.
    let target_has_main = target_files.iter()
        .filter(|f| f.ends_with(".c"))
        .any(|f| {
            let src = std::fs::read_to_string(f).unwrap_or_default();
            src.contains("int main(") || src.contains("int main (")
        });

    let mut cmd = Command::new(&clang);
    cmd.arg(&sanitize_flag);

    for inc in &settings.includes {
        cmd.arg(format!("-I{inc}"));
    }
    for flag in settings.extra_flags.split_whitespace() {
        cmd.arg(flag);
    }

    // Harness as C++
    cmd.arg("-x").arg("c++");
    cmd.arg(harness_path.to_str().unwrap());

    // Target files in their native language
    for tf in &target_files {
        let lang = if tf.ends_with(".c") { "c" } else { "c++" };
        cmd.arg("-x").arg(lang);
        // Rename main() in target files so libFuzzer's main wins
        if target_has_main && tf.ends_with(".c") {
            cmd.arg("-Dmain=__guzzle_target_main");
        }
        cmd.arg(tf);
    }

    // Pre-built library files (.a, .so, .dylib) — reset -x so clang treats them as
    // archives/objects to link rather than source to compile
    if !settings.library_files.is_empty() {
        cmd.arg("-x").arg("none");
        for lib in &settings.library_files {
            cmd.arg(lib);
        }
    }

    // Windows fuzzer runtime requires these system libraries.
    #[cfg(target_os = "windows")]
    cmd.args(["-ldbghelp", "-lshell32"]);

    cmd.arg("-o").arg(&out_path);
    cmd.stdout(Stdio::piped());
    cmd.stderr(Stdio::piped());

    let args_display = cmd.get_args()
        .map(|a| a.to_string_lossy().to_string())
        .collect::<Vec<_>>()
        .join(" ");
    let _ = app.emit("compile_output", format!("$ {clang} {args_display}"));

    let mut child = cmd.spawn().map_err(|e| format!("Failed to spawn clang: {e}"))?;

    let stderr = child.stderr.take().unwrap();
    let app_e = app.clone();
    let t_err = tokio::task::spawn_blocking(move || {
        BufReader::new(stderr).lines().map_while(Result::ok)
            .for_each(|l| { let _ = app_e.emit("compile_output", l); });
    });

    let stdout = child.stdout.take().unwrap();
    let app_o = app.clone();
    let t_out = tokio::task::spawn_blocking(move || {
        BufReader::new(stdout).lines().map_while(Result::ok)
            .for_each(|l| { let _ = app_o.emit("compile_output", l); });
    });

    let status = tokio::task::spawn_blocking(move || child.wait())
        .await.map_err(|e| format!("join: {e}"))?
        .map_err(|e| format!("wait: {e}"))?;

    let _ = t_err.await;
    let _ = t_out.await;

    if status.success() {
        let _ = app.emit("compile_output", format!("\n✓ Compiled: {out_path}"));
        Ok(out_path)
    } else {
        Err(format!("Compilation failed with exit code {}", status.code().unwrap_or(-1)))
    }
}

pub fn strip_target_includes(harness: &str, target_files: &[String]) -> String {
    let stems: Vec<&str> = target_files.iter()
        .map(|f| f.rsplit('/').next().unwrap_or(f.as_str()))
        .collect();

    harness.lines()
        .filter(|line| {
            let trimmed = line.trim();
            if !trimmed.starts_with("#include") { return true; }
            !stems.iter().any(|stem| trimmed.contains(stem))
        })
        .collect::<Vec<_>>()
        .join("\n")
}

pub fn build_extern_c_block(target_files: &[String]) -> String {
    let c_files: Vec<&String> = target_files.iter()
        .filter(|f| f.ends_with(".c"))
        .collect();

    if c_files.is_empty() {
        return String::new();
    }

    let mut decls = Vec::new();
    for path in &c_files {
        for sig in get_all_functions(path) {
            if sig.name == "main" { continue; }
            let params: Vec<String> = sig.params.iter().map(|p| {
                if p.param_name.is_empty() {
                    p.type_name.clone()
                } else {
                    format!("{} {}", p.type_name, p.param_name)
                }
            }).collect();
            decls.push(format!(
                "    {} {}({});",
                sig.return_type, sig.name, params.join(", ")
            ));
        }
    }

    if decls.is_empty() {
        return String::new();
    }

    format!(
        "/* --- extern \"C\" declarations injected by Guzzle --- */\nextern \"C\" {{\n{}\n}}\n/* ---------------------------------------------------- */\n\n",
        decls.join("\n")
    )
}
