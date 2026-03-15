use std::io::{BufRead, BufReader};
use std::path::PathBuf;
use std::process::{Command, Stdio};
use tauri::{AppHandle, Emitter};

use super::ai::{call_ai, AiProvider};
use super::compile::{build_extern_c_block, fix_c_fn_linkage, strip_target_includes};
use super::parser::FunctionSignature;
use super::toolchain::find_best_clang;

/// C stub that reads the crash file and calls LLVMFuzzerTestOneInput.
const REPRODUCER_MAIN: &str = r#"#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size);

int main(int argc, char **argv) {
    if (argc < 2) { fprintf(stderr, "usage: reproducer <crash_file>\n"); return 1; }
    FILE *f = fopen(argv[1], "rb");
    if (!f) { perror("fopen"); return 1; }
    fseek(f, 0, SEEK_END);
    long size = ftell(f);
    rewind(f);
    if (size <= 0) { fclose(f); return 1; }
    uint8_t *buf = (uint8_t *)malloc((size_t)size);
    if (!buf) { fclose(f); return 1; }
    fread(buf, 1, (size_t)size, f);
    fclose(f);
    int ret = LLVMFuzzerTestOneInput(buf, (size_t)size);
    free(buf);
    return ret;
}
"#;

enum RopTool {
    ROPgadget,
    Ropper,
}

fn find_rop_tool() -> Option<RopTool> {
    // Try ROPgadget first, then ropper
    for (name, variant) in &[("ROPgadget", true), ("ropper", false)] {
        // Probe by running --help and checking exit status or simply if the binary exists
        let found = Command::new(name)
            .arg("--help")
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .is_ok();
        if found {
            return Some(if *variant { RopTool::ROPgadget } else { RopTool::Ropper });
        }
    }
    None
}

fn run_rop_tool(tool: &RopTool, binary: &str, work_dir: &std::path::Path) -> Result<String, String> {
    let output = match tool {
        RopTool::ROPgadget => Command::new("ROPgadget")
            .args(["--binary", binary, "--rop", "--nosys"])
            .current_dir(work_dir)
            .output()
            .map_err(|e| format!("ROPgadget error: {e}"))?,
        RopTool::Ropper => Command::new("ropper")
            .args(["-f", binary])
            .current_dir(work_dir)
            .output()
            .map_err(|e| format!("ropper error: {e}"))?,
    };

    let text = String::from_utf8_lossy(&output.stdout).to_string();
    // Truncate to first 200 gadget lines
    let lines: Vec<&str> = text.lines().take(200).collect();
    Ok(lines.join("\n"))
}

fn emit(app: &AppHandle, msg: impl Into<String>) {
    let _ = app.emit("poc_log", msg.into());
}

#[tauri::command]
#[allow(clippy::too_many_arguments)]
#[cfg_attr(not(target_os = "linux"), allow(unused_variables, unreachable_code))]
pub async fn generate_poc(
    app: AppHandle,
    crash_path: String,
    harness_source: String,
    target_files: Vec<String>,
    includes: Vec<String>,
    library_files: Vec<String>,
    clang_override: Option<String>,
    provider: AiProvider,
    function_signature: FunctionSignature,
) -> Result<String, String> {
    // PoC generation depends on pwntools and Linux-specific tools (ROPgadget,
    // core dump analysis). Gate hard here rather than generating a broken script.
    #[cfg(not(target_os = "linux"))]
    return Err("PoC generation is only supported on Linux. \
        pwntools, core dump analysis, and ROP tooling require a Linux environment.".to_string());

    // ── Step 1: Check for ROP tool ──────────────────────────────────────────
    emit(&app, "[ 1/5 ] Checking for ROP gadget tool…");
    let rop_tool = find_rop_tool().ok_or_else(|| {
        "No ROP gadget tool found. Install one:\n  pip3 install ROPgadget\n  pip3 install ropper"
            .to_string()
    })?;
    let tool_name = match &rop_tool {
        RopTool::ROPgadget => "ROPgadget",
        RopTool::Ropper => "ropper",
    };
    emit(&app, format!("      Found: {tool_name}"));

    // ── Step 2: Write temp files ─────────────────────────────────────────────
    emit(&app, "[ 2/5 ] Preparing reproducer source…");
    let temp_dir = std::env::temp_dir().join("guzzle_poc");
    std::fs::create_dir_all(&temp_dir)
        .map_err(|e| format!("Failed to create temp dir: {e}"))?;

    // Write reproducer_main.c
    let main_path = temp_dir.join("reproducer_main.c");
    std::fs::write(&main_path, REPRODUCER_MAIN)
        .map_err(|e| format!("Failed to write reproducer_main.c: {e}"))?;

    // Prepare harness: strip direct target includes, prepend extern "C" block.
    // The extern "C" block uses uint8_t / size_t etc., so inject the standard
    // headers before it — the harness's own includes come after via harness_clean.
    let preamble = "#include <stdint.h>\n#include <stddef.h>\n#include <stdlib.h>\n#include <string.h>\n#include <stdio.h>\n";
    let harness_clean = strip_target_includes(&harness_source, &target_files);
    let harness_clean = fix_c_fn_linkage(&harness_clean, &target_files);
    let extern_c_block = build_extern_c_block(&target_files, &harness_clean);
    let harness_final = format!("{preamble}{extern_c_block}{harness_clean}");
    let harness_path = temp_dir.join("poc_harness.cpp");
    std::fs::write(&harness_path, &harness_final)
        .map_err(|e| format!("Failed to write poc_harness.cpp: {e}"))?;

    // ── Step 3: Compile reproducer binary ────────────────────────────────────
    emit(&app, "[ 3/5 ] Compiling reproducer binary (no sanitizers, -no-pie)…");

    let clang = clang_override
        .filter(|p| !p.is_empty())
        .or_else(find_best_clang)
        .ok_or_else(|| "No suitable clang found.".to_string())?;

    // Derive .guzzle dir from crash_path (crashes/.guzzle/crashes/crash-xxx -> .guzzle)
    let guzzle_dir = PathBuf::from(&crash_path)
        .parent()          // crashes/
        .and_then(|p| p.parent()) // .guzzle/
        .map(|p| p.to_path_buf())
        .unwrap_or_else(|| std::env::temp_dir().join("guzzle_poc"));
    let reproducer_path = guzzle_dir.join(if cfg!(windows) { "reproducer.exe" } else { "reproducer" });

    // Detect if any C target file defines main() — rename it to avoid conflict
    let target_has_main = target_files.iter()
        .filter(|f| f.ends_with(".c"))
        .any(|f| {
            let src = std::fs::read_to_string(f).unwrap_or_default();
            src.contains("int main(") || src.contains("int main (")
        });

    // -Dmain=__guzzle_target_main is a global preprocessor flag — if passed in a
    // single clang invocation it renames main in reproducer_main.c too, causing a
    // duplicate symbol. Fix: pre-compile any target C file that defines main() into
    // an object file (with the rename), then link the object instead of the source.
    let mut precompiled_objs: Vec<PathBuf> = Vec::new();
    for tf in &target_files {
        if !target_has_main || !tf.ends_with(".c") { continue; }
        let src = std::fs::read_to_string(tf).unwrap_or_default();
        if !src.contains("int main(") && !src.contains("int main (") { continue; }

        let stem = PathBuf::from(tf)
            .file_stem()
            .map(|s| s.to_string_lossy().to_string())
            .unwrap_or_else(|| "target".to_string());
        let obj_path = temp_dir.join(format!("{stem}.o"));

        let mut obj_cmd = Command::new(&clang);
        obj_cmd.args(["-O0", "-g", "-c", "-Dmain=__guzzle_target_main"]);
        #[cfg(target_os = "windows")]
        obj_cmd.arg("-D_CRT_SECURE_NO_WARNINGS");
        for inc in &includes { obj_cmd.arg(format!("-I{inc}")); }
        obj_cmd.arg("-x").arg("c").arg(tf);
        obj_cmd.arg("-o").arg(&obj_path);
        obj_cmd.stdout(Stdio::piped());
        obj_cmd.stderr(Stdio::piped());

        let args_display = obj_cmd.get_args()
            .map(|a| a.to_string_lossy().to_string())
            .collect::<Vec<_>>()
            .join(" ");
        emit(&app, format!("      [pre-compile] $ {clang} {args_display}"));

        obj_cmd.current_dir(&temp_dir);
        let mut obj_child = obj_cmd.spawn()
            .map_err(|e| format!("Failed to spawn clang for pre-compile: {e}"))?;
        let obj_stderr = obj_child.stderr.take().unwrap();
        let obj_stdout = obj_child.stdout.take().unwrap();
        let app_pre = app.clone();
        let t1 = tokio::task::spawn_blocking(move || {
            BufReader::new(obj_stderr).lines().map_while(Result::ok)
                .for_each(|l| emit(&app_pre, format!("      {l}")));
        });
        let app_pre2 = app.clone();
        let t2 = tokio::task::spawn_blocking(move || {
            BufReader::new(obj_stdout).lines().map_while(Result::ok)
                .for_each(|l| emit(&app_pre2, format!("      {l}")));
        });
        let obj_status = tokio::task::spawn_blocking(move || obj_child.wait())
            .await.map_err(|e| format!("join: {e}"))?
            .map_err(|e| format!("wait: {e}"))?;
        let _ = t1.await;
        let _ = t2.await;
        if !obj_status.success() {
            return Err(format!("Pre-compile of {tf} failed (exit {}). Check poc_log.", obj_status.code().unwrap_or(-1)));
        }
        precompiled_objs.push(obj_path);
    }

    let mut cmd = Command::new(&clang);
    // No sanitizers — we want real crashes, not ASan-caught ones
    cmd.args(["-O0", "-no-pie", "-fno-stack-protector", "-g"]);
    #[cfg(target_os = "windows")]
    cmd.arg("-D_CRT_SECURE_NO_WARNINGS");

    for inc in &includes {
        cmd.arg(format!("-I{inc}"));
    }

    // Harness as C++
    cmd.arg("-x").arg("c++");
    cmd.arg(harness_path.to_str().unwrap());

    // Target files — skip ones we pre-compiled to objects
    let precompiled_sources: std::collections::HashSet<&str> =
        if precompiled_objs.is_empty() { Default::default() }
        else { target_files.iter().filter(|f| f.ends_with(".c") && {
            let src = std::fs::read_to_string(f).unwrap_or_default();
            src.contains("int main(") || src.contains("int main (")
        }).map(|s| s.as_str()).collect() };

    for tf in &target_files {
        if precompiled_sources.contains(tf.as_str()) { continue; }
        let lang = if tf.ends_with(".c") { "c" } else { "c++" };
        cmd.arg("-x").arg(lang).arg(tf);
    }

    // reproducer_main.c as C — no -D rename, so its main() stays as main()
    cmd.arg("-x").arg("c");
    cmd.arg(main_path.to_str().unwrap());

    // Pre-compiled object files (no -x)
    if !precompiled_objs.is_empty() {
        cmd.arg("-x").arg("none");
        for obj in &precompiled_objs {
            cmd.arg(obj);
        }
    }

    // Pre-built libraries
    if !library_files.is_empty() {
        cmd.arg("-x").arg("none");
        for lib in &library_files {
            cmd.arg(lib);
        }
    }

    cmd.arg("-o").arg(reproducer_path.to_str().unwrap());
    cmd.stdout(Stdio::piped());
    cmd.stderr(Stdio::piped());

    let args_display = cmd.get_args()
        .map(|a| a.to_string_lossy().to_string())
        .collect::<Vec<_>>()
        .join(" ");
    emit(&app, format!("      $ {clang} {args_display}"));

    cmd.current_dir(&temp_dir);
    let mut child = cmd.spawn()
        .map_err(|e| format!("Failed to spawn clang: {e}"))?;

    let stderr = child.stderr.take().unwrap();
    let app_e = app.clone();
    let t_err = tokio::task::spawn_blocking(move || {
        BufReader::new(stderr)
            .lines()
            .map_while(Result::ok)
            .for_each(|l| emit(&app_e, format!("      {l}")));
    });

    let stdout = child.stdout.take().unwrap();
    let app_o = app.clone();
    let t_out = tokio::task::spawn_blocking(move || {
        BufReader::new(stdout)
            .lines()
            .map_while(Result::ok)
            .for_each(|l| emit(&app_o, format!("      {l}")));
    });

    let status = tokio::task::spawn_blocking(move || child.wait())
        .await
        .map_err(|e| format!("join: {e}"))?
        .map_err(|e| format!("wait: {e}"))?;

    let _ = t_err.await;
    let _ = t_out.await;

    if !status.success() {
        return Err(format!(
            "Reproducer compilation failed (exit {}). Check poc_log for details.",
            status.code().unwrap_or(-1)
        ));
    }
    emit(&app, format!("      Compiled: {}", reproducer_path.display()));
    emit(&app, format!("      Run it as: {} <crash_file>", reproducer_path.display()));

    // ── Step 4: Verify crash reproduces ──────────────────────────────────────
    emit(&app, "[ 4/5 ] Verifying crash reproduces…");
    let verify = Command::new(reproducer_path.to_str().unwrap())
        .arg(&crash_path)
        .current_dir(&temp_dir)
        .output();

    match verify {
        Ok(out) => {
            let code = out.status.code().unwrap_or(-1);
            if out.status.success() {
                emit(&app, "      WARNING: reproducer exited 0 — crash may not reproduce on clean binary.");
                emit(&app, "      (This is expected if the overflow is only caught by ASan, not a native SIGSEGV.)");
            } else {
                emit(&app, format!("      Crash reproduced (exit code {code}) ✓"));
            }
        }
        Err(e) => {
            emit(&app, format!("      WARNING: Could not run reproducer: {e}"));
        }
    }

    // ── Step 5: Extract ROP gadgets ──────────────────────────────────────────
    emit(&app, format!("[ 5/5 ] Extracting ROP gadgets with {tool_name}…"));
    let gadgets = match run_rop_tool(&rop_tool, reproducer_path.to_str().unwrap(), &temp_dir) {
        Ok(g) => {
            let count = g.lines().count();
            emit(&app, format!("      Found {count} gadget lines (truncated at 200)"));
            g
        }
        Err(e) => {
            emit(&app, format!("      WARNING: gadget extraction failed: {e}"));
            String::from("(gadget extraction failed)")
        }
    };

    // ── Step 6: Call AI ──────────────────────────────────────────────────────
    emit(&app, "[ AI  ] Sending to AI for PoC script generation…");

    let crash_bytes = std::fs::read(&crash_path).unwrap_or_default();
    let crash_size = crash_bytes.len();
    // Send up to 512 bytes — enough to capture full chunk structures in format-based
    // parsers (e.g. length-prefixed inputs) so the AI can identify the bug class
    // from the actual input layout rather than guessing.
    let preview_cap = 512.min(crash_size);
    let truncated = crash_size > preview_cap;
    let hex_preview: String = crash_bytes
        .iter()
        .take(preview_cap)
        .map(|b| format!("{b:02x}"))
        .collect::<Vec<_>>()
        .join(" ");
    let hex_preview = if truncated {
        format!("{hex_preview}  … ({} bytes total, first {preview_cap} shown)", crash_size)
    } else {
        hex_preview
    };

    // Extract the target function's source so the AI can see the actual bug
    // (e.g. integer overflow in size calculation before malloc) rather than
    // guessing the vulnerability class from the signature alone.
    let target_func_source: String = target_files.iter()
        .find_map(|tf| {
            let src = std::fs::read_to_string(tf).ok()?;
            let lines: Vec<&str> = src.lines().collect();
            let start = (function_signature.start_line as usize).saturating_sub(1);
            let end = (function_signature.end_line as usize).min(lines.len());
            let snippet = lines.get(start..end)?.join("\n");
            if snippet.contains(&function_signature.name) { Some(snippet) } else { None }
        })
        .unwrap_or_else(|| "(source not available)".to_string());

    let param_str = function_signature
        .params
        .iter()
        .map(|p| format!("{} {}", p.type_name, p.param_name))
        .collect::<Vec<_>>()
        .join(", ");
    let func_sig = format!(
        "{} {}({})",
        function_signature.return_type, function_signature.name, param_str
    );

    let system = "You are an expert binary exploitation researcher. \
        Generate complete, runnable pwntools Python3 exploit scripts. \
        Output only raw Python code with no markdown fences and no explanation."
        .to_string();

    // Truncate harness source to avoid blowing the context window — first 100
    // lines are enough for the AI to see how the crash input is parsed and
    // which function is called, which is what determines the vuln class.
    let harness_preview: String = harness_final
        .lines()
        .take(100)
        .collect::<Vec<_>>()
        .join("\n");

    let user = format!(
        r#"You are an expert binary exploitation researcher.

Target function: {func_sig}
Crash input hex: {hex_preview}
Crash input size: {crash_size} bytes
Binary: compiled with -no-pie -O0 -fno-stack-protector, NX enabled, no ASan
Reproducer binary: {reproducer_path}
Reproducer invocation: {reproducer_path} <crash_file_path>
IMPORTANT: the reproducer reads the payload from a FILE passed as argv[1], NOT from stdin.
To deliver a payload: write the bytes to a temp file, then run the reproducer with that path as the argument.
Do NOT use p.send() or p.sendline() — the process will exit immediately with code 1 if no file argument is given.

Target function source:
```c
{target_func_source}
```

Fuzzer harness source (shows how the crash input maps to function arguments):
```c
{harness_preview}
```

Available ROP gadgets:
{gadgets}

Step 1 — Identify the vulnerability class from the function signature and crash context:
- Stack buffer overflow: local buffer overwritten past its bounds, RIP/EIP control likely
- Heap buffer overflow: heap allocation too small for the data written into it (e.g. integer
  overflow in size calculation → undersized malloc → oversized copy)
- Use-after-free: memory accessed after free()
- Out-of-bounds read: read past allocation, useful for leaks
- Type confusion / integer overflow: incorrect type used for size/index arithmetic

Step 2 — Generate a complete pwntools Python3 exploit script appropriate for that class:

If STACK overflow:
  - Use cyclic() to find the exact offset to RIP/EIP
  - Demonstrate RIP control
  - If pop/ret gadgets are available, attempt ret2libc to call system("/bin/sh")

If HEAP overflow:
  - Do NOT use cyclic() to find a stack offset — there is none
  - Craft an input that triggers the overflow (demonstrate the allocator corruption or
    controlled write beyond the heap allocation)
  - Describe what heap metadata or adjacent object could be corrupted for further exploitation
  - If the binary is glibc, note relevant tcache/fastbin/unsorted-bin techniques

If USE-AFTER-FREE or OOB READ:
  - Craft an input that triggers the condition
  - Show how to achieve an information leak or controlled write

Always:
- Explain which vulnerability class was identified and why, in a comment at the top
- Include comments explaining each step
- Note ASLR: suggest disabling with:
    echo 0 | sudo tee /proc/sys/kernel/randomize_va_space

Return ONLY the Python3 source code, no markdown fences."#,
        reproducer_path = reproducer_path.display(),
    );

    let script = call_ai(&provider, system, user).await?;
    emit(&app, "      PoC script generated ✓");

    Ok(script)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reproducer_binary_name_has_exe_on_windows() {
        let name = if cfg!(windows) { "reproducer.exe" } else { "reproducer" };
        if cfg!(windows) {
            assert!(name.ends_with(".exe"));
        } else {
            assert!(!name.contains('.'));
        }
    }

    #[test]
    fn reproducer_main_contains_llvm_entry_point() {
        assert!(REPRODUCER_MAIN.contains("LLVMFuzzerTestOneInput"));
        assert!(REPRODUCER_MAIN.contains("int main("));
    }

    #[test]
    fn reproducer_main_no_main_rename_define() {
        // REPRODUCER_MAIN must never contain the rename macro — that would
        // defeat the purpose of the two-pass pre-compile workaround.
        assert!(!REPRODUCER_MAIN.contains("__guzzle_target_main"));
    }

    /// Guard that the Linux-only gate is never accidentally removed.
    #[test]
    fn poc_generation_gated_to_linux() {
        let src = include_str!("poc.rs");
        assert!(
            src.contains("#[cfg(not(target_os = \"linux\"))]"),
            "generate_poc must have a #[cfg(not(target_os = \"linux\"))] early-return gate"
        );
        assert!(
            src.contains("only supported on Linux"),
            "the Linux gate error message must mention 'only supported on Linux'"
        );
    }

    #[test]
    fn reproducer_verify_uses_temp_dir_not_src_tauri() {
        // This is a static analysis guard: the verification Command must call
        // current_dir so the harness can't write temp files to the cargo cwd
        // (src-tauri/), which would trigger Tauri's file watcher and restart
        // the app. We verify the source contains the expected call.
        let src = include_str!("poc.rs");
        // Find the verify block and confirm current_dir appears before .output()
        let verify_pos = src.find("let verify = Command::new").expect("verify block not found");
        let output_pos = src[verify_pos..].find(".output()").expect(".output() not found") + verify_pos;
        let current_dir_pos = src[verify_pos..].find(".current_dir(&temp_dir)").map(|p| p + verify_pos);
        assert!(
            current_dir_pos.map_or(false, |p| p < output_pos),
            "reproducer verify Command must set current_dir before .output()"
        );
    }
}
