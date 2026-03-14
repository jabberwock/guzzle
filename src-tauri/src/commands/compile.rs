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
#ifndef _WIN32
#include <unistd.h>
#include <fcntl.h>
#endif
#include <setjmp.h>

/* Rename the user's entry point so we can wrap it with setjmp protection */
#define LLVMFuzzerTestOneInput __guzzle_fuzz_impl

/* Override exit() — some targets call exit(0) on bad input which would kill
   the entire fuzzer process. longjmp back to our wrapper instead.
   NOTE: abort() is intentionally NOT overridden — ASan uses it to signal
   crashes to libFuzzer's signal handler.
   NOTE: Windows/lld-link statically links the CRT so exit() cannot be
   redefined; skip the override there. */
jmp_buf __guzzle_exit_buf;
static int __guzzle_jmp_ready = 0;
#ifndef _WIN32
extern "C" void exit(int code) {
    if (__guzzle_jmp_ready) { longjmp(__guzzle_exit_buf, 1); }
    /* setjmp not called yet (e.g. during startup) — let it propagate */
    __builtin_trap();
}
#endif
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

        guzzle_dir.join(if cfg!(windows) { "fuzzer.exe" } else { "fuzzer" }).to_string_lossy().to_string()
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
    cmd.args(["-D_CRT_SECURE_NO_WARNINGS", "-ldbghelp", "-lshell32"]);

    cmd.arg("-o").arg(&out_path);
    cmd.stdout(Stdio::piped());
    cmd.stderr(Stdio::piped());

    let args_display = cmd.get_args()
        .map(|a| a.to_string_lossy().to_string())
        .collect::<Vec<_>>()
        .join(" ");
    let _ = app.emit("compile_output", format!("$ {clang} {args_display}"));

    // Set working dir to temp so clang's intermediate files don't land in
    // src-tauri/ (the cargo run cwd), which would trigger Tauri's file watcher.
    cmd.current_dir(&temp_dir);
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

    let mut lines = vec![
        "/* --- extern \"C\" declarations injected by Guzzle --- */".to_string(),
        "extern \"C\" {".to_string(),
    ];

    for path in &c_files {
        // If a companion header exists (e.g. msgparse.h for msgparse.c), include it.
        // This brings in type definitions that forward-declarations alone can't provide.
        let header = std::path::Path::new(path).with_extension("h");
        if header.exists() {
            lines.push(format!("    #include \"{}\"", header.to_string_lossy().replace('\\', "/")));
            continue;
        }

        // No header — fall back to forward-declaring each function.
        // Collect any unknown struct/typedef names used in signatures so we
        // can emit forward declarations and avoid "unknown type" errors.
        let mut seen_types: std::collections::HashSet<String> = std::collections::HashSet::new();
        let sigs: Vec<_> = get_all_functions(path)
            .into_iter()
            .filter(|s| s.name != "main")
            .collect();

        // Strip storage-class specifiers and qualifiers to get the bare type name.
        // e.g. "static TlvField *" -> "TlvField"
        let bare_type = |t: &str| -> String {
            let mut s = t.trim();
            for kw in &["static ", "extern ", "inline ", "volatile ", "const ",
                        "static\t", "extern\t", "inline\t", "volatile\t", "const\t"] {
                while s.starts_with(kw) {
                    s = s[kw.len()..].trim();
                }
            }
            s.trim_end_matches('*').trim()
             .trim_end_matches("const").trim()
             .trim_end_matches('*').trim()
             .to_string()
        };

        // Emit `typedef struct X X;` for any non-primitive pointer types.
        let primitive = |t: &str| {
            matches!(t, "void"|"int"|"char"|"float"|"double"|"long"|"short"
                       |"uint8_t"|"uint16_t"|"uint32_t"|"uint64_t"
                       |"int8_t"|"int16_t"|"int32_t"|"int64_t"
                       |"size_t"|"bool"|"unsigned"|"signed")
        };
        for sig in &sigs {
            let all_types = std::iter::once(sig.return_type.as_str())
                .chain(sig.params.iter().map(|p| p.type_name.as_str()));
            for t in all_types {
                let base = bare_type(t);
                if !base.is_empty() && !primitive(&base) && seen_types.insert(base.clone()) {
                    lines.push(format!("    typedef struct {base} {base};"));
                }
            }
        }

        for sig in &sigs {
            // Skip static functions — they have internal linkage and can't be
            // called from outside the translation unit, so declaring them in
            // an extern "C" block would be both wrong and unnecessary.
            let ret = sig.return_type.trim();
            if ret.starts_with("static ") || ret.starts_with("static\t") {
                continue;
            }
            let params: Vec<String> = sig.params.iter().map(|p| {
                if p.param_name.is_empty() {
                    p.type_name.clone()
                } else {
                    format!("{} {}", p.type_name, p.param_name)
                }
            }).collect();
            lines.push(format!(
                "    {} {}({});",
                ret, sig.name, params.join(", ")
            ));
        }
    }

    lines.push("}".to_string());
    lines.push("/* ---------------------------------------------------- */\n".to_string());
    lines.join("\n") + "\n"
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    // --- strip_target_includes ---

    #[test]
    fn strip_removes_target_include() {
        let harness = "#include \"msgparse.c\"\nint x;";
        let result = strip_target_includes(harness, &["/path/to/msgparse.c".to_string()]);
        assert!(!result.contains("#include \"msgparse.c\""));
        assert!(result.contains("int x;"));
    }

    #[test]
    fn strip_keeps_system_include() {
        let harness = "#include <stdio.h>\nint x;";
        let result = strip_target_includes(harness, &["msgparse.c".to_string()]);
        assert!(result.contains("#include <stdio.h>"));
    }

    #[test]
    fn strip_keeps_other_header() {
        let harness = "#include \"other.h\"\nint x;";
        let result = strip_target_includes(harness, &["msgparse.c".to_string()]);
        assert!(result.contains("#include \"other.h\""));
    }

    #[test]
    fn strip_empty_targets_unchanged() {
        let harness = "#include \"foo.c\"\nint x;";
        let result = strip_target_includes(harness, &[]);
        assert_eq!(result, harness);
    }

    #[test]
    fn strip_preserves_comment_containing_target_name() {
        // A comment that mentions a target filename is not an include — keep it
        let harness = "// msgparse.c is the parser\nint x;";
        let result = strip_target_includes(harness, &["msgparse.c".to_string()]);
        assert!(result.contains("// msgparse.c is the parser"));
    }

    // --- build_extern_c_block ---

    #[test]
    fn extern_c_empty_input() {
        assert_eq!(build_extern_c_block(&[]), "");
    }

    #[test]
    fn extern_c_cpp_only() {
        assert_eq!(build_extern_c_block(&["foo.cpp".to_string()]), "");
    }

    #[test]
    fn extern_c_c_file_primitive_types() {
        let mut f = tempfile::Builder::new().suffix(".c").tempfile().unwrap();
        writeln!(f, "int add(int a, int b) {{ return a + b; }}").unwrap();
        let path = f.path().to_string_lossy().to_string();

        let result = build_extern_c_block(&[path]);
        assert!(result.contains("extern \"C\""));
        assert!(result.contains("int add("));
        assert!(!result.contains("typedef struct"));
    }

    #[test]
    fn extern_c_c_file_custom_type_emits_typedef() {
        let mut f = tempfile::Builder::new().suffix(".c").tempfile().unwrap();
        // TlvField is a non-primitive type — build_extern_c_block should emit a typedef
        writeln!(f, "TlvField *parse(unsigned char *buf, int len) {{ return 0; }}").unwrap();
        let path = f.path().to_string_lossy().to_string();

        let result = build_extern_c_block(&[path]);
        assert!(result.contains("typedef struct TlvField TlvField;"));
    }

    #[test]
    fn extern_c_static_qualifier_stripped_from_typedef() {
        // Functions with `static` return types (e.g. `static TlvField *parse(...)`)
        // must not produce `typedef struct static TlvField static TlvField;`
        let mut f = tempfile::Builder::new().suffix(".c").tempfile().unwrap();
        writeln!(f, "typedef struct TlvField TlvField;").unwrap();
        writeln!(f, "static TlvField *parse(const unsigned char *buf, int len) {{ return 0; }}").unwrap();
        let path = f.path().to_string_lossy().to_string();

        let result = build_extern_c_block(&[path]);
        assert!(!result.contains("struct static"), "static must not appear inside typedef struct");
        assert!(result.contains("typedef struct TlvField TlvField") || result.contains("TlvField"));
    }

    #[test]
    fn extern_c_c_file_with_companion_header() {
        let dir = tempfile::tempdir().unwrap();
        let c_path = dir.path().join("mylib.c");
        let h_path = dir.path().join("mylib.h");
        std::fs::write(&c_path, "int foo(int x) { return x; }").unwrap();
        std::fs::write(&h_path, "int foo(int x);").unwrap();

        let result = build_extern_c_block(&[c_path.to_string_lossy().to_string()]);
        let h_str = h_path.to_string_lossy().replace('\\', "/");
        assert!(result.contains(&format!("#include \"{h_str}\"")));
    }

    // --- Preamble regression tests ---

    #[test]
    fn preamble_unistd_guarded_by_ifndef_win32() {
        let ifndef_pos = HARNESS_PREAMBLE.find("#ifndef _WIN32")
            .expect("#ifndef _WIN32 not found in preamble");
        let unistd_pos = HARNESS_PREAMBLE.find("unistd.h")
            .expect("unistd.h not found in preamble");
        assert!(ifndef_pos < unistd_pos,
            "#ifndef _WIN32 must appear before unistd.h");
    }

    #[test]
    fn preamble_exit_override_guarded_by_ifndef_win32() {
        let exit_pos = HARNESS_PREAMBLE.find("extern \"C\" void exit(")
            .expect("exit() override not found in preamble");
        // The nearest #ifndef _WIN32 before the exit() declaration must exist
        HARNESS_PREAMBLE[..exit_pos].rfind("#ifndef _WIN32")
            .expect("exit() override must be inside #ifndef _WIN32 guard");
    }

    #[test]
    fn preamble_no_crt_secure_no_warnings() {
        assert!(!HARNESS_PREAMBLE.contains("_CRT_SECURE_NO_WARNINGS"),
            "_CRT_SECURE_NO_WARNINGS must be a compiler flag, not in the preamble");
    }

    #[test]
    fn fuzzer_binary_name_has_exe_on_windows() {
        let name = if cfg!(windows) { "fuzzer.exe" } else { "fuzzer" };
        if cfg!(windows) {
            assert!(name.ends_with(".exe"));
        } else {
            assert!(!name.contains('.'));
        }
    }
}
