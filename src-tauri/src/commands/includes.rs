use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

#[derive(Debug, Serialize, Deserialize)]
pub struct ResolvedIncludes {
    /// Non-default include directories that resolve headers from the target file.
    /// Pass as -I flags to the compiler.
    pub include_dirs: Vec<String>,
    /// Header include paths (e.g. "znc/Message.h") confirmed to exist on this system.
    /// Pass to the AI so it knows which #include <...> directives are safe to use.
    pub available_headers: Vec<String>,
    /// Header include paths not found in any candidate directory.
    pub unresolved: Vec<String>,
}

/// Extract `#include <path/to/header.h>` directives that look like library headers.
/// Standard-lib headers (e.g. `<stdio.h>`, `<stdint.h>`) have no slash and are skipped —
/// those are always available and the AI already knows to use them.
pub fn parse_angle_includes(source: &str) -> Vec<String> {
    source
        .lines()
        .filter_map(|line| {
            let line = line.trim();
            if !line.starts_with("#include") {
                return None;
            }
            let rest = line["#include".len()..].trim();
            if rest.starts_with('<') {
                let end = rest.find('>')?;
                let header = &rest[1..end];
                // Only library headers have a directory component (e.g. znc/Message.h)
                if header.contains('/') {
                    return Some(header.to_string());
                }
            }
            None
        })
        .collect()
}

/// Candidate system include directories to search, in preference order.
fn candidate_dirs() -> Vec<PathBuf> {
    let mut dirs: Vec<PathBuf> = Vec::new();

    // ── macOS ─────────────────────────────────────────────────────────────────
    #[cfg(target_os = "macos")]
    {
        dirs.push("/opt/homebrew/include".into()); // Homebrew Apple Silicon
        dirs.push("/usr/local/include".into());    // Homebrew Intel / manual installs
        dirs.push("/opt/local/include".into());    // MacPorts
        dirs.push("/usr/include".into());          // Xcode CLI tools
    }

    // ── Linux ─────────────────────────────────────────────────────────────────
    #[cfg(target_os = "linux")]
    {
        dirs.push("/usr/include".into());
        dirs.push("/usr/local/include".into());
        // Debian/Ubuntu multiarch paths
        #[cfg(target_arch = "x86_64")]
        dirs.push("/usr/include/x86_64-linux-gnu".into());
        #[cfg(target_arch = "aarch64")]
        dirs.push("/usr/include/aarch64-linux-gnu".into());
    }

    // ── Windows ───────────────────────────────────────────────────────────────
    #[cfg(target_os = "windows")]
    {
        for base in &[
            r"C:\Program Files\LLVM\include",
            r"C:\Program Files (x86)\LLVM\include",
        ] {
            dirs.push((*base).into());
        }
        if let Ok(home) = std::env::var("USERPROFILE") {
            dirs.push(format!(r"{home}\scoop\apps\llvm\current\include").into());
        }
        // INCLUDE env var (MSVC-style)
        if let Ok(inc) = std::env::var("INCLUDE") {
            for p in inc.split(';').filter(|p| !p.is_empty()) {
                dirs.push(p.into());
            }
        }
    }

    // ── All platforms: CPATH / C_INCLUDE_PATH / CPLUS_INCLUDE_PATH ───────────
    #[cfg(not(target_os = "windows"))]
    let sep = ':';
    #[cfg(target_os = "windows")]
    let sep = ';';

    for var in &["CPATH", "C_INCLUDE_PATH", "CPLUS_INCLUDE_PATH"] {
        if let Ok(val) = std::env::var(var) {
            for p in val.split(sep).filter(|p| !p.is_empty()) {
                dirs.push(p.into());
            }
        }
    }

    dirs
}

/// Returns true for directories that clang already searches without any -I flag.
/// We still report headers found there as `available_headers`, but we skip adding
/// them to `include_dirs` since the compiler would see them anyway.
fn is_default_search_dir(dir: &Path) -> bool {
    let defaults: &[&str] = &[
        "/usr/include",
        "/usr/local/include",
        "/usr/include/x86_64-linux-gnu",
        "/usr/include/aarch64-linux-gnu",
    ];
    defaults.iter().any(|d| dir == Path::new(d))
}

#[tauri::command]
pub async fn resolve_includes(file_path: String) -> Result<ResolvedIncludes, String> {
    let source = std::fs::read_to_string(&file_path)
        .map_err(|e| format!("Failed to read file: {e}"))?;

    let headers = parse_angle_includes(&source);

    if headers.is_empty() {
        return Ok(ResolvedIncludes {
            include_dirs: vec![],
            available_headers: vec![],
            unresolved: vec![],
        });
    }

    let candidates = candidate_dirs();
    let mut include_dirs: Vec<String> = Vec::new();
    let mut available_headers: Vec<String> = Vec::new();
    let mut unresolved: Vec<String> = Vec::new();

    for header in &headers {
        let mut found = false;
        for dir in &candidates {
            if dir.join(header).exists() {
                found = true;
                available_headers.push(header.clone());
                if !is_default_search_dir(dir) {
                    let dir_str = dir.to_string_lossy().to_string();
                    if !include_dirs.contains(&dir_str) {
                        include_dirs.push(dir_str);
                    }
                }
                break; // first match wins
            }
        }
        if !found {
            unresolved.push(header.clone());
        }
    }

    Ok(ResolvedIncludes {
        include_dirs,
        available_headers,
        unresolved,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_skips_standard_headers() {
        let src = r#"
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
"#;
        assert!(parse_angle_includes(src).is_empty());
    }

    #[test]
    fn parse_extracts_library_headers() {
        let src = r#"
#include <stdio.h>
#include <znc/Message.h>
#include <openssl/ssl.h>
#include <libpng16/png.h>
"#;
        let headers = parse_angle_includes(src);
        assert_eq!(headers, vec!["znc/Message.h", "openssl/ssl.h", "libpng16/png.h"]);
    }

    #[test]
    fn parse_skips_quoted_includes() {
        let src = r#"
#include "myheader.h"
#include <znc/Message.h>
"#;
        let headers = parse_angle_includes(src);
        assert_eq!(headers, vec!["znc/Message.h"]);
    }

    #[test]
    fn parse_handles_whitespace_variants() {
        let src = "#include  <foo/bar.h>\n  #include <baz/qux.h>";
        let headers = parse_angle_includes(src);
        assert_eq!(headers, vec!["foo/bar.h", "baz/qux.h"]);
    }

    #[test]
    fn resolve_nonexistent_file_returns_error() {
        let rt = tokio::runtime::Runtime::new().unwrap();
        let result = rt.block_on(resolve_includes("/nonexistent/path/file.h".to_string()));
        assert!(result.is_err());
    }

    #[test]
    fn is_default_dir_recognises_standard_paths() {
        assert!(is_default_search_dir(Path::new("/usr/include")));
        assert!(is_default_search_dir(Path::new("/usr/local/include")));
        assert!(!is_default_search_dir(Path::new("/opt/homebrew/include")));
        assert!(!is_default_search_dir(Path::new("/opt/local/include")));
    }
}
