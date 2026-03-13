use std::collections::HashMap;
use std::path::Path;

fn fnv1a(data: &[u8]) -> u64 {
    let mut h: u64 = 14695981039346656037;
    for b in data {
        h ^= *b as u64;
        h = h.wrapping_mul(1099511628211);
    }
    h
}

fn cache_path(file_path: &str) -> Option<std::path::PathBuf> {
    Path::new(file_path)
        .parent()
        .map(|p| p.join(".guzzle").join("harness_cache.json"))
}

fn build_key(file_path: &str, function_name: &str) -> Result<String, String> {
    let data = std::fs::read(file_path).map_err(|e| e.to_string())?;
    let hash = fnv1a(&data);
    Ok(format!("{:016x}:{}", hash, function_name))
}

#[tauri::command]
pub fn get_cached_harness(
    file_path: String,
    function_name: String,
) -> Result<Option<String>, String> {
    let key = match build_key(&file_path, &function_name) {
        Ok(k) => k,
        Err(_) => return Ok(None), // file unreadable → cache miss
    };

    let cache_file = cache_path(&file_path).ok_or("invalid file path")?;
    if !cache_file.exists() {
        return Ok(None);
    }

    let contents = std::fs::read_to_string(&cache_file).map_err(|e| e.to_string())?;
    let map: HashMap<String, String> =
        serde_json::from_str(&contents).map_err(|e| e.to_string())?;
    Ok(map.get(&key).cloned())
}

#[tauri::command]
pub fn save_cached_harness(
    file_path: String,
    function_name: String,
    harness: String,
) -> Result<(), String> {
    let key = build_key(&file_path, &function_name)?;

    let cache_file = cache_path(&file_path).ok_or("invalid file path")?;

    let mut map: HashMap<String, String> = if cache_file.exists() {
        let contents = std::fs::read_to_string(&cache_file).map_err(|e| e.to_string())?;
        serde_json::from_str(&contents).unwrap_or_default()
    } else {
        HashMap::new()
    };

    map.insert(key, harness);

    if let Some(dir) = cache_file.parent() {
        std::fs::create_dir_all(dir).map_err(|e| e.to_string())?;
    }
    let json = serde_json::to_string_pretty(&map).map_err(|e| e.to_string())?;
    std::fs::write(&cache_file, json).map_err(|e| e.to_string())?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::TempDir;

    /// Create a temp dir with a single C source file inside it.
    /// Returns (TempDir, path-string-of-the-file). TempDir must stay alive for the test.
    fn make_tmpfile(content: &str) -> (TempDir, String) {
        let dir = tempfile::tempdir().unwrap();
        let file_path = dir.path().join("src.c");
        let mut f = std::fs::File::create(&file_path).unwrap();
        writeln!(f, "{}", content).unwrap();
        let path = file_path.to_str().unwrap().to_string();
        (dir, path)
    }

    #[test]
    fn cache_miss_nonexistent_file() {
        let result = get_cached_harness(
            "/nonexistent/path/that/does/not/exist.c".to_string(),
            "my_func".to_string(),
        );
        assert_eq!(result, Ok(None));
    }

    #[test]
    fn round_trip_save_and_get() {
        let (_dir, path) = make_tmpfile("int foo() { return 42; }");

        save_cached_harness(path.clone(), "foo".to_string(), "harness_code".to_string())
            .unwrap();
        let result = get_cached_harness(path.clone(), "foo".to_string()).unwrap();
        assert_eq!(result, Some("harness_code".to_string()));
    }

    #[test]
    fn different_function_name_different_entry() {
        let (_dir, path) = make_tmpfile("void bar() {}");

        save_cached_harness(path.clone(), "func_a".to_string(), "harness_a".to_string())
            .unwrap();
        save_cached_harness(path.clone(), "func_b".to_string(), "harness_b".to_string())
            .unwrap();

        assert_eq!(
            get_cached_harness(path.clone(), "func_a".to_string()).unwrap(),
            Some("harness_a".to_string())
        );
        assert_eq!(
            get_cached_harness(path.clone(), "func_b".to_string()).unwrap(),
            Some("harness_b".to_string())
        );
    }

    #[test]
    fn file_content_change_causes_cache_miss() {
        let (_dir, path) = make_tmpfile("int baz() { return 1; }");

        save_cached_harness(path.clone(), "baz".to_string(), "harness_v1".to_string())
            .unwrap();

        // Overwrite file content
        let mut f = std::fs::OpenOptions::new()
            .write(true)
            .truncate(true)
            .open(&path)
            .unwrap();
        writeln!(f, "int baz() {{ return 999; }}").unwrap();
        drop(f);

        let result = get_cached_harness(path.clone(), "baz".to_string()).unwrap();
        assert_eq!(result, None);
    }
}
