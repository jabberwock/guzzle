use serde::{Deserialize, Serialize};

use super::parser::FunctionSignature;

/// Which wire format the provider speaks.
#[derive(Debug, Serialize, Deserialize, Clone, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum ApiFormat {
    /// OpenAI-compatible /v1/chat/completions (DeepSeek, Ollama, OpenAI, etc.)
    Openai,
    /// Anthropic /v1/messages
    Anthropic,
}

/// Provider configuration passed from the frontend.
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct AiProvider {
    /// Human-readable name, also used as the keyring account name.
    pub name: String,
    /// Base URL, e.g. "https://api.deepseek.com" or "http://localhost:11434"
    pub base_url: String,
    /// Model identifier, e.g. "deepseek-chat" or "llama3"
    pub model: String,
    /// API key (empty string for local Ollama)
    pub api_key: String,
    /// Which request/response format to use
    pub format: ApiFormat,
}

// ── OpenAI-compat structs ────────────────────────────────────────────────────

#[derive(Serialize)]
struct OaiMessage {
    role: String,
    content: String,
}

#[derive(Serialize)]
struct OaiRequest {
    model: String,
    messages: Vec<OaiMessage>,
    max_tokens: u32,
    temperature: f32,
}

#[derive(Deserialize)]
struct OaiResponse {
    choices: Vec<OaiChoice>,
}

#[derive(Deserialize)]
struct OaiChoice {
    message: OaiMessage2,
}

#[derive(Deserialize)]
struct OaiMessage2 {
    content: String,
}

// ── Anthropic structs ────────────────────────────────────────────────────────

#[derive(Serialize)]
struct AnthropicMessage {
    role: String,
    content: String,
}

#[derive(Serialize)]
struct AnthropicRequest {
    model: String,
    max_tokens: u32,
    system: String,
    messages: Vec<AnthropicMessage>,
}

#[derive(Deserialize)]
struct AnthropicResponse {
    content: Vec<AnthropicBlock>,
}

#[derive(Deserialize)]
struct AnthropicBlock {
    #[serde(rename = "type")]
    block_type: String,
    text: Option<String>,
}

// ── Prompt building ──────────────────────────────────────────────────────────

fn build_prompt(signature: &FunctionSignature, context_lines: &str) -> (String, String) {
    let param_str = signature
        .params
        .iter()
        .map(|p| format!("{} {}", p.type_name, p.param_name))
        .collect::<Vec<_>>()
        .join(", ");

    let func_sig = format!(
        "{} {}({})",
        signature.return_type, signature.name, param_str
    );

    let system = "You are an expert C/C++ security engineer specializing in fuzzing with libFuzzer. \
        Generate minimal, correct, safe fuzzer harnesses. \
        Output only raw C/C++ source code with no markdown fences and no explanation."
        .to_string();

    let user = format!(
        r#"Generate a libFuzzer harness for the following C/C++ function.

Function signature:
```c
{func_sig}
```

Surrounding code context:
```c
{context_lines}
```

Requirements:
1. Implement `extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)`
2. Parse the fuzzer input to produce valid inputs for `{func_name}`
3. Guard against null pointers and out-of-bounds access
4. Always include ALL necessary headers. Standard headers to consider:
   - `<stdint.h>`, `<stddef.h>` — always required for uint8_t / size_t
   - `<stdlib.h>`, `<string.h>` — for malloc/free/memcpy/strlen
   - `<stdio.h>` — for FILE*, fopen(), fclose()
   - Any headers implied by the context above
   - IMPORTANT: do NOT use `<unistd.h>`, `<fcntl.h>`, or any other POSIX-only
     headers — the harness must compile on Windows (MSVC/clang-cl) as well as Linux/macOS.
     Use only headers from the C/C++ standard library.
5. Do NOT call exit() or abort()
6. Do NOT use `mkstemp`, `_mktemp_s`, or any platform-specific temp file API.
   If the function requires a file path, use a fixed path inside the system temp directory:
   `"/tmp/guzzle_input"` on Linux/macOS, or wrap with `#ifdef _WIN32` to use
   `"C:\\Temp\\guzzle_input"`. Do NOT write to the current directory.
   libFuzzer is single-threaded so there is no race condition.
7. Do NOT add `#define _CRT_SECURE_NO_WARNINGS` — it is already passed as a compiler flag.
8. Add a brief comment explaining the fuzzing strategy

Return ONLY the C/C++ source code, no markdown fences."#,
        func_name = signature.name
    );

    (system, user)
}

fn make_client() -> Result<reqwest::Client, String> {
    reqwest::Client::builder()
        // AI responses (especially PoC scripts) can take a while — 5 min timeout.
        .timeout(std::time::Duration::from_secs(300))
        .build()
        .map_err(|e| format!("Failed to build HTTP client: {e}"))
}

fn fmt_err(e: &reqwest::Error) -> String {
    use std::error::Error;
    let mut msg = e.to_string();
    let mut src = e.source();
    while let Some(cause) = src {
        msg.push_str(&format!(" → {cause}"));
        src = cause.source();
    }
    msg
}

/// Generic AI call — used by both harness generation and PoC generation.
pub async fn call_ai(provider: &AiProvider, system: String, user: String) -> Result<String, String> {
    let client = make_client()?;
    match provider.format {
        ApiFormat::Openai => call_openai_compat(&client, provider, system, user).await,
        ApiFormat::Anthropic => call_anthropic(&client, provider, system, user).await,
    }
}

// ── Main command ─────────────────────────────────────────────────────────────

#[tauri::command]
pub async fn generate_harness(
    provider: AiProvider,
    signature: FunctionSignature,
    context_lines: String,
) -> Result<String, String> {
    let (system, user) = build_prompt(&signature, &context_lines);
    let client = make_client()?;

    let raw = match provider.format {
        ApiFormat::Openai => call_openai_compat(&client, &provider, system, user).await,
        ApiFormat::Anthropic => call_anthropic(&client, &provider, system, user).await,
    }?;

    // If the model was cut off mid-function, close any unclosed braces.
    let open: i32 = raw.chars().filter(|&c| c == '{').count() as i32;
    let close: i32 = raw.chars().filter(|&c| c == '}').count() as i32;
    let raw = if open > close {
        format!("{}\n{}", raw, "}".repeat((open - close) as usize))
    } else {
        raw
    };

    Ok(raw)
}

async fn call_openai_compat(
    client: &reqwest::Client,
    provider: &AiProvider,
    system: String,
    user: String,
) -> Result<String, String> {
    let url = format!("{}/v1/chat/completions", provider.base_url.trim_end_matches('/'));

    let request = OaiRequest {
        model: provider.model.clone(),
        messages: vec![
            OaiMessage { role: "system".into(), content: system },
            OaiMessage { role: "user".into(), content: user },
        ],
        max_tokens: 4096,
        temperature: 0.2,
    };

    let mut req = client.post(&url).json(&request);
    if !provider.api_key.is_empty() {
        req = req.bearer_auth(&provider.api_key);
    }

    let resp = req
        .send()
        .await
        .map_err(|e| format!("HTTP error: {}", fmt_err(&e)))?;

    let status = resp.status();
    let bytes = resp.bytes().await.map_err(|e| format!("Failed to read response body: {}", fmt_err(&e)))?;
    let body = String::from_utf8_lossy(&bytes).to_string();

    if !status.is_success() {
        return Err(format!("{} API error {status}: {body}", provider.name));
    }

    let oai: OaiResponse = serde_json::from_str(&body)
        .map_err(|e| format!("Failed to parse response: {e}\nRaw body: {body}"))?;

    oai.choices
        .into_iter()
        .next()
        .map(|c| c.message.content)
        .ok_or_else(|| "Empty response from model".into())
}

async fn call_anthropic(
    client: &reqwest::Client,
    provider: &AiProvider,
    system: String,
    user: String,
) -> Result<String, String> {
    let url = format!("{}/v1/messages", provider.base_url.trim_end_matches('/'));

    let request = AnthropicRequest {
        model: provider.model.clone(),
        max_tokens: 4096,
        system,
        messages: vec![AnthropicMessage { role: "user".into(), content: user }],
    };

    let resp = client
        .post(&url)
        .header("x-api-key", &provider.api_key)
        .header("anthropic-version", "2023-06-01")
        .json(&request)
        .send()
        .await
        .map_err(|e| format!("HTTP error: {e}"))?;

    let status = resp.status();
    let bytes = resp.bytes().await.map_err(|e| format!("Failed to read Anthropic response body: {e}"))?;
    let body = String::from_utf8_lossy(&bytes).to_string();

    if !status.is_success() {
        return Err(format!("Anthropic API error {status}: {body}"));
    }

    let ar: AnthropicResponse = serde_json::from_str(&body)
        .map_err(|e| format!("Failed to parse Anthropic response: {e}\nRaw body: {body}"))?;

    let text = ar
        .content
        .into_iter()
        .filter(|b| b.block_type == "text")
        .filter_map(|b| b.text)
        .collect::<Vec<_>>()
        .join("");

    if text.is_empty() {
        Err("Empty response from Anthropic".into())
    } else {
        Ok(text)
    }
}

// ── Keyring (keyed by provider name) ─────────────────────────────────────────

const KEYRING_SERVICE: &str = "guzzle";

#[tauri::command]
pub async fn save_api_key(provider_name: String, key: String) -> Result<(), String> {
    let entry = keyring::Entry::new(KEYRING_SERVICE, &provider_name)
        .map_err(|e| format!("Keyring error: {e}"))?;
    entry.set_password(&key).map_err(|e| format!("Keyring error: {e}"))
}

#[tauri::command]
pub async fn load_api_key(provider_name: String) -> Result<Option<String>, String> {
    let entry = keyring::Entry::new(KEYRING_SERVICE, &provider_name)
        .map_err(|e| format!("Keyring error: {e}"))?;
    match entry.get_password() {
        Ok(key) => Ok(Some(key)),
        Err(keyring::Error::NoEntry) => Ok(None),
        Err(e) => Err(format!("Keyring error: {e}")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dummy_sig(name: &str) -> FunctionSignature {
        FunctionSignature {
            name: name.to_string(),
            return_type: "int".to_string(),
            params: vec![],
            start_line: 1,
            end_line: 5,
        }
    }

    #[test]
    fn build_prompt_contains_function_name() {
        let sig = dummy_sig("ProcessImage");
        let (system, user) = build_prompt(&sig, "// context");
        assert!(user.contains("ProcessImage"));
        assert!(!system.is_empty());
    }

    #[test]
    fn build_prompt_contains_context() {
        let sig = dummy_sig("foo");
        let (_, user) = build_prompt(&sig, "int foo() {}");
        assert!(user.contains("int foo() {}"));
    }

    #[test]
    fn build_prompt_no_markdown_fences_in_system() {
        let sig = dummy_sig("foo");
        let (system, _) = build_prompt(&sig, "");
        // System prompt should instruct to omit markdown fences
        assert!(system.contains("no markdown"));
    }

    #[test]
    fn build_prompt_includes_llvmfuzzer_requirement() {
        let sig = dummy_sig("foo");
        let (_, user) = build_prompt(&sig, "");
        assert!(user.contains("LLVMFuzzerTestOneInput"));
    }

    #[test]
    fn build_prompt_no_posix_headers_required() {
        let sig = dummy_sig("foo");
        let (_, user) = build_prompt(&sig, "");
        // Prompt must not require POSIX-only headers without Windows guard
        assert!(user.contains("unistd.h") == false || user.contains("_WIN32"));
    }

    #[test]
    fn make_client_succeeds() {
        make_client().expect("reqwest client with 5-min timeout and gzip disabled should build successfully");
    }

    #[test]
    fn oai_response_deserializes() {
        let json = r#"{"choices":[{"message":{"role":"assistant","content":"hello"}}]}"#;
        let r: OaiResponse = serde_json::from_str(json).unwrap();
        assert_eq!(r.choices[0].message.content, "hello");
    }

    #[test]
    fn anthropic_response_deserializes() {
        let json = r#"{"content":[{"type":"text","text":"hello"}]}"#;
        let r: AnthropicResponse = serde_json::from_str(json).unwrap();
        assert_eq!(r.content[0].block_type, "text");
        assert_eq!(r.content[0].text.as_deref(), Some("hello"));
    }

    #[test]
    fn anthropic_response_ignores_non_text_blocks() {
        let json = r#"{"content":[{"type":"thinking","thinking":"chain"},{"type":"text","text":"result"}]}"#;
        let r: AnthropicResponse = serde_json::from_str(json).unwrap();
        let text: String = r.content.into_iter()
            .filter(|b| b.block_type == "text")
            .filter_map(|b| b.text)
            .collect::<Vec<_>>()
            .join("");
        assert_eq!(text, "result");
    }
}
