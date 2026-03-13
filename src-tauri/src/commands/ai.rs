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
6. Add `#define _CRT_SECURE_NO_WARNINGS` before any includes to suppress MSVC
   deprecation warnings for standard C functions like fopen, strcpy, etc.
7. Add a brief comment explaining the fuzzing strategy

Return ONLY the C/C++ source code, no markdown fences."#,
        func_name = signature.name
    );

    (system, user)
}

/// Generic AI call — used by both harness generation and PoC generation.
pub async fn call_ai(provider: &AiProvider, system: String, user: String) -> Result<String, String> {
    let client = reqwest::Client::new();
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
    let client = reqwest::Client::new();

    match provider.format {
        ApiFormat::Openai => call_openai_compat(&client, &provider, system, user).await,
        ApiFormat::Anthropic => call_anthropic(&client, &provider, system, user).await,
    }
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
        max_tokens: 2048,
        temperature: 0.2,
    };

    let mut req = client.post(&url).json(&request);
    if !provider.api_key.is_empty() {
        req = req.bearer_auth(&provider.api_key);
    }

    let resp = req
        .send()
        .await
        .map_err(|e| format!("HTTP error: {e}"))?;

    if !resp.status().is_success() {
        let status = resp.status();
        let body = resp.text().await.unwrap_or_default();
        return Err(format!("{} API error {status}: {body}", provider.name));
    }

    let oai: OaiResponse = resp
        .json()
        .await
        .map_err(|e| format!("Failed to parse response: {e}"))?;

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
        max_tokens: 2048,
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

    if !resp.status().is_success() {
        let status = resp.status();
        let body = resp.text().await.unwrap_or_default();
        return Err(format!("Anthropic API error {status}: {body}"));
    }

    let ar: AnthropicResponse = resp
        .json()
        .await
        .map_err(|e| format!("Failed to parse Anthropic response: {e}"))?;

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
