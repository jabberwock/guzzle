use serde::{Deserialize, Serialize};
use tree_sitter::{Node, Parser};

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Param {
    pub type_name: String,
    pub param_name: String,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct FunctionSignature {
    pub name: String,
    pub return_type: String,
    pub params: Vec<Param>,
    pub start_line: u32,
    pub end_line: u32,
}

#[tauri::command]
pub async fn parse_function_at_line(
    file_path: String,
    line_number: u32,
) -> Result<Option<FunctionSignature>, String> {
    let source = std::fs::read_to_string(&file_path)
        .map_err(|e| format!("Failed to read file: {e}"))?;

    parse_function(&source, line_number)
}

/// Extract all top-level function definitions from a C/C++ source file.
/// Used by the compile step to generate extern "C" forward declarations.
pub fn get_all_functions(file_path: &str) -> Vec<FunctionSignature> {
    let source = match std::fs::read_to_string(file_path) {
        Ok(s) => s,
        Err(_) => return vec![],
    };
    let mut parser = Parser::new();
    if parser.set_language(&tree_sitter_c::language()).is_err() {
        return vec![];
    }
    let tree = match parser.parse(&source, None) {
        Some(t) => t,
        None => return vec![],
    };

    let mut sigs = Vec::new();
    let root = tree.root_node();
    let mut cursor = root.walk();
    for child in root.children(&mut cursor) {
        if child.kind() == "function_definition" {
            if let Some(sig) = extract_signature(child, &source) {
                // Skip main() — the harness provides its own entry point
                if sig.name != "main" {
                    sigs.push(sig);
                }
            }
        }
    }
    sigs
}

fn parse_function(source: &str, line_number: u32) -> Result<Option<FunctionSignature>, String> {
    let mut parser = Parser::new();
    parser
        .set_language(&tree_sitter_c::language())
        .map_err(|e| format!("Tree-sitter language error: {e}"))?;

    let tree = parser
        .parse(source, None)
        .ok_or_else(|| "Failed to parse source".to_string())?;

    let root = tree.root_node();
    let target_line = (line_number - 1) as usize; // tree-sitter is 0-indexed

    // Walk to find a function_definition enclosing target_line
    if let Some(func_node) = find_function_at_line(root, target_line) {
        let sig = extract_signature(func_node, source);
        return Ok(sig);
    }

    // Fallback: regex-based extraction from surrounding lines
    Ok(regex_fallback(source, line_number))
}

fn find_function_at_line<'a>(node: Node<'a>, line: usize) -> Option<Node<'a>> {
    if node.kind() == "function_definition" {
        let start = node.start_position().row;
        let end = node.end_position().row;
        if line >= start && line <= end {
            return Some(node);
        }
    }

    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        if let Some(found) = find_function_at_line(child, line) {
            return Some(found);
        }
    }
    None
}

fn extract_signature(node: Node, source: &str) -> Option<FunctionSignature> {
    let start_line = node.start_position().row as u32 + 1;
    let end_line = node.end_position().row as u32 + 1;

    // Get function name from the declarator chain
    let name = find_function_name(node, source)?;
    let return_type = extract_return_type(node, source);
    let params = extract_params(node, source);

    Some(FunctionSignature {
        name,
        return_type,
        params,
        start_line,
        end_line,
    })
}

fn find_function_name(node: Node, source: &str) -> Option<String> {
    // Walk into function_declarator -> identifier
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        if child.kind() == "function_declarator" {
            let mut c2 = child.walk();
            for sub in child.children(&mut c2) {
                if sub.kind() == "identifier" || sub.kind() == "field_identifier" {
                    return Some(sub.utf8_text(source.as_bytes()).unwrap_or("").to_string());
                }
                // Handle pointer declarator: (*func_name)
                if sub.kind() == "parenthesized_declarator" || sub.kind() == "pointer_declarator" {
                    if let Some(name) = find_identifier_in(sub, source) {
                        return Some(name);
                    }
                }
            }
        }
        // Try pointer_declarator wrapping function_declarator
        if child.kind() == "pointer_declarator" {
            if let Some(name) = find_function_name(child, source) {
                return Some(name);
            }
        }
    }
    None
}

fn find_identifier_in(node: Node, source: &str) -> Option<String> {
    if node.kind() == "identifier" {
        return Some(node.utf8_text(source.as_bytes()).unwrap_or("").to_string());
    }
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        if let Some(name) = find_identifier_in(child, source) {
            return Some(name);
        }
    }
    None
}

fn count_pointer_depth(node: Node) -> usize {
    // pointer_declarator nodes nest for each level: char ** -> pointer(pointer(fn))
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        if child.kind() == "pointer_declarator" {
            return 1 + count_pointer_depth(child);
        }
    }
    1
}

fn extract_return_type(node: Node, source: &str) -> String {
    // The first child before the declarator is the type specifier.
    // For pointer return types (e.g. `char *fn(...)`) tree-sitter wraps the
    // declarator in a pointer_declarator — collect the stars before breaking.
    let mut cursor = node.walk();
    let mut parts = Vec::new();
    for child in node.children(&mut cursor) {
        match child.kind() {
            "function_declarator" => break,
            "pointer_declarator" => {
                parts.push("*".repeat(count_pointer_depth(child)));
                break;
            }
            _ => {
                let text = child.utf8_text(source.as_bytes()).unwrap_or("").trim().to_string();
                if !text.is_empty() {
                    parts.push(text);
                }
            }
        }
    }
    parts.join(" ")
}

fn extract_params(node: Node, source: &str) -> Vec<Param> {
    let mut params = Vec::new();

    fn find_param_list<'a>(n: Node<'a>) -> Option<Node<'a>> {
        if n.kind() == "parameter_list" {
            return Some(n);
        }
        let mut cursor = n.walk();
        for child in n.children(&mut cursor) {
            if let Some(found) = find_param_list(child) {
                return Some(found);
            }
        }
        None
    }

    let Some(param_list) = find_param_list(node) else {
        return params;
    };

    let mut cursor = param_list.walk();
    for child in param_list.children(&mut cursor) {
        if child.kind() == "parameter_declaration" {
            let param = parse_parameter(child, source);
            params.push(param);
        }
    }

    params
}

fn parse_parameter(node: Node, source: &str) -> Param {
    let full_text = node.utf8_text(source.as_bytes()).unwrap_or("").trim().to_string();

    // Try to split into type and name
    // Heuristic: last identifier that isn't a type keyword is the param name
    let type_keywords = ["const", "volatile", "static", "unsigned", "signed", "long", "short",
                         "int", "char", "float", "double", "void", "struct", "enum", "union",
                         "size_t", "uint8_t", "uint16_t", "uint32_t", "uint64_t",
                         "int8_t", "int16_t", "int32_t", "int64_t"];

    // Get declarator (last identifier-ish child)
    let mut param_name = String::new();
    let mut type_parts: Vec<String> = Vec::new();

    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        match child.kind() {
            "identifier" => {
                param_name = child.utf8_text(source.as_bytes()).unwrap_or("").to_string();
            }
            "pointer_declarator" => {
                if let Some(name) = find_identifier_in(child, source) {
                    param_name = name;
                    type_parts.push("*".to_string());
                }
            }
            "abstract_declarator" => {
                // void parameter or no-name param
            }
            _ => {
                let text = child.utf8_text(source.as_bytes()).unwrap_or("").trim().to_string();
                if !text.is_empty() {
                    type_parts.push(text);
                }
            }
        }
    }

    let type_name = if type_parts.is_empty() {
        full_text.clone()
    } else {
        type_parts.join(" ")
    };

    // If we couldn't extract a separate name, use the full text
    if param_name.is_empty() && type_keywords.iter().any(|kw| type_name.contains(kw)) {
        Param { type_name, param_name: String::new() }
    } else if param_name.is_empty() {
        Param { type_name: full_text, param_name: String::new() }
    } else {
        Param { type_name, param_name }
    }
}

fn regex_fallback(source: &str, line_number: u32) -> Option<FunctionSignature> {
    let lines: Vec<&str> = source.lines().collect();
    let target = (line_number as usize).saturating_sub(1);

    // Search upward from target line for a function signature
    let start = target.saturating_sub(10);
    let snippet = lines[start..=target.min(lines.len() - 1)].join("\n");

    // Very rough regex: look for "type name(" pattern
    let re = regex_simple(&snippet)?;
    Some(FunctionSignature {
        name: re.0,
        return_type: re.1,
        params: vec![],
        start_line: line_number,
        end_line: line_number,
    })
}

fn regex_simple(text: &str) -> Option<(String, String)> {
    // Match: optional_type identifier (
    for line in text.lines().rev() {
        let line = line.trim();
        if line.contains('(') && !line.starts_with("//") && !line.starts_with("if")
            && !line.starts_with("while") && !line.starts_with("for")
        {
            if let Some(paren_pos) = line.find('(') {
                let before_paren = &line[..paren_pos];
                let parts: Vec<&str> = before_paren.split_whitespace().collect();
                if parts.len() >= 2 {
                    let name = parts.last()?.trim_start_matches('*').to_string();
                    let ret = parts[..parts.len() - 1].join(" ");
                    if !name.is_empty() {
                        return Some((name, ret));
                    }
                }
            }
        }
    }
    None
}
