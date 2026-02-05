//! ZAP Schema Compiler
//!
//! Inspired by Cap'n Proto's zero-copy serialization approach, the ZAP Schema
//! Compiler provides a unified schema language with two supported syntaxes:
//!
//! - **`.zap` (default)** - Whitespace-significant, clean minimal syntax
//! - **`.capnp` (compatible)** - Backwards-compatible with existing Cap'n Proto schemas
//!
//! The `.zap` syntax is the recommended format for all new schemas, offering
//! cleaner, more readable definitions where ordering determines field ordinals.
//!
//! # ZAP Syntax Example (Recommended)
//!
//! ```zap
//! # ZAP Schema - clean and minimal
//! # Colons and semicolons are auto-inserted by the compiler
//!
//! struct Person
//!   name Text
//!   age UInt32
//!   email Text
//!   address Address
//!
//! struct Address
//!   street Text
//!   city Text
//!   zip Text
//!
//! enum Status
//!   pending
//!   active
//!   completed
//!
//! interface Greeter
//!   sayHello (name Text) -> (greeting Text)
//!   sayGoodbye (name Text) -> ()
//! ```
//!
//! # Cap'n Proto Compatibility
//!
//! For migration purposes, the compiler also accepts `.capnp` files with
//! standard Cap'n Proto syntax including explicit ordinals (@0, @1, etc.)
//! and brace-delimited blocks. This allows gradual migration from existing
//! Cap'n Proto schemas to the cleaner ZAP format.

use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};
use std::path::Path;

use crate::{Error, Result};

/// Schema format type
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SchemaFormat {
    /// ZAP whitespace-significant syntax (default for new schemas)
    Zap,
    /// Cap'n Proto syntax (backwards compatible)
    Capnp,
}

/// ZAP schema compiler
///
/// Supports both `.zap` (whitespace-significant) and `.capnp` (Cap'n Proto
/// compatible) syntaxes. The `.zap` format is the recommended default for
/// all new schema definitions.
pub struct ZapSchema {
    /// Source content
    source: String,
    /// File path (for ID generation)
    path: String,
    /// Schema format (auto-detected from extension or explicit)
    format: SchemaFormat,
}

#[derive(Debug, Clone)]
enum Item {
    Comment(String),
    Using(String),
    Const {
        name: String,
        typ: String,
        value: String,
    },
    Struct {
        name: String,
        fields: Vec<Field>,
        unions: Vec<Union>,
        nested: Vec<Item>,
    },
    Enum {
        name: String,
        variants: Vec<String>,
    },
    Interface {
        name: String,
        extends: Option<String>,
        methods: Vec<Method>,
        nested: Vec<Item>,
    },
}

#[derive(Debug, Clone)]
struct Field {
    name: String,
    typ: String,
    default: Option<String>,
}

#[derive(Debug, Clone)]
struct Union {
    name: Option<String>,
    fields: Vec<Field>,
}

#[derive(Debug, Clone)]
struct Method {
    name: String,
    params: Vec<Field>,
    results: Vec<Field>,
}

impl ZapSchema {
    /// Create a new ZAP schema from source (defaults to .zap format)
    pub fn new(source: &str, path: &str) -> Self {
        let format = Self::detect_format(path, source);
        Self {
            source: source.to_string(),
            path: path.to_string(),
            format,
        }
    }

    /// Create a schema with explicit format
    pub fn with_format(source: &str, path: &str, format: SchemaFormat) -> Self {
        Self {
            source: source.to_string(),
            path: path.to_string(),
            format,
        }
    }

    /// Load a ZAP schema from file (auto-detects format from extension)
    pub fn from_file(path: &Path) -> Result<Self> {
        let source = std::fs::read_to_string(path)
            .map_err(|e| Error::Config(format!("failed to read schema: {}", e)))?;
        let path_str = path.to_str().unwrap_or("schema.zap");
        let format = Self::detect_format(path_str, &source);
        Ok(Self {
            source,
            path: path_str.to_string(),
            format,
        })
    }

    /// Detect schema format from file extension or content
    fn detect_format(path: &str, source: &str) -> SchemaFormat {
        // Check file extension first
        if path.ends_with(".capnp") {
            return SchemaFormat::Capnp;
        }
        if path.ends_with(".zap") {
            return SchemaFormat::Zap;
        }

        // Heuristic: if source contains @0x (file ID) or @N; patterns, it's capnp
        if source.contains("@0x") || source.contains("@0;") || source.contains("@1;") {
            return SchemaFormat::Capnp;
        }

        // Default to ZAP format for new schemas
        SchemaFormat::Zap
    }

    /// Get the detected schema format
    pub fn format(&self) -> &SchemaFormat {
        &self.format
    }

    /// Generate a stable ID from a string
    fn generate_id(seed: &str) -> u64 {
        let mut hasher = DefaultHasher::new();
        seed.hash(&mut hasher);
        // ZAP IDs must have high bit set for uniqueness
        hasher.finish() | 0x8000_0000_0000_0000
    }

    /// Parse the schema (dispatches based on format)
    fn parse(&self) -> Result<Vec<Item>> {
        match self.format {
            SchemaFormat::Zap => self.parse_zap(),
            SchemaFormat::Capnp => self.parse_capnp(),
        }
    }

    /// Parse ZAP whitespace-significant format
    fn parse_zap(&self) -> Result<Vec<Item>> {
        let mut items = Vec::new();
        let lines: Vec<&str> = self.source.lines().collect();
        let mut i = 0;

        while i < lines.len() {
            let line = lines[i].trim();

            // Skip empty lines
            if line.is_empty() {
                i += 1;
                continue;
            }

            // Comments
            if line.starts_with('#') {
                items.push(Item::Comment(line[1..].trim().to_string()));
                i += 1;
                continue;
            }

            // Using/import
            if line.starts_with("using ") {
                items.push(Item::Using(line[6..].trim().to_string()));
                i += 1;
                continue;
            }

            // Const
            if line.starts_with("const ") {
                let rest = line[6..].trim();
                if let Some((name_type, value)) = rest.split_once('=') {
                    let name_type = name_type.trim();
                    let value = value.trim().to_string();
                    if let Some((name, typ)) = name_type.split_once(':') {
                        items.push(Item::Const {
                            name: name.trim().to_string(),
                            typ: typ.trim().to_string(),
                            value,
                        });
                    }
                }
                i += 1;
                continue;
            }

            // Struct
            if line.starts_with("struct ") {
                let name = line[7..].trim().to_string();
                let (fields, unions, nested, consumed) = self.parse_struct_body(&lines[i + 1..])?;
                items.push(Item::Struct { name, fields, unions, nested });
                i += 1 + consumed;
                continue;
            }

            // Enum
            if line.starts_with("enum ") {
                let name = line[5..].trim().to_string();
                let (variants, consumed) = self.parse_enum_body(&lines[i + 1..])?;
                items.push(Item::Enum { name, variants });
                i += 1 + consumed;
                continue;
            }

            // Interface
            if line.starts_with("interface ") {
                let rest = line[10..].trim();
                let (name, extends) = if let Some((n, e)) = rest.split_once("extends") {
                    (n.trim().to_string(), Some(e.trim().to_string()))
                } else {
                    (rest.to_string(), None)
                };
                let (methods, nested, consumed) = self.parse_interface_body(&lines[i + 1..])?;
                items.push(Item::Interface { name, extends, methods, nested });
                i += 1 + consumed;
                continue;
            }

            // Unknown line - skip
            i += 1;
        }

        Ok(items)
    }

    /// Parse Cap'n Proto brace-delimited format (backwards compatible)
    fn parse_capnp(&self) -> Result<Vec<Item>> {
        let mut items = Vec::new();

        // Remove comments and normalize whitespace for simpler parsing
        let mut source = String::new();
        for line in self.source.lines() {
            let line = if let Some(idx) = line.find('#') {
                &line[..idx]
            } else {
                line
            };
            source.push_str(line);
            source.push(' ');
        }

        // Tokenize: split on whitespace and punctuation, keeping punctuation
        let tokens = self.tokenize_capnp(&source);
        let mut pos = 0;

        while pos < tokens.len() {
            let token = &tokens[pos];

            // Skip file ID (@0xABC...)
            if token.starts_with('@') {
                pos += 1;
                if pos < tokens.len() && tokens[pos] == ";" {
                    pos += 1;
                }
                continue;
            }

            // Using/import
            if token == "using" {
                let mut import = String::new();
                pos += 1;
                while pos < tokens.len() && tokens[pos] != ";" {
                    import.push_str(&tokens[pos]);
                    import.push(' ');
                    pos += 1;
                }
                items.push(Item::Using(import.trim().to_string()));
                pos += 1; // skip ;
                continue;
            }

            // Const
            if token == "const" {
                pos += 1;
                let name = tokens.get(pos).cloned().unwrap_or_default();
                pos += 1;
                if tokens.get(pos).map(|s| s.as_str()) == Some(":") {
                    pos += 1;
                }
                let typ = tokens.get(pos).cloned().unwrap_or_default();
                pos += 1;
                if tokens.get(pos).map(|s| s.as_str()) == Some("=") {
                    pos += 1;
                }
                let value = tokens.get(pos).cloned().unwrap_or_default();
                pos += 1;
                if tokens.get(pos).map(|s| s.as_str()) == Some(";") {
                    pos += 1;
                }
                items.push(Item::Const { name, typ, value });
                continue;
            }

            // Struct
            if token == "struct" {
                pos += 1;
                let name = tokens.get(pos).cloned().unwrap_or_default();
                pos += 1;
                // Skip optional ID
                if pos < tokens.len() && tokens[pos].starts_with('@') {
                    pos += 1;
                }
                // Find opening brace
                while pos < tokens.len() && tokens[pos] != "{" {
                    pos += 1;
                }
                pos += 1; // skip {

                let (fields, unions, nested, new_pos) = self.parse_capnp_struct_body(&tokens, pos)?;
                pos = new_pos;

                items.push(Item::Struct { name, fields, unions, nested });
                continue;
            }

            // Enum
            if token == "enum" {
                pos += 1;
                let name = tokens.get(pos).cloned().unwrap_or_default();
                pos += 1;
                // Skip optional ID
                if pos < tokens.len() && tokens[pos].starts_with('@') {
                    pos += 1;
                }
                // Find opening brace
                while pos < tokens.len() && tokens[pos] != "{" {
                    pos += 1;
                }
                pos += 1; // skip {

                let (variants, new_pos) = self.parse_capnp_enum_body(&tokens, pos)?;
                pos = new_pos;

                items.push(Item::Enum { name, variants });
                continue;
            }

            // Interface
            if token == "interface" {
                pos += 1;
                let name = tokens.get(pos).cloned().unwrap_or_default();
                pos += 1;

                // Check for extends
                let mut extends = None;
                if pos < tokens.len() && tokens[pos] == "extends" {
                    pos += 1;
                    if pos < tokens.len() && tokens[pos] == "(" {
                        pos += 1;
                        extends = tokens.get(pos).cloned();
                        pos += 1;
                        if pos < tokens.len() && tokens[pos] == ")" {
                            pos += 1;
                        }
                    }
                }

                // Skip optional ID
                if pos < tokens.len() && tokens[pos].starts_with('@') {
                    pos += 1;
                }
                // Find opening brace
                while pos < tokens.len() && tokens[pos] != "{" {
                    pos += 1;
                }
                pos += 1; // skip {

                let (methods, nested, new_pos) = self.parse_capnp_interface_body(&tokens, pos)?;
                pos = new_pos;

                items.push(Item::Interface { name, extends, methods, nested });
                continue;
            }

            pos += 1;
        }

        Ok(items)
    }

    /// Tokenize Cap'n Proto source
    fn tokenize_capnp(&self, source: &str) -> Vec<String> {
        let mut tokens = Vec::new();
        let mut current = String::new();
        let mut in_string = false;
        let mut chars = source.chars().peekable();

        while let Some(c) = chars.next() {
            if in_string {
                current.push(c);
                if c == '"' {
                    tokens.push(std::mem::take(&mut current));
                    in_string = false;
                }
                continue;
            }

            match c {
                '"' => {
                    if !current.is_empty() {
                        tokens.push(std::mem::take(&mut current));
                    }
                    current.push(c);
                    in_string = true;
                }
                '{' | '}' | '(' | ')' | ';' | ':' | '=' | ',' => {
                    if !current.is_empty() {
                        tokens.push(std::mem::take(&mut current));
                    }
                    tokens.push(c.to_string());
                }
                '-' if chars.peek() == Some(&'>') => {
                    if !current.is_empty() {
                        tokens.push(std::mem::take(&mut current));
                    }
                    chars.next();
                    tokens.push("->".to_string());
                }
                c if c.is_whitespace() => {
                    if !current.is_empty() {
                        tokens.push(std::mem::take(&mut current));
                    }
                }
                _ => {
                    current.push(c);
                }
            }
        }

        if !current.is_empty() {
            tokens.push(current);
        }

        tokens
    }

    /// Parse Cap'n Proto struct body
    fn parse_capnp_struct_body(&self, tokens: &[String], mut pos: usize) -> Result<(Vec<Field>, Vec<Union>, Vec<Item>, usize)> {
        let mut fields = Vec::new();
        let mut unions = Vec::new();
        let mut nested = Vec::new();

        while pos < tokens.len() && tokens[pos] != "}" {
            let token = &tokens[pos];

            // Nested struct
            if token == "struct" {
                pos += 1;
                let name = tokens.get(pos).cloned().unwrap_or_default();
                pos += 1;
                if pos < tokens.len() && tokens[pos].starts_with('@') {
                    pos += 1;
                }
                while pos < tokens.len() && tokens[pos] != "{" {
                    pos += 1;
                }
                pos += 1;
                let (nfields, nunions, nnested, new_pos) = self.parse_capnp_struct_body(tokens, pos)?;
                pos = new_pos;
                nested.push(Item::Struct { name, fields: nfields, unions: nunions, nested: nnested });
                continue;
            }

            // Nested enum
            if token == "enum" {
                pos += 1;
                let name = tokens.get(pos).cloned().unwrap_or_default();
                pos += 1;
                if pos < tokens.len() && tokens[pos].starts_with('@') {
                    pos += 1;
                }
                while pos < tokens.len() && tokens[pos] != "{" {
                    pos += 1;
                }
                pos += 1;
                let (variants, new_pos) = self.parse_capnp_enum_body(tokens, pos)?;
                pos = new_pos;
                nested.push(Item::Enum { name, variants });
                continue;
            }

            // Union
            if token == "union" {
                pos += 1;
                if pos < tokens.len() && tokens[pos] == "{" {
                    pos += 1;
                }
                let mut union_fields = Vec::new();
                while pos < tokens.len() && tokens[pos] != "}" {
                    if let Some((field, new_pos)) = self.parse_capnp_field(tokens, pos)? {
                        union_fields.push(field);
                        pos = new_pos;
                    } else {
                        pos += 1;
                    }
                }
                pos += 1; // skip }
                unions.push(Union { name: None, fields: union_fields });
                continue;
            }

            // Regular field
            if let Some((field, new_pos)) = self.parse_capnp_field(tokens, pos)? {
                fields.push(field);
                pos = new_pos;
            } else {
                pos += 1;
            }
        }

        if pos < tokens.len() && tokens[pos] == "}" {
            pos += 1;
        }

        Ok((fields, unions, nested, pos))
    }

    /// Parse a single Cap'n Proto field
    fn parse_capnp_field(&self, tokens: &[String], mut pos: usize) -> Result<Option<(Field, usize)>> {
        // Field format: name @N :Type = default;
        if pos >= tokens.len() {
            return Ok(None);
        }

        let name = &tokens[pos];
        if name == "}" || name == "union" || name == "struct" || name == "enum" {
            return Ok(None);
        }

        pos += 1;

        // Skip ordinal @N
        if pos < tokens.len() && tokens[pos].starts_with('@') {
            pos += 1;
        }

        // Expect :
        if pos < tokens.len() && tokens[pos] == ":" {
            pos += 1;
        } else {
            return Ok(None);
        }

        // Get type (may be compound like List(Foo))
        let mut typ = String::new();
        let mut paren_depth = 0;
        while pos < tokens.len() {
            let t = &tokens[pos];
            if t == "=" || (t == ";" && paren_depth == 0) {
                break;
            }
            if t == "(" {
                paren_depth += 1;
            }
            if t == ")" {
                paren_depth -= 1;
            }
            typ.push_str(t);
            pos += 1;
        }

        // Check for default value
        let default = if pos < tokens.len() && tokens[pos] == "=" {
            pos += 1;
            let mut val = String::new();
            while pos < tokens.len() && tokens[pos] != ";" {
                val.push_str(&tokens[pos]);
                pos += 1;
            }
            Some(val)
        } else {
            None
        };

        // Skip ;
        if pos < tokens.len() && tokens[pos] == ";" {
            pos += 1;
        }

        Ok(Some((Field {
            name: name.clone(),
            typ,
            default,
        }, pos)))
    }

    /// Parse Cap'n Proto enum body
    fn parse_capnp_enum_body(&self, tokens: &[String], mut pos: usize) -> Result<(Vec<String>, usize)> {
        let mut variants = Vec::new();

        while pos < tokens.len() && tokens[pos] != "}" {
            let name = tokens[pos].clone();
            if name != ";" && !name.starts_with('@') {
                variants.push(name);
            }
            pos += 1;
        }

        if pos < tokens.len() && tokens[pos] == "}" {
            pos += 1;
        }

        Ok((variants, pos))
    }

    /// Parse Cap'n Proto interface body
    fn parse_capnp_interface_body(&self, tokens: &[String], mut pos: usize) -> Result<(Vec<Method>, Vec<Item>, usize)> {
        let mut methods = Vec::new();
        let mut nested = Vec::new();

        while pos < tokens.len() && tokens[pos] != "}" {
            let token = &tokens[pos];

            // Nested enum
            if token == "enum" {
                pos += 1;
                let name = tokens.get(pos).cloned().unwrap_or_default();
                pos += 1;
                if pos < tokens.len() && tokens[pos].starts_with('@') {
                    pos += 1;
                }
                while pos < tokens.len() && tokens[pos] != "{" {
                    pos += 1;
                }
                pos += 1;
                let (variants, new_pos) = self.parse_capnp_enum_body(tokens, pos)?;
                pos = new_pos;
                nested.push(Item::Enum { name, variants });
                continue;
            }

            // Nested struct
            if token == "struct" {
                pos += 1;
                let name = tokens.get(pos).cloned().unwrap_or_default();
                pos += 1;
                if pos < tokens.len() && tokens[pos].starts_with('@') {
                    pos += 1;
                }
                while pos < tokens.len() && tokens[pos] != "{" {
                    pos += 1;
                }
                pos += 1;
                let (nfields, nunions, nnested, new_pos) = self.parse_capnp_struct_body(tokens, pos)?;
                pos = new_pos;
                nested.push(Item::Struct { name, fields: nfields, unions: nunions, nested: nnested });
                continue;
            }

            // Method: name @N (params) -> (results);
            if let Some((method, new_pos)) = self.parse_capnp_method(tokens, pos)? {
                methods.push(method);
                pos = new_pos;
            } else {
                pos += 1;
            }
        }

        if pos < tokens.len() && tokens[pos] == "}" {
            pos += 1;
        }

        Ok((methods, nested, pos))
    }

    /// Parse a Cap'n Proto method
    fn parse_capnp_method(&self, tokens: &[String], mut pos: usize) -> Result<Option<(Method, usize)>> {
        if pos >= tokens.len() {
            return Ok(None);
        }

        let name = &tokens[pos];
        if name == "}" || name == "enum" || name == "struct" {
            return Ok(None);
        }

        pos += 1;

        // Skip ordinal @N
        if pos < tokens.len() && tokens[pos].starts_with('@') {
            pos += 1;
        }

        // Parse params
        let params = if pos < tokens.len() && tokens[pos] == "(" {
            let (p, new_pos) = self.parse_capnp_param_list(tokens, pos)?;
            pos = new_pos;
            p
        } else {
            Vec::new()
        };

        // Skip ->
        if pos < tokens.len() && tokens[pos] == "->" {
            pos += 1;
        }

        // Parse results
        let results = if pos < tokens.len() && tokens[pos] == "(" {
            let (r, new_pos) = self.parse_capnp_param_list(tokens, pos)?;
            pos = new_pos;
            r
        } else {
            Vec::new()
        };

        // Skip ;
        if pos < tokens.len() && tokens[pos] == ";" {
            pos += 1;
        }

        Ok(Some((Method {
            name: name.clone(),
            params,
            results,
        }, pos)))
    }

    /// Parse a Cap'n Proto parameter list
    fn parse_capnp_param_list(&self, tokens: &[String], mut pos: usize) -> Result<(Vec<Field>, usize)> {
        let mut params = Vec::new();

        if pos < tokens.len() && tokens[pos] == "(" {
            pos += 1;
        }

        while pos < tokens.len() && tokens[pos] != ")" {
            if tokens[pos] == "," {
                pos += 1;
                continue;
            }

            let name = tokens[pos].clone();
            pos += 1;

            if pos < tokens.len() && tokens[pos] == ":" {
                pos += 1;

                // Get type
                let mut typ = String::new();
                let mut paren_depth = 0;
                while pos < tokens.len() {
                    let t = &tokens[pos];
                    if (t == "," || t == ")") && paren_depth == 0 {
                        break;
                    }
                    if t == "(" {
                        paren_depth += 1;
                    }
                    if t == ")" && paren_depth > 0 {
                        paren_depth -= 1;
                    }
                    typ.push_str(t);
                    pos += 1;
                }

                params.push(Field { name, typ, default: None });
            }
        }

        if pos < tokens.len() && tokens[pos] == ")" {
            pos += 1;
        }

        Ok((params, pos))
    }

    /// Parse struct body (indented fields)
    fn parse_struct_body(&self, lines: &[&str]) -> Result<(Vec<Field>, Vec<Union>, Vec<Item>, usize)> {
        let mut fields = Vec::new();
        let mut unions = Vec::new();
        let mut nested = Vec::new();
        let mut i = 0;

        while i < lines.len() {
            let line = lines[i];

            // Check if still indented (part of struct)
            if !line.starts_with("  ") && !line.starts_with("\t") && !line.trim().is_empty() {
                break;
            }

            let trimmed = line.trim();
            i += 1;

            if trimmed.is_empty() {
                continue;
            }

            // Skip comments
            if trimmed.starts_with('#') {
                continue;
            }

            // Nested struct
            if trimmed.starts_with("struct ") {
                let name = trimmed[7..].trim().to_string();
                let (nfields, nunions, nnested, nconsumed) = self.parse_struct_body(&lines[i..])?;
                nested.push(Item::Struct { name, fields: nfields, unions: nunions, nested: nnested });
                i += nconsumed;
                continue;
            }

            // Nested enum
            if trimmed.starts_with("enum ") {
                let name = trimmed[5..].trim().to_string();
                let (variants, nconsumed) = self.parse_enum_body(&lines[i..])?;
                nested.push(Item::Enum { name, variants });
                i += nconsumed;
                continue;
            }

            // Union
            if trimmed.starts_with("union") {
                let union_name = if trimmed.len() > 5 {
                    Some(trimmed[5..].trim().to_string())
                } else {
                    None
                };

                // Parse union fields (more deeply indented)
                let mut union_fields = Vec::new();
                while i < lines.len() {
                    let uline = lines[i];
                    if !uline.starts_with("    ") && !uline.starts_with("\t\t") {
                        if !uline.trim().is_empty() && (uline.starts_with("  ") || uline.starts_with("\t")) {
                            break;
                        }
                    }
                    let utrimmed = uline.trim();
                    if utrimmed.is_empty() {
                        i += 1;
                        continue;
                    }
                    if !uline.starts_with("    ") && !uline.starts_with("\t\t") {
                        break;
                    }
                    if let Some(field) = self.parse_field(utrimmed) {
                        union_fields.push(field);
                    }
                    i += 1;
                }

                unions.push(Union {
                    name: union_name.filter(|n| !n.is_empty()),
                    fields: union_fields,
                });
                continue;
            }

            // Regular field
            if let Some(field) = self.parse_field(trimmed) {
                fields.push(field);
            }
        }

        Ok((fields, unions, nested, i))
    }

    /// Parse a single field
    fn parse_field(&self, line: &str) -> Option<Field> {
        // Format: name Type = default (new clean format)
        // or: name :Type = default (legacy format with colon)
        let (name_type, default) = if let Some((nt, d)) = line.split_once('=') {
            (nt.trim(), Some(d.trim().to_string()))
        } else {
            (line, None)
        };

        // Try colon format first (legacy): name :Type
        if let Some((name, typ)) = name_type.split_once(':') {
            return Some(Field {
                name: name.trim().to_string(),
                typ: typ.trim().to_string(),
                default,
            });
        }

        // Clean format (new): name Type
        // Split on first whitespace to get name, rest is type
        let parts: Vec<&str> = name_type.splitn(2, char::is_whitespace).collect();
        if parts.len() == 2 {
            let name = parts[0].trim();
            let typ = parts[1].trim();
            // Avoid matching keywords as field names
            if !typ.is_empty() && !["struct", "enum", "interface", "union", "using", "const"].contains(&name) {
                return Some(Field {
                    name: name.to_string(),
                    typ: typ.to_string(),
                    default,
                });
            }
        }

        None
    }

    /// Parse enum body
    fn parse_enum_body(&self, lines: &[&str]) -> Result<(Vec<String>, usize)> {
        let mut variants = Vec::new();
        let mut consumed = 0;

        for line in lines {
            if !line.starts_with("  ") && !line.starts_with("\t") && !line.trim().is_empty() {
                break;
            }

            let trimmed = line.trim();
            consumed += 1;

            if trimmed.is_empty() || trimmed.starts_with('#') {
                continue;
            }

            variants.push(trimmed.to_string());
        }

        Ok((variants, consumed))
    }

    /// Parse interface body
    fn parse_interface_body(&self, lines: &[&str]) -> Result<(Vec<Method>, Vec<Item>, usize)> {
        let mut methods = Vec::new();
        let mut nested = Vec::new();
        let mut i = 0;

        while i < lines.len() {
            let line = lines[i];

            if !line.starts_with("  ") && !line.starts_with("\t") && !line.trim().is_empty() {
                break;
            }

            let trimmed = line.trim();
            i += 1;

            if trimmed.is_empty() || trimmed.starts_with('#') {
                continue;
            }

            // Nested enum
            if trimmed.starts_with("enum ") {
                let name = trimmed[5..].trim().to_string();
                let (variants, nconsumed) = self.parse_enum_body(&lines[i..])?;
                nested.push(Item::Enum { name, variants });
                i += nconsumed;
                continue;
            }

            // Nested struct
            if trimmed.starts_with("struct ") {
                let name = trimmed[7..].trim().to_string();
                let (nfields, nunions, nnested, nconsumed) = self.parse_struct_body(&lines[i..])?;
                nested.push(Item::Struct { name, fields: nfields, unions: nunions, nested: nnested });
                i += nconsumed;
                continue;
            }

            // Method
            if let Some(method) = self.parse_method(trimmed) {
                methods.push(method);
            }
        }

        Ok((methods, nested, i))
    }

    /// Parse a method signature
    fn parse_method(&self, line: &str) -> Option<Method> {
        // Format: methodName (param :Type, ...) -> (result :Type, ...)
        // or: methodName (param :Type) -> ()
        // or: methodName () -> (result :Type)

        let (name_params, results_str) = line.split_once("->")?;
        let name_params = name_params.trim();

        // Extract method name and params
        let (name, params_str) = if let Some(idx) = name_params.find('(') {
            let name = name_params[..idx].trim();
            let params = name_params[idx..].trim();
            (name, params)
        } else {
            (name_params, "()")
        };

        let params = self.parse_param_list(params_str);
        let results = self.parse_param_list(results_str.trim());

        Some(Method {
            name: name.to_string(),
            params,
            results,
        })
    }

    /// Parse a parameter list like "(name Text, age UInt32)" or "(name :Text, age :UInt32)"
    fn parse_param_list(&self, s: &str) -> Vec<Field> {
        let s = s.trim();
        if s == "()" || s.is_empty() {
            return Vec::new();
        }

        // Remove parens
        let inner = s.trim_start_matches('(').trim_end_matches(')').trim();
        if inner.is_empty() {
            return Vec::new();
        }

        // Handle nested parentheses in types like List(Text)
        let mut params = Vec::new();
        let mut current = String::new();
        let mut depth = 0;

        for c in inner.chars() {
            match c {
                '(' => {
                    depth += 1;
                    current.push(c);
                }
                ')' => {
                    depth -= 1;
                    current.push(c);
                }
                ',' if depth == 0 => {
                    if let Some(field) = self.parse_field(current.trim()) {
                        params.push(field);
                    }
                    current.clear();
                }
                _ => {
                    current.push(c);
                }
            }
        }

        // Handle last parameter
        if !current.is_empty() {
            if let Some(field) = self.parse_field(current.trim()) {
                params.push(field);
            }
        }

        params
    }

    /// Compile to ZAP wire format schema (internal representation)
    pub fn compile(&self) -> Result<String> {
        let items = self.parse()?;
        let mut output = String::new();

        // File ID
        let file_id = Self::generate_id(&self.path);
        output.push_str(&format!("@{:#018x};\n\n", file_id));

        for item in items {
            self.emit_item(&mut output, &item, 0)?;
        }

        Ok(output)
    }

    /// Emit an item at the given indentation level
    fn emit_item(&self, output: &mut String, item: &Item, indent: usize) -> Result<()> {
        let pad = "  ".repeat(indent);

        match item {
            Item::Comment(text) => {
                output.push_str(&format!("{}# {}\n", pad, text));
            }
            Item::Using(import) => {
                output.push_str(&format!("{}using {};\n", pad, import));
            }
            Item::Const { name, typ, value } => {
                output.push_str(&format!("{}const {} :{} = {};\n", pad, name, typ, value));
            }
            Item::Struct { name, fields, unions, nested } => {
                let struct_id = Self::generate_id(&format!("{}:{}", self.path, name));
                output.push_str(&format!("{}struct {} @{:#018x} {{\n", pad, name, struct_id));

                let mut ordinal = 0u16;

                for field in fields {
                    let default_str = field
                        .default
                        .as_ref()
                        .map(|d| format!(" = {}", d))
                        .unwrap_or_default();
                    output.push_str(&format!(
                        "{}  {} @{} :{}{};\n",
                        pad, field.name, ordinal, field.typ, default_str
                    ));
                    ordinal += 1;
                }

                for union in unions {
                    if let Some(ref uname) = union.name {
                        output.push_str(&format!("{}  {} :union {{\n", pad, uname));
                    } else {
                        output.push_str(&format!("{}  union {{\n", pad));
                    }
                    for field in &union.fields {
                        let default_str = field
                            .default
                            .as_ref()
                            .map(|d| format!(" = {}", d))
                            .unwrap_or_default();
                        output.push_str(&format!(
                            "{}    {} @{} :{}{};\n",
                            pad, field.name, ordinal, field.typ, default_str
                        ));
                        ordinal += 1;
                    }
                    output.push_str(&format!("{}  }}\n", pad));
                }

                for nested_item in nested {
                    self.emit_item(output, nested_item, indent + 1)?;
                }

                output.push_str(&format!("{}}}\n\n", pad));
            }
            Item::Enum { name, variants } => {
                let enum_id = Self::generate_id(&format!("{}:{}", self.path, name));
                output.push_str(&format!("{}enum {} @{:#018x} {{\n", pad, name, enum_id));

                for (i, variant) in variants.iter().enumerate() {
                    output.push_str(&format!("{}  {} @{};\n", pad, variant, i));
                }

                output.push_str(&format!("{}}}\n\n", pad));
            }
            Item::Interface { name, extends, methods, nested } => {
                let iface_id = Self::generate_id(&format!("{}:{}", self.path, name));
                let extends_str = extends
                    .as_ref()
                    .map(|e| format!(" extends({})", e))
                    .unwrap_or_default();
                output.push_str(&format!(
                    "{}interface {}{} @{:#018x} {{\n",
                    pad, name, extends_str, iface_id
                ));

                for (i, method) in methods.iter().enumerate() {
                    let params_str = if method.params.is_empty() {
                        "()".to_string()
                    } else {
                        let ps: Vec<String> = method
                            .params
                            .iter()
                            .map(|p| format!("{} :{}", p.name, p.typ))
                            .collect();
                        format!("({})", ps.join(", "))
                    };

                    let results_str = if method.results.is_empty() {
                        "()".to_string()
                    } else {
                        let rs: Vec<String> = method
                            .results
                            .iter()
                            .map(|r| format!("{} :{}", r.name, r.typ))
                            .collect();
                        format!("({})", rs.join(", "))
                    };

                    output.push_str(&format!(
                        "{}  {} @{} {} -> {};\n",
                        pad, method.name, i, params_str, results_str
                    ));
                }

                for nested_item in nested {
                    self.emit_item(output, nested_item, indent + 1)?;
                }

                output.push_str(&format!("{}}}\n\n", pad));
            }
        }

        Ok(())
    }

    /// Compile to the legacy format (for compatibility)
    #[deprecated(note = "use compile() instead")]
    pub fn to_capnp(&self) -> Result<String> {
        self.compile()
    }

    /// Convert any schema to clean ZAP whitespace-significant format
    ///
    /// This is useful for migrating existing .capnp schemas to the
    /// recommended .zap format.
    pub fn to_zap(&self) -> Result<String> {
        let items = self.parse()?;
        let mut output = String::new();

        output.push_str("# ZAP Schema - converted to whitespace format\n\n");

        for item in items {
            self.emit_zap_item(&mut output, &item, 0)?;
        }

        Ok(output)
    }

    /// Emit an item in ZAP whitespace format
    fn emit_zap_item(&self, output: &mut String, item: &Item, indent: usize) -> Result<()> {
        let pad = "  ".repeat(indent);

        match item {
            Item::Comment(text) => {
                output.push_str(&format!("{}# {}\n", pad, text));
            }
            Item::Using(import) => {
                output.push_str(&format!("{}using {}\n", pad, import));
            }
            Item::Const { name, typ, value } => {
                output.push_str(&format!("{}const {} :{} = {}\n", pad, name, typ, value));
            }
            Item::Struct { name, fields, unions, nested } => {
                output.push_str(&format!("{}struct {}\n", pad, name));

                for field in fields {
                    let default_str = field
                        .default
                        .as_ref()
                        .map(|d| format!(" = {}", d))
                        .unwrap_or_default();
                    output.push_str(&format!(
                        "{}  {} :{}{}\n",
                        pad, field.name, field.typ, default_str
                    ));
                }

                for union in unions {
                    if let Some(ref uname) = union.name {
                        output.push_str(&format!("{}  union {}\n", pad, uname));
                    } else {
                        output.push_str(&format!("{}  union\n", pad));
                    }
                    for field in &union.fields {
                        let default_str = field
                            .default
                            .as_ref()
                            .map(|d| format!(" = {}", d))
                            .unwrap_or_default();
                        output.push_str(&format!(
                            "{}    {} :{}{}\n",
                            pad, field.name, field.typ, default_str
                        ));
                    }
                }

                for nested_item in nested {
                    output.push('\n');
                    self.emit_zap_item(output, nested_item, indent + 1)?;
                }

                output.push('\n');
            }
            Item::Enum { name, variants } => {
                output.push_str(&format!("{}enum {}\n", pad, name));
                for variant in variants {
                    output.push_str(&format!("{}  {}\n", pad, variant));
                }
                output.push('\n');
            }
            Item::Interface { name, extends, methods, nested } => {
                let extends_str = extends
                    .as_ref()
                    .map(|e| format!(" extends {}", e))
                    .unwrap_or_default();
                output.push_str(&format!("{}interface {}{}\n", pad, name, extends_str));

                for method in methods {
                    let params_str = if method.params.is_empty() {
                        "()".to_string()
                    } else {
                        let ps: Vec<String> = method
                            .params
                            .iter()
                            .map(|p| format!("{} :{}", p.name, p.typ))
                            .collect();
                        format!("({})", ps.join(", "))
                    };

                    let results_str = if method.results.is_empty() {
                        "()".to_string()
                    } else {
                        let rs: Vec<String> = method
                            .results
                            .iter()
                            .map(|r| format!("{} :{}", r.name, r.typ))
                            .collect();
                        format!("({})", rs.join(", "))
                    };

                    output.push_str(&format!(
                        "{}  {} {} -> {}\n",
                        pad, method.name, params_str, results_str
                    ));
                }

                for nested_item in nested {
                    output.push('\n');
                    self.emit_zap_item(output, nested_item, indent + 1)?;
                }

                output.push('\n');
            }
        }

        Ok(())
    }

    /// Compile and write to file
    pub fn write(&self, output_path: &Path) -> Result<()> {
        let compiled = self.compile()?;
        std::fs::write(output_path, compiled)
            .map_err(|e| Error::Config(format!("failed to write schema: {}", e)))?;
        Ok(())
    }

    /// Generate Rust structs from schema
    pub fn to_rust(&self) -> Result<String> {
        let items = self.parse()?;
        let mut output = String::new();

        output.push_str("//! Generated by ZAP Schema Compiler\n");
        output.push_str("//! Do not edit manually\n\n");
        output.push_str("use serde::{Serialize, Deserialize};\n\n");

        for item in items {
            self.emit_rust_item(&mut output, &item)?;
        }

        Ok(output)
    }

    /// Emit Rust code for an item
    fn emit_rust_item(&self, output: &mut String, item: &Item) -> Result<()> {
        match item {
            Item::Comment(text) => {
                output.push_str(&format!("/// {}\n", text));
            }
            Item::Struct { name, fields, unions, nested } => {
                output.push_str("#[derive(Debug, Clone, Serialize, Deserialize)]\n");
                output.push_str(&format!("pub struct {} {{\n", name));

                for field in fields {
                    let rust_type = self.zap_type_to_rust(&field.typ);
                    output.push_str(&format!("    pub {}: {},\n",
                        to_snake_case(&field.name), rust_type));
                }

                // Handle unions as enum fields
                for (i, union) in unions.iter().enumerate() {
                    let union_name = union.name.as_ref()
                        .cloned()
                        .unwrap_or_else(|| format!("{}Union{}", name, i));
                    output.push_str(&format!("    pub {}: {},\n",
                        to_snake_case(&union_name), union_name));
                }

                output.push_str("}\n\n");

                // Emit union enums
                for (i, union) in unions.iter().enumerate() {
                    let union_name = union.name.as_ref()
                        .cloned()
                        .unwrap_or_else(|| format!("{}Union{}", name, i));
                    output.push_str("#[derive(Debug, Clone, Serialize, Deserialize)]\n");
                    output.push_str(&format!("pub enum {} {{\n", union_name));
                    for field in &union.fields {
                        let rust_type = self.zap_type_to_rust(&field.typ);
                        output.push_str(&format!("    {}({}),\n",
                            to_pascal_case(&field.name), rust_type));
                    }
                    output.push_str("}\n\n");
                }

                // Emit nested items
                for nested_item in nested {
                    self.emit_rust_item(output, nested_item)?;
                }
            }
            Item::Enum { name, variants } => {
                output.push_str("#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]\n");
                output.push_str(&format!("pub enum {} {{\n", name));
                for variant in variants {
                    output.push_str(&format!("    {},\n", to_pascal_case(variant)));
                }
                output.push_str("}\n\n");
            }
            Item::Interface { name, methods, nested, .. } => {
                // Generate trait
                output.push_str("#[async_trait::async_trait]\n");
                output.push_str(&format!("pub trait {} {{\n", name));
                for method in methods {
                    let params_str = method.params.iter()
                        .map(|p| format!("{}: {}", to_snake_case(&p.name), self.zap_type_to_rust(&p.typ)))
                        .collect::<Vec<_>>()
                        .join(", ");

                    let result_type = if method.results.is_empty() {
                        "()".to_string()
                    } else if method.results.len() == 1 {
                        self.zap_type_to_rust(&method.results[0].typ)
                    } else {
                        let types: Vec<_> = method.results.iter()
                            .map(|r| self.zap_type_to_rust(&r.typ))
                            .collect();
                        format!("({})", types.join(", "))
                    };

                    output.push_str(&format!("    async fn {}(&self{}{}) -> Result<{}, ZapError>;\n",
                        to_snake_case(&method.name),
                        if params_str.is_empty() { "" } else { ", " },
                        params_str,
                        result_type
                    ));
                }
                output.push_str("}\n\n");

                // Emit nested items
                for nested_item in nested {
                    self.emit_rust_item(output, nested_item)?;
                }
            }
            _ => {}
        }

        Ok(())
    }

    /// Convert ZAP type to Rust type
    fn zap_type_to_rust(&self, typ: &str) -> String {
        match typ {
            "Text" => "String".to_string(),
            "Data" => "Vec<u8>".to_string(),
            "Void" => "()".to_string(),
            "Bool" => "bool".to_string(),
            "Int8" => "i8".to_string(),
            "Int16" => "i16".to_string(),
            "Int32" => "i32".to_string(),
            "Int64" => "i64".to_string(),
            "UInt8" => "u8".to_string(),
            "UInt16" => "u16".to_string(),
            "UInt32" => "u32".to_string(),
            "UInt64" => "u64".to_string(),
            "Float32" => "f32".to_string(),
            "Float64" => "f64".to_string(),
            t if t.starts_with("List(") && t.ends_with(")") => {
                let inner = &t[5..t.len()-1];
                format!("Vec<{}>", self.zap_type_to_rust(inner))
            }
            t => t.to_string(),  // Custom types pass through
        }
    }
}

/// Convert to snake_case
fn to_snake_case(s: &str) -> String {
    let mut result = String::new();
    for (i, c) in s.chars().enumerate() {
        if c.is_uppercase() {
            if i > 0 {
                result.push('_');
            }
            result.push(c.to_lowercase().next().unwrap());
        } else {
            result.push(c);
        }
    }
    result
}

/// Convert to PascalCase
fn to_pascal_case(s: &str) -> String {
    let mut result = String::new();
    let mut capitalize_next = true;
    for c in s.chars() {
        if c == '_' {
            capitalize_next = true;
        } else if capitalize_next {
            result.push(c.to_uppercase().next().unwrap());
            capitalize_next = false;
        } else {
            result.push(c);
        }
    }
    result
}

/// Compile a .zap file
pub fn transpile(input: &Path, output: &Path) -> Result<()> {
    let schema = ZapSchema::from_file(input)?;
    schema.write(output)
}

/// Compile .zap source string
pub fn transpile_str(source: &str, name: &str) -> Result<String> {
    let schema = ZapSchema::new(source, name);
    schema.compile()
}

/// Compile .zap source to Rust code
pub fn compile_to_rust(source: &str, name: &str) -> Result<String> {
    let schema = ZapSchema::new(source, name);
    schema.to_rust()
}

/// Convert .capnp source to .zap whitespace format
///
/// This is the recommended migration path for existing Cap'n Proto schemas.
pub fn capnp_to_zap(source: &str) -> Result<String> {
    let schema = ZapSchema::with_format(source, "input.capnp", SchemaFormat::Capnp);
    schema.to_zap()
}

/// Convert a .capnp file to .zap file
pub fn migrate_capnp_to_zap(input: &Path, output: &Path) -> Result<()> {
    let schema = ZapSchema::from_file(input)?;
    let zap_source = schema.to_zap()?;
    std::fs::write(output, zap_source)
        .map_err(|e| Error::Config(format!("failed to write schema: {}", e)))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_simple_struct() {
        // Test new clean syntax (no colons)
        let source = r#"
struct Person
  name Text
  age UInt32
  email Text
"#;
        let result = transpile_str(source, "test.zap").unwrap();
        assert!(result.contains("struct Person"));
        assert!(result.contains("name @0 :Text"));
        assert!(result.contains("age @1 :UInt32"));
        assert!(result.contains("email @2 :Text"));
    }

    #[test]
    fn test_simple_struct_legacy_syntax() {
        // Test legacy syntax with colons (backwards compatible)
        let source = r#"
struct Person
  name :Text
  age :UInt32
  email :Text
"#;
        let result = transpile_str(source, "test.zap").unwrap();
        assert!(result.contains("struct Person"));
        assert!(result.contains("name @0 :Text"));
        assert!(result.contains("age @1 :UInt32"));
        assert!(result.contains("email @2 :Text"));
    }

    #[test]
    fn test_enum() {
        let source = r#"
enum Status
  pending
  active
  completed
  failed
"#;
        let result = transpile_str(source, "test.zap").unwrap();
        assert!(result.contains("enum Status"));
        assert!(result.contains("pending @0"));
        assert!(result.contains("active @1"));
        assert!(result.contains("completed @2"));
        assert!(result.contains("failed @3"));
    }

    #[test]
    fn test_interface() {
        // Test new clean syntax (no colons)
        let source = r#"
interface Greeter
  sayHello (name Text) -> (greeting Text)
  sayGoodbye (name Text) -> ()
"#;
        let result = transpile_str(source, "test.zap").unwrap();
        assert!(result.contains("interface Greeter"));
        assert!(result.contains("sayHello @0"));
        assert!(result.contains("sayGoodbye @1"));
    }

    #[test]
    fn test_interface_legacy_syntax() {
        // Test legacy syntax with colons (backwards compatible)
        let source = r#"
interface Greeter
  sayHello (name :Text) -> (greeting :Text)
  sayGoodbye (name :Text) -> ()
"#;
        let result = transpile_str(source, "test.zap").unwrap();
        assert!(result.contains("interface Greeter"));
        assert!(result.contains("sayHello @0"));
        assert!(result.contains("sayGoodbye @1"));
    }

    #[test]
    fn test_struct_with_defaults() {
        // Test new clean syntax with defaults
        let source = r#"
struct Config
  host Text = "localhost"
  port UInt16 = 9999
  enabled Bool = true
"#;
        let result = transpile_str(source, "test.zap").unwrap();
        assert!(result.contains("host @0 :Text = \"localhost\""));
        assert!(result.contains("port @1 :UInt16 = 9999"));
        assert!(result.contains("enabled @2 :Bool = true"));
    }

    #[test]
    fn test_comments_preserved() {
        let source = r#"
# This is a comment
struct Foo
  bar Text
"#;
        let result = transpile_str(source, "test.zap").unwrap();
        assert!(result.contains("# This is a comment"));
    }

    #[test]
    fn test_using_import() {
        let source = r#"
using import "other.zap"
using Foo = import "foo.zap"

struct Bar
  x Int32
"#;
        let result = transpile_str(source, "test.zap").unwrap();
        assert!(result.contains("using import \"other.zap\""));
        assert!(result.contains("using Foo = import \"foo.zap\""));
    }

    #[test]
    fn test_interface_extends() {
        let source = r#"
interface Child extends Parent
  childMethod () -> ()
"#;
        let result = transpile_str(source, "test.zap").unwrap();
        assert!(result.contains("interface Child extends(Parent)"));
    }

    #[test]
    fn test_const() {
        let source = r#"
const version :Text = "1.0.0"
const maxSize :UInt32 = 1024
"#;
        let result = transpile_str(source, "test.zap").unwrap();
        assert!(result.contains("const version :Text = \"1.0.0\""));
        assert!(result.contains("const maxSize :UInt32 = 1024"));
    }

    #[test]
    fn test_rust_codegen() {
        let source = r#"
struct Person
  name Text
  age UInt32

enum Status
  pending
  active
"#;
        let result = compile_to_rust(source, "test.zap").unwrap();
        assert!(result.contains("pub struct Person"));
        assert!(result.contains("pub name: String"));
        assert!(result.contains("pub age: u32"));
        assert!(result.contains("pub enum Status"));
        assert!(result.contains("Pending"));
        assert!(result.contains("Active"));
    }

    #[test]
    fn test_complex_types() {
        // Test new clean syntax with complex types like List(Type)
        let source = r#"
struct Order
  items List(Item)
  quantities List(Int32)
  tags List(Text)

struct Item
  name Text
  price Float64
"#;
        let result = transpile_str(source, "test.zap").unwrap();
        assert!(result.contains("items @0 :List(Item)"));
        assert!(result.contains("quantities @1 :List(Int32)"));
        assert!(result.contains("tags @2 :List(Text)"));
    }

    #[test]
    fn test_interface_with_complex_params() {
        // Test interface with List types in parameters
        let source = r#"
interface Calculator
  sum (numbers List(Float64)) -> (total Float64)
  average (values List(Float64)) -> (avg Float64)
"#;
        let result = transpile_str(source, "test.zap").unwrap();
        // Output format: method @ordinal (params) -> (results);
        assert!(result.contains("sum @0"));
        assert!(result.contains("numbers :List(Float64)"));
        assert!(result.contains("total :Float64"));
        assert!(result.contains("average @1"));
        assert!(result.contains("values :List(Float64)"));
        assert!(result.contains("avg :Float64"));
    }

    // Cap'n Proto backwards compatibility tests

    #[test]
    fn test_capnp_struct() {
        let source = r#"
@0x9eb32e19f86ee174;

struct Person @0xabcd1234 {
  name @0 :Text;
  age @1 :UInt32;
  email @2 :Text;
}
"#;
        let schema = ZapSchema::new(source, "test.capnp");
        assert_eq!(schema.format, SchemaFormat::Capnp);
        let result = schema.compile().unwrap();
        assert!(result.contains("struct Person"));
        assert!(result.contains("name @0 :Text"));
        assert!(result.contains("age @1 :UInt32"));
        assert!(result.contains("email @2 :Text"));
    }

    #[test]
    fn test_capnp_enum() {
        let source = r#"
@0x9eb32e19f86ee174;

enum Status @0x1234 {
  pending @0;
  active @1;
  completed @2;
}
"#;
        let schema = ZapSchema::new(source, "test.capnp");
        assert_eq!(schema.format, SchemaFormat::Capnp);
        let result = schema.compile().unwrap();
        assert!(result.contains("enum Status"));
        assert!(result.contains("pending @0"));
        assert!(result.contains("active @1"));
        assert!(result.contains("completed @2"));
    }

    #[test]
    fn test_capnp_interface() {
        let source = r#"
@0x9eb32e19f86ee174;

interface Greeter @0xabcd {
  sayHello @0 (name :Text) -> (greeting :Text);
  sayGoodbye @1 (name :Text) -> ();
}
"#;
        let schema = ZapSchema::new(source, "test.capnp");
        assert_eq!(schema.format, SchemaFormat::Capnp);
        let result = schema.compile().unwrap();
        assert!(result.contains("interface Greeter"));
        assert!(result.contains("sayHello @0"));
        assert!(result.contains("sayGoodbye @1"));
    }

    #[test]
    fn test_capnp_interface_extends() {
        let source = r#"
@0x9eb32e19f86ee174;

interface Child extends(Parent) @0xabcd {
  childMethod @0 () -> ();
}
"#;
        let schema = ZapSchema::new(source, "test.capnp");
        let result = schema.compile().unwrap();
        assert!(result.contains("interface Child extends(Parent)"));
    }

    #[test]
    fn test_capnp_nested_types() {
        let source = r#"
@0x9eb32e19f86ee174;

struct Outer @0x1234 {
  value @0 :Text;

  struct Inner @0x5678 {
    x @0 :Int32;
  }

  enum InnerEnum @0x9abc {
    a @0;
    b @1;
  }
}
"#;
        let schema = ZapSchema::new(source, "test.capnp");
        let result = schema.compile().unwrap();
        assert!(result.contains("struct Outer"));
        assert!(result.contains("struct Inner"));
        assert!(result.contains("enum InnerEnum"));
    }

    #[test]
    fn test_format_detection_by_extension() {
        let zap_schema = ZapSchema::new("struct Foo { }", "test.zap");
        assert_eq!(zap_schema.format, SchemaFormat::Zap);

        let capnp_schema = ZapSchema::new("struct Foo { }", "test.capnp");
        assert_eq!(capnp_schema.format, SchemaFormat::Capnp);
    }

    #[test]
    fn test_format_detection_by_content() {
        // Content with @0; ordinals detected as capnp
        let source = "@0x1234; struct Foo { bar @0; }";
        let schema = ZapSchema::new(source, "test.schema");
        assert_eq!(schema.format, SchemaFormat::Capnp);

        // Clean content defaults to zap (new syntax)
        let source = "struct Foo\n  bar Text";
        let schema = ZapSchema::new(source, "test.schema");
        assert_eq!(schema.format, SchemaFormat::Zap);

        // Legacy zap syntax also detected as zap
        let source = "struct Foo\n  bar :Text";
        let schema = ZapSchema::new(source, "test.schema");
        assert_eq!(schema.format, SchemaFormat::Zap);
    }

    #[test]
    fn test_explicit_format() {
        let source = "struct Foo { bar @0 :Text; }";
        let schema = ZapSchema::with_format(source, "test.txt", SchemaFormat::Zap);
        assert_eq!(schema.format, SchemaFormat::Zap);
    }

    #[test]
    fn test_capnp_to_zap_conversion() {
        let capnp_source = r#"
@0x9eb32e19f86ee174;

struct Person @0xabcd1234 {
  name @0 :Text;
  age @1 :UInt32;
  email @2 :Text;
}

enum Status @0x1234 {
  pending @0;
  active @1;
  completed @2;
}

interface Greeter @0xabcd {
  sayHello @0 (name :Text) -> (greeting :Text);
  sayGoodbye @1 () -> ();
}
"#;
        let result = capnp_to_zap(capnp_source).unwrap();

        // Check struct is converted properly
        assert!(result.contains("struct Person"));
        assert!(result.contains("  name :Text"));
        assert!(result.contains("  age :UInt32"));
        assert!(result.contains("  email :Text"));

        // Check enum
        assert!(result.contains("enum Status"));
        assert!(result.contains("  pending"));
        assert!(result.contains("  active"));
        assert!(result.contains("  completed"));

        // Check interface
        assert!(result.contains("interface Greeter"));
        assert!(result.contains("sayHello"));
        assert!(result.contains("sayGoodbye"));

        // Ensure no ordinals in output (clean zap format)
        assert!(!result.contains("@0"));
        assert!(!result.contains("@1"));
        assert!(!result.contains("@2"));
    }

    // ==========================================================================
    // Extensive ZAP Syntax Tests
    // ==========================================================================

    #[test]
    fn test_all_primitive_types() {
        let source = r#"
struct AllTypes
  int8Val Int8
  int16Val Int16
  int32Val Int32
  int64Val Int64
  uint8Val UInt8
  uint16Val UInt16
  uint32Val UInt32
  uint64Val UInt64
  float32Val Float32
  float64Val Float64
  boolVal Bool
  textVal Text
  dataVal Data
  voidVal Void
"#;
        let result = transpile_str(source, "test.zap").unwrap();
        assert!(result.contains("int8Val @0 :Int8"));
        assert!(result.contains("int16Val @1 :Int16"));
        assert!(result.contains("int32Val @2 :Int32"));
        assert!(result.contains("int64Val @3 :Int64"));
        assert!(result.contains("uint8Val @4 :UInt8"));
        assert!(result.contains("uint16Val @5 :UInt16"));
        assert!(result.contains("uint32Val @6 :UInt32"));
        assert!(result.contains("uint64Val @7 :UInt64"));
        assert!(result.contains("float32Val @8 :Float32"));
        assert!(result.contains("float64Val @9 :Float64"));
        assert!(result.contains("boolVal @10 :Bool"));
        assert!(result.contains("textVal @11 :Text"));
        assert!(result.contains("dataVal @12 :Data"));
        assert!(result.contains("voidVal @13 :Void"));
    }

    #[test]
    fn test_nested_structs_deep() {
        let source = r#"
struct Level1
  name Text
  level2 Level2

  struct Level2
    value Int32
    level3 Level3

    struct Level3
      data Data
      count UInt64
"#;
        let result = transpile_str(source, "test.zap").unwrap();
        assert!(result.contains("struct Level1"));
        assert!(result.contains("struct Level2"));
        assert!(result.contains("struct Level3"));
        assert!(result.contains("name @0 :Text"));
        assert!(result.contains("level2 @1 :Level2"));
    }

    #[test]
    fn test_union_in_struct() {
        let source = r#"
struct Result
  id Text
  union
    success Data
    error Text
    pending Void
"#;
        let result = transpile_str(source, "test.zap").unwrap();
        assert!(result.contains("struct Result"));
        assert!(result.contains("id @0 :Text"));
        assert!(result.contains("union {"));
        assert!(result.contains("success"));
        assert!(result.contains("error"));
        assert!(result.contains("pending"));
    }

    #[test]
    fn test_named_union() {
        let source = r#"
struct Shape
  name Text
  union geometry
    circle Circle
    rectangle Rectangle
"#;
        let result = transpile_str(source, "test.zap").unwrap();
        assert!(result.contains("struct Shape"));
        assert!(result.contains("geometry :union"));
    }

    #[test]
    fn test_multiple_interfaces() {
        let source = r#"
interface Reader
  read (offset UInt64, size UInt32) -> (data Data)
  size () -> (bytes UInt64)

interface Writer
  write (data Data) -> (written UInt64)
  flush () -> ()
  close () -> ()

interface ReadWriter extends Reader
  write (data Data) -> (written UInt64)
"#;
        let result = transpile_str(source, "test.zap").unwrap();
        assert!(result.contains("interface Reader"));
        assert!(result.contains("interface Writer"));
        assert!(result.contains("interface ReadWriter extends(Reader)"));
        assert!(result.contains("read @0"));
        assert!(result.contains("write @0"));
    }

    #[test]
    fn test_interface_with_nested_types() {
        let source = r#"
interface Database
  query (sql Text) -> (results QueryResult)
  execute (sql Text) -> (affected UInt64)

  struct QueryResult
    columns List(Text)
    rows List(Row)

  struct Row
    values List(Text)

  enum ErrorCode
    notFound
    permissionDenied
    timeout
    internal
"#;
        let result = transpile_str(source, "test.zap").unwrap();
        assert!(result.contains("interface Database"));
        assert!(result.contains("struct QueryResult"));
        assert!(result.contains("struct Row"));
        assert!(result.contains("enum ErrorCode"));
    }

    #[test]
    fn test_list_of_lists() {
        let source = r#"
struct Matrix
  rows List(List(Float64))
  labels List(Text)
"#;
        let result = transpile_str(source, "test.zap").unwrap();
        assert!(result.contains("rows @0 :List(List(Float64))"));
        assert!(result.contains("labels @1 :List(Text)"));
    }

    #[test]
    fn test_default_values_various_types() {
        let source = r#"
struct Config
  host Text = "localhost"
  port UInt16 = 8080
  maxConnections UInt32 = 100
  timeout Float64 = 30.0
  enabled Bool = true
  retryCount Int32 = 3
"#;
        let result = transpile_str(source, "test.zap").unwrap();
        assert!(result.contains("host @0 :Text = \"localhost\""));
        assert!(result.contains("port @1 :UInt16 = 8080"));
        assert!(result.contains("maxConnections @2 :UInt32 = 100"));
        assert!(result.contains("timeout @3 :Float64 = 30.0"));
        assert!(result.contains("enabled @4 :Bool = true"));
        assert!(result.contains("retryCount @5 :Int32 = 3"));
    }

    #[test]
    fn test_enum_many_variants() {
        let source = r#"
enum HttpStatus
  continue100
  ok200
  created201
  accepted202
  noContent204
  movedPermanently301
  found302
  notModified304
  badRequest400
  unauthorized401
  forbidden403
  notFound404
  methodNotAllowed405
  internalServerError500
  notImplemented501
  badGateway502
  serviceUnavailable503
"#;
        let result = transpile_str(source, "test.zap").unwrap();
        assert!(result.contains("enum HttpStatus"));
        assert!(result.contains("continue100 @0"));
        assert!(result.contains("ok200 @1"));
        assert!(result.contains("serviceUnavailable503 @16"));
    }

    #[test]
    fn test_method_multiple_params() {
        let source = r#"
interface DataService
  search (query Text, limit UInt32, offset UInt64, filters List(Text)) -> (results List(Data), total UInt64)
  aggregate (keys List(Text), operation Text, groupBy Text) -> (result Data)
"#;
        let result = transpile_str(source, "test.zap").unwrap();
        assert!(result.contains("search @0"));
        assert!(result.contains("query :Text"));
        assert!(result.contains("limit :UInt32"));
        assert!(result.contains("offset :UInt64"));
        assert!(result.contains("filters :List(Text)"));
        assert!(result.contains("results :List(Data)"));
        assert!(result.contains("total :UInt64"));
    }

    #[test]
    fn test_empty_interface() {
        let source = r#"
interface Empty
"#;
        let result = transpile_str(source, "test.zap").unwrap();
        assert!(result.contains("interface Empty"));
    }

    #[test]
    fn test_empty_struct() {
        let source = r#"
struct Empty
"#;
        let result = transpile_str(source, "test.zap").unwrap();
        assert!(result.contains("struct Empty"));
    }

    #[test]
    fn test_comments_multiline() {
        let source = r#"
# This is the first comment
# This is the second comment
# This is the third comment
struct Documented
  # Field comment
  value Text
"#;
        let result = transpile_str(source, "test.zap").unwrap();
        assert!(result.contains("# This is the first comment"));
        assert!(result.contains("# This is the second comment"));
        assert!(result.contains("# This is the third comment"));
    }

    #[test]
    fn test_mixed_syntax_colon_and_space() {
        // Test that both syntaxes work in the same file
        let source = r#"
struct MixedSyntax
  fieldWithColon :Text
  fieldWithSpace Int32
  anotherColon :UInt64
  anotherSpace Bool
"#;
        let result = transpile_str(source, "test.zap").unwrap();
        assert!(result.contains("fieldWithColon @0 :Text"));
        assert!(result.contains("fieldWithSpace @1 :Int32"));
        assert!(result.contains("anotherColon @2 :UInt64"));
        assert!(result.contains("anotherSpace @3 :Bool"));
    }

    #[test]
    fn test_complex_nested_lists() {
        let source = r#"
struct ComplexData
  matrix List(List(List(Float64)))
  records List(Record)
  tags List(List(Text))

struct Record
  id UInt64
  data Data
"#;
        let result = transpile_str(source, "test.zap").unwrap();
        assert!(result.contains("matrix @0 :List(List(List(Float64)))"));
        assert!(result.contains("records @1 :List(Record)"));
        assert!(result.contains("tags @2 :List(List(Text))"));
    }

    #[test]
    fn test_interface_method_no_params_no_results() {
        let source = r#"
interface Simple
  ping () -> ()
  noop () -> ()
"#;
        let result = transpile_str(source, "test.zap").unwrap();
        assert!(result.contains("ping @0 () -> ()"));
        assert!(result.contains("noop @1 () -> ()"));
    }

    #[test]
    fn test_interface_method_only_results() {
        let source = r#"
interface Generator
  generate () -> (value UInt64)
  timestamp () -> (seconds Int64, nanos UInt32)
"#;
        let result = transpile_str(source, "test.zap").unwrap();
        assert!(result.contains("generate @0 () -> (value :UInt64)"));
        assert!(result.contains("timestamp @1 () -> (seconds :Int64, nanos :UInt32)"));
    }

    #[test]
    fn test_stable_ids_deterministic() {
        let source = r#"
struct TestStruct
  field Text
"#;
        let result1 = transpile_str(source, "test.zap").unwrap();
        let result2 = transpile_str(source, "test.zap").unwrap();
        // Same input should produce same output (deterministic IDs)
        assert_eq!(result1, result2);
    }

    #[test]
    fn test_different_paths_different_ids() {
        let source = r#"
struct TestStruct
  field Text
"#;
        let result1 = transpile_str(source, "path1.zap").unwrap();
        let result2 = transpile_str(source, "path2.zap").unwrap();
        // Different paths should produce different file IDs
        assert_ne!(result1, result2);
    }

    #[test]
    fn test_rust_codegen_interface() {
        let source = r#"
interface Calculator
  add (a Float64, b Float64) -> (result Float64)
  multiply (a Float64, b Float64) -> (result Float64)
"#;
        let result = compile_to_rust(source, "test.zap").unwrap();
        assert!(result.contains("pub trait Calculator"));
        assert!(result.contains("async fn add"));
        assert!(result.contains("async fn multiply"));
        assert!(result.contains("a: f64"));
        assert!(result.contains("b: f64"));
    }

    #[test]
    fn test_rust_codegen_union() {
        let source = r#"
struct Response
  union
    success Data
    error Text
"#;
        let result = compile_to_rust(source, "test.zap").unwrap();
        assert!(result.contains("pub struct Response"));
        assert!(result.contains("pub enum"));
        assert!(result.contains("Success(Vec<u8>)"));
        assert!(result.contains("Error(String)"));
    }

    #[test]
    fn test_full_mcp_like_schema() {
        // Test a realistic MCP-like schema
        let source = r#"
struct Tool
  name Text
  description Text
  schema Data
  annotations Metadata

struct Metadata
  entries List(Entry)

  struct Entry
    key Text
    value Text

struct ToolCall
  id Text
  name Text
  args Data

struct ToolResult
  id Text
  union
    content Data
    error Text

interface ToolService
  listTools () -> (tools List(Tool))
  callTool (call ToolCall) -> (result ToolResult)

enum LogLevel
  debug
  info
  warn
  error
"#;
        let result = transpile_str(source, "test.zap").unwrap();
        assert!(result.contains("struct Tool"));
        assert!(result.contains("struct Metadata"));
        assert!(result.contains("struct Entry"));
        assert!(result.contains("struct ToolCall"));
        assert!(result.contains("struct ToolResult"));
        assert!(result.contains("interface ToolService"));
        assert!(result.contains("enum LogLevel"));
        assert!(result.contains("listTools @0"));
        assert!(result.contains("callTool @1"));
    }

    #[test]
    fn test_whitespace_variations() {
        // Test various whitespace patterns
        let source1 = "struct Foo\n  bar Text";
        let source2 = "struct Foo\n  bar Text\n";
        let source3 = "struct Foo\n  bar Text\n\n";
        let source4 = "\nstruct Foo\n  bar Text";

        for (i, source) in [source1, source2, source3, source4].iter().enumerate() {
            let result = transpile_str(source, "test.zap");
            assert!(result.is_ok(), "Failed on source variant {}", i);
            let output = result.unwrap();
            assert!(output.contains("bar @0 :Text"), "Missing field in variant {}", i);
        }
    }

    #[test]
    fn test_tab_indentation() {
        let source = "struct Foo\n\tbar Text\n\tbaz Int32";
        let result = transpile_str(source, "test.zap").unwrap();
        assert!(result.contains("bar @0 :Text"));
        assert!(result.contains("baz @1 :Int32"));
    }

    #[test]
    fn test_special_characters_in_strings() {
        let source = r#"
struct Config
  path Text = "/usr/local/bin"
  pattern Text = ".*\\.txt"
  message Text = "Hello, World!"
"#;
        let result = transpile_str(source, "test.zap").unwrap();
        assert!(result.contains("\"/usr/local/bin\""));
        assert!(result.contains("\".*\\\\.txt\""));
        assert!(result.contains("\"Hello, World!\""));
    }

    #[test]
    fn test_camel_case_names() {
        let source = r#"
struct MyComplexStructName
  myFieldName Text
  anotherFieldWithLongName UInt64
  yetAnotherOne Bool

interface MyServiceInterface
  myMethodName (myParam Text) -> (myResult Data)
"#;
        let result = transpile_str(source, "test.zap").unwrap();
        assert!(result.contains("struct MyComplexStructName"));
        assert!(result.contains("myFieldName @0 :Text"));
        assert!(result.contains("interface MyServiceInterface"));
        assert!(result.contains("myMethodName @0"));
    }

    #[test]
    fn test_snake_case_to_rust() {
        let source = r#"
struct TestStruct
  myFieldName Text
  anotherField Int32
"#;
        let result = compile_to_rust(source, "test.zap").unwrap();
        // Rust codegen should convert to snake_case
        assert!(result.contains("my_field_name"));
        assert!(result.contains("another_field"));
    }

    // ==========================================================================
    // Edge Case Tests
    // ==========================================================================

    #[test]
    fn test_single_field_struct() {
        let source = r#"
struct Single
  value Text
"#;
        let result = transpile_str(source, "test.zap").unwrap();
        assert!(result.contains("struct Single"));
        assert!(result.contains("value @0 :Text"));
    }

    #[test]
    fn test_single_variant_enum() {
        let source = r#"
enum Single
  only
"#;
        let result = transpile_str(source, "test.zap").unwrap();
        assert!(result.contains("enum Single"));
        assert!(result.contains("only @0"));
    }

    #[test]
    fn test_single_method_interface() {
        let source = r#"
interface Single
  method () -> ()
"#;
        let result = transpile_str(source, "test.zap").unwrap();
        assert!(result.contains("interface Single"));
        assert!(result.contains("method @0"));
    }

    #[test]
    fn test_numeric_looking_names() {
        let source = r#"
struct Data123
  field456 Text
  x789 Int32
"#;
        let result = transpile_str(source, "test.zap").unwrap();
        assert!(result.contains("struct Data123"));
        assert!(result.contains("field456 @0 :Text"));
        assert!(result.contains("x789 @1 :Int32"));
    }

    #[test]
    fn test_underscore_names() {
        let source = r#"
struct Under_Score
  field_name Text
  another_field Int32
"#;
        let result = transpile_str(source, "test.zap").unwrap();
        assert!(result.contains("struct Under_Score"));
        assert!(result.contains("field_name @0 :Text"));
    }

    #[test]
    fn test_large_ordinals() {
        // Test struct with many fields to ensure ordinals count correctly
        let source = r#"
struct ManyFields
  f0 Text
  f1 Text
  f2 Text
  f3 Text
  f4 Text
  f5 Text
  f6 Text
  f7 Text
  f8 Text
  f9 Text
  f10 Text
  f11 Text
  f12 Text
  f13 Text
  f14 Text
  f15 Text
  f16 Text
  f17 Text
  f18 Text
  f19 Text
"#;
        let result = transpile_str(source, "test.zap").unwrap();
        assert!(result.contains("f0 @0 :Text"));
        assert!(result.contains("f10 @10 :Text"));
        assert!(result.contains("f19 @19 :Text"));
    }
}
