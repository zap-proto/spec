//! ZAP Schema Compiler (zapc)
//!
//! A CLI tool for compiling ZAP schemas to various output formats.
//!
//! # Usage
//!
//! ```bash
//! # Compile to Cap'n Proto format
//! zapc compile schema.zap --out=schema.capnp
//!
//! # Generate code for a specific language
//! zapc generate schema.zap --lang=rust --out=./gen/
//!
//! # Convert Cap'n Proto to ZAP format
//! zapc migrate schema.capnp schema.zap
//!
//! # Validate a schema
//! zapc check schema.zap
//!
//! # Format a schema
//! zapc fmt schema.zap
//! ```

use clap::{Parser, Subcommand};
use std::fs;
use std::path::PathBuf;
use zap::schema::{compile_to_rust, migrate_capnp_to_zap, transpile_str, ZapSchema};

#[derive(Parser)]
#[command(name = "zapc")]
#[command(author = "Hanzo AI <dev@hanzo.ai>")]
#[command(version = env!("CARGO_PKG_VERSION"))]
#[command(about = "ZAP Schema Compiler - compile .zap schemas to various formats")]
#[command(long_about = r#"
ZAP Schema Compiler

Compile ZAP schemas (.zap) to Cap'n Proto format (.capnp) or generate
code for various languages. Also supports migrating existing Cap'n Proto
schemas to the cleaner ZAP format.

Examples:
  # Compile a schema
  zapc compile schema.zap

  # Generate Rust code
  zapc generate schema.zap --lang=rust --out=./gen/

  # Migrate from Cap'n Proto to ZAP
  zapc migrate old.capnp new.zap

  # Check schema for errors
  zapc check schema.zap
"#)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Compile a ZAP schema to Cap'n Proto format
    Compile {
        /// Input schema file (.zap or .capnp)
        input: PathBuf,

        /// Output file (defaults to stdout)
        #[arg(short, long)]
        out: Option<PathBuf>,

        /// Force overwrite existing files
        #[arg(short, long)]
        force: bool,
    },

    /// Generate code from a ZAP schema
    Generate {
        /// Input schema file (.zap or .capnp)
        input: PathBuf,

        /// Target language (rust, go, ts, python, c, cpp, haskell, elixir)
        #[arg(short, long)]
        lang: String,

        /// Output directory
        #[arg(short, long)]
        out: PathBuf,

        /// Force overwrite existing files
        #[arg(short, long)]
        force: bool,
    },

    /// Convert Cap'n Proto schema to ZAP format
    Migrate {
        /// Input Cap'n Proto file (.capnp)
        input: PathBuf,

        /// Output ZAP file (.zap)
        output: PathBuf,

        /// Force overwrite existing files
        #[arg(short, long)]
        force: bool,
    },

    /// Check a schema for errors
    Check {
        /// Schema file to check
        input: PathBuf,

        /// Show verbose output
        #[arg(short, long)]
        verbose: bool,
    },

    /// Format a ZAP schema
    Fmt {
        /// Schema file to format
        input: PathBuf,

        /// Write output back to file (otherwise print to stdout)
        #[arg(short, long)]
        write: bool,
    },

    /// Print version information
    Version,
}

fn main() {
    let cli = Cli::parse();

    let result = match cli.command {
        Commands::Compile { input, out, force } => cmd_compile(input, out, force),
        Commands::Generate { input, lang, out, force } => cmd_generate(input, lang, out, force),
        Commands::Migrate { input, output, force } => cmd_migrate(input, output, force),
        Commands::Check { input, verbose } => cmd_check(input, verbose),
        Commands::Fmt { input, write } => cmd_fmt(input, write),
        Commands::Version => cmd_version(),
    };

    if let Err(e) = result {
        eprintln!("Error: {}", e);
        std::process::exit(1);
    }
}

fn cmd_compile(input: PathBuf, out: Option<PathBuf>, force: bool) -> Result<(), String> {
    let source = fs::read_to_string(&input)
        .map_err(|e| format!("Failed to read {}: {}", input.display(), e))?;

    let filename = input.file_name()
        .and_then(|s| s.to_str())
        .unwrap_or("schema.zap");

    let result = transpile_str(&source, filename)
        .map_err(|e| format!("Compilation failed: {}", e))?;

    match out {
        Some(path) => {
            if path.exists() && !force {
                return Err(format!("Output file {} already exists. Use --force to overwrite.", path.display()));
            }
            fs::write(&path, &result)
                .map_err(|e| format!("Failed to write {}: {}", path.display(), e))?;
            println!("Compiled {} -> {}", input.display(), path.display());
        }
        None => {
            println!("{}", result);
        }
    }

    Ok(())
}

fn cmd_generate(input: PathBuf, lang: String, out: PathBuf, force: bool) -> Result<(), String> {
    let source = fs::read_to_string(&input)
        .map_err(|e| format!("Failed to read {}: {}", input.display(), e))?;

    let filename = input.file_name()
        .and_then(|s| s.to_str())
        .unwrap_or("schema.zap");

    let code = match lang.to_lowercase().as_str() {
        "rust" | "rs" => {
            compile_to_rust(&source, filename)
                .map_err(|e| format!("Rust code generation failed: {}", e))?
        }
        "go" => {
            // TODO: Implement Go code generation
            return Err("Go code generation not yet implemented".to_string());
        }
        "typescript" | "ts" => {
            // TODO: Implement TypeScript code generation
            return Err("TypeScript code generation not yet implemented".to_string());
        }
        "python" | "py" => {
            // TODO: Implement Python code generation
            return Err("Python code generation not yet implemented".to_string());
        }
        "c" => {
            // TODO: Implement C code generation
            return Err("C code generation not yet implemented".to_string());
        }
        "cpp" | "c++" => {
            // TODO: Implement C++ code generation
            return Err("C++ code generation not yet implemented".to_string());
        }
        "haskell" | "hs" => {
            // TODO: Implement Haskell code generation
            return Err("Haskell code generation not yet implemented".to_string());
        }
        "elixir" | "ex" => {
            // TODO: Implement Elixir code generation
            return Err("Elixir code generation not yet implemented".to_string());
        }
        _ => {
            return Err(format!("Unknown language: {}. Supported: rust, go, ts, python, c, cpp, haskell, elixir", lang));
        }
    };

    // Create output directory if it doesn't exist
    fs::create_dir_all(&out)
        .map_err(|e| format!("Failed to create output directory {}: {}", out.display(), e))?;

    // Determine output filename
    let stem = input.file_stem()
        .and_then(|s| s.to_str())
        .unwrap_or("schema");

    let ext = match lang.to_lowercase().as_str() {
        "rust" | "rs" => "rs",
        "go" => "go",
        "typescript" | "ts" => "ts",
        "python" | "py" => "py",
        "c" => "h",
        "cpp" | "c++" => "hpp",
        "haskell" | "hs" => "hs",
        "elixir" | "ex" => "ex",
        _ => "txt",
    };

    let output_path = out.join(format!("{}.{}", stem, ext));

    if output_path.exists() && !force {
        return Err(format!("Output file {} already exists. Use --force to overwrite.", output_path.display()));
    }

    fs::write(&output_path, &code)
        .map_err(|e| format!("Failed to write {}: {}", output_path.display(), e))?;

    println!("Generated {} ({}) -> {}", input.display(), lang, output_path.display());

    Ok(())
}

fn cmd_migrate(input: PathBuf, output: PathBuf, force: bool) -> Result<(), String> {
    if output.exists() && !force {
        return Err(format!("Output file {} already exists. Use --force to overwrite.", output.display()));
    }

    migrate_capnp_to_zap(&input, &output)
        .map_err(|e| format!("Migration failed: {}", e))?;

    println!("Migrated {} -> {}", input.display(), output.display());

    Ok(())
}

fn cmd_check(input: PathBuf, verbose: bool) -> Result<(), String> {
    let source = fs::read_to_string(&input)
        .map_err(|e| format!("Failed to read {}: {}", input.display(), e))?;

    let filename = input.file_name()
        .and_then(|s| s.to_str())
        .unwrap_or("schema.zap");

    let schema = ZapSchema::new(&source, filename);

    if verbose {
        println!("Checking: {}", input.display());
        println!("Format: {:?}", schema.format());
    }

    // Try to parse and compile
    let result = schema.compile();

    match result {
        Ok(compiled) => {
            if verbose {
                let lines: Vec<_> = compiled.lines().collect();
                let structs = lines.iter().filter(|l| l.contains("struct ")).count();
                let enums = lines.iter().filter(|l| l.contains("enum ")).count();
                let interfaces = lines.iter().filter(|l| l.contains("interface ")).count();

                println!("Structures: {}", structs);
                println!("Enums: {}", enums);
                println!("Interfaces: {}", interfaces);
            }
            println!("✓ {} is valid", input.display());
            Ok(())
        }
        Err(e) => {
            Err(format!("✗ {} has errors: {}", input.display(), e))
        }
    }
}

fn cmd_fmt(input: PathBuf, write: bool) -> Result<(), String> {
    let source = fs::read_to_string(&input)
        .map_err(|e| format!("Failed to read {}: {}", input.display(), e))?;

    // For now, just normalize whitespace and ensure consistent indentation
    let mut formatted = String::new();
    let mut in_block = 0;

    for line in source.lines() {
        let trimmed = line.trim();

        // Decrease indent for closing or before struct/enum/interface at same level
        if trimmed.is_empty() {
            formatted.push('\n');
            continue;
        }

        // Check if this line decreases indentation
        if trimmed.starts_with("struct ") || trimmed.starts_with("enum ") || trimmed.starts_with("interface ") {
            // Top-level definitions get no indent
            if in_block == 0 {
                formatted.push_str(trimmed);
                formatted.push('\n');
                in_block = 1;
                continue;
            }
        }

        // Add appropriate indentation
        let indent = "  ".repeat(in_block);
        formatted.push_str(&indent);
        formatted.push_str(trimmed);
        formatted.push('\n');

        // Adjust block level based on content
        if trimmed.starts_with("struct ") || trimmed.starts_with("enum ") || trimmed.starts_with("interface ") || trimmed.starts_with("union") {
            in_block += 1;
        }
    }

    if write {
        fs::write(&input, &formatted)
            .map_err(|e| format!("Failed to write {}: {}", input.display(), e))?;
        println!("Formatted {}", input.display());
    } else {
        print!("{}", formatted);
    }

    Ok(())
}

fn cmd_version() -> Result<(), String> {
    println!("zapc {} (ZAP Schema Compiler)", env!("CARGO_PKG_VERSION"));
    println!("Copyright (C) 2024 Hanzo AI");
    println!("License: Apache-2.0 OR MIT");
    println!();
    println!("Features:");
    println!("  - ZAP whitespace syntax (.zap)");
    println!("  - Cap'n Proto compatibility (.capnp)");
    println!("  - Code generation: Rust (more coming)");
    println!("  - Schema migration tools");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::NamedTempFile;

    #[test]
    fn test_compile_simple_schema() {
        let mut file = NamedTempFile::new().unwrap();
        writeln!(file, "struct Person").unwrap();
        writeln!(file, "  name Text").unwrap();
        writeln!(file, "  age UInt32").unwrap();

        let result = cmd_compile(file.path().to_path_buf(), None, false);
        assert!(result.is_ok());
    }

    #[test]
    fn test_check_valid_schema() {
        let mut file = NamedTempFile::new().unwrap();
        writeln!(file, "struct Person").unwrap();
        writeln!(file, "  name Text").unwrap();

        let result = cmd_check(file.path().to_path_buf(), false);
        assert!(result.is_ok());
    }

    #[test]
    fn test_generate_rust() {
        let mut file = NamedTempFile::with_suffix(".zap").unwrap();
        writeln!(file, "struct Person").unwrap();
        writeln!(file, "  name Text").unwrap();
        writeln!(file, "  age UInt32").unwrap();

        let out_dir = tempfile::tempdir().unwrap();
        let result = cmd_generate(
            file.path().to_path_buf(),
            "rust".to_string(),
            out_dir.path().to_path_buf(),
            false,
        );
        assert!(result.is_ok());
    }
}
