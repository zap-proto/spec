//! Build script for schema compilation.
//!
//! - Cap'n Proto schemas: Always compiled (core ZAP functionality)
//! - Protobuf schemas: Only compiled with `grpc` feature
//!
//! This ensures gRPC/protobuf code is NEVER included unless explicitly requested.

fn main() {
    // ========================================================================
    // Cap'n Proto (ZAP) - Always compile
    // ========================================================================
    println!("cargo:rerun-if-changed=schema/rust/zap.capnp");
    println!("cargo:rerun-if-changed=schema/zap.zap");

    capnpc::CompilerCommand::new()
        .src_prefix("schema/rust")
        .file("schema/rust/zap.capnp")
        .run()
        .expect("capnp compile failed");

    // ========================================================================
    // gRPC/Protobuf - Only with +grpc feature
    // ========================================================================
    #[cfg(feature = "grpc")]
    {
        println!("cargo:rerun-if-changed=proto/zap.proto");
        println!("cargo:rerun-if-changed=proto/benchmark.proto");

        // Only compile protos if the feature is enabled
        tonic_build::configure()
            .build_server(true)
            .build_client(true)
            .out_dir("src/generated")
            .compile(
                &["proto/zap.proto", "proto/benchmark.proto"],
                &["proto/"],
            )
            .unwrap_or_else(|e| {
                eprintln!("Warning: protobuf compilation skipped: {}", e);
            });
    }

    // Print feature status for build visibility
    #[cfg(feature = "grpc")]
    println!("cargo:warning=Building with gRPC support (+grpc)");

    #[cfg(not(feature = "grpc"))]
    println!("cargo:warning=Building WITHOUT gRPC (use --features grpc to enable)");
}
