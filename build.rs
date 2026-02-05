//! Build script for Cap'n Proto schema compilation.

fn main() {
    // Rerun if schema changes
    println!("cargo:rerun-if-changed=schema/rust/zap.capnp");

    capnpc::CompilerCommand::new()
        .src_prefix("schema/rust")
        .file("schema/rust/zap.capnp")
        .run()
        .expect("capnp compile failed");
}
