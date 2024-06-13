use std::error::Error;

fn main() -> Result<(), Box<dyn Error>> {
    println!("cargo:rerun-if-changed=proto");
    build_consensus_service();
    build_vergen()?;
    Ok(())
}

// This function only gets compiled if the target OS is linux
#[cfg(target_os = "linux")]
fn build_consensus_service() {
    tonic_build::configure()
        .out_dir("src/proto")
        .compile(&["proto/types.proto", "proto/service.proto"], &["proto"])
        .expect("Failed to compile proto(s)");
}
// And this function only gets compiled if the target OS is *not* linux
#[cfg(not(target_os = "linux"))]
fn build_consensus_service() {
    tonic_build::configure()
        .out_dir("src/proto")
        .compile(&["proto/types.proto", "proto/service.proto"], &["proto"])
        .expect("Failed to compile proto(s)");
}

fn build_vergen() -> Result<(), Box<dyn Error>> {
    // Emit the instructions
    vergen::EmitBuilder::builder()
        .git_sha(true)
        .build_timestamp()
        .cargo_features()
        .cargo_target_triple()
        .emit()?;
    Ok(())
}
