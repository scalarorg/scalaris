use std::{env, error::Error, path::PathBuf};

use tonic_build::manual::{Builder, Method, Service};

fn main() -> Result<(), Box<dyn Error>> {
    println!("cargo:rerun-if-changed=proto");
    let out_dir = if env::var("DUMP_GENERATED_GRPC").is_ok() {
        PathBuf::from("")
    } else {
        PathBuf::from(env::var("OUT_DIR")?)
    };

    build_validator_service(&out_dir);
    build_proto_service();
    build_vergen()?;
    Ok(())
}

fn build_validator_service(out_dir: &PathBuf) {
    let codec_path = "mysten_network::codec::BcsCodec";
    let validator_service = Service::builder()
        .name("Validator")
        .package("scalaris.validator")
        .comment("The Validator interface")
        .method(
            Method::builder()
                .name("verify_message")
                .route_name("Message")
                .input_type("crate::consensus_types::RawTransaction")
                .output_type("crate::consensus_types::HandleVerifyMessageResponse")
                .codec_path(codec_path)
                .build(),
        )
        .build();
    Builder::new()
        .out_dir(&out_dir)
        .compile(&[validator_service]);
}
// This function only gets compiled if the target OS is linux
#[cfg(target_os = "linux")]
fn build_proto_service() {
    tonic_build::configure()
        .out_dir("src/proto")
        .compile(&["proto/types.proto", "proto/service.proto"], &["proto"])
        .expect("Failed to compile proto(s)");
}
// And this function only gets compiled if the target OS is *not* linux
#[cfg(not(target_os = "linux"))]
fn build_proto_service() {
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
