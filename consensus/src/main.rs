use clap::{ArgGroup, Parser};
use mysten_common::sync::async_once_cell::AsyncOnceCell;
use scalaris::{ConsensusNode, NodeConfig};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;
use sui_config::Config;
use sui_types::committee::EpochId;
use sui_types::messages_checkpoint::CheckpointSequenceNumber;
use sui_types::multiaddr::Multiaddr;
use tokio::runtime;
use tokio::sync::broadcast;
use tracing::error;
// Define the `GIT_REVISION` and `VERSION` consts
bin_version::bin_version!();

#[derive(Parser)]
#[clap(rename_all = "kebab-case")]
#[clap(name = env!("CARGO_BIN_NAME"))]
#[clap(version = VERSION)]
#[clap(group(ArgGroup::new("exclusive").required(false)))]
struct Args {
    #[clap(long)]
    pub config_path: PathBuf,

    #[clap(long, help = "Specify address to listen on")]
    listen_address: Option<Multiaddr>,

    #[clap(long, group = "exclusive")]
    run_with_range_epoch: Option<EpochId>,

    #[clap(long, group = "exclusive")]
    run_with_range_checkpoint: Option<CheckpointSequenceNumber>,
}
fn main() {
    let args = Args::parse();
    let mut config = NodeConfig::load(&args.config_path).unwrap();
    let node_once_cell = Arc::new(AsyncOnceCell::<Arc<ConsensusNode>>::new());
    let node_once_cell_clone = node_once_cell.clone();
    let runtime = runtime::Builder::new_multi_thread()
        .thread_name("scalaris-consensus-runtime")
        .enable_all()
        .build()
        .unwrap();
    let registry_service = mysten_metrics::start_prometheus_server(config.metrics_address);
    let (runtime_shutdown_tx, runtime_shutdown_rx) = broadcast::channel::<()>(1);
    runtime.spawn(async move {
        match ConsensusNode::start(config, registry_service).await {
            Ok(node) => node_once_cell_clone
                .set(node)
                .expect("Failed to set node in AsyncOnceCell"),

            Err(e) => {
                error!("Failed to start node: {e:?}");
                std::process::exit(1);
            }
        }
        // get node, subscribe to shutdown channel
        let node = node_once_cell_clone.get().await;
        let mut shutdown_rx = node.subscribe_to_shutdown_channel();

        // when we get a shutdown signal from sui-node, forward it on to the runtime_shutdown_channel here in
        // main to signal runtimes to all shutdown.
        tokio::select! {
           _ = shutdown_rx.recv() => {
                runtime_shutdown_tx.send(()).expect("failed to forward shutdown signal from sui-node to sui-node main");
            }
        }
        // TODO: Do we want to provide a way for the node to gracefully shutdown?
        loop {
            tokio::time::sleep(Duration::from_secs(1000)).await;
        }
    });
    // wait for SIGINT on the main thread
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap()
        .block_on(wait_termination(runtime_shutdown_rx));
}

#[cfg(not(unix))]
async fn wait_termination(mut shutdown_rx: tokio::sync::broadcast::Receiver<()>) {
    tokio::select! {
        _ = tokio::signal::ctrl_c() => {},
        _ = shutdown_rx.recv() => {},
    }
}

#[cfg(unix)]
async fn wait_termination(mut shutdown_rx: tokio::sync::broadcast::Receiver<()>) {
    use futures::FutureExt;
    use tokio::signal::unix::*;

    let sigint = tokio::signal::ctrl_c().boxed();
    let mut sigterm = signal(SignalKind::terminate()).unwrap();
    let sigterm_recv = sigterm.recv().boxed();
    let shutdown_recv = shutdown_rx.recv().boxed();

    tokio::select! {
        _ = sigint => {},
        _ = sigterm_recv => {},
        _ = shutdown_recv => {},
    }
}
