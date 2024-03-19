use crate::protobuf_interface::{
    consensus_server::{Consensus, ConsensusServer},
    *,
};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::Mutex;
use tokio_stream::wrappers::ReceiverStream;
use tonic::{transport::Server, Request, Response, Status};

pub struct SimpleConsensus {
    nodes: Arc<Mutex<HashMap<Vec<u8>, Node>>>, // Using HashMap for easier node management based on public_key
}

pub mod protobuf_interface {
    tonic::include_proto!("protobuf_interface");
}

#[tonic::async_trait]
impl Consensus for SimpleConsensus {
    async fn clear_nodes(&self, request: Request<Empty>) -> Result<Response<Empty>, Status> {
        let mut nodes = self.nodes.lock().await;
        nodes.clear();
        Ok(Response::new(Empty {}))
    }

    type EnumerateNodesStream = ReceiverStream<Result<Node, Status>>;

    async fn enumerate_nodes(
        &self,
        request: Request<Empty>,
    ) -> Result<Response<Self::EnumerateNodesStream>, Status> {
        let nodes = self.nodes.lock().await;
        let (tx, rx) = tokio::sync::mpsc::channel(4);

        for node in nodes.values() {
            tx.send(Ok(node.clone())).await.unwrap();
        }

        Ok(Response::new(ReceiverStream::new(rx)))
    }

    async fn add_node(&self, request: Request<Node>) -> Result<Response<Empty>, Status> {
        let node = request.into_inner();
        let mut nodes = self.nodes.lock().await;
        nodes.insert(node.public_key.clone(), node);
        Ok(Response::new(Empty {}))
    }

    async fn remove_node(&self, request: Request<PublicKey>) -> Result<Response<Empty>, Status> {
        let public_key = request.into_inner().data;
        let mut nodes = self.nodes.lock().await;
        nodes.remove(&public_key);
        Ok(Response::new(Empty {}))
    }

    async fn change_voting_power(&self, request: Request<Node>) -> Result<Response<Empty>, Status> {
        // Simplified change voting power logic
        let node_update = request.into_inner();
        let mut nodes = self.nodes.lock().await;
        if let Some(node) = nodes.get_mut(&node_update.public_key) {
            node.voting_power = node_update.voting_power;
        }
        Ok(Response::new(Empty {}))
    }

    async fn submit_block(&self, request: Request<Block>) -> Result<Response<Empty>, Status> {
        // Minimal logic for block submission
        Ok(Response::new(Empty {}))
    }

    type GetBlockStreamStream = ReceiverStream<Result<Block, Status>>;

    async fn get_block_stream(
        &self,
        request: Request<Empty>,
    ) -> Result<Response<Self::GetBlockStreamStream>, Status> {
        let (tx, rx) = tokio::sync::mpsc::channel(4);

        // Example: Sending an empty block for demonstration
        tx.send(Ok(Block { data: vec![] })).await.unwrap();

        Ok(Response::new(ReceiverStream::new(rx)))
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let addr = "[::1]:50051".parse()?;
    let consensus = SimpleConsensus {
        nodes: Arc::new(Mutex::new(HashMap::new())),
    };

    println!("Server listening on {}", addr);

    Server::builder()
        .add_service(ConsensusServer::new(consensus))
        .serve(addr)
        .await?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protobuf_interface::{consensus_client::ConsensusClient, Node, PublicKey};
    use std::collections::HashMap;
    use std::sync::Arc;
    use tokio::time::{sleep, Duration};
    use tonic::transport::Channel;

    #[tokio::test]
    async fn test_grpc_server() {
        let mut retries = 0;
        loop {
            retries += 1;
            // Start the gRPC server in a separate task
            let server_task = tokio::spawn(async {
                let addr = "[::1]:39212".parse().unwrap();
                let consensus = SimpleConsensus {
                    nodes: Arc::new(Mutex::new(HashMap::new())),
                };

                Server::builder()
                    .add_service(ConsensusServer::new(consensus))
                    .serve(addr)
                    .await
                    .unwrap();
            });

            sleep(Duration::from_secs(1)).await;

            // Create an in-memory gRPC client to interact with the server
            let channel = match Channel::from_static("http://[::1]:39212").connect().await {
                Ok(channel) => channel,
                Err(error) => {
                    if retries >= 100000 {
                        println!("Failed to connect after 100000 retries. Exiting.");
                        panic!("{}", error);
                    }
                    continue;
                }
            };
            let mut client = ConsensusClient::new(channel);

            // Test RPC calls
            let _ = client.clear_nodes(Empty {}).await.unwrap();
            let _ = client
                .add_node(Node {
                    public_key: vec![],
                    address: "localhost".to_string(),
                    voting_power: 1,
                })
                .await
                .unwrap();

            // Add more test cases for other RPC calls as needed

            // Stop the server after testing
            server_task.abort();
            break;
        }
    }
}
