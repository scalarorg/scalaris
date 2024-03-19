use protobuf_interface::{consensus_server::Consensus, AddNodeRequest, Empty, Node};
use tonic::{transport::Server, Request, Response, Status};

pub mod protobuf_interface {
    tonic::include_proto!("protobuf_interface");
}

#[derive(Debug, Default)]
pub struct MyConsensus {}

#[tonic::async_trait]
impl Consensus for MyConsensus {
    async fn clear_nodes(&self, _request: Request<Empty>) -> Result<Response<Empty>, Status> {
        Ok(Response::new(Empty {}))
    }

    type EnumerateNodesStream = std::vec::IntoIter<Node>;

    async fn enumerate_nodes(
        &self,
        _request: Request<Empty>,
    ) -> Result<Response<Self::EnumerateNodesStream>, Status> {
        let nodes = vec![Node {
            public_key: vec![1, 2, 3],
            address: "127.0.0.1".to_string(),
            voting_power: 100,
        }];
        Ok(Response::new(nodes.into_iter()))
    }

    async fn add_node(&self, request: Request<Node>) -> Result<Response<Empty>, Status> {
        println!("Received request to add node: {:?}", request.get_ref());
        Ok(Response::new(Empty {}))
    }

    async fn remove_node(&self, request: Request<Empty>) -> Result<Response<Empty>, Status> {
        println!(
            "Received request to remove node with public key: {:?}",
            request.get_ref()
        );
        Ok(Response::new(Empty {}))
    }

    async fn change_voting_power(&self, request: Request<Node>) -> Result<Response<Empty>, Status> {
        println!(
            "Received request to change voting power for node: {:?}",
            request.get_ref()
        );
        Ok(Response::new(Empty {}))
    }

    async fn submit_block(&self, request: Request<Block>) -> Result<Response<Empty>, Status> {
        println!(
            "Received request to submit block with data: {:?}",
            request.get_ref()
        );
        Ok(Response::new(Empty {}))
    }

    type GetBlockStreamStream = std::vec::IntoIter<Block>;

    async fn get_block_stream(
        &self,
        _request: Request<Empty>,
    ) -> Result<Response<Self::GetBlockStreamStream>, Status> {
        let blocks = vec![Block {
            data: vec![4, 5, 6],
        }];
        Ok(Response::new(blocks.into_iter()))
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let addr = "[::1]:50051".parse().unwrap();
    let consensus = MyConsensus::default();

    println!("Consensus server running on {}", addr);

    Server::builder()
        .add_service(ConsensusServer::new(consensus))
        .serve(addr)
        .await?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use protobuf_interface::consensus_client::ConsensusClient;
    use tonic::transport::Channel;

    async fn create_client() -> ConsensusClient<Channel> {
        let addr = "[::1]:50051".parse().unwrap();
        let channel = tonic::transport::Channel::from_shared(addr)
            .unwrap()
            .connect()
            .await
            .unwrap();
        ConsensusClient::new(channel)
    }

    #[tokio::test]
    async fn test_add_node() {
        let client = create_client().await;
        let request = tonic::Request::new(Node {
            public_key: vec![1, 2, 3],
            address: "127.0.0.1".to_string(),
            voting_power: 100,
        });

        let response = client.add_node(request).await.unwrap();
        assert_eq!(response.get_ref(), &Empty {});
    }

    #[tokio::test]
    async fn test_remove_node() {
        let client = create_client().await;
        let request = tonic::Request::new(Empty {});

        let response = client.remove_node(request).await.unwrap();
        assert_eq!(response.get_ref(), &Empty {});
    }

    #[tokio::test]
    async fn test_change_voting_power() {
        let client = create_client().await;
        let request = tonic::Request::new(Node {
            public_key: vec![1, 2, 3],
            address: "127.0.0.1".to_string(),
            voting_power: 200,
        });

        let response = client.change_voting_power(request).await.unwrap();
        assert_eq!(response.get_ref(), &Empty {});
    }

    #[tokio::test]
    async fn test_submit_block() {
        let client = create_client().await;
        let request = tonic::Request::new(Block {
            data: vec![4, 5, 6],
        });

        let response = client.submit_block(request).await.unwrap();
        assert_eq!(response.get_ref(), &Empty {});
    }

    #[tokio::test]
    async fn test_get_block_stream() {
        let client = create_client().await;
        let request = tonic::Request::new(Empty {});

        let mut stream = client.get_block_stream(request).await.unwrap().into_inner();
        let block = stream.next().await.unwrap().unwrap();
        assert_eq!(block.data, vec![4, 5, 6]);
    }
}
