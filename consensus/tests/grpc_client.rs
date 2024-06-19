#[cfg(test)]
mod tests {
    use futures::StreamExt;
    pub use scalaris::proto::service::consensus_api_client::ConsensusApiClient;
    pub use scalaris::proto::{ConsensusOutput, ExternalTransaction};
    use std::error::Error;
    use std::time::{self, Duration};
    use tokio::{
        sync::mpsc::unbounded_channel,
        time::{sleep, timeout},
    };
    use tracing::{error, info};
    const CONSENSUS_ADDR: &str = "http://127.0.0.1:8081";
    const CHAIN_ID: &str = "scalar";

    #[tokio::test]
    async fn send_transactions() -> Result<(), Box<dyn Error>> {
        const START_TIMEOUT: Duration = Duration::from_secs(30);
        const RETRY_INTERVAL: Duration = Duration::from_millis(100);
        if let Ok(mut client) = timeout(START_TIMEOUT, async {
            loop {
                if let Ok(client) = ConsensusApiClient::connect(CONSENSUS_ADDR).await {
                    return client;
                } else {
                    sleep(RETRY_INTERVAL).await;
                }
            }
        })
        .await
        {
            let (tx_transaction, mut rx_transaction) = unbounded_channel();
            let stream = async_stream::stream! {
                while let Some(tx_bytes) = rx_transaction.recv().await {
                    //Received serialized data from a slice &[ConsensusTransaction]
                    info!("Receive a pending transaction hash, send it into scalaris consensus {:?}", &tx_bytes);
                    let consensus_transaction = ExternalTransaction { chain_id: String::from(CHAIN_ID), tx_bytes };
                    yield consensus_transaction;
                }
            };
            //pin_mut!(stream);
            let stream = Box::pin(stream);
            let response = client.init_transaction(stream).await?;
            let mut resp_stream = response.into_inner();
            tokio::spawn(async move {
                while let Some(received) = resp_stream.next().await {
                    match received {
                        Ok(grpc_output) => {
                            let consensus_output: ConsensusOutput = grpc_output.into();
                            println!("Consensus output {:?}", &consensus_output);
                            // consensus_handler
                            //     .handle_scalaris_ouput(consensus_output)
                            //     .await;
                        }
                        Err(err) => error!("{:?}", err),
                    }
                }
            });
            //Client for send transaction
            loop {
                let tx = vec![0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15];
                let res = tx_transaction.send(vec![tx]);
                println!("Send tx result {:?}", res);
                let onehundred_millis = time::Duration::from_millis(1000);
                let _now = time::Instant::now();
                sleep(onehundred_millis).await;
                break;
            }
        } else {
            println!(
                "Error while connect to the consensus grpc {}",
                CONSENSUS_ADDR
            );
        }
        Ok(())
    }
}
