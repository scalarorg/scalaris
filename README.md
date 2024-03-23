# PackagedNarwhalBullshark
## High level strategy
- Expose ordered blocks in `async fn analyze()`
- Drive the Narwhal Bullshark code using an external process written in Rust
- Every X amount of time, the committee is destroyed and changes to the committee are applied
## Interface
### Committee
A node consists of public key, network address and voting power. Changes to the committee are only applied in the next epoch.
- Add node
- Delete node
- Clear all nodes
- Change voting power
### Blocks
**Namespacing:** There are multiple chains, they have separate streams. When sending a transaction you have to specify the chain. When reading ordered blocks you also have to specify the chain. All chains have the same committee.

Multiple transactions form a batch. Multiple batches form a block.

Transactions are sent through the interface, then the interface routes transactions to workers for processing. A transaction is just binary data, this code doesn't try to understand the content of the transaction.
- Send transaction
  + The interface calls a remote function provided by the execution layer to check if the transaction actually makes sense. If the transaction doesn't make sense, it is ignored. Otherwise, the transaction can be included in a block.
- Get a stream of blocks
  + The Narwhal Bullshark consensus protocol orders blocks and emits them to the execution layer.
## Testing
- Existing code is tested with `cargo test`
- End to end test:
  + Three nodes are spawned on
    * one machine
    * or three separate machines
  + Each node has three workers
  + Submit transactions to three nodes
  + Check if all three nodes emit the same stream of blocks
  + Check if the blocks emitted include all the submitted transactions
