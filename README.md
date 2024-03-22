# PackagedNarwhalBullshark
## High level strategy
- Expose ordered blocks in `async fn analyze()`
- Drive the Narwhal Bullshark code using an external process
## Interface
### Committee
A node consists of public key, network address and voting power. Changes to the committee are only applied in the next epoch.
- Add node
- Delete node
- Clear all nodes
- Change voting power
