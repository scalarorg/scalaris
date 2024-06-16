# Scalaris Network Docker Compose

This was tested using MacOS 14.3.1, Docker Compose: v2.13.0.

This compose brings up 3 validators, 1 fullnode, and 1 stress (load gen) client

Steps for running:

1. Build scalaris image

```
cd docker/scalaris-network
docker/scalaris-network/build.sh -t scalaris:latest
```

2. Build genesis (Required for first startup)

```
cd docker/scalaris-network
docker build --file genesis.Dockerfile --output "type=local,dest=./" .
```

3. run compose

```
(optional) `rm -r /tmp/scalaris`
docker compose up
```

**additional info**
The version of `sui` which is used to generate the genesis outputs much be on the same protocol version as the fullnode/validators (eg: `mysten/sui-node:mainnet-v1.19.1`)
Here's an example of how to build a `sui` binary that creates a genesis which is compatible with the release: `v1.19.1`

```
git checkout releases/sui-v1.19.0-release
cargo build --bin sui
```
