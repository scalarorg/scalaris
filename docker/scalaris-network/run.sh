#!/bin/sh
# fast fail.
set -e

DIR="$( cd "$( dirname "$0" )" && pwd )"
REPO_ROOT="$(git rev-parse --show-toplevel)"
RUST_DOCKERFILE="$DIR/rust.Dockerfile"
RUNNER_DOCKERFILE="$DIR/runner.Dockerfile"
IMAGE=scalaris/rust:1.75-bullseye
GIT_REVISION="$(git describe --always --abbrev=12 --dirty --exclude '*')"
BUILD_DATE="$(date -u +'%Y-%m-%d')"

# option to build using debug symbols
if [ "$1" = "--debug-symbols" ]; then
	PROFILE="bench"
	echo "Building with full debug info enabled ... WARNING: binary size might significantly increase"
	shift
else
	PROFILE="release"
fi

echo
echo "Building sui-node docker image"
echo "Dockerfile: \t$DOCKERFILE"
echo "docker context: $REPO_ROOT"
echo "build date: \t$BUILD_DATE"
echo "git revision: \t$GIT_REVISION"
echo

runner() {
	docker start scalaris_builder
	docker exec -it scalaris_builder cargo build --profile ${PROFILE} --bin scalaris 
	docker stop scalaris_builder
	docker build -f "${RUNNER_DOCKERFILE}" -t scalaris/consensus:latest ${DIR}/../..
}

builder() {
	docker build -f "${RUST_DOCKERFILE}" -t ${IMAGE} .
	docker run --name scalaris_builder \
		-v ${DIR}/../..:/workspace \
		-w /workspace \
		-d ${IMAGE} sleep infinity
}

$@