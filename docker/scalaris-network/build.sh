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
CONTAINER_BUILDER=scalaris-builder

# option to build using debug symbols
if [ "$1" = "--debug-symbols" ]; then
	PROFILE="bench"
	echo "Building with full debug info enabled ... WARNING: binary size might significantly increase"
	shift
else
	PROFILE="release"
fi

scalaris() {
	echo
	echo "Building sui-node docker image"
	echo "Dockerfile: \t$DOCKERFILE"
	echo "docker context: $REPO_ROOT"
	echo "build date: \t$BUILD_DATE"
	echo "git revision: \t$GIT_REVISION"
	echo

	docker-compose -f ${DIR}/docker-compose-builder.yaml up -d
	cd ${REPO_ROOT}
	docker cp Cargo.toml ${CONTAINER_BUILDER}:/workspace
	docker cp Cargo.lock ${CONTAINER_BUILDER}:/workspace
	docker cp consensus ${CONTAINER_BUILDER}:/workspace
	docker exec ${CONTAINER_BUILDER} cargo build --profile ${PROFILE} --bin scalaris
	docker cp ${CONTAINER_BUILDER}:/workspace/target/release/scalaris ${REPO_ROOT}/scalaris
	echo "docker context: $REPO_ROOT"
	docker build -f "${RUNNER_DOCKERFILE}" "$REPO_ROOT" \
		--build-arg GIT_REVISION="$GIT_REVISION" \
		--build-arg BUILD_DATE="$BUILD_DATE" \
		--build-arg PROFILE="$PROFILE" \
		"$@"
	rm ${REPO_ROOT}/scalaris
}

genesis() {
	OUTDIR=${1:-/tmp/scalaris}
	docker build --file ${DIR}/genesis.Dockerfile --output "type=local,dest=./" .
	if [ -d "$OUTDIR" ]; then 
		rm -rf "$OUTDIR" 
	fi
	mkdir -p ${OUTDIR}/genesis
	cp -R genesis/files ${OUTDIR}/genesis
	cp -R genesis/static ${OUTDIR}/genesis
}

$@