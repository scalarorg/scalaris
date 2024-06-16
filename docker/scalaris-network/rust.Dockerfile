FROM rust:1.78.0-bookworm
ARG PROFILE=release
ARG GIT_REVISION
ENV GIT_REVISION=$GIT_REVISION
WORKDIR "/workspace"
RUN apt-get update && apt-get install -y cmake clang protobuf-compiler
