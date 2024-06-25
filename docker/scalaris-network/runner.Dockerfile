# Production Image
FROM debian:bookworm-slim AS runtime
# Use jemalloc as memory allocator
RUN apt-get update && apt-get install -y libjemalloc-dev ca-certificates curl
ENV LD_PRELOAD /usr/lib/x86_64-linux-gnu/libjemalloc.so
ARG PROFILE=release
WORKDIR "$WORKDIR/scalaris"

# Both bench and release profiles copy from release dir
#COPY --from=builder /scalaris/target/release/scalaris /opt/sui/bin/scalaris
# Support legacy usages of /usr/local/bin/scalaris
#COPY --from=builder /scalaris/target/release/scalaris /usr/local/bin
COPY scalaris /usr/local/bin

ARG BUILD_DATE
ARG GIT_REVISION
LABEL build-date=$BUILD_DATE
LABEL git-revision=$GIT_REVISION
