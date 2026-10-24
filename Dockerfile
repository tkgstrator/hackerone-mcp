# syntax=docker/dockerfile:1

# Builder: Debian 12 (bookworm) so the binary links against glibc 2.36,
# matching the distroless/cc-debian12 runtime below.
FROM rust:1.98.1-bookworm@sha256:93ce27a88655056a51dbdd8f5f2d7ddc071c7b0070fb288a37b5a285fc83971e AS builder
WORKDIR /src
COPY Cargo.toml Cargo.lock ./
COPY src ./src
RUN cargo build --release --locked \
 && cp target/release/hackerone-mcp /hackerone-mcp \
 && mkdir -p /rootfs/data/drafts /rootfs/usr/local/bin \
 && cp /hackerone-mcp /rootfs/usr/local/bin/hackerone-mcp \
 && chmod 0700 /rootfs/data/drafts

# Artifact: only the binary, for `docker buildx build --target artifact --output type=local,...`.
FROM scratch AS artifact
COPY --from=builder /hackerone-mcp /hackerone-mcp

# Runtime (final stage): distroless cc-debian12 provides glibc 2.36, libgcc and
# CA certificates (reqwest's rustls uses the platform verifier, which reads the
# system trust store, so certificates are required) with no shell or package manager.
FROM gcr.io/distroless/cc-debian12@sha256:e5d81ddde149641e2a9ba55be4545bc125c67de07508b03ba4c22e6eb0ded5aa AS runtime
LABEL org.opencontainers.image.source="https://github.com/tkgstrator/hackerone-mcp" \
      org.opencontainers.image.description="Read-only HackerOne MCP server that prepares report drafts locally (stdio)" \
      org.opencontainers.image.licenses="MIT"
COPY --from=builder --chown=10001:10001 --chmod=0755 /rootfs/usr/local/bin/hackerone-mcp /usr/local/bin/hackerone-mcp
COPY --from=builder --chown=10001:10001 --chmod=0700 /rootfs/data/drafts /data/drafts
ENV H1_MCP_DRAFTS_DIR=/data/drafts
VOLUME ["/data/drafts"]
USER 10001:10001
ENTRYPOINT ["/usr/local/bin/hackerone-mcp"]
