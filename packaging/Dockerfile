# LATTICE container image, built from source.
#
#   docker build -f packaging/Dockerfile -t lattice:0.1.0 .
#   docker run --rm -v "$PWD/estate:/estate:ro" -v "$PWD/out:/out" lattice:0.1.0 \
#       scan /estate -o /out/estate.cbom.json --report /out/estate.report.json
#   docker run --rm -p 127.0.0.1:7443:7443 -v "$PWD/estate:/estate:ro" -v lattice-data:/data \
#       -e LATTICE_TOKEN=... lattice:0.1.0 serve --bind 0.0.0.0:7443 --root estate=/estate --data-dir /data
#
# The final image is `scratch`: one static binary, the cockpit and the knowledge files, no shell,
# no package manager, a non-root user. LATTICE's own sandbox needs the landlock_* system calls,
# which Docker's default seccomp profile allows from Docker 23; on older engines it reports
# "filesystem unavailable" and keeps its system-call filter.

FROM node:22-bookworm-slim AS cockpit
WORKDIR /src/cockpit
COPY cockpit/package.json cockpit/package-lock.json ./
RUN npm ci --no-audit --no-fund
COPY cockpit/ ./
RUN npm run build

FROM rust:1-bookworm AS build
RUN apt-get update && apt-get install -y --no-install-recommends musl-tools && rm -rf /var/lib/apt/lists/*
WORKDIR /src
COPY rust-toolchain.toml ./
RUN rustup show active-toolchain && rustup target add "$(uname -m)-unknown-linux-musl"
COPY . .
RUN RUSTFLAGS="--remap-path-prefix=/src=/lattice" \
    cargo build --release --locked -p lattice-cli --target "$(uname -m)-unknown-linux-musl" \
 && install -D -m 0755 "target/$(uname -m)-unknown-linux-musl/release/lattice" /out/usr/bin/lattice \
 && mkdir -p /out/usr/share/lattice /out/data /out/out \
 && cp -r knowledge rules /out/usr/share/lattice/
COPY --from=cockpit /src/cockpit/dist /out/usr/share/lattice/cockpit

FROM scratch
COPY --from=build --chown=65532:65532 /out/ /
USER 65532:65532
WORKDIR /out
EXPOSE 7443
ENV LATTICE_SANDBOX=best-effort
ENTRYPOINT ["/usr/bin/lattice"]
CMD ["--help"]
