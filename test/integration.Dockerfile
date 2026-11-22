# syntax=docker/dockerfile:1
# Linux integration tests: a real VRF, real WireGuard links and the BIRD from
# the router's own image (images/bird). Build that first: make bird-image.
# Run privileged (it creates links and network namespaces):
#   make integration
ARG BIRD_IMAGE=dn42-bird:dev
FROM docker.io/library/golang:1.27.4@sha256:205c7636d74e0ffbe3d007162df7d74f859f5a8c8322dfb9f907977686c126cf AS go
FROM ${BIRD_IMAGE}
RUN apt-get update -qq \
 && apt-get install -y -qq --no-install-recommends wireguard-tools ca-certificates gcc libc6-dev >/dev/null \
 && rm -rf /var/lib/apt/lists/*
COPY --from=go /usr/local/go /usr/local/go
ENV PATH=/usr/local/go/bin:/root/go/bin:$PATH DN42_INTEGRATION=1
WORKDIR /src
COPY go.mod go.sum ./
RUN --mount=type=cache,target=/root/go/pkg/mod go mod download
COPY . .
# Cache mounts keep the module and build caches between runs, so a change
# only recompiles the packages it touches.
RUN --mount=type=cache,target=/root/go/pkg/mod --mount=type=cache,target=/root/.cache/go-build \
    go test -c -tags integration -o /it-netdev ./internal/netdev \
 && go test -c -tags integration -o /it-controller ./internal/controller
ENTRYPOINT []
CMD ["sh", "-c", "set -e; bird --version; cd /src/internal/netdev && /it-netdev -test.v -test.run Integration; cd /src/internal/controller && /it-controller -test.v -test.run Integration"]
