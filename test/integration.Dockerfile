# Linux integration tests: a real VRF, real WireGuard links, real BIRD.
# Run privileged (it creates links and network namespaces):
#   make integration
FROM golang:1.27-trixie
RUN apt-get update -qq \
 && apt-get install -y -qq --no-install-recommends bird2 iproute2 wireguard-tools >/dev/null \
 && rm -rf /var/lib/apt/lists/*
ENV DN42_INTEGRATION=1
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN go test -c -tags integration -o /it-netdev ./internal/netdev \
 && go test -c -tags integration -o /it-controller ./internal/controller
CMD ["sh", "-c", "set -e; cd /src/internal/netdev && /it-netdev -test.v -test.run Integration; cd /src/internal/controller && /it-controller -test.v -test.run Integration"]
