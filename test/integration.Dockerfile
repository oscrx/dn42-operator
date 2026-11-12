# Linux integration tests: a real VRF, real WireGuard links and the BIRD from
# the router's own image (images/bird). Build that first: make bird-image.
# Run privileged (it creates links and network namespaces):
#   make integration
ARG BIRD_IMAGE=dn42-bird:dev
FROM golang:1.27-trixie AS go
FROM ${BIRD_IMAGE}
RUN apt-get update -qq \
 && apt-get install -y -qq --no-install-recommends wireguard-tools ca-certificates gcc libc6-dev >/dev/null \
 && rm -rf /var/lib/apt/lists/*
COPY --from=go /usr/local/go /usr/local/go
ENV PATH=/usr/local/go/bin:/root/go/bin:$PATH DN42_INTEGRATION=1
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN go test -c -tags integration -o /it-netdev ./internal/netdev \
 && go test -c -tags integration -o /it-controller ./internal/controller
ENTRYPOINT []
CMD ["sh", "-c", "set -e; bird --version; cd /src/internal/netdev && /it-netdev -test.v -test.run Integration; cd /src/internal/controller && /it-controller -test.v -test.run Integration"]
