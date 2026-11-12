FROM --platform=$BUILDPLATFORM golang:1.27-trixie AS build
ARG TARGETOS TARGETARCH
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH \
    go build -trimpath -ldflags="-s -w" -o /dn42-operator ./cmd/dn42-operator

# Runs as root: netlink, wgctrl and /proc/sys need it (the pod is privileged).
FROM gcr.io/distroless/static-debian12
COPY --from=build /dn42-operator /dn42-operator
ENTRYPOINT ["/dn42-operator"]
