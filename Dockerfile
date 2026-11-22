# Cross-compiles rather than emulating: the build stage runs on the builder's
# native architecture and Go emits a binary for the target.
FROM --platform=$BUILDPLATFORM docker.io/library/golang:1.27.4@sha256:205c7636d74e0ffbe3d007162df7d74f859f5a8c8322dfb9f907977686c126cf AS build
WORKDIR /src

COPY go.mod go.sum ./
RUN go mod download

COPY api/ api/
COPY cmd/ cmd/
COPY internal/ internal/

ARG TARGETOS
ARG TARGETARCH
RUN CGO_ENABLED=0 GOOS=${TARGETOS:-linux} GOARCH=${TARGETARCH:-amd64} \
    go build -trimpath -ldflags="-s -w" -o /out/dn42-operator ./cmd/dn42-operator \
 && CGO_ENABLED=0 GOOS=${TARGETOS:-linux} GOARCH=${TARGETARCH:-amd64} \
    go build -trimpath -ldflags="-s -w" -o /out/autopeer ./cmd/autopeer

# distroless static as root, not :nonroot: the operator needs netlink,
# wgctrl and /proc/sys in the host network namespace (the pod is privileged).
# autopeer ships in the same image and runs as 65532 (its Deployment sets it).
FROM gcr.io/distroless/static@sha256:1a64f46364620465ef9e9a8f5413757dfdf22695e050bbfd7303eeaf17a59383
COPY --from=build /out/dn42-operator /dn42-operator
COPY --from=build /out/autopeer /autopeer
ENTRYPOINT ["/dn42-operator"]
