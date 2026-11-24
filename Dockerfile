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

# Two images from one build, one binary each:
#   --target autopeer  the public web front end: nonroot, nothing else inside
#   (default)          dn42-operator: root, because it needs netlink, wgctrl
#                      and /proc/sys in the host network namespace
FROM gcr.io/distroless/static:nonroot@sha256:aafe993665bf6200db38a02c11a9351e782a84b6a45e7f33b6695638c88e3931 AS autopeer
COPY --from=build /out/autopeer /autopeer
USER 65532:65532
ENTRYPOINT ["/autopeer"]

FROM gcr.io/distroless/static@sha256:4c2cd1dee442c9a99924a378c7c126fac8fef14771579ef567c3f2bdd7a5122a AS operator
COPY --from=build /out/dn42-operator /dn42-operator
ENTRYPOINT ["/dn42-operator"]
