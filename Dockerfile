# Cross-compiles rather than emulating: the build stage runs on the builder's
# native architecture and Go emits a binary for the target.
FROM --platform=$BUILDPLATFORM docker.io/library/golang:1.27.4@sha256:205c7636d74e0ffbe3d007162df7d74f859f5a8c8322dfb9f907977686c126cf AS src
WORKDIR /src

COPY go.mod go.sum ./
RUN go mod download

COPY api/ api/
COPY cmd/ cmd/
COPY internal/ internal/

ARG TARGETOS
ARG TARGETARCH
ENV CGO_ENABLED=0 GOOS=${TARGETOS:-linux} GOARCH=${TARGETARCH:-amd64}

# One build stage per binary: BuildKit only runs the stages a --target
# needs, so each image job compiles just its own binary.
FROM src AS build-operator
RUN go build -trimpath -ldflags="-s -w" -o /out/dn42-operator ./cmd/dn42-operator

FROM src AS build-autopeer
RUN go build -trimpath -ldflags="-s -w" -o /out/autopeer ./cmd/autopeer

# Two images, one binary each:
#   --target autopeer  the public web front end: nonroot, nothing else inside
#   (default)          dn42-operator: root, because it needs netlink, wgctrl
#                      and /proc/sys in the host network namespace
FROM gcr.io/distroless/static:nonroot@sha256:8ce6dd87e9823c5b48dcfb2c8604714ccb351ce59607327bcc4957448da279b5 AS autopeer
COPY --from=build-autopeer /out/autopeer /autopeer
USER 65532:65532
ENTRYPOINT ["/autopeer"]

FROM gcr.io/distroless/static@sha256:4c2cd1dee442c9a99924a378c7c126fac8fef14771579ef567c3f2bdd7a5122a AS operator
COPY --from=build-operator /out/dn42-operator /dn42-operator
ENTRYPOINT ["/dn42-operator"]
