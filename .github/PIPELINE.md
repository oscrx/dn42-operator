# Pipeline

Two workflows: [`ci.yaml`](workflows/ci.yaml) checks every change, and
[`release.yaml`](workflows/release.yaml) publishes. Same layout and
conventions as tlsa-dnsendpoint-controller, plus the tests that need a
Linux kernel.

## CI

Runs on every push and pull request to `main`. All jobs run in parallel and
are independent of each other. A newer push to the same ref cancels the run
in progress.

```mermaid
flowchart LR
    trigger(["Push / PR → main"])

    trigger --> test["<b>Test</b><br/>toolchain check, go mod tidy, gofmt,<br/>generated CRD current, vet, go test -race"]
    trigger --> lint["<b>Lint</b><br/>golangci-lint v2.15<br/>(incl. integration-tagged files)"]
    trigger --> audit["<b>Audit workflows</b><br/>zizmor → SARIF"]
    trigger --> build["<b>Build images</b><br/>operator, autopeer, bird<br/>amd64 + arm64, no push"]
    trigger --> renovate["<b>Renovate config</b><br/>validator --strict"]
    trigger --> manifests["<b>Manifests</b><br/>kubeconform on deploy/, config/crd/, test/k3s/"]
    trigger --> integration["<b>Integration</b><br/>privileged container: real VRF,<br/>WireGuard, BIRD, BGP Established"]
    trigger -- "main / on demand" --> k3s["<b>k3s</b><br/>3-node cluster in Docker:<br/>rolling update, failover"]
```

## Release

Runs on a `v*` tag, or by hand through `workflow_dispatch`. The tests run
first, without any cache, so nothing a pull request could have written ends
up in a signed image. The three images are built and signed in parallel.
The GitHub release comes last, so its page only appears once everything it
points to exists. The tag is also what the peers repo's gate installs
(`go install …/cmd/peercheck@<tag>`).

```mermaid
flowchart TD
    tag(["Tag v*"])
    dispatch(["workflow_dispatch"])

    tag --> test
    dispatch --> test

    test["<b>Test</b><br/>go test -race, integration tests<br/>(no cache)"]
    test --> operator["<b>dn42-operator</b><br/>root, privileged on the router"]
    test --> autopeer["<b>dn42-autopeer</b><br/>nonroot, only the web app"]
    test --> bird["<b>bird2</b><br/>BIRD for dn42-bird"]
    operator & autopeer & bird --> release["<b>GitHub release</b><br/>generated notes (tags only)"]
```

Each image is multi-arch, pushed to ghcr.io with SBOM and provenance, and
signed with cosign (keyless). A manual dispatch only publishes the moving
`:main` tags; a GitHub release is only created for a `v*` tag.
