IMG          ?= ghcr.io/oscrx/dn42-operator:dev
AUTOPEER_IMG ?= ghcr.io/oscrx/dn42-autopeer:dev
BIRD_IMG     ?= dn42-bird:dev

# Pinned, and kept in step with ci.yaml by Renovate. Both are run from source
# with this repo's toolchain, as CI does.
GOLANGCI_LINT_VERSION ?= v2.15.0
CONTROLLER_GEN_VERSION ?= v0.23.0
CONTROLLER_GEN ?= go run sigs.k8s.io/controller-tools/cmd/controller-gen@$(CONTROLLER_GEN_VERSION)

.PHONY: help
help: ## Show this help
	@grep -hE '^[a-zA-Z0-9_.-]+:.*?## ' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-18s\033[0m %s\n", $$1, $$2}'

.PHONY: generate
generate: ## Regenerate deepcopy and the chart's CRD (controller-gen)
	$(CONTROLLER_GEN) object paths=./api/...
	$(CONTROLLER_GEN) crd paths=./api/... output:crd:artifacts:config=charts/dn42-operator/crds

.PHONY: generate.verify
generate.verify: generate ## Fail if generated code is out of date
	git diff --exit-code -- api charts/dn42-operator/crds

.PHONY: build
build: ## Build all binaries for the host
	go build ./...

.PHONY: run-local
run-local: ## Try autopeer locally as any ASN: fake login provider + in-memory repo (http://localhost:8099)
	./hack/run-local.sh

.PHONY: test
test: ## Unit tests with race detection
	go test -race -count=1 ./...

.PHONY: vet
vet: ## go vet, including the Linux-only and integration-tagged files
	go vet ./...
	GOOS=linux go vet -tags integration ./...

.PHONY: fmt
fmt: ## Format the code
	gofmt -l -s -w .

# Built for the host, then run for the host and for Linux (the netlink code
# and the integration tests only exist there).
GOLANGCI_LINT := bin/golangci-lint-$(GOLANGCI_LINT_VERSION)
$(GOLANGCI_LINT):
	GOBIN=$(CURDIR)/bin go install github.com/golangci/golangci-lint/v2/cmd/golangci-lint@$(GOLANGCI_LINT_VERSION)
	mv bin/golangci-lint $@

.PHONY: lint
lint: $(GOLANGCI_LINT) ## golangci-lint, for the host and for Linux incl. integration-tagged files
	$(GOLANGCI_LINT) run --timeout=5m ./...
	GOOS=linux $(GOLANGCI_LINT) run --timeout=5m --build-tags integration ./...

# The images must compile with the Go the tests ran on. Renovate groups the
# two, but the golang image is often published after the toolchain, so this
# keeps a toolchain-only PR red until the image catches up.
.PHONY: toolchain.verify
toolchain.verify: ## Check the Dockerfiles' Go matches go.mod's toolchain
	@want=$$(awk '$$1=="toolchain"{sub("go","",$$2); print $$2}' go.mod); \
	for f in Dockerfile test/integration.Dockerfile; do \
		got=$$(sed -nE 's|.*golang:([0-9.]+)@.*|\1|p' $$f); \
		if [ -z "$$want" ] || [ "$$want" != "$$got" ]; then \
			echo "go.mod toolchain is $$want but $$f builds with golang:$$got"; exit 1; \
		fi; \
	done

.PHONY: verify
verify: toolchain.verify generate.verify vet lint test ## Everything the CI test and lint jobs run

# Needs Docker; runs the Linux-only tests in a privileged container with a
# real VRF, WireGuard links and BIRD.
.PHONY: integration
integration: bird-image ## Integration tests (privileged container)
	docker build -f test/integration.Dockerfile --build-arg BIRD_IMAGE=$(BIRD_IMG) -t dn42-operator-it .
	docker run --rm --privileged dn42-operator-it

.PHONY: image
image: ## Operator image for the host platform
	docker build --target operator -t $(IMG) .

.PHONY: autopeer-image
autopeer-image: ## autopeer image for the host platform
	docker build --target autopeer -t $(AUTOPEER_IMG) .

.PHONY: bird-image
bird-image: ## BIRD image for the host platform
	docker build -t $(BIRD_IMG) images/bird

# Multi-node k3s in Docker: DaemonSet rolling update and failover.
.PHONY: k3s-test
k3s-test: image bird-image ## Rolling update and failover on a 3-node k3s in Docker
	IMG=$(IMG) BIRD_IMG=$(BIRD_IMG) bash test/k3s/run.sh
