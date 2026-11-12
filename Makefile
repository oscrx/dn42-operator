CONTROLLER_GEN ?= controller-gen
IMG ?= ghcr.io/oscrx/dn42-operator:dev

.PHONY: generate build test integration image

generate:
	$(CONTROLLER_GEN) object paths=./api/...
	$(CONTROLLER_GEN) crd paths=./api/... output:crd:artifacts:config=config/crd

build:
	go build ./...

test:
	go test ./...

# Needs Docker; runs the Linux-only tests in a privileged container with a
# real VRF, WireGuard links and BIRD.
integration:
	docker build -f test/integration.Dockerfile -t dn42-operator-it .
	docker run --rm --privileged dn42-operator-it

image:
	docker build -t $(IMG) .
