CONTROLLER_GEN ?= controller-gen
IMG ?= ghcr.io/oscrx/dn42-operator:dev
BIRD_IMG ?= dn42-bird:dev

.PHONY: generate build test integration image bird-image k3s-test

generate:
	$(CONTROLLER_GEN) object paths=./api/...
	$(CONTROLLER_GEN) crd paths=./api/... output:crd:artifacts:config=config/crd

build:
	go build ./...

test:
	go test ./...

# Needs Docker; runs the Linux-only tests in a privileged container with a
# real VRF, WireGuard links and BIRD.
integration: bird-image
	docker build -f test/integration.Dockerfile --build-arg BIRD_IMAGE=$(BIRD_IMG) -t dn42-operator-it .
	docker run --rm --privileged dn42-operator-it

image:
	docker build -t $(IMG) .

bird-image:
	docker build -t $(BIRD_IMG) images/bird

# Multi-node k3s in Docker: DaemonSet rolling update and failover.
k3s-test: image bird-image
	IMG=$(IMG) BIRD_IMG=$(BIRD_IMG) bash test/k3s/run.sh
