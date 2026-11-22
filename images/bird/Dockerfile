# BIRD 2 image for the bird container of the router pod (also the base of
# the integration test image). iproute2 is for debugging (ip vrf, ip -d link)
# and the test's VRF init container. Published as ghcr.io/oscrx/bird2 by release.yaml.
FROM docker.io/library/debian:trixie-slim@sha256:a72b4433de1cf7d6bae0c4cee74d0547f58601a643b3375f070c51600d63b6b2
RUN apt-get update -qq \
 && apt-get install -y -qq --no-install-recommends bird2 iproute2 \
 && rm -rf /var/lib/apt/lists/* \
 && mkdir -p /run/bird /etc/bird/peers
ENTRYPOINT ["bird", "-f", "-c", "/etc/bird/bird.conf", "-s", "/run/bird/bird.ctl"]
