# BIRD 2 image for the bird container of the router pod (also the base of
# the integration test image). iproute2 is for debugging (ip vrf, ip -d link)
# and the test's VRF init container. Not published from this repo yet.
FROM debian:trixie-slim
RUN apt-get update -qq \
 && apt-get install -y -qq --no-install-recommends bird2 iproute2 \
 && rm -rf /var/lib/apt/lists/* \
 && mkdir -p /run/bird /etc/bird/peers
ENTRYPOINT ["bird", "-f", "-c", "/etc/bird/bird.conf", "-s", "/run/bird/bird.ctl"]
