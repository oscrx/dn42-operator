# Minimal BIRD 2 image for the bird container of the router pod. Not
# published from this repo yet; build it wherever the router images live.
FROM debian:trixie-slim
RUN apt-get update -qq \
 && apt-get install -y -qq --no-install-recommends bird2 \
 && rm -rf /var/lib/apt/lists/*
ENTRYPOINT ["bird", "-f", "-c", "/etc/bird/bird.conf", "-s", "/run/bird/bird.ctl"]
