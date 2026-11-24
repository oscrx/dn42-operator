# BIRD 2 image for the dn42-bird DaemonSet (also the base of the integration
# test image), built from the upstream source. Published as
# ghcr.io/oscrx/bird2:<BIRD version> by bird-image.yaml.
#
# The source is the upstream git repo at a tag, checked against the pinned
# commit: bird.network.cz refuses automated downloads, and a commit hash is as
# strict as a tarball checksum. It is cloned from CZ-NIC's GitHub mirror of
# gitlab.nic.cz/labs/bird (same commits), because gitlab.nic.cz refuses
# GitHub's runners at times; the commit check makes the mirror as safe as the
# origin. Renovate bumps BIRD_TAG and BIRD_COMMIT together (github-tags,
# BIRD 2 only); a new BIRD is reviewed by hand.
# .git goes after the check, so BIRD reports its VERSION ("2.20.0") instead
# of a development version with the commit appended.
# iproute2 is for debugging (ip vrf, ip -d link) and the test's VRF init
# container.

FROM docker.io/library/debian:trixie-slim@sha256:8aa5a7bf5a1955bddbe7d74fcdd0b91ab30e74362a8b73af672b0481b35b44a0 AS build
# renovate: datasource=github-tags depName=CZ-NIC/bird
ARG BIRD_TAG=v2.20.0
ARG BIRD_COMMIT=0355729c3a546c910e20bcde423bf36da901f8b5
RUN apt-get update -qq \
 && apt-get install -y -qq --no-install-recommends \
      ca-certificates git build-essential autoconf flex bison \
      libncurses-dev libreadline-dev >/dev/null
RUN git clone -q --depth 1 --branch "${BIRD_TAG}" https://github.com/CZ-NIC/bird.git /src \
 && test "$(git -C /src rev-parse HEAD)" = "${BIRD_COMMIT}" \
      || { echo "${BIRD_TAG} is not ${BIRD_COMMIT}" >&2; exit 1; } \
 && test "v$(cat /src/VERSION)" = "${BIRD_TAG}" \
 && rm -rf /src/.git
WORKDIR /src
RUN autoreconf -i \
 && ./configure -q --prefix=/usr --sysconfdir=/etc/bird --localstatedir=/var \
      --runstatedir=/run/bird --disable-libssh \
 && make -s -j"$(nproc)" \
 && make -s install DESTDIR=/out \
 && /out/usr/sbin/bird --version

FROM docker.io/library/debian:trixie-slim@sha256:8aa5a7bf5a1955bddbe7d74fcdd0b91ab30e74362a8b73af672b0481b35b44a0
ARG BIRD_TAG
LABEL org.opencontainers.image.title="bird2" \
      org.opencontainers.image.version="${BIRD_TAG}" \
      org.opencontainers.image.description="BIRD ${BIRD_TAG} for dn42-operator"
RUN apt-get update -qq \
 && apt-get install -y -qq --no-install-recommends libreadline8t64 libncursesw6 iproute2 >/dev/null \
 && rm -rf /var/lib/apt/lists/* \
 && mkdir -p /run/bird /etc/bird/peers
COPY --from=build /out/usr/sbin/ /usr/sbin/
ENTRYPOINT ["bird", "-f", "-c", "/etc/bird/bird.conf", "-s", "/run/bird/bird.ctl"]
