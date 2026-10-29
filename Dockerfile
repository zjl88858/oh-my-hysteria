FROM golang:1.26-alpine AS builder

# Override with --build-arg GOPROXY=... if a different proxy is needed.
ARG GOPROXY="https://proxy.golang.org,direct"

ENV GOPROXY=${GOPROXY}

WORKDIR /src

COPY . .

RUN set -ex \
    && apk add --no-cache python3 \
    && python3 hyperbole.py build -r \
    && mv ./build/oh-my-hysteria-* /go/bin/oh-my-hysteria

# multi-stage builds to create the final image
FROM alpine AS dist

# set up nsswitch.conf for Go's "netgo" implementation
# - https://github.com/golang/go/blob/go1.9.1/src/net/conf.go#L194-L275
# - docker run --rm debian:stretch grep '^hosts:' /etc/nsswitch.conf
RUN if [ ! -e /etc/nsswitch.conf ]; then echo 'hosts: files dns' > /etc/nsswitch.conf; fi

# bash is used for debugging, tzdata is used to add timezone information.
# iptables and nftables are used to change firewall rules.
# Install ca-certificates to ensure no CA certificate errors.
#
# Do not try to add the "--no-cache" option when there are multiple "apk"
# commands, this will cause the build process to become very slow.
RUN set -ex \
    && apk upgrade \
    && apk add bash tzdata ca-certificates iptables nftables \
    && rm -rf /var/cache/apk/*

COPY --from=builder /go/bin/oh-my-hysteria /usr/local/bin/oh-my-hysteria
COPY --from=builder /src/LICENSE.md /src/LICENSE-THIRD-PARTY.md /usr/share/licenses/oh-my-hysteria/
COPY --from=builder /src/third_party/quic-go/LICENSE /usr/share/licenses/oh-my-hysteria/LICENSE-quic-go.txt
COPY --from=builder /src/third_party/quic-go/OHMY-FORK.md /usr/share/licenses/oh-my-hysteria/QUIC-FORK.md
COPY --from=builder /src/third_party/tquic/LICENSE /usr/share/licenses/oh-my-hysteria/LICENSE-tquic.txt
COPY --from=builder /src/third_party/geodesic/LICENSE-kcc /usr/share/licenses/oh-my-hysteria/LICENSE-geodesic-kcc.txt
COPY --from=builder /src/third_party/geodesic/LICENSE-ucp /usr/share/licenses/oh-my-hysteria/LICENSE-geodesic-ucp.txt

ENTRYPOINT ["oh-my-hysteria"]
