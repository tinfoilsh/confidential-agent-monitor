# syntax=docker/dockerfile:1
FROM docker.io/library/golang:1.27.3-alpine@sha256:f2c872bcee949b7be9c490efd02b48a8a2fbf947cdf533f1c58525ec9d8170fd AS toolchain

FROM docker.io/oven/bun:1.3.13@sha256:87416c977a612a204eb54ab9f3927023c2a3c971f4f345a01da08ea6262ae30e AS ui-build
WORKDIR /src/ui
COPY ui/package.json ui/bun.lock ./
COPY ui/vendor/ ./vendor/
RUN bun install --frozen-lockfile
COPY ui/ ./
RUN bun run build

# A static, unprivileged launcher keeps the final image shell-free. No daemon,
# image pull or package manager is needed when a connection starts a worker.
FROM toolchain AS sandbox-build
RUN apk add --no-cache build-base meson ninja pkgconf libcap-dev libcap-static
WORKDIR /src
ADD https://github.com/containers/bubblewrap/releases/download/v0.13.0/bubblewrap-0.13.0.tar.xz /src/bubblewrap.tar.xz
RUN echo '4734237473c0e5d695e4e9034a34e43b2dbf5164655bd13fa59ae376b2b7a765  bubblewrap.tar.xz' | sha256sum -c - \
    && tar xf bubblewrap.tar.xz \
    && meson setup out bubblewrap-0.13.0 -Dselinux=disabled -Dman=disabled -Dtests=false -Dprefer_static=true -Dc_link_args=-static \
    && meson compile -C out \
    && strip out/bwrap

FROM toolchain AS build
ENV GOWORK=off CGO_ENABLED=0
WORKDIR /src/monitor
COPY go.mod go.sum ./
RUN go mod download
COPY . .
COPY --from=ui-build /src/ui/dist ./ui/dist
RUN go build -mod=readonly -trimpath -buildvcs=false -ldflags='-s -w -buildid=' -o /monitor .
# The worker gets one prepared filesystem, with no mounts derived from accounts.
# Static connectors need only trust roots; custom images can install programs here.
RUN mkdir -p /worker-root/etc/ssl/certs /worker-root/dev /worker-root/proc /worker-root/tmp \
    && touch /worker-root/worker /worker-root/broker.sock

FROM gcr.io/distroless/static-debian12:nonroot@sha256:e8a4044e0b4ae4257efa45fc026c0bc30ad320d43bd4c1a7d5271bd241e386d0 AS trust

FROM gcr.io/distroless/static-debian12:nonroot@sha256:e8a4044e0b4ae4257efa45fc026c0bc30ad320d43bd4c1a7d5271bd241e386d0
COPY --from=build /monitor /monitor
COPY --from=build /worker-root /opt/monitor/worker
COPY --from=trust /etc/ssl/certs/ca-certificates.crt /opt/monitor/worker/etc/ssl/certs/ca-certificates.crt
COPY --from=sandbox-build /src/out/bwrap /usr/bin/bwrap
COPY --from=sandbox-build /src/bubblewrap-0.13.0/LICENSE /src/bubblewrap-0.13.0/COPYING /src/bubblewrap-0.13.0/COPYING.LIB /usr/share/licenses/bubblewrap/
USER 65532:65532
EXPOSE 8080 2223
HEALTHCHECK --interval=10s --timeout=5s CMD ["/monitor", "-healthcheck"]
ENTRYPOINT ["/monitor"]
