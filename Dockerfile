# syntax=docker/dockerfile:1
FROM docker.io/library/golang:1.27.1-alpine@sha256:8a5910f31396cd4d89662f56c68b3ae31d374308270a1c3bd96672ee5ed43414 AS build
ENV GOWORK=off CGO_ENABLED=0
WORKDIR /src/monitor
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN go build -mod=readonly -trimpath -buildvcs=false -ldflags='-s -w -buildid=' -o /monitor .

FROM gcr.io/distroless/static-debian12:nonroot@sha256:e8a4044e0b4ae4257efa45fc026c0bc30ad320d43bd4c1a7d5271bd241e386d0
COPY --from=build /monitor /monitor
USER 65532:65532
EXPOSE 8080 2223
HEALTHCHECK --interval=10s --timeout=5s CMD ["/monitor", "-healthcheck"]
ENTRYPOINT ["/monitor"]
