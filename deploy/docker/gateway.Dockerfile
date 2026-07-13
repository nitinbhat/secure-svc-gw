# syntax=docker/dockerfile:1

FROM golang:1.24-alpine AS build
# GOTOOLCHAIN=local: use exactly the version in this image, never auto-download.
ENV GOTOOLCHAIN=local
WORKDIR /src
COPY go.mod go.sum* ./
RUN go mod download || true
COPY . .
RUN CGO_ENABLED=0 go build -trimpath -buildvcs=false -ldflags="-s -w" -o /out/gateway ./cmd/gateway

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/gateway /gateway
EXPOSE 8080 9090
USER nonroot
ENTRYPOINT ["/gateway"]
