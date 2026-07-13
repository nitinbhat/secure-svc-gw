FROM golang:1.24-alpine AS builder
WORKDIR /src
ENV GOTOOLCHAIN=local

COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN CGO_ENABLED=0 go build -trimpath -buildvcs=false \
    -ldflags="-s -w" \
    -o /out/controller ./cmd/controller

# ---- runtime image -------------------------------------------------------
FROM scratch
COPY --from=builder /out/controller /controller
COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/
ENTRYPOINT ["/controller"]
