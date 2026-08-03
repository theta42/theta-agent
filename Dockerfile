# Multi-stage build for minimal runtime image
FROM golang:1.23-alpine AS builder

# Install build dependencies
RUN apk add --no-cache git

WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -v -o theta-agent .

# Final runtime image
FROM alpine:latest
RUN apk add --no-cache ca-certificates

WORKDIR /

# Create config directory
RUN mkdir -p /etc/theta42

COPY --from=builder /app/theta-agent /usr/local/bin/theta-agent

# Run as root for system management
USER root

ENTRYPOINT ["/usr/local/bin/theta-agent"]
