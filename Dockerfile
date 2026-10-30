# One image with two commands: `touchstone serve` (the page and POST /v1/scans)
# and `touchstone scan <url>` (the CLI). See docs/architecture/touchstone.md,
# "Deployment shape".

# The page is embedded at build time (web/embed.go), so it is built first.
FROM node:20-alpine AS web
RUN apk add --no-cache make
WORKDIR /src
COPY Makefile ./
COPY web ./web
RUN make web-build

FROM golang:1.26 AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
COPY --from=web /src/web/out/ ./web/out/
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/touchstone ./cmd/touchstone

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/touchstone /touchstone
# serve listens on all interfaces inside the container; the default is loopback.
ENV TOUCHSTONE_ADDR=0.0.0.0:8080
EXPOSE 8080
USER nonroot:nonroot
ENTRYPOINT ["/touchstone"]
CMD ["serve"]
