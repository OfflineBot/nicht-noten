FROM golang:1.26-alpine AS build
WORKDIR /src

COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="-s -w" -o /out/notendurchschnitt .

# Pre-create /data owned by uid:gid 65532 (matches distroless "nonroot")
# so the named volume inherits the right ownership on first mount.
RUN mkdir -p /out/data && chown -R 65532:65532 /out/data

FROM gcr.io/distroless/static-debian12:nonroot
WORKDIR /app
COPY --from=build /out/notendurchschnitt /app/notendurchschnitt
COPY --from=build --chown=65532:65532 /out/data /data

ENV ADDR=:8080 \
    DB_PATH=/data/data.db
VOLUME ["/data"]
EXPOSE 8080
USER nonroot:nonroot

ENTRYPOINT ["/app/notendurchschnitt"]
