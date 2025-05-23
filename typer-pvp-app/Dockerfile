FROM rust:latest AS build
WORKDIR /build

COPY . .
#needed to "cargo run" outside docker to modify cached app binary
RUN --mount=type=cache,dst=/build/target \
    --mount=type=cache,dst=/usr/local/cargo/registry \
    cargo build

FROM ubuntu
WORKDIR /app

COPY --from=build /build/target/debug/app ./main
COPY --from=build /build/static ./static
COPY --from=build /build/.env .

CMD ["./main"]

