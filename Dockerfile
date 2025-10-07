# Build stage
FROM rust:1.90 as builder
WORKDIR /app
# copy source
COPY . .
RUN cargo build --release

# Runtime
FROM debian:stable-slim
COPY --from=builder /app/target/release/auth /usr/local/bin/auth
EXPOSE 8080
CMD ["/usr/local/bin/auth"]
