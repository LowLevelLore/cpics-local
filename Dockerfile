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
ENV AUTH_DB_URL=postgres://auth_user:12345678@34.93.18.235:5432/auth_service_db
ENV ACCESS_TOKEN_EXP=86400
ENV JWT_SECRET=12345678
ENV SERVER_PORT=8080
CMD ["/usr/local/bin/auth"]
