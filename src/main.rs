// src/main.rs
use actix_web::{web, App, HttpServer, HttpResponse, Responder, middleware::Logger};
use serde::{Deserialize, Serialize};
use sqlx::{Pool, Postgres, postgres::PgPoolOptions, Row};
use dotenv::dotenv;
use std::env;
use bcrypt::{hash as bcrypt_hash, verify as bcrypt_verify};
use uuid::Uuid;
use jsonwebtoken::{encode, decode, Header, EncodingKey, DecodingKey, Validation, errors::Error as JwtError};
use chrono::{Utc, Duration};
use anyhow::Context;

#[derive(Debug, Serialize, Deserialize)]
struct RegisterRequest {
    username: String,
    password: String,
}

#[derive(Debug, Serialize, Deserialize)]
struct LoginRequest {
    username: String,
    password: String,
}

#[derive(Debug, Serialize, Deserialize)]
struct TokenResponse {
    access_token: String,
    refresh_token: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct Claims {
    sub: String,
    exp: usize,
}

async fn hello() -> impl Responder {
    HttpResponse::Ok().json(serde_json::json!({"message": "auth service running"}))
}

// DB health check
async fn health(db: web::Data<Pool<Postgres>>) -> impl Responder {
    match sqlx::query("SELECT 1").execute(db.get_ref()).await {
        Ok(_) => HttpResponse::Ok().json(serde_json::json!({"db": "ok"})),
        Err(e) => {
            log::error!("DB healthcheck failed: {}", e);
            HttpResponse::InternalServerError().json(serde_json::json!({"db": "error"}))
        }
    }
}

fn create_jwt(sub: &str, secret: &str, exp_seconds: i64) -> Result<String, JwtError> {
    let exp = Utc::now() + Duration::seconds(exp_seconds);
    let claims = Claims {
        sub: sub.to_string(),
        exp: exp.timestamp() as usize,
    };
    encode(&Header::default(), &claims, &EncodingKey::from_secret(secret.as_bytes()))
}

async fn register(db: web::Data<Pool<Postgres>>, req: web::Json<RegisterRequest>) -> impl Responder {
    if req.username.trim().is_empty() || req.password.is_empty() {
        return HttpResponse::BadRequest().body("username and password required");
    }

    let hashed = match bcrypt_hash(&req.password, 12) {
        Ok(h) => h,
        Err(e) => {
            log::error!("bcrypt error: {}", e);
            return HttpResponse::InternalServerError().body("hash error");
        }
    };
    let id = Uuid::new_v4();

    let res = sqlx::query("INSERT INTO users (id, username, password_hash) VALUES ($1, $2, $3)")
        .bind(id)
        .bind(&req.username)
        .bind(&hashed)
        .execute(db.get_ref())
        .await;

    match res {
        Ok(_) => HttpResponse::Ok().json(serde_json::json!({"id": id, "username": req.username})),
        Err(e) => {
            log::error!("DB insert error: {}", e);
            if e.to_string().to_lowercase().contains("unique") {
                HttpResponse::Conflict().body("username already exists")
            } else {
                HttpResponse::InternalServerError().body("DB error")
            }
        }
    }
}

async fn login(db: web::Data<Pool<Postgres>>, req: web::Json<LoginRequest>) -> impl Responder {
    if req.username.trim().is_empty() || req.password.is_empty() {
        return HttpResponse::BadRequest().body("username and password required");
    }

    let row_result = sqlx::query("SELECT id, username, password_hash FROM users WHERE username = $1")
        .bind(&req.username)
        .fetch_one(db.get_ref())
        .await;

    match row_result {
        Ok(row) => {
            let id: Uuid = row.try_get("id").unwrap_or_else(|_| Uuid::new_v4());
            let _username: String = row.try_get("username").unwrap_or_default();
            let password_hash: String = row.try_get("password_hash").unwrap_or_default();

            let pass_ok = bcrypt_verify(&req.password, &password_hash).unwrap_or(false);
            if pass_ok {
                let secret = env::var("JWT_SECRET").unwrap_or_else(|_| {
                    log::warn!("JWT_SECRET not set, using default (unsafe)");
                    "secret".to_string()
                });

                let access_exp: i64 = env::var("ACCESS_TOKEN_EXP").unwrap_or_else(|_| "3600".into()).parse().unwrap_or(3600);
                let refresh_exp: i64 = env::var("REFRESH_TOKEN_EXP").unwrap_or_else(|_| "86400".into()).parse().unwrap_or(86400);

                let access_token = match create_jwt(&id.to_string(), &secret, access_exp) {
                    Ok(t) => t,
                    Err(e) => {
                        log::error!("Failed to create access token: {}", e);
                        return HttpResponse::InternalServerError().body("token error");
                    }
                };
                let refresh_token = match create_jwt(&id.to_string(), &secret, refresh_exp) {
                    Ok(t) => t,
                    Err(e) => {
                        log::error!("Failed to create refresh token: {}", e);
                        return HttpResponse::InternalServerError().body("token error");
                    }
                };

                HttpResponse::Ok().json(TokenResponse { access_token, refresh_token })
            } else {
                HttpResponse::Unauthorized().body("Invalid credentials")
            }
        }
        Err(_) => HttpResponse::Unauthorized().body("Invalid credentials"),
    }
}

#[derive(Deserialize)]
struct RefreshRequest {
    refresh_token: String,
}

async fn refresh(req: web::Json<RefreshRequest>) -> impl Responder {
    let secret = env::var("JWT_SECRET").unwrap_or_else(|_| "secret".to_string());

    match decode::<Claims>(&req.refresh_token, &DecodingKey::from_secret(secret.as_bytes()), &Validation::default()) {
        Ok(token_data) => {
            let access_exp: i64 = env::var("ACCESS_TOKEN_EXP").unwrap_or_else(|_| "3600".into()).parse().unwrap_or(3600);
            match create_jwt(&token_data.claims.sub, &secret, access_exp) {
                Ok(new_access) => HttpResponse::Ok().json(serde_json::json!({"access_token": new_access})),
                Err(_) => HttpResponse::InternalServerError().body("token creation error"),
            }
        },
        Err(e) => {
            log::warn!("Refresh token decode failed: {}", e);
            HttpResponse::Unauthorized().body("Invalid refresh token")
        },
    }
}

#[derive(Deserialize)]
struct VerifyRequest {
    token: String,
}

async fn verify_token(req: web::Query<VerifyRequest>) -> impl Responder {
    let secret = env::var("JWT_SECRET").unwrap_or_else(|_| "secret".to_string());
    match decode::<Claims>(&req.token, &DecodingKey::from_secret(secret.as_bytes()), &Validation::default()) {
        Ok(data) => HttpResponse::Ok().json(serde_json::json!({"valid": true, "sub": data.claims.sub})),
        Err(_) => HttpResponse::Unauthorized().json(serde_json::json!({"valid": false})),
    }
}

async fn ensure_users_table(pool: &Pool<Postgres>) -> anyhow::Result<()> {
    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS users (
            id UUID PRIMARY KEY,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL
        )
        "#
    )
    .execute(pool)
    .await
    .context("create users table")?;
    Ok(())
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    dotenv().ok();
    env_logger::init_from_env(env_logger::Env::new().default_filter_or("info"));

    let db_url = env::var("AUTH_DB_URL").expect("AUTH_DB_URL must be set");
    let pool = PgPoolOptions::new()
        .max_connections(10)
        .connect(&db_url)
        .await
        .expect("Failed to connect to DB");

    // Ensure table exists
    ensure_users_table(&pool).await.expect("failed to create users table");

    let port = env::var("SERVER_PORT").unwrap_or_else(|_| "8080".to_string());

    log::info!("Auth service starting on 0.0.0.0:{}", port);

    HttpServer::new(move || {
        App::new()
            .wrap(Logger::default())
            .app_data(web::Data::new(pool.clone()))
            .route("/hello", web::get().to(hello))
            .route("/health", web::get().to(health))
            .route("/register", web::post().to(register))
            .route("/login", web::post().to(login))
            .route("/refresh", web::post().to(refresh))
            .route("/verify", web::get().to(verify_token))
    })
    .bind(format!("0.0.0.0:{}", port))?
    .run()
    .await
}
