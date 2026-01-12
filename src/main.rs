use axum::Extension;
use axum::body::{Body, Bytes};
use axum::http::{HeaderMap, HeaderValue, Response};
use axum::{Router, extract::Query, response::IntoResponse, routing::get};
use dashmap::DashMap;
use reqwest::{Client, StatusCode};
use serde::Deserialize;
use std::collections::HashSet;
use std::env;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};

const MAX_CACHE_ENTRIES: usize = 10_000;
const MAX_CACHE_SIZE_BYTES: usize = 100 * 1024 * 1024;
const MAX_RESPONSE_SIZE: usize = 10 * 1024 * 1024;

struct AppState {
    cache: Arc<DashMap<String, CacheResponse>>,
    client: Client,
    secret: String,
    cache_size_bytes: AtomicUsize,
}

struct CacheControl {
    max_age: Option<u64>,
    no_store: bool,
}

#[derive(Deserialize)]
struct FetchParams {
    url: String,
}

#[derive(Clone)]
struct CacheResponse {
    body: Arc<Bytes>,
    status: StatusCode,
    headers: HeaderMap,
    expires_at: Instant,
    size: usize,
}

fn validate_url(raw: &str) -> Result<reqwest::Url, String> {
    let url = raw
        .parse::<reqwest::Url>()
        .map_err(|_| "Invalid URL format")?;

    match url.scheme() {
        "http" | "https" => {}
        _ => return Err("Only HTTP(S) URLs allowed".into()),
    }

    // SSRF protection
    if let Some(host) = url.host_str() {
        if host == "localhost"
            || host == "127.0.0.1"
            || host.starts_with("192.168.")
            || host.starts_with("10.")
            || host.starts_with("172.16.")
            || host == "0.0.0.0"
            || host == "[::1]"
        {
            return Err("Cannot fetch from private networks".into());
        }
    }

    Ok(url)
}

fn get_whitelisted_headers(headers: &HeaderMap) -> HeaderMap {
    let whitelisted: HashSet<&str> = [
        "user-agent",
        "accept",
        "accept-language",
        "accept-encoding",
        "referer",
    ]
    .iter()
    .copied()
    .collect();

    let mut new_headers = HeaderMap::new();

    for (key, value) in headers.iter() {
        if whitelisted.contains(key.as_str()) {
            new_headers.append(key.clone(), value.clone());
        }
    }

    new_headers
}

fn build_response(status: StatusCode, headers: HeaderMap, body: Bytes) -> Response<Body> {
    let mut builder = Response::builder().status(status);

    for (k, v) in headers.iter() {
        builder = builder.header(k, v);
    }

    builder.body(Body::from(body)).unwrap_or_else(|e| {
        eprintln!("Failed to build response: {}", e);
        Response::builder()
            .status(StatusCode::INTERNAL_SERVER_ERROR)
            .body(Body::from("Internal Server Error"))
            .unwrap()
    })
}

fn parse_cache_control(header: Option<&HeaderValue>) -> CacheControl {
    let mut cc = CacheControl {
        max_age: None,
        no_store: false,
    };

    if let Some(hv) = header {
        if let Ok(s) = hv.to_str() {
            for part in s.split(",") {
                let part = part.trim();
                if part.eq_ignore_ascii_case("no-store") {
                    cc.no_store = true;
                } else if let Some(secs) = part.strip_prefix("max-age=") {
                    if let Ok(seconds) = secs.parse::<u64>() {
                        cc.max_age = Some(seconds);
                    }
                }
            }
        }
    }

    cc
}

fn evict_if_needed(state: &AppState) {
    let cache_size = state.cache_size_bytes.load(Ordering::Relaxed);

    if state.cache.len() > MAX_CACHE_ENTRIES || cache_size > MAX_CACHE_SIZE_BYTES {
        // remove expired entries first
        let now = Instant::now();
        let to_remove: Vec<String> = state
            .cache
            .iter()
            .filter(|entry| entry.expires_at <= now)
            .map(|entry| entry.key().clone())
            .collect();

        for key in to_remove {
            if let Some((_, removed)) = state.cache.remove(&key) {
                state
                    .cache_size_bytes
                    .fetch_sub(removed.size, Ordering::Relaxed);
            }
        }

        // remove oldest entries if still over limit
        if state.cache.len() > MAX_CACHE_ENTRIES {
            let to_remove: Vec<String> = state
                .cache
                .iter()
                .take(state.cache.len() - MAX_CACHE_ENTRIES + 100)
                .map(|entry| entry.key().clone())
                .collect();

            for key in to_remove {
                if let Some((_, removed)) = state.cache.remove(&key) {
                    state
                        .cache_size_bytes
                        .fetch_sub(removed.size, Ordering::Relaxed);
                }
            }
        }
    }
}

async fn fetch_handler(
    headers: HeaderMap,
    Query(params): Query<FetchParams>,
    Extension(state): Extension<Arc<AppState>>,
) -> impl IntoResponse {
    enum CacheState {
        Hit,
        Miss,
        Stale,
        Bypass,
    }

    // auth
    let authorized = headers
        .get("authorization")
        .and_then(|h| h.to_str().ok())
        .and_then(|h| h.strip_prefix("Bearer "))
        .map(|token| token == state.secret)
        .unwrap_or(false);

    if !authorized {
        return (StatusCode::UNAUTHORIZED, "Unauthorized").into_response();
    }

    // validate URL
    let url = match validate_url(&params.url) {
        Ok(u) => u,
        Err(e) => return (StatusCode::BAD_REQUEST, e).into_response(),
    };

    let cache_control = parse_cache_control(headers.get("cache-control"));
    let ttl = cache_control.max_age.map(Duration::from_secs);
    let no_store = cache_control.no_store;

    // response parts
    let mut final_status: Option<StatusCode> = None;
    let mut final_headers = HeaderMap::new();
    let mut final_body: Option<Arc<Bytes>> = None;
    let mut cache_state = if no_store {
        CacheState::Bypass
    } else {
        CacheState::Miss
    };

    // cache lookup
    if no_store {
        if let Some((_, removed)) = state.cache.remove(&params.url) {
            state
                .cache_size_bytes
                .fetch_sub(removed.size, Ordering::Relaxed);
        }
    } else {
        if let Some(cached) = state.cache.get(&params.url) {
            if cached.expires_at > Instant::now() {
                final_status = Some(cached.status);
                final_headers = cached.headers.clone();
                final_body = Some(cached.body.clone());
                cache_state = CacheState::Hit;
            } else {
                drop(cached);
                state.cache.remove(&params.url);
                cache_state = CacheState::Stale;
            }
        }
    }

    // fetch upstream
    if final_body.is_none() {
        let forward_headers = get_whitelisted_headers(&headers);

        let response = match state
            .client
            .get(url.clone())
            .headers(forward_headers)
            .send()
            .await
        {
            Ok(r) => r,
            Err(e) => {
                return (
                    StatusCode::BAD_GATEWAY,
                    format!("Upstream request failed {}", e),
                )
                    .into_response();
            }
        };

        final_status = Some(response.status());
        let response_headers = response.headers().clone();

        if let Some(cl) = response.content_length() {
            if cl > MAX_RESPONSE_SIZE as u64 {
                return (
                    StatusCode::PAYLOAD_TOO_LARGE,
                    "Response exceeds maximum size",
                )
                    .into_response();
            }
        }

        let body_bytes = match response.bytes().await {
            Ok(b) => {
                if b.len() > MAX_RESPONSE_SIZE {
                    return (
                        StatusCode::PAYLOAD_TOO_LARGE,
                        "Response exceeds maximum size",
                    )
                        .into_response();
                }
                b
            }
            Err(_) => {
                return (StatusCode::BAD_GATEWAY, "Failed to read response body").into_response();
            }
        };

        final_body = Some(Arc::new(body_bytes));

        for (k, v) in response_headers.iter() {
            final_headers.append(k.clone(), v.clone());
        }
    }

    final_headers.append(
        "x-cache",
        HeaderValue::from_static(match cache_state {
            CacheState::Hit => "HIT",
            CacheState::Miss => "MISS",
            CacheState::Stale => "STALE",
            CacheState::Bypass => "BYPASS",
        }),
    );

    let final_status = final_status.expect("final_status must be set");
    let final_body = final_body.expect("final_body must be set");

    // store in cache
    if !matches!(cache_state, CacheState::Hit) && !no_store && final_status.is_success() {
        evict_if_needed(&state);

        let mut headers_to_cache = final_headers.clone();
        headers_to_cache.remove("x-cache");

        let expires_at = Instant::now() + ttl.unwrap_or(Duration::from_secs(3600));
        let size = final_body.len();

        state.cache.insert(
            params.url.clone(),
            CacheResponse {
                body: final_body.clone(),
                status: final_status,
                headers: headers_to_cache,
                expires_at,
                size,
            },
        );

        state.cache_size_bytes.fetch_add(size, Ordering::Relaxed);
    }

    let body_bytes = (*final_body).clone();
    build_response(final_status, final_headers, body_bytes)
}

async fn health_check() -> impl IntoResponse {
    (StatusCode::OK, "OK")
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    dotenvy::dotenv().ok();

    let secret = env::var("FETCH_SECRET").expect("FETCH_SECRET must be set");

    let client = Client::builder()
        .timeout(Duration::from_secs(30))
        .connect_timeout(Duration::from_secs(10))
        .pool_max_idle_per_host(10)
        .build()?;

    let state = Arc::new(AppState {
        cache: Arc::new(DashMap::<String, CacheResponse>::new()),
        client,
        secret,
        cache_size_bytes: AtomicUsize::new(0),
    });

    let app = Router::new()
        .route("/fetch", get(fetch_handler))
        .route("/health", get(health_check))
        .layer(Extension(state));

    let server_addr = env::var("SERVER_ADDR").unwrap_or_else(|_| "0.0.0.0:3000".to_string());

    let listener = tokio::net::TcpListener::bind(&server_addr).await?;
    println!("Listening on {}", server_addr);

    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown_signal())
        .await?;

    Ok(())
}

async fn shutdown_signal() {
    tokio::signal::ctrl_c()
        .await
        .expect("Failed to install graceful shutdown signal handler");
}
