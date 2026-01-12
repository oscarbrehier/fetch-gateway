use axum::Extension;
use axum::body::{Body, Bytes};
use axum::http::{HeaderMap, HeaderName, HeaderValue, Response};
use axum::{Router, extract::Query, response::IntoResponse, routing::get};
use dashmap::DashMap;
use reqwest::{Client, StatusCode};
use serde::Deserialize;
use std::collections::HashSet;
use std::env;
use std::sync::Arc;
use std::time::{Duration, Instant};

#[derive(Deserialize)]
struct FetchParams {
    url: String,
    key: Option<String>,
}

struct CacheResponse {
    body: Bytes,
    status: StatusCode,
    headers: HeaderMap,
    expires_at: Instant,
}

fn validate_url(raw: &str) -> Result<reqwest::Url, String> {
    let url = raw.parse::<reqwest::Url>().map_err(|_| "Invalid URL")?;

    match url.scheme() {
        "http" | "https" => Ok(url),
        _ => Err("Only http and https URLs are allowed".into()),
    }
}

fn get_whitelisted_headers(headers: &HeaderMap) -> HeaderMap {
    let whitelisted_headers: HashSet<HeaderName> =
        ["user-agent", "accept", "x-forwarded-for", "referer"]
            .iter()
            .map(|s| s.parse().expect("valid header name"))
            .collect();

    let mut new_headers = HeaderMap::new();

    for (key, value) in headers.iter() {
        if whitelisted_headers.contains(key) {
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

async fn fetch_handler(
    headers: HeaderMap,
    Query(params): Query<FetchParams>,
    Extension(cache): Extension<Arc<DashMap<String, CacheResponse>>>,
    Extension(secret): Extension<String>,
) -> impl IntoResponse {
    enum CacheState {
        Hit,
        Miss,
        Stale,
    }

    // auth
    match params.key {
        Some(key) if key == secret => {}
        _ => {
            return (StatusCode::UNAUTHORIZED, "Unauthorized").into_response();
        }
    };

    // validate URL
    let url = match validate_url(&params.url) {
        Ok(u) => u,
        Err(e) => return (StatusCode::BAD_REQUEST, e).into_response(),
    };

    // response parts
    let mut final_status: Option<StatusCode> = None;
    let mut final_headers = HeaderMap::new();
    let mut final_body: Option<Bytes> = None;
    let mut cache_state = CacheState::Miss;

    // cache lookup
    if let Some(cached) = cache.get(&params.url) {
        let now = Instant::now();

        if cached.expires_at > now {
            final_status = Some(cached.status);
            final_headers = cached.headers.clone();
            final_body = Some(cached.body.clone());

            cache_state = CacheState::Hit;
        } else {
            cache.remove(&params.url);
            cache_state = CacheState::Stale;
        }
    }

    // fetch upstream
    if !matches!(cache_state, CacheState::Hit) {
        let client = match Client::builder().timeout(Duration::from_secs(10)).build() {
            Ok(c) => c,
            Err(e) => {
                eprintln!("Failed to build reqwest client: {}", e);
                return (StatusCode::INTERNAL_SERVER_ERROR, "Internal Server Error")
                    .into_response();
            }
        };

        let forward_headers = get_whitelisted_headers(&headers);

        let response = match client.get(url).headers(forward_headers).send().await {
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

        final_body = match response.bytes().await {
            Ok(b) => Some(b),
            Err(_) => {
                return (StatusCode::BAD_GATEWAY, "Failed to read response body").into_response();
            }
        };

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
        }),
    );

    let final_status = final_status.expect("final_status must be set");
    let final_body = final_body.expect("final_body must be set");

    // store in cache
    if !matches!(cache_state, CacheState::Hit) {
        let mut headers_to_cache = final_headers.clone();
        headers_to_cache.remove("x-cache");

        cache.insert(
            params.url.clone(),
            CacheResponse {
                body: final_body.clone(),
                status: final_status,
                headers: headers_to_cache,
                expires_at: Instant::now() + Duration::from_secs(60 * 60),
            },
        );
    }

    build_response(final_status, final_headers, final_body)
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    dotenvy::dotenv().ok();

    let cache = Arc::new(DashMap::<String, CacheResponse>::new());

    let secret = env::var("FETCH_SECRET").expect("FETCH_SECRET must be set");

    let app = Router::new()
        .route("/fetch", get(fetch_handler))
        .layer(Extension(cache.clone()))
        .layer(Extension(secret.clone()));

    let server_addr = env::var("SERVER_ADDR").unwrap_or("127.0.0.1:3000".to_string());

    let listener = tokio::net::TcpListener::bind(&server_addr).await?;
    println!("Listening on {}", server_addr);

    axum::serve(listener, app).await?;

    Ok(())
}
