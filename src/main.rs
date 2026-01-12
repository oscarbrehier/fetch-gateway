use axum::http::{HeaderMap, HeaderName};
use axum::{Router, extract::Query, response::IntoResponse, routing::get};
use reqwest::{Client, StatusCode};
use serde::Deserialize;
use std::collections::HashSet;
use std::env;
use std::time::Duration;

#[derive(Deserialize)]
struct FetchParams {
    url: String,
    key: Option<String>,
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

async fn fetch_handler(headers: HeaderMap, Query(params): Query<FetchParams>) -> impl IntoResponse {
    let secret = env::var("FETCH_SECRET").expect("FETCH_SECRET must be set");

    match params.key {
        Some(key) if key == secret => {}
        _ => {
            return (StatusCode::UNAUTHORIZED, "Unauthorized").into_response();
        }
    };

    let url = match validate_url(&params.url) {
        Ok(u) => u,
        Err(e) => return (StatusCode::BAD_REQUEST, e).into_response(),
    };

    let client = Client::builder().timeout(Duration::from_secs(10)).build();

    let client = match client {
        Ok(c) => c,
        Err(e) => {
            eprintln!("Failed to build reqwest client: {}", e);
            return (StatusCode::INTERNAL_SERVER_ERROR, "Internal Server Error. Please check logs.").into_response();
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

    let status = response.status();

    let response_headers = response.headers().clone();

    let body = match response.bytes().await {
        Ok(b) => b,
        Err(_) => {
            return (StatusCode::BAD_GATEWAY, "Failed to read response body").into_response();
        }
    };
    
    let mut axum_headers = HeaderMap::new();
    for (key, value) in response_headers.iter() {
        axum_headers.append(key.clone(), value.clone());
    }

    (status, axum_headers, body).into_response()
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    dotenvy::dotenv().ok();

    let app = Router::new().route("/fetch", get(fetch_handler));

    let server_addr = env::var("SERVER_ADDR").unwrap_or("127.0.0.1:3000".to_string());

    let listener = tokio::net::TcpListener::bind(&server_addr).await?;
    println!("Listening on {}", server_addr);

    axum::serve(listener, app).await?;

    Ok(())
}
