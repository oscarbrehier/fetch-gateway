use axum::{Router, extract::Query, response::IntoResponse, routing::get};
use reqwest::{Client, StatusCode};
use serde::Deserialize;
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

async fn fetch_handler(Query(params): Query<FetchParams>) -> impl IntoResponse {
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

    let client = Client::builder()
        .timeout(Duration::from_secs(10))
        .build()
        .unwrap();

    let response = match client.get(url).send().await {
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
    let body = match response.bytes().await {
        Ok(b) => b,
        Err(_) => {
            return (StatusCode::BAD_GATEWAY, "Failed to read response body").into_response();
        }
    };

    (status, body).into_response()
}

#[tokio::main]
async fn main() {
    dotenvy::dotenv().ok();

    let app = Router::new().route("/fetch", get(fetch_handler));

    let listener = tokio::net::TcpListener::bind("127.0.0.1:3000")
        .await
        .unwrap();

    axum::serve(listener, app).await.unwrap();
}
