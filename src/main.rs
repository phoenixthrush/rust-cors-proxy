use bytes::Bytes;
use once_cell::sync::Lazy;
use reqwest::Client;
use std::convert::Infallible;
use std::time::Duration;
use warp::{http::Response, Filter};

static CLIENT: Lazy<Client> = Lazy::new(|| {
    Client::builder()
        .pool_max_idle_per_host(32)
        .timeout(Duration::from_secs(30)) // 30 seconds timeout
        .build()
        .expect("Failed building reqwest client")
});

#[tokio::main(flavor = "multi_thread")]
async fn main() {
    let route = warp::path("proxy")
        .and(warp::path::tail())
        .and(warp::method())
        .and(warp::body::bytes())
        .and_then(handle);

    println!("Running on http://127.0.0.1:8080");
    warp::serve(route).run(([127, 0, 0, 1], 8080)).await;
}

async fn handle(
    tail: warp::path::Tail,
    method: warp::http::Method,
    body: Bytes,
) -> Result<impl warp::Reply, Infallible> {
    let url = tail.as_str();

    if !(url.starts_with("http://") || url.starts_with("https://")) {
        return Ok(Response::builder()
            .status(400)
            .body(Bytes::from_static(b"URL must begin with http:// or https://"))
            .unwrap());
    }

    // Handle CORS preflight
    if method == warp::http::Method::OPTIONS {
        return Ok(Response::builder()
            .status(204)
            .header("Access-Control-Allow-Origin", "*")
            .header("Access-Control-Allow-Headers", "*")
            .header("Access-Control-Allow-Methods", "*")
            .header("Access-Control-Max-Age", "86400")
            .body(Bytes::new())
            .unwrap());
    }

    let mut req = CLIENT.request(method.clone(), url);

    if !body.is_empty() {
        req = req.body(body);
    }

    let upstream = match req.send().await {
        Ok(r) => r,
        Err(_) => {
            return Ok(Response::builder()
                .status(502)
                .body(Bytes::from_static(b"Upstream request failed"))
                .unwrap());
        }
    };

    let status = upstream.status();
    let headers = upstream.headers().clone();
    let bytes = upstream.bytes().await.unwrap_or_else(|_| Bytes::new());

    let mut resp = Response::builder().status(status);

    for (k, v) in headers.iter() {
        resp = resp.header(k, v);
    }

    resp = resp
        .header("Access-Control-Allow-Origin", "*")
        .header("Access-Control-Allow-Headers", "*")
        .header("Access-Control-Allow-Methods", "*")
        .header("Access-Control-Expose-Headers", "*");

    Ok(resp.body(bytes).unwrap())
}
