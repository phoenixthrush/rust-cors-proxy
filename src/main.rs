use bytes::Bytes;
use once_cell::sync::Lazy;
use reqwest::Client;
use serde_json::json;
use std::convert::Infallible;
use std::net::IpAddr;
use std::time::Duration;
use tokio::net::lookup_host;
use url::Url;
use warp::{Filter, http::Response};

static CLIENT: Lazy<Client> = Lazy::new(|| {
    Client::builder()
        .pool_max_idle_per_host(32)
        .timeout(Duration::from_secs(30))
        .redirect(reqwest::redirect::Policy::none()) // prevent redirect SSRF
        .build()
        .expect("Failed building reqwest client")
});

#[tokio::main(flavor = "multi_thread")]
async fn main() {
    let route = warp::path::tail()
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
    let url_str = tail.as_str();

    // Validate URL early
    let url = match Url::parse(url_str) {
        Ok(u) if u.scheme() == "http" || u.scheme() == "https" => u,
        _ => return Ok(json_error(400, "Invalid or unsupported URL")),
    };

    // Handle CORS preflight
    if method == warp::http::Method::OPTIONS {
        return Ok(cors_response(204, Bytes::new()));
    }

    // DNS rebinding & safe IP check
    if !is_safe_url(&url).await.unwrap_or(false) {
        return Ok(json_error(403, "Destination IP is not allowed"));
    }

    let mut req = CLIENT.request(method.clone(), url.as_str());

    if !body.is_empty() {
        req = req.body(body);
    }

    let upstream = match req.send().await {
        Ok(r) => r,
        Err(_) => return Ok(json_error(502, "Upstream request failed")),
    };

    let status = upstream.status();
    let headers = upstream.headers().clone();
    let bytes = upstream.bytes().await.unwrap_or_else(|_| Bytes::new());

    println!(
        "[{}] {} -> {:?} [OK {}]",
        method,
        url,
        resolve_ips(&url).await,
        status
    );

    let mut resp = Response::builder().status(status);
    for (k, v) in headers.iter() {
        resp = resp.header(k, v);
    }

    Ok(with_cors(resp.body(bytes).unwrap()))
}

// Helper to add CORS headers
fn with_cors(mut builder: Response<Bytes>) -> Response<Bytes> {
    builder
        .headers_mut()
        .insert("Access-Control-Allow-Origin", "*".parse().unwrap());
    builder
        .headers_mut()
        .insert("Access-Control-Allow-Headers", "*".parse().unwrap());
    builder
        .headers_mut()
        .insert("Access-Control-Allow-Methods", "*".parse().unwrap());
    builder
        .headers_mut()
        .insert("Access-Control-Expose-Headers", "*".parse().unwrap());
    builder
}

// Preflight CORS response
fn cors_response(status: u16, body: Bytes) -> Response<Bytes> {
    with_cors(Response::builder().status(status).body(body).unwrap())
}

// JSON error response
fn json_error(status: u16, msg: &str) -> Response<Bytes> {
    let body = Bytes::from(json!({ "error": msg }).to_string());
    with_cors(Response::builder().status(status).body(body).unwrap())
}

// Check if an IP is private, loopback, link-local, multicast, unspecified, or unique-local (stricter IPv6)
fn is_blocked_ip(ip: &IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            v4.is_private()
                || v4.is_loopback()
                || v4.is_link_local()
                || v4.is_multicast()
                || v4.is_broadcast()
                || v4.is_unspecified()
        }
        IpAddr::V6(v6) => {
            v6.is_loopback()
                || v6.is_multicast()
                || v6.is_unspecified()
                || v6.is_unique_local()
                || v6.is_unicast_link_local()
                || v6
                    .to_ipv4_mapped()
                    .map_or(false, |ipv4| ipv4.is_private() || ipv4.is_loopback())
        }
    }
}

// Resolve hostname and ensure all addresses are safe
async fn is_safe_url(url: &Url) -> Result<bool, ()> {
    let host = url.host_str().ok_or(())?;
    let port = url.port_or_known_default().ok_or(())?;

    // Direct IP literal
    if let Ok(ip) = host.parse::<IpAddr>() {
        return Ok(!is_blocked_ip(&ip));
    }

    // DNS resolution (all IPs must be safe)
    let mut all_safe = true;
    let addrs = lookup_host((host, port)).await.map_err(|_| ())?;
    for addr in addrs {
        if is_blocked_ip(&addr.ip()) {
            all_safe = false;
            break;
        }
    }
    Ok(all_safe)
}

// Resolve IPs for logging
async fn resolve_ips(url: &Url) -> Vec<String> {
    if let Some(host) = url.host_str() {
        let port = url.port_or_known_default().unwrap_or(80);
        if let Ok(addrs) = lookup_host((host, port)).await {
            return addrs.map(|addr| addr.ip().to_string()).collect();
        }
    }
    vec!["<unresolvable>".to_string()]
}
