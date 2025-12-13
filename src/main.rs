use bytes::Bytes;
use once_cell::sync::Lazy;
use reqwest::Client;
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
    let url = tail.as_str();

    // Resolve hostname to IPs for logging
    let resolved_ips = match Url::parse(url) {
        Ok(parsed) => {
            if let Some(host) = parsed.host_str() {
                let port = parsed.port_or_known_default().unwrap_or(80);
                match lookup_host((host, port)).await {
                    Ok(addrs) => addrs.map(|addr| addr.ip().to_string()).collect::<Vec<_>>(),
                    Err(_) => vec!["<unresolvable>".to_string()],
                }
            } else {
                vec!["<no host>".to_string()]
            }
        }
        Err(_) => vec!["<invalid url>".to_string()],
    };

    if !(url.starts_with("http://") || url.starts_with("https://")) {
        return Ok(bad_request("URL must begin with http:// or https://"));
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

    // Block private / local IPs
    if !is_safe_url(url).await.unwrap_or(false) {
        println!("{} {} [BLOCKED]", method, url);
        return Ok(Response::builder()
            .status(403)
            .body(Bytes::from_static(b"Destination IP is not allowed"))
            .unwrap());
    }

    let mut req = CLIENT.request(method.clone(), url);

    if !body.is_empty() {
        req = req.body(body);
    }

    let upstream = match req.send().await {
        Ok(r) => r,
        Err(_) => {
            println!("{} {} [UPSTREAM FAILED]", method, url);
            return Ok(Response::builder()
                .status(502)
                .body(Bytes::from_static(b"Upstream request failed"))
                .unwrap());
        }
    };

    let status = upstream.status();
    let headers = upstream.headers().clone();
    let bytes = upstream.bytes().await.unwrap_or_else(|_| Bytes::new());

    println!("[{}] {} -> {:?} [OK {}]", method, url, resolved_ips, status);

    let mut resp = Response::builder().status(status);
    for (k, v) in headers.iter() {
        resp = resp.header(k, v);
    }

    Ok(resp
        .header("Access-Control-Allow-Origin", "*")
        .header("Access-Control-Allow-Headers", "*")
        .header("Access-Control-Allow-Methods", "*")
        .header("Access-Control-Expose-Headers", "*")
        .body(bytes)
        .unwrap())
}

fn bad_request(msg: &str) -> warp::http::Response<Bytes> {
    Response::builder()
        .status(400)
        .body(Bytes::from(msg.to_string()))
        .unwrap()
}

/// Check if an IP is private, loopback, link-local, multicast, etc.
fn is_blocked_ip(ip: &IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            v4.is_private()
                || v4.is_loopback()
                || v4.is_link_local()
                || v4.is_multicast()
                || v4.is_unspecified()
        }
        IpAddr::V6(v6) => {
            v6.is_loopback()
                || v6.is_multicast()
                || v6.is_unspecified()
                || v6.is_unique_local()      // fc00::/7
                || v6.is_unicast_link_local() // fe80::/10
        }
    }
}

/// Resolve hostname and ensure it does not map to a private IP
async fn is_safe_url(url: &str) -> Result<bool, ()> {
    let parsed = Url::parse(url).map_err(|_| ())?;

    let host = parsed.host_str().ok_or(())?;
    let port = parsed.port_or_known_default().ok_or(())?;

    // Direct IP literal
    if let Ok(ip) = host.parse::<IpAddr>() {
        return Ok(!is_blocked_ip(&ip));
    }

    // DNS resolution
    let addrs = lookup_host((host, port)).await.map_err(|_| ())?;

    for addr in addrs {
        if is_blocked_ip(&addr.ip()) {
            return Ok(false);
        }
    }

    Ok(true)
}
