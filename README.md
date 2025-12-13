# rust-cors-proxy

A lightweight HTTP/HTTPS proxy server written in Rust that safely forwards requests, blocks private network addresses, and logs each request with method, URL, resolved IPs, and status.

## Features

- Forwards HTTP/HTTPS requests to specified URLs.
- Prevents SSRF and DNS rebinding attacks.
- Blocks private, loopback, link-local, multicast, unspecified, and unique-local IPs.
- Handles CORS preflight requests and adds CORS headers to responses.
- Logs request method, target URL, resolved IPs, and upstream status.
- Built using `warp`, `reqwest`, `tokio`, and `serde_json`.

## Usage

Run the proxy locally:

```bash
cargo run --release
```

By default the server listens on:

```text
http://127.0.0.1:8080
```

To make a request through the proxy:

```text
http://127.0.0.1:8080/https://example.com
```

## License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.
