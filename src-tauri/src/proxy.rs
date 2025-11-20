use crate::cert::CertManager;
use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use hyper::body::{Body, Incoming};
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::{Method, Request, Response, StatusCode};
use hyper_util::client::legacy::Client;
use hyper_util::rt::TokioExecutor;
use hyper_util::rt::TokioIo;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::net::{TcpListener, TcpStream};
use parking_lot::RwLock;

#[allow(dead_code)]
type ProxyResult<T> = Result<T, Box<dyn std::error::Error + Send + Sync>>;

#[derive(Clone)]
pub struct ProxyConfig {
    pub port: u16,
    #[allow(dead_code)]
    pub enable_https_intercept: bool,
    pub log_requests: bool,
}

impl Default for ProxyConfig {
    fn default() -> Self {
        Self {
            port: 8888,
            enable_https_intercept: true,
            log_requests: true,
        }
    }
}

pub struct ProxyServer {
    config: ProxyConfig,
    #[allow(dead_code)]
    cert_manager: Arc<CertManager>,
    log_sender: Arc<RwLock<Option<tokio::sync::mpsc::UnboundedSender<ProxyLog>>>>,
    client: Client<hyper_util::client::legacy::connect::HttpConnector, Incoming>,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct ProxyLog {
    pub timestamp: String,
    pub method: String,
    pub url: String,
    pub status: u16,
    pub request_size: usize,
    pub response_size: usize,
}

impl ProxyServer {
    pub fn new(config: ProxyConfig) -> Result<Self, Box<dyn std::error::Error>> {
        let cert_manager = Arc::new(CertManager::new()?);

        // Create HTTP client for forwarding requests
        let client = Client::builder(TokioExecutor::new())
            .build_http();

        Ok(Self {
            config,
            cert_manager,
            log_sender: Arc::new(RwLock::new(None)),
            client,
        })
    }

    pub fn set_log_sender(&self, sender: tokio::sync::mpsc::UnboundedSender<ProxyLog>) {
        *self.log_sender.write() = Some(sender);
    }

    fn log_request(&self, log: ProxyLog) {
        if let Some(sender) = self.log_sender.read().as_ref() {
            let _ = sender.send(log);
        }
    }

    pub async fn start(self: Arc<Self>) -> Result<(), Box<dyn std::error::Error>> {
        let addr = SocketAddr::from(([127, 0, 0, 1], self.config.port));
        let listener = TcpListener::bind(addr).await?;

        println!("代理服务器启动在 {}", addr);

        loop {
            let (stream, client_addr) = listener.accept().await?;
            let proxy = Arc::clone(&self);

            tokio::spawn(async move {
                println!("收到来自 {} 的连接", client_addr);

                let io = hyper_util::rt::TokioIo::new(stream);

                let service = service_fn(move |req| {
                    let proxy = Arc::clone(&proxy);
                    async move { proxy.handle_request(req).await }
                });

                let result = http1::Builder::new()
                    .preserve_header_case(true)
                    .title_case_headers(true)
                    .serve_connection(io, service)
                    .with_upgrades()
                    .await;

                if let Err(e) = result {
                    eprintln!("连接错误: {}", e);
                }
            });
        }
    }

    async fn handle_request(
        &self,
        req: Request<Incoming>,
    ) -> Result<Response<Full<Bytes>>, hyper::Error> {
        let method = req.method().clone();
        let uri = req.uri().clone();

        println!("收到请求: {} {}", method, uri);

        // Handle CONNECT method for HTTPS tunneling
        if method == Method::CONNECT {
            println!("建立 HTTPS 隧道: {}", uri);

            // 在单独的任务中处理 CONNECT
            tokio::spawn(async move {
                match hyper::upgrade::on(req).await {
                    Ok(upgraded) => {
                        println!("连接已升级，开始建立隧道到 {}", uri);

                        // 连接到目标服务器
                        let host_port = uri.to_string();
                        match TcpStream::connect(&host_port).await {
                            Ok(server) => {
                                println!("成功连接到目标服务器: {}", host_port);

                                // 在客户端和服务器之间传输数据
                                let mut upgraded = TokioIo::new(upgraded);
                                let mut server = server;

                                match tokio::io::copy_bidirectional(&mut upgraded, &mut server).await {
                                    Ok((client_to_server, server_to_client)) => {
                                        println!(
                                            "隧道关闭: {} -> 服务器 {} 字节, 服务器 -> {} {} 字节",
                                            host_port, client_to_server, host_port, server_to_client
                                        );
                                    }
                                    Err(e) => {
                                        eprintln!("隧道传输错误: {}", e);
                                    }
                                }
                            }
                            Err(e) => {
                                eprintln!("无法连接到目标服务器 {}: {}", host_port, e);
                            }
                        }
                    }
                    Err(e) => {
                        eprintln!("升级连接失败: {}", e);
                    }
                }
            });

            // 返回 200 Connection Established
            return Ok(Response::builder()
                .status(StatusCode::OK)
                .body(Full::new(Bytes::new()))
                .unwrap());
        }

        // Handle regular HTTP requests
        self.handle_http_request(req).await
    }

    async fn handle_http_request(
        &self,
        mut req: Request<Incoming>,
    ) -> Result<Response<Full<Bytes>>, hyper::Error> {
        let method = req.method().clone();
        let uri = req.uri().clone();

        // Build absolute URI if needed
        let target_uri = if uri.scheme().is_none() {
            // Extract host from headers
            let host = req
                .headers()
                .get("host")
                .and_then(|h| h.to_str().ok())
                .unwrap_or("localhost");

            let scheme = "http";
            let path_and_query = uri.path_and_query()
                .map(|pq| pq.as_str())
                .unwrap_or("/");

            format!("{}://{}{}", scheme, host, path_and_query)
        } else {
            uri.to_string()
        };

        // Parse the target URI
        let target_uri = match target_uri.parse::<hyper::Uri>() {
            Ok(uri) => uri,
            Err(e) => {
                eprintln!("Invalid URI: {} - {}", target_uri, e);
                return Ok(Response::builder()
                    .status(StatusCode::BAD_REQUEST)
                    .body(Full::new(Bytes::from("Invalid URI")))
                    .unwrap());
            }
        };

        // Update request URI
        *req.uri_mut() = target_uri.clone();

        // Remove hop-by-hop headers
        let headers = req.headers_mut();
        headers.remove("proxy-connection");
        headers.remove("connection");
        headers.remove("keep-alive");
        headers.remove("transfer-encoding");
        headers.remove("upgrade");

        let start_time = std::time::Instant::now();
        let request_size = req.body().size_hint().lower() as usize;

        // Forward the request
        let response = match self.client.request(req).await {
            Ok(resp) => resp,
            Err(e) => {
                eprintln!("Request failed: {} - {}", target_uri, e);
                return Ok(Response::builder()
                    .status(StatusCode::BAD_GATEWAY)
                    .body(Full::new(Bytes::from(format!("Proxy error: {}", e))))
                    .unwrap());
            }
        };

        let status = response.status();

        // Collect response body
        let (parts, body) = response.into_parts();
        let body_bytes = match body.collect().await {
            Ok(collected) => collected.to_bytes(),
            Err(e) => {
                eprintln!("Failed to read response body: {}", e);
                Bytes::new()
            }
        };

        let response_size = body_bytes.len();
        let elapsed = start_time.elapsed();

        // Log the request
        if self.config.log_requests {
            self.log_request(ProxyLog {
                timestamp: chrono::Local::now().format("%Y-%m-%d %H:%M:%S%.3f").to_string(),
                method: method.to_string(),
                url: target_uri.to_string(),
                status: status.as_u16(),
                request_size,
                response_size,
            });

            println!(
                "{} {} - {} ({} bytes, {:.2}ms)",
                method,
                target_uri,
                status.as_u16(),
                response_size,
                elapsed.as_secs_f64() * 1000.0
            );
        }

        // Build response
        let mut builder = Response::builder()
            .status(status)
            .version(parts.version);

        // Copy headers
        if let Some(headers) = builder.headers_mut() {
            for (key, value) in parts.headers.iter() {
                // Skip hop-by-hop headers
                if key == "connection" || key == "keep-alive" || key == "transfer-encoding" || key == "upgrade" {
                    continue;
                }
                headers.insert(key, value.clone());
            }
        }

        Ok(builder.body(Full::new(body_bytes)).unwrap())
    }
}
