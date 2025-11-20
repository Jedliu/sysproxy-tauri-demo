// ============================================================================
// 代理服务器模块 (Proxy Server Module)
// ============================================================================
// 这个模块实现了一个支持 HTTPS MITM（中间人）拦截的代理服务器。
// 它使用 hudsucker 库来处理 HTTPS 隧道建立和 TLS 终止。
//
// 核心功能：
// 1. 接收浏览器的 HTTP/HTTPS 请求
// 2. 对于 HTTPS，使用动态生成的证书进行 TLS 终止
// 3. 通过 Interceptor 对请求/响应进行拦截和修改
// 4. 将请求转发到目标服务器
// 5. 记录所有请求的日志
// ============================================================================

use crate::cert::CertManager;
use crate::interceptor::Interceptor;
use bytes::Bytes;
use hyper::{Method, Request, Response, StatusCode};
use http_body_util::{BodyExt, Full};
use ideamans_hudsucker::certificate_authority::RcgenAuthority;
use ideamans_hudsucker::Body;
use ideamans_hudsucker::rcgen::{Issuer, KeyPair};
use ideamans_hudsucker::rustls::crypto::aws_lc_rs;
use ideamans_hudsucker::{HttpContext, HttpHandler, Proxy, RequestOrResponse};
use std::future::Future;
use std::net::SocketAddr;
use std::sync::Arc;
use parking_lot::RwLock;

#[allow(dead_code)]
type ProxyResult<T> = Result<T, Box<dyn std::error::Error + Send + Sync>>;

/// 代理服务器配置
#[derive(Clone)]
pub struct ProxyConfig {
    /// 代理服务器监听端口（默认 8888）
    pub port: u16,
    /// 是否启用 HTTPS 拦截（必须启用才能看到 HTTPS 流量）
    pub enable_https_intercept: bool,
    /// 是否记录请求日志
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

/// 代理请求日志
/// 用于记录每个通过代理的请求的基本信息
#[derive(Debug, Clone, serde::Serialize)]
pub struct ProxyLog {
    /// 请求时间戳
    pub timestamp: String,
    /// HTTP 方法（GET, POST, PUT 等）
    pub method: String,
    /// 请求的完整 URL
    pub url: String,
    /// 响应状态码（200, 404, 500 等）
    pub status: u16,
    /// 请求体大小（字节）
    pub request_size: usize,
    /// 响应体大小（字节）
    pub response_size: usize,
}

/// 代理服务器
///
/// 这是代理服务器的主要结构，包含：
/// - 配置信息
/// - CA 证书管理器（用于 HTTPS MITM）
/// - 日志发送通道（用于将日志发送到 UI）
/// - 拦截器（用于修改请求/响应）
pub struct ProxyServer {
    config: ProxyConfig,
    cert_manager: Arc<CertManager>,
    log_sender: Arc<RwLock<Option<tokio::sync::mpsc::UnboundedSender<ProxyLog>>>>,
    interceptor: Arc<Interceptor>,
}

impl ProxyServer {
    /// 创建新的代理服务器实例
    ///
    /// # 参数
    /// - `config`: 代理服务器配置
    /// - `interceptor`: 用于拦截和修改请求/响应的拦截器
    ///
    /// # 返回
    /// 成功返回 ProxyServer 实例，失败返回错误信息
    pub fn new(config: ProxyConfig, interceptor: Arc<Interceptor>) -> Result<Self, Box<dyn std::error::Error>> {
        let cert_manager = Arc::new(CertManager::new()?);

        Ok(Self {
            config,
            cert_manager,
            log_sender: Arc::new(RwLock::new(None)),
            interceptor,
        })
    }

    /// 设置日志发送通道
    ///
    /// 这个通道用于将代理日志发送到 UI 界面显示
    pub fn set_log_sender(&self, sender: tokio::sync::mpsc::UnboundedSender<ProxyLog>) {
        *self.log_sender.write() = Some(sender);
    }

    /// 内部方法：发送日志到通道
    fn log_request(&self, log: ProxyLog) {
        if let Some(sender) = self.log_sender.read().as_ref() {
            let _ = sender.send(log);
        }
    }

    /// 启动代理服务器
    ///
    /// 这是代理服务器的主入口点。它会：
    /// 1. 创建 TCP 监听器（监听 127.0.0.1:port）
    /// 2. 配置 CA 证书（用于 HTTPS MITM）
    /// 3. 创建 hudsucker 代理实例
    /// 4. 开始接受连接
    ///
    /// # 返回
    /// 这个方法会一直运行直到出错或被停止
    pub async fn start(self: Arc<Self>) -> Result<(), Box<dyn std::error::Error>> {
        let addr = SocketAddr::from(([127, 0, 0, 1], self.config.port));

        println!("代理服务器启动在 {}", addr);

        // 创建 hudsucker 代理处理器，包含我们的自定义拦截逻辑
        let handler = ProxyHandler {
            config: self.config.clone(),
            interceptor: Arc::clone(&self.interceptor),
            log_sender: Arc::clone(&self.log_sender),
        };

        // 从证书管理器获取 CA 证书和私钥（PEM 格式）
        let ca_cert_pem = self.cert_manager.get_ca_cert_pem()?;
        let ca_key_pem = self.cert_manager.get_ca_key_pem()?;

        // 解析密钥对并创建证书颁发者
        // 这个颁发者将用于为每个 HTTPS 域名动态生成证书
        let key_pair = KeyPair::from_pem(&ca_key_pem)
            .map_err(|e| format!("解析密钥失败: {}", e))?;
        let issuer = Issuer::from_ca_cert_pem(&ca_cert_pem, key_pair)
            .map_err(|e| format!("解析证书失败: {}", e))?;

        // 创建证书颁发机构
        // - issuer: CA 证书和私钥
        // - 1_000: 缓存最多 1000 个动态生成的证书
        // - aws_lc_rs: 使用 AWS 的 libcrypto 实现
        let ca = RcgenAuthority::new(issuer, 1_000, aws_lc_rs::default_provider());

        // 构建代理服务器
        let proxy = Proxy::builder()
            .with_addr(addr)                                      // 监听地址
            .with_ca(ca)                                          // CA 证书（用于 HTTPS）
            .with_rustls_connector(aws_lc_rs::default_provider()) // TLS 连接器
            .with_http_handler(handler)                           // 请求/响应处理器
            .build()?;

        // 启动代理服务器（会一直运行）
        if let Err(e) = proxy.start().await {
            eprintln!("代理服务器错误: {}", e);
        }

        Ok(())
    }
}

/// 自定义代理处理器
///
/// 这个处理器实现了 hudsucker 的 HttpHandler trait，
/// 负责处理每个通过代理的 HTTP/HTTPS 请求和响应。
#[derive(Clone)]
struct ProxyHandler {
    config: ProxyConfig,
    interceptor: Arc<Interceptor>,
    log_sender: Arc<RwLock<Option<tokio::sync::mpsc::UnboundedSender<ProxyLog>>>>,
}

impl HttpHandler for ProxyHandler {
    /// 处理 HTTP 请求
    ///
    /// 这是 HTTPS MITM 拦截的关键方法。工作流程：
    ///
    /// 1. **CONNECT 请求特殊处理**（重要！）
    ///    - CONNECT 请求用于建立 HTTPS 隧道
    ///    - 必须让 hudsucker 自己处理，不能拦截
    ///    - 如果拦截 CONNECT，会导致 HTTPS 连接失败
    ///
    /// 2. **普通请求处理流程**（GET, POST 等）
    ///    - 读取请求头和请求体
    ///    - 调用 Interceptor 拦截器处理
    ///    - 如果拦截器返回 Mock 响应，直接返回给客户端
    ///    - 否则，将（可能修改过的）请求发送到目标服务器
    ///
    /// # 参数
    /// - `_ctx`: HTTP 上下文（包含客户端地址等信息）
    /// - `req`: HTTP 请求
    ///
    /// # 返回
    /// - `RequestOrResponse::Request`: 继续转发请求到目标服务器
    /// - `RequestOrResponse::Response`: 返回 Mock 响应给客户端
    fn handle_request(
        &mut self,
        _ctx: &HttpContext,
        req: Request<Body>,
    ) -> impl Future<Output = RequestOrResponse> + Send {
        let interceptor = Arc::clone(&self.interceptor);

        async move {
            let method = req.method().clone();
            let uri = req.uri().clone();

            println!("收到请求: {} {}", method, uri);

            // ================================================================
            // 重要！不要拦截 CONNECT 请求！
            // ================================================================
            // CONNECT 请求用于建立 HTTPS 隧道，必须由 hudsucker 内部处理。
            //
            // HTTPS 连接流程：
            // 1. 浏览器发送 CONNECT www.example.com:443
            // 2. hudsucker 接收并建立 TCP 隧道
            // 3. hudsucker 用动态生成的证书进行 TLS 握手
            // 4. 隧道建立后，真正的 GET/POST 请求才会到达这里
            //
            // 如果我们拦截 CONNECT 请求，隧道无法建立，会导致：
            // - ERR_CONNECTION_CLOSED
            // - net::ERR_SSL_PROTOCOL_ERROR
            // ================================================================
            if method == Method::CONNECT {
                println!("CONNECT request - letting hudsucker handle tunnel establishment");
                return RequestOrResponse::Request(req);
            }

            // 将请求体转换为 Bytes，以便拦截器读取和修改
            let (parts, body) = req.into_parts();
            let body_bytes = match body.collect().await {
                Ok(collected) => collected.to_bytes(),
                Err(e) => {
                    eprintln!("读取请求体失败: {}", e);
                    return RequestOrResponse::Response(
                        Response::builder()
                            .status(StatusCode::BAD_REQUEST)
                            .body(Body::from(Full::new(Bytes::from("Failed to read request body"))))
                            .unwrap(),
                    );
                }
            };

            let mut request_body = body_bytes.clone();
            let mut request_headers = parts.headers.clone();

            // 调用拦截器处理请求
            let intercepted = interceptor.intercept_request(
                &method,
                &uri,
                &mut request_headers,
                &mut request_body,
            );

            // 如果拦截器返回了 Mock 响应，直接返回给客户端
            if let Ok(Some(mocked)) = intercepted {
                println!("Request intercepted with mock response: {} {}", method, uri);

                let mut response_builder = Response::builder().status(mocked.status);
                if let Some(headers) = response_builder.headers_mut() {
                    for (key, value) in mocked.headers {
                        if let (Ok(header_name), Ok(header_value)) = (
                            key.parse::<hyper::header::HeaderName>(),
                            value.parse::<hyper::header::HeaderValue>(),
                        ) {
                            headers.insert(header_name, header_value);
                        }
                    }
                }

                return RequestOrResponse::Response(
                    response_builder.body(Body::from(Full::new(mocked.body))).unwrap(),
                );
            }

            // 重建请求（可能已被拦截器修改了头部和body）
            let mut req_builder = Request::builder()
                .method(&method)
                .uri(&uri)
                .version(parts.version);

            if let Some(headers) = req_builder.headers_mut() {
                *headers = request_headers.clone();
            }

            let rebuilt_req = req_builder.body(Body::from(Full::new(request_body.clone()))).unwrap();

            // 返回请求，让 hudsucker 转发到目标服务器
            RequestOrResponse::Request(rebuilt_req)
        }
    }

    /// 处理 HTTP 响应
    ///
    /// 当目标服务器返回响应后，这个方法会被调用。工作流程：
    ///
    /// 1. 收集响应体（从 Stream 转换为 Bytes）
    /// 2. 调用 Interceptor 拦截器处理响应
    ///    - 拦截器可能会修改响应头、响应体
    ///    - 或者将数据保存到文件
    /// 3. 记录请求日志（如果启用）
    /// 4. 重建响应并返回给客户端
    ///
    /// 注意：由于 hudsucker 的限制，我们在这里无法获取原始请求的 body，
    /// 所以传给拦截器的 request_body 是空的。
    ///
    /// # 参数
    /// - `_ctx`: HTTP 上下文（包含请求方法、URI等）
    /// - `res`: 从目标服务器返回的 HTTP 响应
    ///
    /// # 返回
    /// 修改后的响应，将发送给客户端
    fn handle_response(
        &mut self,
        _ctx: &HttpContext,
        res: Response<Body>,
    ) -> impl Future<Output = Response<Body>> + Send {
        let config = self.config.clone();
        let interceptor = Arc::clone(&self.interceptor);
        let log_sender = Arc::clone(&self.log_sender);
        let method = _ctx.request_method.clone();
        let uri = _ctx.request_uri.clone();

        async move {
            let response_status = res.status().as_u16();
            let start_time = std::time::Instant::now();

            // 创建空的请求上下文
            // 注意：hudsucker 在响应处理器中不提供请求体/头部
            // 所以这里传入的是空值
            let request_headers = hyper::HeaderMap::new();
            let request_body = Bytes::new();

            // 收集响应体
            let (response_parts, response_body) = res.into_parts();
            let mut response_body_bytes = match response_body.collect().await {
                Ok(collected) => collected.to_bytes(),
                Err(e) => {
                    eprintln!("读取响应体失败: {}", e);
                    Bytes::new()
                }
            };

            let response_size = response_body_bytes.len();
            let request_size = 0; // 我们在这里无法获取原始请求大小

            // 调用拦截器处理响应
            // 拦截器可能会：
            // - 修改响应头/体
            // - 将请求/响应保存到文件
            let mut response_headers = response_parts.headers.clone();
            let _ = interceptor.intercept_response(
                &method,
                &uri,
                &request_headers,
                &request_body,
                response_status,
                &mut response_headers,
                &mut response_body_bytes,
            );

            // 记录请求日志
            if config.log_requests {
                // 发送日志到 UI
                if let Some(sender) = log_sender.read().as_ref() {
                    let _ = sender.send(ProxyLog {
                        timestamp: chrono::Local::now().format("%Y-%m-%d %H:%M:%S%.3f").to_string(),
                        method: method.to_string(),
                        url: uri.to_string(),
                        status: response_status,
                        request_size,
                        response_size,
                    });
                }

                // 输出日志到控制台
                let elapsed = start_time.elapsed();
                println!(
                    "{} {} - {} ({} bytes, {:.2}ms)",
                    method,
                    uri,
                    response_status,
                    response_size,
                    elapsed.as_secs_f64() * 1000.0
                );
            }

            // 重建响应（可能已被拦截器修改）
            let mut builder = Response::builder()
                .status(response_status)
                .version(response_parts.version);

            // 设置响应头
            if let Some(headers) = builder.headers_mut() {
                for (key, value) in response_headers.iter() {
                    headers.insert(key, value.clone());
                }
            }

            // 返回重建的响应
            builder.body(Body::from(Full::new(response_body_bytes))).unwrap()
        }
    }
}
