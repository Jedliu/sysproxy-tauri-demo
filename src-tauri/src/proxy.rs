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
use crate::process_filter::ProcessFilterManager;
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
    /// 是否启用 HTTPS 拦截（MITM）
    /// 如果为 false，代理只转发 HTTPS 流量而不解密
    pub enable_https_intercept: bool,
    /// 是否记录请求日志
    pub log_requests: bool,
}

impl Default for ProxyConfig {
    fn default() -> Self {
        Self {
            port: 8888,
            enable_https_intercept: false,
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
    /// 发起请求的进程名称
    pub process_name: Option<String>,
}

/// 代理服务器
///
/// 这是代理服务器的主要结构，包含：
/// - 配置信息
/// - CA 证书管理器（用于 HTTPS MITM）
/// - 日志发送通道（用于将日志发送到 UI）
/// - 拦截器（用于修改请求/响应）
/// - 进程过滤器（用于过滤特定进程的流量）
/// - 停止标志（用于优雅停止）
pub struct ProxyServer {
    config: ProxyConfig,
    cert_manager: Arc<CertManager>,
    log_sender: Arc<RwLock<Option<tokio::sync::mpsc::UnboundedSender<ProxyLog>>>>,
    interceptor: Arc<Interceptor>,
    process_filter: Arc<ProcessFilterManager>,
    /// 停止标志，设置为 true 后代理将拒绝所有新请求
    shutdown_flag: Arc<RwLock<bool>>,
}

impl ProxyServer {
    /// 创建新的代理服务器实例
    ///
    /// # 参数
    /// - `config`: 代理服务器配置
    /// - `interceptor`: 用于拦截和修改请求/响应的拦截器
    /// - `process_filter`: 用于过滤进程的过滤器
    ///
    /// # 返回
    /// 成功返回 ProxyServer 实例，失败返回错误信息
    pub fn new(
        config: ProxyConfig,
        interceptor: Arc<Interceptor>,
        process_filter: Arc<ProcessFilterManager>,
    ) -> Result<Self, Box<dyn std::error::Error>> {
        let cert_manager = Arc::new(CertManager::new()?);

        Ok(Self {
            config,
            cert_manager,
            log_sender: Arc::new(RwLock::new(None)),
            interceptor,
            process_filter,
            shutdown_flag: Arc::new(RwLock::new(false)),
        })
    }

    /// 设置停止标志
    ///
    /// 设置后，代理服务器将拒绝所有新的请求
    pub fn shutdown(&self) {
        *self.shutdown_flag.write() = true;
        println!("代理服务器停止标志已设置");
    }

    /// 设置日志发送通道
    ///
    /// 这个通道用于将代理日志发送到 UI 界面显示
    pub fn set_log_sender(&self, sender: tokio::sync::mpsc::UnboundedSender<ProxyLog>) {
        *self.log_sender.write() = Some(sender);
    }

    /// 检查端口是否可用
    ///
    /// 在启动服务器之前，检查指定的端口是否已被占用。
    /// 这个方法会尝试绑定端口，然后立即释放，以测试端口的可用性。
    ///
    /// # 返回
    /// - `Ok(())`: 端口可用
    /// - `Err(...)`: 端口被占用，返回详细的错误信息
    pub async fn check_port(&self) -> Result<(), Box<dyn std::error::Error>> {
        let addr = SocketAddr::from(([127, 0, 0, 1], self.config.port));

        match tokio::net::TcpListener::bind(addr).await {
            Ok(listener) => {
                // 端口可用，立即关闭测试监听器
                drop(listener);
                Ok(())
            }
            Err(e) => {
                // 端口被占用，返回友好的错误消息
                Err(format!(
                    "端口 {} 已被占用，无法启动代理服务器。\n\n\
                    可能的原因：\n\
                    1. 已经有另一个代理服务器在运行\n\
                    2. 该端口被其他程序占用\n\n\
                    解决方法：\n\
                    1. 在设置中更改代理端口\n\
                    2. 或者关闭占用该端口的程序\n\n\
                    错误详情: {}",
                    self.config.port,
                    e
                ).into())
            }
        }
    }

    /// 启动代理服务器
    ///
    /// 这是代理服务器的主入口点。它会：
    /// 1. 创建 TCP 监听器（监听 127.0.0.1:port）
    /// 2. 如果启用了 HTTPS 拦截，配置 CA 证书（用于 HTTPS MITM）
    /// 3. 创建 hudsucker 代理实例
    /// 4. 开始接受连接
    ///
    /// 注意：在调用此方法之前，应该先调用 `check_port()` 检查端口是否可用
    ///
    /// # 返回
    /// 这个方法会一直运行直到出错或被停止
    pub async fn start(self: Arc<Self>) -> Result<(), Box<dyn std::error::Error>> {
        let addr = SocketAddr::from(([127, 0, 0, 1], self.config.port));

        println!("代理服务器启动在 {}", addr);
        println!("HTTPS 拦截: {}", if self.config.enable_https_intercept { "已启用" } else { "已禁用" });

        // 创建 hudsucker 代理处理器，包含我们的自定义拦截逻辑
        let handler = ProxyHandler {
            config: self.config.clone(),
            interceptor: Arc::clone(&self.interceptor),
            process_filter: Arc::clone(&self.process_filter),
            log_sender: Arc::clone(&self.log_sender),
            shutdown_flag: Arc::clone(&self.shutdown_flag),
        };

        // 构建代理服务器
        // 从证书管理器获取 CA 证书和私钥（PEM 格式）
        // 注意：即使不启用 HTTPS 拦截，hudsucker 的构建器模式也需要提供 CA
        // 这是由于 hudsucker 的类型状态机要求必须按顺序调用：
        // with_addr() -> with_ca() -> with_rustls_connector() -> with_http_handler() -> build()
        let ca_cert_pem = self.cert_manager.get_ca_cert_pem()?;
        let ca_key_pem = self.cert_manager.get_ca_key_pem()?;

        // 解析密钥对并创建证书颁发者
        // 这个颁发者将用于为每个 HTTPS 域名动态生成证书（当启用 HTTPS 拦截时）
        let key_pair = KeyPair::from_pem(&ca_key_pem)
            .map_err(|e| format!("解析密钥失败: {}", e))?;
        let issuer = Issuer::from_ca_cert_pem(&ca_cert_pem, key_pair)
            .map_err(|e| format!("解析证书失败: {}", e))?;

        // 创建证书颁发机构
        // - issuer: CA 证书和私钥
        // - 1_000: 缓存最多 1000 个动态生成的证书
        // - aws_lc_rs: 使用 AWS 的 libcrypto 实现
        let ca = RcgenAuthority::new(issuer, 1_000, aws_lc_rs::default_provider());

        // 构建 hudsucker 代理实例
        // 注意：必须按照特定顺序调用构建器方法，否则会出现编译错误
        let proxy = Proxy::builder()
            .with_addr(addr)
            .with_ca(ca)
            .with_rustls_connector(aws_lc_rs::default_provider())
            .with_http_handler(handler)
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
    process_filter: Arc<ProcessFilterManager>,
    log_sender: Arc<RwLock<Option<tokio::sync::mpsc::UnboundedSender<ProxyLog>>>>,
    /// 停止标志，当设置为 true 时拒绝所有新请求
    shutdown_flag: Arc<RwLock<bool>>,
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
        let process_filter = Arc::clone(&self.process_filter);
        let shutdown_flag = Arc::clone(&self.shutdown_flag);
        let client_addr = _ctx.client_addr;

        async move {
            // ================================================================
            // 重要！检查停止标志
            // ================================================================
            // 如果代理服务器已经收到停止信号，返回空响应
            // 让浏览器显示 ERR_PROXY_CONNECTION_FAILED 错误
            // ================================================================
            if *shutdown_flag.read() {
                println!("代理服务器已停止，拒绝新请求");
                // 返回 502 Bad Gateway 空响应，让浏览器显示代理连接失败
                return RequestOrResponse::Response(
                    Response::builder()
                        .status(StatusCode::BAD_GATEWAY)
                        .body(Body::from(Full::new(Bytes::new())))
                        .unwrap(),
                );
            }

            let method = req.method().clone();
            let uri = req.uri().clone();

            // ================================================================
            // 进程过滤检查
            // ================================================================
            // 从客户端 socket 地址获取进程名称，并检查是否应该被过滤
            // ================================================================
            use crate::socket_process::get_process_name_from_socket;
            let process_name = get_process_name_from_socket(&client_addr);

            // 检查进程过滤器
            let filter = process_filter.get_filter();
            if filter.enabled {
                // 调试信息
                println!(
                    "进程过滤调试 - 当前进程: {:?}, 允许列表: {:?}, 黑名单模式: {}",
                    process_name, filter.allowed_processes, filter.blacklist_mode
                );

                let should_block = if let Some(ref name) = process_name {
                    // 如果是黑名单模式，列表中的进程被拒绝
                    // 如果是白名单模式，不在列表中的进程被拒绝
                    if filter.blacklist_mode {
                        filter.allowed_processes.contains(name)
                    } else {
                        !filter.allowed_processes.contains(name)
                    }
                } else {
                    // 无法获取进程名，根据模式决定
                    // 白名单模式：拒绝未知进程
                    // 黑名单模式：允许未知进程
                    !filter.blacklist_mode
                };

                if should_block {
                    println!(
                        "进程过滤：拒绝请求 {} {} (进程: {:?})",
                        method, uri, process_name
                    );
                    return RequestOrResponse::Response(
                        Response::builder()
                            .status(StatusCode::FORBIDDEN)
                            .body(Body::from(Full::new(Bytes::from("Blocked by process filter"))))
                            .unwrap(),
                    );
                } else {
                    println!(
                        "进程过滤：允许请求 {} {} (进程: {:?})",
                        method, uri, process_name
                    );
                }
            }

            println!(
                "收到请求: {} {} (进程: {:?})",
                method, uri, process_name
            );

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
        let client_addr = _ctx.client_addr;

        async move {
            let response_status = res.status().as_u16();
            let start_time = std::time::Instant::now();

            // 获取进程名称
            use crate::socket_process::get_process_name_from_socket;
            let process_name = get_process_name_from_socket(&client_addr);

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
                        process_name: process_name.clone(),
                    });
                }

                // 输出日志到控制台
                let elapsed = start_time.elapsed();
                println!(
                    "{} {} - {} ({} bytes, {:.2}ms) [进程: {:?}]",
                    method,
                    uri,
                    response_status,
                    response_size,
                    elapsed.as_secs_f64() * 1000.0,
                    process_name
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
