// ============================================================================
// 拦截器模块 (Interceptor Module)
// ============================================================================
// 这个模块实现了基于规则的 HTTP 请求/响应拦截系统。
//
// 核心功能：
// 1. 规则匹配：根据 URL、方法、Content-Type 等条件匹配请求
// 2. 请求拦截：在请求发送到目标服务器前进行修改或返回 Mock 响应
// 3. 响应拦截：在响应返回给客户端前进行修改或保存数据
// 4. 多种操作：修改头部、修改body、重定向、阻断、保存数据等
//
// 使用场景：
// - 调试：保存请求/响应数据到文件
// - 测试：返回 Mock 数据，不实际请求服务器
// - 修改：动态修改请求头、请求体
// - 分析：拦截和分析 API 调用
// ============================================================================

use bytes::Bytes;
use hyper::{HeaderMap, Method, Uri};
use regex::Regex;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use parking_lot::RwLock;

/// 拦截规则
///
/// 每条规则定义了：
/// - 何时触发（匹配模式）
/// - 作用于什么（请求/响应/两者）
/// - 做什么操作（修改/Mock/保存等）
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InterceptRule {
    /// 规则唯一标识
    pub id: String,
    /// 是否启用此规则
    pub enabled: bool,
    /// 规则名称（用于显示）
    pub name: String,
    /// 规则类型：只作用于请求、只作用于响应、或两者都作用
    pub rule_type: RuleType,
    /// 匹配模式：定义何时触发此规则
    pub match_pattern: MatchPattern,
    /// 要执行的操作
    pub action: Action,
}

/// 规则类型
///
/// 决定规则在哪个阶段生效
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum RuleType {
    /// 只在请求阶段生效
    Request,
    /// 只在响应阶段生效
    Response,
    /// 在请求和响应阶段都生效
    Both,
}

/// 匹配模式
///
/// 所有条件都是可选的，只有满足所有指定的条件才会触发规则。
/// 例如：如果只指定了 url_pattern，则只要 URL 匹配就触发。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MatchPattern {
    /// URL 正则表达式模式（例如：`.*baidu\.com.*`）
    pub url_pattern: Option<String>,
    /// HTTP 方法（例如：`GET`, `POST`）
    pub method: Option<String>,
    /// Content-Type 模式（例如：`application/json`）
    pub content_type: Option<String>,
}

/// 拦截操作
///
/// 定义规则匹配后要执行的操作
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Action {
    /// 修改 HTTP 头部
    ModifyHeaders {
        /// 要添加的头部（键值对列表）
        add: Vec<(String, String)>,
        /// 要删除的头部（键列表）
        remove: Vec<String>
    },

    /// 修改 body 内容（文本替换）
    ModifyBody {
        /// 要查找的文本
        find: String,
        /// 替换成的文本
        replace: String
    },

    /// 完全替换 body
    ReplaceBody {
        /// 新的 body 内容
        content: String
    },

    /// 返回 Mock 响应（只在请求阶段有效）
    MockResponse {
        /// HTTP 状态码
        status: u16,
        /// 响应头部
        headers: Vec<(String, String)>,
        /// 响应 body
        body: String
    },

    /// 重定向到另一个 URL（返回 302 响应）
    Redirect {
        /// 目标 URL
        target_url: String
    },

    /// 阻断请求（返回错误响应）
    Block {
        /// HTTP 状态码（通常是 403 或 404）
        status: u16,
        /// 错误消息
        message: String
    },

    /// 保存请求/响应数据到文件
    SaveData {
        /// 是否保存请求数据
        save_request: bool,
        /// 是否保存响应数据
        save_response: bool,
        /// 保存的文件路径
        file_path: String
    },
}

/// 拦截器
///
/// 管理所有拦截规则，并在请求/响应通过时应用这些规则。
/// 使用线程安全的 RwLock 保护规则列表，支持并发访问。
pub struct Interceptor {
    /// 拦截规则列表（使用读写锁保护，支持多线程并发读取）
    rules: Arc<RwLock<Vec<InterceptRule>>>,
}

impl Interceptor {
    /// 创建新的拦截器实例
    pub fn new() -> Self {
        Self {
            rules: Arc::new(RwLock::new(Vec::new())),
        }
    }

    /// 添加规则到拦截器
    pub fn add_rule(&self, rule: InterceptRule) {
        let mut rules = self.rules.write();
        rules.push(rule);
    }

    /// 根据 ID 删除规则
    pub fn remove_rule(&self, rule_id: &str) {
        let mut rules = self.rules.write();
        rules.retain(|r| r.id != rule_id);
    }

    /// 获取所有规则的副本
    pub fn get_rules(&self) -> Vec<InterceptRule> {
        self.rules.read().clone()
    }

    /// 更新已存在的规则
    pub fn update_rule(&self, rule: InterceptRule) {
        let mut rules = self.rules.write();
        if let Some(pos) = rules.iter().position(|r| r.id == rule.id) {
            rules[pos] = rule;
        }
    }

    /// 清空所有规则
    pub fn clear_rules(&self) {
        let mut rules = self.rules.write();
        rules.clear();
    }

    /// 拦截并可能修改出站请求
    ///
    /// 这个方法会遍历所有启用的规则，对每个匹配的规则执行相应的操作。
    ///
    /// 工作流程：
    /// 1. 遍历所有规则
    /// 2. 跳过未启用的规则
    /// 3. 检查规则类型（必须是 Request 或 Both）
    /// 4. 检查是否匹配（URL、方法、Content-Type）
    /// 5. 执行操作（修改、Mock、阻断等）
    ///
    /// # 参数
    /// - `method`: HTTP 方法（GET, POST 等）
    /// - `uri`: 请求 URI
    /// - `headers`: 请求头部（可变，可被修改）
    /// - `body`: 请求体（可变，可被修改）
    ///
    /// # 返回
    /// - `Ok(Some(InterceptedResponse))`: 返回 Mock 响应，不发送请求
    /// - `Ok(None)`: 继续发送请求（可能已被修改）
    /// - `Err(...)`: 处理错误
    #[allow(dead_code)]
    pub fn intercept_request(
        &self,
        method: &Method,
        uri: &Uri,
        headers: &mut HeaderMap,
        body: &mut Bytes,
    ) -> Result<Option<InterceptedResponse>, Box<dyn std::error::Error + Send + Sync>> {
        let rules = self.rules.read();

        for rule in rules.iter() {
            // 跳过未启用的规则
            if !rule.enabled {
                continue;
            }

            // 检查规则类型 - 只处理 Request 或 Both 类型
            if !matches!(rule.rule_type, RuleType::Request | RuleType::Both) {
                continue;
            }

            // 检查是否匹配此规则
            if !self.matches_pattern(&rule.match_pattern, method, uri, headers, body) {
                continue;
            }

            // 应用操作
            match &rule.action {
                Action::ModifyHeaders { add, remove } => {
                    for key in remove {
                        headers.remove(key);
                    }
                    for (key, value) in add {
                        if let (Ok(header_name), Ok(header_value)) = (
                            key.parse::<hyper::header::HeaderName>(),
                            value.parse::<hyper::header::HeaderValue>(),
                        ) {
                            headers.insert(header_name, header_value);
                        }
                    }
                }
                Action::ModifyBody { find, replace } => {
                    let body_str = String::from_utf8_lossy(body);
                    let modified = body_str.replace(find, replace);
                    *body = Bytes::from(modified.into_bytes());
                }
                Action::ReplaceBody { content } => {
                    *body = Bytes::from(content.clone());
                }
                Action::MockResponse { status, headers: mock_headers, body: mock_body } => {
                    return Ok(Some(InterceptedResponse {
                        status: *status,
                        headers: mock_headers.clone(),
                        body: Bytes::from(mock_body.clone()),
                    }));
                }
                Action::Redirect { target_url } => {
                    return Ok(Some(InterceptedResponse {
                        status: 302,
                        headers: vec![("Location".to_string(), target_url.clone())],
                        body: Bytes::from("Redirected"),
                    }));
                }
                Action::Block { status, message } => {
                    return Ok(Some(InterceptedResponse {
                        status: *status,
                        headers: vec![],
                        body: Bytes::from(message.clone()),
                    }));
                }
                Action::SaveData { save_request, file_path, .. } => {
                    if *save_request {
                        self.save_request_data(method, uri, headers, body, file_path);
                    }
                }
            }
        }

        Ok(None)
    }

    /// 拦截并可能修改入站响应
    ///
    /// 这个方法会在响应返回给客户端之前被调用，允许修改响应或保存数据。
    ///
    /// 工作流程：
    /// 1. 遍历所有规则
    /// 2. 跳过未启用的规则
    /// 3. **重要**：检查规则类型（必须是 Response 或 Both）
    ///    - 如果规则类型是 Request，会跳过此规则
    ///    - 这是为什么设置为"请求"类型时看不到响应数据的原因！
    /// 4. 根据请求信息检查是否匹配
    /// 5. 执行操作（修改响应、保存数据等）
    ///
    /// # 参数
    /// - `method`: 原始请求的 HTTP 方法
    /// - `uri`: 原始请求的 URI
    /// - `request_headers`: 原始请求的头部（只读）
    /// - `request_body`: 原始请求的 body（只读）
    /// - `response_status`: 响应状态码
    /// - `response_headers`: 响应头部（可变，可被修改）
    /// - `response_body`: 响应体（可变，可被修改）
    ///
    /// # 返回
    /// - `Ok(())`: 成功
    /// - `Err(...)`: 处理错误
    #[allow(dead_code)]
    pub fn intercept_response(
        &self,
        method: &Method,
        uri: &Uri,
        request_headers: &HeaderMap,
        request_body: &Bytes,
        response_status: u16,
        response_headers: &mut HeaderMap,
        response_body: &mut Bytes,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let rules = self.rules.read();

        for rule in rules.iter() {
            // 跳过未启用的规则
            if !rule.enabled {
                continue;
            }

            // ================================================================
            // 重要！检查规则类型 - 只处理 Response 或 Both 类型
            // ================================================================
            // 如果规则类型是 Request（只针对请求），这里会 continue，
            // 导致无法处理响应，SaveData 的 save_response 也不会执行。
            //
            // 用户场景：
            // - 如果 UI 中设置为「请求」类型
            // - 即使勾选了「保存响应」复选框
            // - 也不会保存响应数据！
            //
            // 解决方法：
            // - 将规则类型改为「响应」或「Both」
            // ================================================================
            if !matches!(rule.rule_type, RuleType::Response | RuleType::Both) {
                continue;
            }

            // 基于原始请求信息检查是否匹配
            // （因为响应本身没有 URL、方法等信息）
            if !self.matches_pattern(&rule.match_pattern, method, uri, request_headers, request_body) {
                continue;
            }

            // 应用操作
            match &rule.action {
                Action::ModifyHeaders { add, remove } => {
                    for key in remove {
                        response_headers.remove(key);
                    }
                    for (key, value) in add {
                        if let (Ok(header_name), Ok(header_value)) = (
                            key.parse::<hyper::header::HeaderName>(),
                            value.parse::<hyper::header::HeaderValue>(),
                        ) {
                            response_headers.insert(header_name, header_value);
                        }
                    }
                }
                Action::ModifyBody { find, replace } => {
                    let body_str = String::from_utf8_lossy(response_body);
                    let modified = body_str.replace(find, replace);
                    *response_body = Bytes::from(modified.into_bytes());
                }
                Action::ReplaceBody { content } => {
                    *response_body = Bytes::from(content.clone());
                }
                Action::SaveData { save_response, file_path, .. } => {
                    if *save_response {
                        self.save_response_data(method, uri, request_headers, request_body,
                            response_status, response_headers, response_body, file_path);
                    }
                }
                _ => {}
            }
        }

        Ok(())
    }

    #[allow(dead_code)]
    fn matches_pattern(
        &self,
        pattern: &MatchPattern,
        method: &Method,
        uri: &Uri,
        headers: &HeaderMap,
        _body: &Bytes,
    ) -> bool {
        // Check URL pattern
        if let Some(url_pattern) = &pattern.url_pattern {
            if let Ok(regex) = Regex::new(url_pattern) {
                let url = uri.to_string();
                if !regex.is_match(&url) {
                    return false;
                }
            }
        }

        // Check method
        if let Some(method_pattern) = &pattern.method {
            if method.as_str() != method_pattern {
                return false;
            }
        }

        // Check content type
        if let Some(content_type_pattern) = &pattern.content_type {
            if let Some(content_type) = headers.get("content-type") {
                if let Ok(ct) = content_type.to_str() {
                    if !ct.contains(content_type_pattern) {
                        return false;
                    }
                } else {
                    return false;
                }
            } else {
                return false;
            }
        }

        true
    }

    /// Save request data to file
    pub fn save_request_data(
        &self,
        method: &Method,
        uri: &Uri,
        headers: &HeaderMap,
        body: &Bytes,
        file_path: &str,
    ) {
        use std::fs::OpenOptions;
        use std::io::Write;

        let timestamp = chrono::Local::now().format("%Y-%m-%d %H:%M:%S%.3f").to_string();

        let mut data = format!("=== REQUEST [{}] ===\n", timestamp);
        data.push_str(&format!("{} {}\n", method, uri));
        data.push_str("Headers:\n");
        for (key, value) in headers.iter() {
            if let Ok(val_str) = value.to_str() {
                data.push_str(&format!("  {}: {}\n", key, val_str));
            }
        }
        data.push_str("\nBody:\n");
        data.push_str(&String::from_utf8_lossy(body));
        data.push_str("\n\n");

        if let Ok(mut file) = OpenOptions::new()
            .create(true)
            .append(true)
            .open(file_path)
        {
            let _ = file.write_all(data.as_bytes());
            println!("Saved request data to {}", file_path);
        } else {
            eprintln!("Failed to save request data to {}", file_path);
        }
    }

    /// Save response data to file
    pub fn save_response_data(
        &self,
        method: &Method,
        uri: &Uri,
        request_headers: &HeaderMap,
        request_body: &Bytes,
        response_status: u16,
        response_headers: &HeaderMap,
        response_body: &Bytes,
        file_path: &str,
    ) {
        use std::fs::OpenOptions;
        use std::io::Write;

        let timestamp = chrono::Local::now().format("%Y-%m-%d %H:%M:%S%.3f").to_string();

        let mut data = format!("=== REQUEST [{}] ===\n", timestamp);
        data.push_str(&format!("{} {}\n", method, uri));
        data.push_str("Request Headers:\n");
        for (key, value) in request_headers.iter() {
            if let Ok(val_str) = value.to_str() {
                data.push_str(&format!("  {}: {}\n", key, val_str));
            }
        }
        data.push_str("\nRequest Body:\n");
        data.push_str(&String::from_utf8_lossy(request_body));

        data.push_str("\n\n=== RESPONSE ===\n");
        data.push_str(&format!("Status: {}\n", response_status));
        data.push_str("Response Headers:\n");
        for (key, value) in response_headers.iter() {
            if let Ok(val_str) = value.to_str() {
                data.push_str(&format!("  {}: {}\n", key, val_str));
            }
        }
        data.push_str("\nResponse Body:\n");
        data.push_str(&String::from_utf8_lossy(response_body));
        data.push_str("\n\n");

        if let Ok(mut file) = OpenOptions::new()
            .create(true)
            .append(true)
            .open(file_path)
        {
            let _ = file.write_all(data.as_bytes());
            println!("Saved response data to {}", file_path);
        } else {
            eprintln!("Failed to save response data to {}", file_path);
        }
    }
}

#[allow(dead_code)]
#[derive(Debug)]
pub struct InterceptedResponse {
    pub status: u16,
    pub headers: Vec<(String, String)>,
    pub body: Bytes,
}
