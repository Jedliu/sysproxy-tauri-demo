use bytes::Bytes;
use hyper::{HeaderMap, Method, Uri};
use regex::Regex;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use parking_lot::RwLock;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InterceptRule {
    pub id: String,
    pub enabled: bool,
    pub name: String,
    pub rule_type: RuleType,
    pub match_pattern: MatchPattern,
    pub action: Action,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum RuleType {
    Request,
    Response,
    Both,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MatchPattern {
    pub url_pattern: Option<String>,  // Regex pattern
    pub method: Option<String>,       // HTTP method
    pub content_type: Option<String>, // Content-Type pattern
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Action {
    // Modify request/response
    ModifyHeaders { add: Vec<(String, String)>, remove: Vec<String> },
    ModifyBody { find: String, replace: String },
    ReplaceBody { content: String },

    // Mock response
    MockResponse { status: u16, headers: Vec<(String, String)>, body: String },

    // Redirect
    Redirect { target_url: String },

    // Block
    Block { status: u16, message: String },
}

pub struct Interceptor {
    rules: Arc<RwLock<Vec<InterceptRule>>>,
}

impl Interceptor {
    pub fn new() -> Self {
        Self {
            rules: Arc::new(RwLock::new(Vec::new())),
        }
    }

    pub fn add_rule(&self, rule: InterceptRule) {
        let mut rules = self.rules.write();
        rules.push(rule);
    }

    pub fn remove_rule(&self, rule_id: &str) {
        let mut rules = self.rules.write();
        rules.retain(|r| r.id != rule_id);
    }

    pub fn get_rules(&self) -> Vec<InterceptRule> {
        self.rules.read().clone()
    }

    pub fn update_rule(&self, rule: InterceptRule) {
        let mut rules = self.rules.write();
        if let Some(pos) = rules.iter().position(|r| r.id == rule.id) {
            rules[pos] = rule;
        }
    }

    pub fn clear_rules(&self) {
        let mut rules = self.rules.write();
        rules.clear();
    }

    /// Intercept and potentially modify an outgoing request
    #[allow(dead_code)]
    pub fn intercept_request(
        &self,
        method: &Method,
        uri: &Uri,
        headers: &mut HeaderMap,
        body: &mut Bytes,
    ) -> Result<Option<InterceptedResponse>, Box<dyn std::error::Error>> {
        let rules = self.rules.read();

        for rule in rules.iter() {
            if !rule.enabled {
                continue;
            }

            // Check if rule applies to requests
            if !matches!(rule.rule_type, RuleType::Request | RuleType::Both) {
                continue;
            }

            // Check if rule matches
            if !self.matches_pattern(&rule.match_pattern, method, uri, headers, body) {
                continue;
            }

            // Apply action
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
            }
        }

        Ok(None)
    }

    /// Intercept and potentially modify an incoming response
    #[allow(dead_code)]
    pub fn intercept_response(
        &self,
        method: &Method,
        uri: &Uri,
        request_headers: &HeaderMap,
        request_body: &Bytes,
        response_headers: &mut HeaderMap,
        response_body: &mut Bytes,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let rules = self.rules.read();

        for rule in rules.iter() {
            if !rule.enabled {
                continue;
            }

            // Check if rule applies to responses
            if !matches!(rule.rule_type, RuleType::Response | RuleType::Both) {
                continue;
            }

            // Check if rule matches (based on request)
            if !self.matches_pattern(&rule.match_pattern, method, uri, request_headers, request_body) {
                continue;
            }

            // Apply action
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
}

#[allow(dead_code)]
#[derive(Debug)]
pub struct InterceptedResponse {
    pub status: u16,
    pub headers: Vec<(String, String)>,
    pub body: Bytes,
}
