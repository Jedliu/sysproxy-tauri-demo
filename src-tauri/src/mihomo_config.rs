/// mihomo 配置生成模块
///
/// 负责将 ProcessFilter 转换为 mihomo YAML 配置

use crate::process_filter::ProcessFilter;
use serde_json::json;
use std::collections::HashMap;

/// 生成 mihomo 配置文件 (YAML 格式)
///
/// # 参数
/// * `filter` - 进程过滤器配置
/// * `http_proxy_port` - 现有 HTTP 代理端口（mihomo 会将流量转发到这里）
/// * `enable_tun` - 是否启用 TUN 模式
///
/// # 返回
/// YAML 格式的配置字符串
pub fn generate_mihomo_config(
    filter: &ProcessFilter,
    http_proxy_port: u16,
    enable_tun: bool,
) -> Result<String, Box<dyn std::error::Error>> {
    let mut config = HashMap::new();

    // 1. 基础配置
    // 不需要 mixed-port，因为我们只使用 TUN 模式转发到现有的 HTTP 代理
    config.insert("allow-lan", json!(false));
    config.insert("mode", json!("rule"));
    config.insert("log-level", json!("info"));
    config.insert("external-controller", json!("127.0.0.1:9091")); // 使用 9091 避免与 Clash Verge 冲突
    config.insert("secret", json!(""));

    // 2. TUN 配置
    if enable_tun {
        let mut tun_config = HashMap::new();
        tun_config.insert("enable", json!(true));
        tun_config.insert("stack", json!("gvisor")); // gvisor 是性能最好的网络栈
        tun_config.insert("auto-route", json!(true));
        tun_config.insert("auto-detect-interface", json!(true));
        tun_config.insert("dns-hijack", json!(vec!["any:53"]));

        // 不指定设备名，让 mihomo 自动选择可用的 TUN 设备
        // 这样可以避免与现有的 TUN 设备冲突

        config.insert("tun", json!(tun_config));
    } else {
        let mut tun_config = HashMap::new();
        tun_config.insert("enable", json!(false));
        config.insert("tun", json!(tun_config));
    }

    // 3. DNS 配置
    let mut dns_config = HashMap::new();
    dns_config.insert("enable", json!(true));
    dns_config.insert("enhanced-mode", json!("fake-ip"));
    dns_config.insert("fake-ip-range", json!("198.18.0.1/16"));
    dns_config.insert("nameserver", json!(vec!["223.5.5.5", "114.114.114.114"]));
    // 添加 fallback DNS
    dns_config.insert(
        "fallback",
        json!(vec!["1.1.1.1", "8.8.8.8"]),
    );
    config.insert("dns", json!(dns_config));

    // 4. 代理配置 (指向现有 HTTP 代理)
    let mut proxy = HashMap::new();
    proxy.insert("name", json!("local-http"));
    proxy.insert("type", json!("http"));
    proxy.insert("server", json!("127.0.0.1"));
    proxy.insert("port", json!(http_proxy_port));

    config.insert("proxies", json!(vec![proxy]));

    // 5. 代理组
    let mut proxy_group = HashMap::new();
    proxy_group.insert("name", json!("PROXY"));
    proxy_group.insert("type", json!("select"));
    proxy_group.insert("proxies", json!(vec!["local-http", "DIRECT"]));

    config.insert("proxy-groups", json!(vec![proxy_group]));

    // 6. 规则配置 (从 ProcessFilter 生成)
    let rules = generate_rules(filter);
    config.insert("rules", json!(rules));

    // 7. 序列化为 YAML
    let yaml = serde_yaml::to_string(&config)?;
    Ok(yaml)
}

/// 根据 ProcessFilter 生成 mihomo 规则列表
///
/// # 逻辑
/// - 白名单模式: 只有列表中的进程走代理，其他直连
/// - 黑名单模式: 列表中的进程不走代理，其他走代理
fn generate_rules(filter: &ProcessFilter) -> Vec<String> {
    let mut rules = Vec::new();

    if filter.enabled && !filter.allowed_processes.is_empty() {
        for process_name in &filter.allowed_processes {
            let rule = if filter.blacklist_mode {
                // 黑名单模式: 列表中的走 DIRECT (不代理)
                format!("PROCESS-NAME,{},DIRECT", process_name)
            } else {
                // 白名单模式: 列表中的走 PROXY
                format!("PROCESS-NAME,{},PROXY", process_name)
            };
            rules.push(rule);
        }
    }

    // 默认规则
    if filter.enabled && !filter.allowed_processes.is_empty() {
        if filter.blacklist_mode {
            // 黑名单模式: 其他走 PROXY
            rules.push("MATCH,PROXY".to_string());
        } else {
            // 白名单模式: 其他走 DIRECT
            rules.push("MATCH,DIRECT".to_string());
        }
    } else {
        // 未启用进程过滤或列表为空: 所有流量都走代理
        rules.push("MATCH,PROXY".to_string());
    }

    rules
}

/// 获取 mihomo 配置文件路径
///
/// 返回应用配置目录下的 mihomo_config.yaml 路径
pub fn get_mihomo_config_path() -> Result<std::path::PathBuf, Box<dyn std::error::Error>> {
    let config_dir = dirs::config_dir()
        .ok_or("无法获取配置目录")?
        .join("sysproxy-tauri-demo");

    // 确保目录存在
    std::fs::create_dir_all(&config_dir)?;

    Ok(config_dir.join("mihomo_config.yaml"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    #[test]
    fn test_generate_config_whitelist() {
        let mut filter = ProcessFilter {
            enabled: true,
            allowed_processes: HashSet::new(),
            blacklist_mode: false,
        };
        filter.allowed_processes.insert("chrome.exe".to_string());
        filter.allowed_processes.insert("firefox.exe".to_string());

        let config = generate_mihomo_config(&filter, 8888, true).unwrap();
        println!("{}", config);

        assert!(config.contains("tun"));
        assert!(config.contains("enable: true"));
        assert!(config.contains("PROCESS-NAME,chrome.exe,PROXY"));
        assert!(config.contains("PROCESS-NAME,firefox.exe,PROXY"));
        assert!(config.contains("MATCH,DIRECT")); // 白名单模式，其他直连
    }

    #[test]
    fn test_generate_config_blacklist() {
        let mut filter = ProcessFilter {
            enabled: true,
            allowed_processes: HashSet::new(),
            blacklist_mode: true,
        };
        filter.allowed_processes.insert("chrome.exe".to_string());

        let config = generate_mihomo_config(&filter, 8888, true).unwrap();
        println!("{}", config);

        assert!(config.contains("PROCESS-NAME,chrome.exe,DIRECT"));
        assert!(config.contains("MATCH,PROXY")); // 黑名单模式，其他走代理
    }

    #[test]
    fn test_generate_config_disabled_filter() {
        let filter = ProcessFilter {
            enabled: false,
            allowed_processes: HashSet::new(),
            blacklist_mode: false,
        };

        let config = generate_mihomo_config(&filter, 8888, true).unwrap();
        println!("{}", config);

        assert!(config.contains("MATCH,PROXY")); // 未启用过滤，所有流量走代理
    }

    #[test]
    fn test_generate_rules_whitelist() {
        let mut filter = ProcessFilter {
            enabled: true,
            allowed_processes: HashSet::new(),
            blacklist_mode: false,
        };
        filter.allowed_processes.insert("chrome".to_string());
        filter.allowed_processes.insert("firefox".to_string());

        let rules = generate_rules(&filter);

        assert!(rules.contains(&"PROCESS-NAME,chrome,PROXY".to_string()));
        assert!(rules.contains(&"PROCESS-NAME,firefox,PROXY".to_string()));
        assert!(rules.contains(&"MATCH,DIRECT".to_string()));
    }

    #[test]
    fn test_generate_rules_blacklist() {
        let mut filter = ProcessFilter {
            enabled: true,
            allowed_processes: HashSet::new(),
            blacklist_mode: true,
        };
        filter.allowed_processes.insert("chrome".to_string());

        let rules = generate_rules(&filter);

        assert!(rules.contains(&"PROCESS-NAME,chrome,DIRECT".to_string()));
        assert!(rules.contains(&"MATCH,PROXY".to_string()));
    }
}
