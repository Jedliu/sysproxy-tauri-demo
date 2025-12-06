/// 透明代理模块
///
/// 使用 macOS pf (Packet Filter) 实现透明代理，无需修改系统代理设置
/// 通过防火墙规则将特定端口的流量重定向到代理服务器

use std::process::Command;
use std::fs;

/// 透明代理管理器
pub struct TransparentProxy {
    /// pf anchor 名称
    anchor_name: String,
    /// 代理服务器端口
    proxy_port: u16,
    /// pf 规则文件路径
    rules_file: String,
}

impl TransparentProxy {
    /// 创建透明代理管理器
    ///
    /// # 参数
    /// - `proxy_port`: 代理服务器监听端口
    pub fn new(proxy_port: u16) -> Self {
        Self {
            anchor_name: "com.sysproxy.transparent".to_string(),
            proxy_port,
            rules_file: "/tmp/sysproxy_pf.rules".to_string(),
        }
    }

    /// 生成 pf 规则
    ///
    /// 重定向 HTTP (80) 和 HTTPS (443) 流量到代理端口
    ///
    /// ⚠️ 重要限制：
    /// macOS 的 pf 无法重定向本机（127.0.0.1/localhost）发起的流量。
    /// 这意味着：
    /// 1. 本机的浏览器、应用需要手动设置代理（使用"系统代理"功能）
    /// 2. 透明代理主要用于拦截：
    ///    - 局域网内其他设备的流量（需要将它们的网关设置为本机）
    ///    - Docker 容器的流量（通过桥接网络）
    ///    - 虚拟机的流量
    fn generate_rules(&self) -> String {
        format!(
            r#"# Sysproxy Transparent Proxy Rules
# Redirect HTTP and HTTPS traffic to proxy server
#
# ⚠️ 注意：macOS pf 无法重定向本机发起的流量 (127.0.0.1)
# 本机应用请使用"系统代理"功能
#
# 这些规则仅对以下情况有效：
# 1. 局域网其他设备（需配置网关为本机 IP）
# 2. Docker 容器/虚拟机流量

# Redirect HTTP traffic (port 80)
rdr pass inet proto tcp from any to any port 80 -> 127.0.0.1 port {}

# Redirect HTTPS traffic (port 443)
rdr pass inet proto tcp from any to any port 443 -> 127.0.0.1 port {}
"#,
            self.proxy_port, self.proxy_port
        )
    }

    /// 启用透明代理
    ///
    /// 1. 生成 pf 规则文件
    /// 2. 使用 osascript 请求管理员权限
    /// 3. 加载规则到 pf
    /// 4. 启用 pf
    ///
    /// # 返回
    /// 成功返回 Ok(())，失败返回错误信息
    pub fn enable(&self) -> Result<(), String> {
        println!("启用透明代理...");

        // 1. 生成并写入规则文件
        let rules = self.generate_rules();
        fs::write(&self.rules_file, rules)
            .map_err(|e| format!("写入规则文件失败: {}", e))?;

        println!("规则文件已写入: {}", self.rules_file);

        // 2. 加载规则（需要管理员权限）
        let load_cmd = format!(
            "pfctl -a {} -f {}",
            self.anchor_name, self.rules_file
        );

        let output = Command::new("osascript")
            .arg("-e")
            .arg(format!(
                "do shell script \"{}\" with administrator privileges",
                load_cmd
            ))
            .output()
            .map_err(|e| format!("执行 osascript 失败: {}", e))?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(format!("加载 pf 规则失败: {}", stderr));
        }

        println!("pf 规则已加载");

        // 3. 启用 pf（如果尚未启用）
        let enable_output = Command::new("osascript")
            .arg("-e")
            .arg("do shell script \"pfctl -e 2>/dev/null || true\" with administrator privileges")
            .output();

        if let Ok(output) = enable_output {
            if output.status.success() {
                println!("pf 已启用");
            }
        }

        println!("✅ 透明代理已启用");
        println!("  - HTTP (80) → 127.0.0.1:{}", self.proxy_port);
        println!("  - HTTPS (443) → 127.0.0.1:{}", self.proxy_port);

        Ok(())
    }

    /// 禁用透明代理
    ///
    /// 清除 pf anchor 中的所有规则
    ///
    /// # 返回
    /// 成功返回 Ok(())，失败返回错误信息
    pub fn disable(&self) -> Result<(), String> {
        println!("禁用透明代理...");

        // 清除 anchor 中的规则
        let flush_cmd = format!("pfctl -a {} -F all", self.anchor_name);

        let output = Command::new("osascript")
            .arg("-e")
            .arg(format!(
                "do shell script \"{}\" with administrator privileges",
                flush_cmd
            ))
            .output()
            .map_err(|e| format!("执行 osascript 失败: {}", e))?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(format!("清除 pf 规则失败: {}", stderr));
        }

        println!("✅ 透明代理已禁用");

        // 清理临时文件
        let _ = fs::remove_file(&self.rules_file);

        Ok(())
    }

    /// 检查透明代理状态
    ///
    /// 查询 pf anchor 中是否有规则
    ///
    /// # 返回
    /// true 表示已启用，false 表示未启用
    pub fn is_enabled(&self) -> bool {
        // 查询 anchor 规则（需要管理员权限）
        let check_cmd = format!("pfctl -a {} -s nat 2>/dev/null", self.anchor_name);

        let output = Command::new("osascript")
            .arg("-e")
            .arg(format!(
                "do shell script \"{}\" with administrator privileges",
                check_cmd
            ))
            .output();

        if let Ok(output) = output {
            if output.status.success() {
                let stdout = String::from_utf8_lossy(&output.stdout);
                // 如果输出包含规则，说明已启用
                return !stdout.trim().is_empty();
            }
        }

        false
    }

    /// 获取当前规则详情
    ///
    /// # 返回
    /// 规则文本，如果未启用则返回 None
    pub fn get_rules(&self) -> Option<String> {
        // 查询 anchor 规则（需要管理员权限）
        let check_cmd = format!("pfctl -a {} -s nat 2>/dev/null", self.anchor_name);

        let output = Command::new("osascript")
            .arg("-e")
            .arg(format!(
                "do shell script \"{}\" with administrator privileges",
                check_cmd
            ))
            .output()
            .ok()?;

        if output.status.success() {
            let stdout = String::from_utf8_lossy(&output.stdout).to_string();
            if !stdout.trim().is_empty() {
                return Some(stdout);
            }
        }

        None
    }
}

// 注意：不实现 Drop trait
// 透明代理规则应该持久化，由用户显式禁用
// 如果实现 Drop，每次函数调用后实例销毁都会自动禁用规则

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_rules() {
        let proxy = TransparentProxy::new(8888);
        let rules = proxy.generate_rules();

        assert!(rules.contains("port 80"));
        assert!(rules.contains("port 443"));
        assert!(rules.contains("127.0.0.1 port 8888"));
    }

    #[test]
    fn test_is_enabled() {
        let proxy = TransparentProxy::new(8888);
        // 初始状态应该是未启用
        // 注意：这个测试不会实际加载规则
        println!("Transparent proxy enabled: {}", proxy.is_enabled());
    }
}
