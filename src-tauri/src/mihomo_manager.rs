/// mihomo 进程管理模块
///
/// 负责启动、停止、监控 mihomo sidecar 进程

use crate::mihomo_config::{generate_mihomo_config, get_mihomo_config_path};
use crate::process_filter::ProcessFilter;
use crate::privilege;
use parking_lot::Mutex;
use reqwest::Client;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use tauri::AppHandle;
use tokio::time::{sleep, Duration};

/// mihomo 状态信息
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MihomoStatus {
    /// mihomo 版本
    pub version: String,
    /// 是否正在运行
    pub running: bool,
    /// TUN 模式是否启用
    pub tun_enabled: bool,
}

/// mihomo 管理器
pub struct MihomoManager {
    /// mihomo 进程句柄
    process: Arc<Mutex<Option<Child>>>,
    /// 是否通过 sudo/osascript 启动（用于检测状态）
    running_via_sudo: Arc<AtomicBool>,
    /// 配置文件路径
    config_path: PathBuf,
    /// HTTP 客户端（用于调用 mihomo API）
    api_client: Client,
    /// mihomo API 基础 URL
    api_base: String,
    /// mihomo 二进制路径
    mihomo_bin_path: Option<PathBuf>,
}

impl MihomoManager {
    /// 创建新的 mihomo 管理器
    pub fn new() -> Result<Self, Box<dyn std::error::Error>> {
        Ok(Self {
            process: Arc::new(Mutex::new(None)),
            running_via_sudo: Arc::new(AtomicBool::new(false)),
            config_path: get_mihomo_config_path()?,
            api_client: Client::builder()
                .timeout(Duration::from_secs(5))
                .build()?,
            api_base: "http://127.0.0.1:9091".to_string(), // 使用 9091 避免与 Clash Verge 冲突
            mihomo_bin_path: None,
        })
    }

    /// 设置 mihomo 二进制路径（由 Tauri 提供）
    pub fn set_mihomo_bin_path(&mut self, path: PathBuf) {
        self.mihomo_bin_path = Some(path);
    }

    /// 检查 mihomo 是否正在运行
    pub fn is_running(&self) -> bool {
        // 检查两种情况：
        // 1. 有 Child 进程对象（通过正常方式启动）
        // 2. 通过 sudo/osascript 启动的标志为 true
        self.process.lock().is_some() || self.running_via_sudo.load(Ordering::Relaxed)
    }

    /// 启动 mihomo
    ///
    /// # 参数
    /// * `filter` - 进程过滤器配置
    /// * `http_proxy_port` - 现有 HTTP 代理端口
    /// * `enable_tun` - 是否启用 TUN 模式
    pub async fn start(
        &self,
        filter: &ProcessFilter,
        http_proxy_port: u16,
        enable_tun: bool,
    ) -> Result<(), Box<dyn std::error::Error>> {
        // 1. 检查权限
        if enable_tun && !privilege::has_admin_privileges() {
            // macOS: 尝试使用 osascript 提权启动
            #[cfg(target_os = "macos")]
            {
                return self.start_with_osascript(filter, http_proxy_port, enable_tun).await;
            }

            #[cfg(not(target_os = "macos"))]
            {
                return Err("TUN 模式需要管理员权限".into());
            }
        }

        // 2. 检查是否已经在运行
        if self.is_running() {
            return Err("mihomo 已经在运行中".into());
        }

        // 3. 生成配置文件
        let config = generate_mihomo_config(filter, http_proxy_port, enable_tun)?;
        std::fs::write(&self.config_path, config)?;

        // 4. 获取 mihomo 二进制路径
        let mihomo_path = self
            .mihomo_bin_path
            .as_ref()
            .ok_or("mihomo 二进制路径未设置")?;

        // 5. 获取配置目录
        let config_dir = self
            .config_path
            .parent()
            .ok_or("无法获取配置目录")?
            .to_path_buf();

        // 6. 启动进程
        let child = Command::new(mihomo_path)
            .args(&[
                "-d",
                config_dir.to_str().unwrap(),
                "-f",
                self.config_path.to_str().unwrap(),
            ])
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()?;

        let pid = child.id();
        *self.process.lock() = Some(child);

        println!("mihomo 已启动，PID: {}", pid);

        // 7. 等待 API 就绪
        self.wait_for_api_ready().await?;

        println!("mihomo API 已就绪");

        Ok(())
    }

    /// macOS: 使用 osascript 提权启动 mihomo
    #[cfg(target_os = "macos")]
    async fn start_with_osascript(
        &self,
        filter: &ProcessFilter,
        http_proxy_port: u16,
        enable_tun: bool,
    ) -> Result<(), Box<dyn std::error::Error>> {
        // 1. 强制清理所有旧的 mihomo 进程
        println!("[DEBUG] 正在清理旧的 mihomo 进程...");
        let cleanup_command = "sudo pkill -f verge-mihomo || true";

        // 使用 osascript 执行清理（忽略错误）
        let _ = privilege::execute_with_admin_prompt(
            cleanup_command,
            "Sysproxy 需要管理员权限来清理旧进程"
        );

        // 等待进程完全退出
        println!("[DEBUG] 等待进程退出...");
        tokio::time::sleep(tokio::time::Duration::from_secs(1)).await;

        // 2. 清理残留的路由表项
        println!("[DEBUG] 正在清理残留路由...");
        let route_cleanup_command = r#"
sudo route -n delete 1.0.0.0/8 2>/dev/null || true
sudo route -n delete 2.0.0.0/7 2>/dev/null || true
sudo route -n delete 4.0.0.0/6 2>/dev/null || true
sudo route -n delete 8.0.0.0/5 2>/dev/null || true
sudo route -n delete 16.0.0.0/4 2>/dev/null || true
sudo route -n delete 32.0.0.0/3 2>/dev/null || true
sudo route -n delete 64.0.0.0/2 2>/dev/null || true
sudo route -n delete 128.0.0.0/1 2>/dev/null || true
"#;

        // 清理路由（忽略错误）
        let _ = privilege::execute_with_admin_prompt(
            route_cleanup_command,
            "Sysproxy 需要管理员权限来清理旧路由"
        );

        // 等待资源完全释放
        println!("[DEBUG] 等待资源释放...");
        tokio::time::sleep(tokio::time::Duration::from_secs(1)).await;

        // 清除运行标志
        self.running_via_sudo.store(false, Ordering::Relaxed);

        println!("[DEBUG] 清理完成");

        // 2. 生成配置文件
        let config = generate_mihomo_config(filter, http_proxy_port, enable_tun)?;
        println!("[DEBUG] 配置文件路径: {:?}", self.config_path);
        println!("[DEBUG] 配置内容:\n{}", config);
        std::fs::write(&self.config_path, config)?;
        println!("[DEBUG] 配置文件已写入");

        // 3. 获取 mihomo 二进制路径
        let mihomo_path = self
            .mihomo_bin_path
            .as_ref()
            .ok_or("mihomo 二进制路径未设置")?;

        // 4. 获取配置目录
        let config_dir = self
            .config_path
            .parent()
            .ok_or("无法获取配置目录")?;

        // 5. 构建启动命令
        // 将输出重定向到日志文件以便调试
        let log_file = config_dir.join("mihomo.log");

        // osascript 的 do shell script 本身会分离进程，不需要 nohup
        // 使用 sh -c 包装整个命令，确保重定向在 sudo 内部执行
        let command = format!(
            "sudo sh -c \"'{}' -d '{}' -f '{}' > '{}' 2>&1 &\"",
            mihomo_path.display(),
            config_dir.display(),
            self.config_path.display(),
            log_file.display()
        );

        println!("[DEBUG] 将要执行的命令: {}", command);
        println!("[DEBUG] 日志文件: {:?}", log_file);

        // 6. 使用 osascript 提权执行
        privilege::execute_with_admin_prompt(
            &command,
            "Sysproxy 需要管理员权限来启动 TUN 代理"
        )?;

        println!("[DEBUG] osascript 执行完成");

        println!("mihomo 已通过 osascript 启动");

        // 7. 设置运行标志
        self.running_via_sudo.store(true, Ordering::Relaxed);

        // 8. 等待 API 就绪
        match self.wait_for_api_ready().await {
            Ok(_) => {
                println!("mihomo API 已就绪");
                Ok(())
            }
            Err(e) => {
                // 如果 API 启动失败，清除运行标志
                self.running_via_sudo.store(false, Ordering::Relaxed);
                Err(e)
            }
        }
    }

    /// 停止 mihomo
    pub fn stop(&self) -> Result<(), Box<dyn std::error::Error>> {
        let mut process_guard = self.process.lock();

        if let Some(mut child) = process_guard.take() {
            println!("正在停止 mihomo...");

            // 尝试优雅停止
            #[cfg(unix)]
            {
                use nix::sys::signal::{kill, Signal};
                use nix::unistd::Pid;

                let pid = Pid::from_raw(child.id() as i32);
                if let Err(e) = kill(pid, Signal::SIGTERM) {
                    eprintln!("发送 SIGTERM 失败: {}", e);
                }
            }

            #[cfg(windows)]
            {
                // Windows 上直接 kill
                if let Err(e) = child.kill() {
                    eprintln!("终止进程失败: {}", e);
                }
            }

            // 等待进程退出
            match child.wait() {
                Ok(status) => {
                    println!("mihomo 已停止，退出状态: {}", status);
                }
                Err(e) => {
                    eprintln!("等待进程退出失败: {}", e);
                }
            }

            // 清除运行标志
            self.running_via_sudo.store(false, Ordering::Relaxed);
        } else {
            // 如果 process guard 中没有 Child 对象，尝试使用 pkill（macOS sudo 启动的情况）
            #[cfg(target_os = "macos")]
            {
                return self.stop_with_pkill();
            }

            #[cfg(not(target_os = "macos"))]
            {
                return Err("mihomo 未运行".into());
            }
        }

        Ok(())
    }

    /// macOS: 使用 pkill 停止 mihomo
    #[cfg(target_os = "macos")]
    fn stop_with_pkill(&self) -> Result<(), Box<dyn std::error::Error>> {
        println!("尝试使用 pkill 停止 mihomo...");

        let command = "sudo pkill -f 'verge-mihomo'";

        privilege::execute_with_admin_prompt(
            command,
            "Sysproxy 需要管理员权限来停止 TUN 代理"
        )?;

        // 清除运行标志
        self.running_via_sudo.store(false, Ordering::Relaxed);

        println!("mihomo 已通过 pkill 停止");
        Ok(())
    }

    /// 重新加载配置
    pub async fn reload_config(
        &self,
        filter: &ProcessFilter,
        http_proxy_port: u16,
        enable_tun: bool,
    ) -> Result<(), Box<dyn std::error::Error>> {
        // 1. 生成新配置
        let config = generate_mihomo_config(filter, http_proxy_port, enable_tun)?;
        std::fs::write(&self.config_path, config)?;

        // 2. 调用 mihomo API 重新加载
        let url = format!("{}/configs", self.api_base);
        let payload = serde_json::json!({
            "path": self.config_path.to_str().unwrap()
        });

        let response = self
            .api_client
            .put(&url)
            .json(&payload)
            .send()
            .await?;

        if !response.status().is_success() {
            return Err(format!("重新加载配置失败: {}", response.status()).into());
        }

        println!("mihomo 配置已重新加载");

        Ok(())
    }

    /// 获取 mihomo 状态
    pub async fn get_status(&self) -> Result<MihomoStatus, Box<dyn std::error::Error>> {
        if !self.is_running() {
            return Ok(MihomoStatus {
                version: "未运行".to_string(),
                running: false,
                tun_enabled: false,
            });
        }

        let url = format!("{}/", self.api_base);
        let response = self.api_client.get(&url).send().await?;

        if !response.status().is_success() {
            return Err(format!("获取状态失败: {}", response.status()).into());
        }

        let data: serde_json::Value = response.json().await?;

        Ok(MihomoStatus {
            version: data["version"]
                .as_str()
                .unwrap_or("unknown")
                .to_string(),
            running: true,
            tun_enabled: data["tun"]["enable"].as_bool().unwrap_or(false),
        })
    }

    /// 等待 mihomo API 就绪
    async fn wait_for_api_ready(&self) -> Result<(), Box<dyn std::error::Error>> {
        for i in 0..30 {
            // 最多等待 30 秒
            // 直接尝试连接 API,而不是调用 get_status() (因为它会在 is_running() 返回 false 时提前返回 Ok)
            let url = format!("{}/", self.api_base);
            if let Ok(response) = self.api_client.get(&url).send().await {
                if response.status().is_success() {
                    // 尝试解析响应以确保API真的在工作
                    if let Ok(data) = response.json::<serde_json::Value>().await {
                        if data.get("version").is_some() {
                            return Ok(());
                        }
                    }
                }
            }

            if i < 29 {
                sleep(Duration::from_secs(1)).await;
            }
        }

        // API 超时，提供诊断信息
        eprintln!("[ERROR] mihomo API 启动超时");

        // 检查进程是否在运行
        if let Ok(output) = std::process::Command::new("pgrep")
            .arg("-f")
            .arg("verge-mihomo")
            .output() {
            if output.status.success() && !output.stdout.is_empty() {
                let pids = String::from_utf8_lossy(&output.stdout);
                eprintln!("[DEBUG] mihomo 进程正在运行，PID: {}", pids.trim());
            } else {
                eprintln!("[ERROR] 未找到 mihomo 进程，可能启动失败");
            }
        }

        // 尝试读取日志文件
        if let Some(config_dir) = self.config_path.parent() {
            let log_file = config_dir.join("mihomo.log");
            if log_file.exists() {
                if let Ok(log_content) = std::fs::read_to_string(&log_file) {
                    let lines: Vec<&str> = log_content.lines().collect();
                    let last_lines = lines.iter().rev().take(10).rev().collect::<Vec<_>>();
                    eprintln!("[DEBUG] 最后 10 行日志:");
                    for line in last_lines {
                        eprintln!("  {}", line);
                    }
                }
            } else {
                eprintln!("[ERROR] 日志文件不存在: {:?}", log_file);
            }
        }

        Err("mihomo API 启动超时。请检查日志文件和进程状态。".into())
    }
}

impl Drop for MihomoManager {
    fn drop(&mut self) {
        // 确保进程被停止
        if self.is_running() {
            let _ = self.stop();
        }
    }
}

/// 全局 mihomo 管理器实例
static MIHOMO_MANAGER: once_cell::sync::Lazy<Arc<tokio::sync::Mutex<Option<MihomoManager>>>> =
    once_cell::sync::Lazy::new(|| Arc::new(tokio::sync::Mutex::new(None)));

/// 初始化全局 mihomo 管理器
pub async fn init_global_manager(app_handle: &AppHandle) -> Result<(), Box<dyn std::error::Error>> {
    let mut manager = MihomoManager::new()?;

    // 获取 sidecar 路径
    use tauri::Manager;

    // 在开发模式下，二进制位于 src-tauri/sidecar/
    // 在生产模式下，二进制位于 resource_dir/sidecar/
    #[cfg(debug_assertions)]
    let sidecar_dir = {
        // 开发模式：使用当前工作目录 + sidecar
        std::env::current_dir()
            .map_err(|e| format!("获取当前目录失败: {}", e))?
            .join("sidecar")
    };

    #[cfg(not(debug_assertions))]
    let sidecar_dir = {
        // 生产模式：使用 resource_dir + sidecar
        app_handle
            .path()
            .resource_dir()
            .map_err(|e| format!("获取资源目录失败: {}", e))?
            .join("sidecar")
    };

    // macOS 需要添加架构后缀
    #[cfg(target_os = "macos")]
    let mihomo_path = {
        use std::env::consts::ARCH;
        let suffix = match ARCH {
            "aarch64" => "-aarch64-apple-darwin",
            "x86_64" => "-x86_64-apple-darwin",
            _ => "",
        };
        sidecar_dir.join(format!("verge-mihomo{}", suffix))
    };

    // Windows 需要 .exe 后缀
    #[cfg(target_os = "windows")]
    let mihomo_path = sidecar_dir.join("verge-mihomo-x86_64-pc-windows-msvc.exe");

    // Linux
    #[cfg(target_os = "linux")]
    let mihomo_path = sidecar_dir.join("verge-mihomo-x86_64-unknown-linux-gnu");

    println!("[DEBUG] mihomo 二进制路径: {:?}", mihomo_path);

    // 检查文件是否存在
    if !mihomo_path.exists() {
        return Err(format!("mihomo 二进制文件不存在: {:?}", mihomo_path).into());
    }

    manager.set_mihomo_bin_path(mihomo_path);

    *MIHOMO_MANAGER.lock().await = Some(manager);

    Ok(())
}

/// 获取全局 mihomo 管理器
pub fn get_global_manager() -> Result<Arc<tokio::sync::Mutex<Option<MihomoManager>>>, Box<dyn std::error::Error>>
{
    Ok(MIHOMO_MANAGER.clone())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_create_manager() {
        let manager = MihomoManager::new();
        assert!(manager.is_ok());
    }

    #[test]
    fn test_manager_not_running_initially() {
        let manager = MihomoManager::new().unwrap();
        assert!(!manager.is_running());
    }
}
