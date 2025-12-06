// Prevents additional console window on Windows in release, DO NOT REMOVE!!
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

mod cert;
mod cert_installer;
mod proxy;
mod interceptor;
mod process_filter;
mod app_icon;
mod socket_process;
mod transparent_proxy;

use once_cell::sync::Lazy;
use serde::Serialize;
use std::sync::{Arc, Mutex};
use sysproxy::{Autoproxy, Sysproxy};
use tauri::{generate_context, generate_handler, Builder, Emitter, RunEvent};
use tokio::sync::mpsc;

use cert::CertManager;
use cert_installer::CertInstaller;
use proxy::{ProxyServer, ProxyConfig, ProxyLog};
use interceptor::{Interceptor, InterceptRule};
use process_filter::{ProcessFilter, ProcessFilterManager, ProcessInfo, get_running_processes, get_running_processes_with_info};
use transparent_proxy::TransparentProxy;

/// 用于存储和序列化代理配置的结构体
#[derive(Clone, Serialize, Debug, PartialEq)]
struct SavedProxy {
    sys_enable: bool,
    sys_host: String,
    sys_port: u16,
    sys_bypass: String,
    auto_enable: bool,
    auto_url: String,
}

/// 全局静态变量，用于在内存中保存原始的系统代理配置。
/// 使用 `Lazy` 和 `Mutex` 确保线程安全地单次初始化。
/// `Option` 表示可能没有保存的配置（例如，在程序首次启动，尚未设置新代理时）。
static SAVED_PROXY: Lazy<Mutex<Option<SavedProxy>>> = Lazy::new(|| Mutex::new(None));

/// 全局静态变量，用于记录最后一次通过事件发出的代理状态。
/// 这用于去重，避免在代理状态未发生实际变化时重复发送事件。
static LAST_EMITTED_PROXY: Lazy<Mutex<Option<SavedProxy>>> = Lazy::new(|| Mutex::new(None));

/// 代理服务器状态结构
struct ProxyServerState {
    server: Option<Arc<ProxyServer>>,
    interceptor: Arc<Interceptor>,
    process_filter: Arc<ProcessFilterManager>,
    log_receiver: Option<mpsc::UnboundedReceiver<ProxyLog>>,
    handle: Option<tokio::task::JoinHandle<()>>,
    /// 停止信号发送端（用于优雅地停止代理服务器）
    shutdown_sender: Option<tokio::sync::oneshot::Sender<()>>,
}

/// 全局代理服务器状态
static PROXY_STATE: Lazy<Mutex<ProxyServerState>> = Lazy::new(|| {
    Mutex::new(ProxyServerState {
        server: None,
        interceptor: Arc::new(Interceptor::new()),
        process_filter: Arc::new(ProcessFilterManager::new()),
        log_receiver: None,
        handle: None,
        shutdown_sender: None,
    })
});

/// 前端监听的事件名称，当代理状态发生变化时，会发出此事件。
const PROXY_CHANGED_EVENT: &str = "proxy-changed";

// 为不同操作系统定义默认的代理绕过（bypass）列表
#[cfg(target_os = "windows")]
const DEFAULT_BYPASS: &str = "localhost;127.*;192.168.*;10.*;172.16.*;172.17.*;172.18.*;172.19.*;172.20.*;172.21.*;172.22.*;172.23.*;172.24.*;172.25.*;172.26.*;172.27.*;172.28.*;172.29.*;172.30.*;172.31.*;<local>";
#[cfg(target_os = "linux")]
const DEFAULT_BYPASS: &str =
    "localhost,127.0.0.1,192.168.0.0/16,10.0.0.0/8,172.16.0.0/12,172.29.0.0/16,::1";
#[cfg(target_os = "macos")]
const DEFAULT_BYPASS: &str = "127.0.0.1,192.168.0.0/16,10.0.0.0/8,172.16.0.0/12,172.29.0.0/16,localhost,*.local,*.crashlytics.com,<local>";

/// Tauri 命令：设置系统代理
///
/// # Arguments
///
/// * `host` - 代理服务器地址
/// * `port` - 代理服务器端口
///
/// # Returns
///
/// * `Result<(), String>` - 成功则返回 Ok，失败则返回错误信息字符串。
#[tauri::command]
fn set_system_proxy(host: String, port: u16) -> Result<(), String> {
    let host = host.trim();
    if host.is_empty() {
        return Err("代理地址不能为空".into());
    }

    // 仅在首次设置代理时，保存当前系统代理配置，以便后续还原。
    {
        // 创建独立作用域以确保 MutexGuard 能及时被释放
        let mut saved = SAVED_PROXY
            .lock()
            .map_err(|_| "无法锁定保存的代理配置".to_string())?;
        if saved.is_none() {
            // 获取当前的手动代理和自动代理（PAC）配置
            let sys = Sysproxy::get_system_proxy().unwrap_or_default();
            let auto = Autoproxy::get_auto_proxy().unwrap_or_default();
            *saved = Some(SavedProxy {
                sys_enable: sys.enable,
                sys_host: sys.host.to_string(),
                sys_port: sys.port,
                sys_bypass: sys.bypass.to_string(),
                auto_enable: auto.enable,
                auto_url: auto.url.to_string(),
            });
        }
    }

    // 在设置手动代理前，先禁用自动代理（PAC），避免冲突。
    if let Ok(mut auto) = Autoproxy::get_auto_proxy() {
        auto.enable = false;
        let _ = auto.set_auto_proxy();
    }

    // 创建新的手动代理配置
    let proxy = Sysproxy {
        enable: true,
        host: host.into(),
        port,
        bypass: DEFAULT_BYPASS.into(),
    };

    // 应用新的系统代理配置
    proxy
        .set_system_proxy()
        .map_err(|e| format!("设置系统代理失败: {e}"))
}

/// Tauri 命令：恢复到原始的系统代理配置
///
/// 只有在用户使用过"应用代理"功能时才会执行恢复操作。
/// 如果用户从未使用"应用代理"，则不会修改系统代理设置。
///
/// # Returns
///
/// * `Result<(), String>` - 成功则返回 Ok，失败则返回错误信息字符串。
#[tauri::command]
fn restore_system_proxy() -> Result<(), String> {
    let saved_option = {
        // 独立作用域，用于提前释放锁
        SAVED_PROXY
            .lock()
            .map_err(|_| "无法锁定保存的代理配置".to_string())?
            .clone()
    };

    if let Some(saved) = saved_option {
        // 如果有保存的配置，则按配置还原
        println!("恢复系统代理配置：{}:{}", saved.sys_host, saved.sys_port);
        let auto = Autoproxy {
            enable: saved.auto_enable,
            url: saved.auto_url.into(),
        };
        let sys = Sysproxy {
            enable: saved.sys_enable,
            host: saved.sys_host.into(),
            port: saved.sys_port,
            bypass: saved.sys_bypass.into(),
        };
        auto.set_auto_proxy()
            .map_err(|e| format!("还原自动代理失败: {e}"))?;
        sys.set_system_proxy()
            .map_err(|e| format!("还原系统代理失败: {e}"))?;
    } else {
        // 如果没有保存的配置，说明用户从未使用过"应用代理"功能
        // 此时不应该修改系统代理设置，保持用户原有的代理配置
        println!("未找到保存的代理配置，跳过恢复操作（保持当前系统代理不变）");
    }
    Ok(())
}

/// Tauri 命令：获取保存在内存中的原始代理配置。
///
/// # Returns
///
/// * `Option<SavedProxy>` - 如果存在已保存的配置，则返回它，否则返回 None。
#[tauri::command]
fn get_saved_proxy() -> Option<SavedProxy> {
    SAVED_PROXY.lock().ok().and_then(|s| s.clone())
}

/// Tauri 命令：获取当前系统的实时代理配置。
///
/// # Returns
///
/// * `Result<SavedProxy, String>` - 成功则返回当前配置，失败则返回错误信息。
#[tauri::command]
fn get_current_proxy() -> Result<SavedProxy, String> {
    let sys = Sysproxy::get_system_proxy().map_err(|e| format!("{e}"))?;
    let auto = Autoproxy::get_auto_proxy().map_err(|e| format!("{e}"))?;
    Ok(SavedProxy {
        sys_enable: sys.enable,
        sys_host: sys.host.to_string(),
        sys_port: sys.port,
        sys_bypass: sys.bypass.to_string(),
        auto_enable: auto.enable,
        auto_url: auto.url.to_string(),
    })
}

/// Tauri 命令：启动代理服务器
#[tauri::command]
async fn start_proxy_server(port: u16, enable_https_intercept: bool) -> Result<String, String> {
    let config = ProxyConfig {
        port,
        enable_https_intercept,
        log_requests: true,
    };

    // Get interceptor and process_filter from global state
    let (interceptor, process_filter) = {
        let state = PROXY_STATE.lock().map_err(|_| "无法锁定代理状态")?;
        (Arc::clone(&state.interceptor), Arc::clone(&state.process_filter))
    };

    let server = Arc::new(ProxyServer::new(config, interceptor, process_filter).map_err(|e| format!("创建代理服务器失败: {}", e))?);

    // 重要：在启动服务器之前先检查端口是否可用
    // 这样可以在端口被占用时立即返回错误给前端，而不是在后台任务中才发现
    server.check_port().await.map_err(|e| e.to_string())?;

    // Create log channel
    let (log_sender, log_receiver) = mpsc::unbounded_channel();
    server.set_log_sender(log_sender);

    // 创建停止信号通道
    let (shutdown_sender, mut shutdown_receiver) = tokio::sync::oneshot::channel::<()>();

    // 端口检查通过后，在后台启动代理服务器
    let server_clone = Arc::clone(&server);
    let handle = tokio::spawn(async move {
        // 使用 tokio::select! 同时等待代理服务器和停止信号
        tokio::select! {
            result = server_clone.start() => {
                if let Err(e) = result {
                    eprintln!("代理服务器错误: {}", e);
                }
            }
            _ = &mut shutdown_receiver => {
                println!("收到停止信号，代理服务器正在关闭...");
                // 停止信号收到，任务将结束
            }
        }
        println!("代理服务器已完全停止");
    });

    // Update global state
    let mut state = PROXY_STATE.lock().map_err(|_| "无法锁定代理状态")?;
    state.server = Some(server);
    state.log_receiver = Some(log_receiver);
    state.handle = Some(handle);
    state.shutdown_sender = Some(shutdown_sender);

    Ok(format!("代理服务器已启动在端口 {}", port))
}

/// Tauri 命令：停止代理服务器
#[tauri::command]
async fn stop_proxy_server() -> Result<String, String> {
    // 首先自动清除系统代理设置
    // 这样可以最大程度减少应用继续尝试连接的情况
    println!("停止代理服务器：正在清除系统代理设置...");
    let _ = restore_system_proxy();

    // 等待一小段时间，让系统代理设置生效
    tokio::time::sleep(std::time::Duration::from_millis(200)).await;

    // 设置停止标志，拒绝所有新请求
    {
        let state = PROXY_STATE.lock().map_err(|_| "无法锁定代理状态")?;
        if let Some(server) = &state.server {
            server.shutdown();
        }
    }

    // 等待一小段时间，让正在处理的请求完成
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;

    // 从状态中提取 shutdown_sender 和 handle
    let (shutdown_sender, handle) = {
        let mut state = PROXY_STATE.lock().map_err(|_| "无法锁定代理状态")?;

        let shutdown_sender = state.shutdown_sender.take();
        let handle = state.handle.take();

        (shutdown_sender, handle)
    }; // 锁在这里释放

    // 发送停止信号
    if let Some(shutdown_sender) = shutdown_sender {
        println!("发送停止信号到代理服务器...");
        // 发送停止信号（忽略错误，因为接收端可能已经关闭）
        let _ = shutdown_sender.send(());
    }

    // 等待任务完成（带超时）
    if let Some(handle) = handle {
        // 等待任务完成，最多等待 3 秒
        match tokio::time::timeout(std::time::Duration::from_secs(3), handle).await {
            Ok(result) => {
                if let Err(e) = result {
                    eprintln!("代理服务器任务错误: {:?}", e);
                }
                println!("代理服务器任务已完成");
            }
            Err(_) => {
                eprintln!("等待代理服务器停止超时");
                println!("注意：某些浏览器或应用可能仍在尝试连接旧的代理");
                println!("建议：重启浏览器以完全停止所有连接");
            }
        }
    }

    // 清理状态
    {
        let mut state = PROXY_STATE.lock().map_err(|_| "无法锁定代理状态")?;
        state.server = None;
        state.log_receiver = None;
    }

    Ok("代理服务器已停止".to_string())
}

/// Tauri 命令：检查代理服务器是否正在运行
#[tauri::command]
fn is_proxy_server_running() -> bool {
    PROXY_STATE
        .lock()
        .ok()
        .map(|s| s.server.is_some())
        .unwrap_or(false)
}

/// Tauri 命令：安装 CA 证书
#[tauri::command]
async fn install_ca_certificate() -> Result<String, String> {
    let cert_manager = CertManager::new().map_err(|e| format!("创建证书管理器失败: {}", e))?;
    let cert_path = cert_manager.get_ca_cert_path().map_err(|e| format!("获取证书路径失败: {}", e))?;

    CertInstaller::install_cert(&cert_path).map_err(|e| format!("安装证书失败: {}", e))
}

/// Tauri 命令：删除 CA 证书
#[tauri::command]
async fn uninstall_ca_certificate() -> Result<String, String> {
    CertInstaller::uninstall_cert().map_err(|e| e.to_string())
}

/// Tauri 命令：检查证书是否已安装
#[tauri::command]
async fn is_certificate_installed() -> Result<bool, String> {
    let cert_manager = CertManager::new().map_err(|e| format!("创建证书管理器失败: {}", e))?;
    let cert_path = cert_manager.get_ca_cert_path().map_err(|e| format!("获取证书路径失败: {}", e))?;

    Ok(CertInstaller::is_cert_installed(&cert_path))
}

/// Tauri 命令：获取 CA 证书路径
#[tauri::command]
async fn get_ca_cert_path() -> Result<String, String> {
    let cert_manager = CertManager::new().map_err(|e| format!("创建证书管理器失败: {}", e))?;
    let cert_path = cert_manager.get_ca_cert_path().map_err(|e| format!("获取证书路径失败: {}", e))?;

    Ok(cert_path.to_string_lossy().to_string())
}

/// Tauri 命令：打开证书所在的文件夹
#[tauri::command]
fn open_cert_folder() -> Result<String, String> {
    let cert_dir = CertManager::get_cert_dir().map_err(|e| format!("获取证书目录失败: {}", e))?;

    #[cfg(target_os = "macos")]
    {
        std::process::Command::new("open")
            .arg(&cert_dir)
            .spawn()
            .map_err(|e| format!("打开文件夹失败: {}", e))?;
    }

    #[cfg(target_os = "windows")]
    {
        std::process::Command::new("explorer")
            .arg(&cert_dir)
            .spawn()
            .map_err(|e| format!("打开文件夹失败: {}", e))?;
    }

    #[cfg(target_os = "linux")]
    {
        std::process::Command::new("xdg-open")
            .arg(&cert_dir)
            .spawn()
            .map_err(|e| format!("打开文件夹失败: {}", e))?;
    }

    Ok(format!("已打开证书文件夹: {}", cert_dir.display()))
}

/// Tauri 命令：添加拦截规则
#[tauri::command]
fn add_intercept_rule(rule: InterceptRule) -> Result<(), String> {
    let state = PROXY_STATE.lock().map_err(|_| "无法锁定代理状态")?;
    state.interceptor.add_rule(rule);
    Ok(())
}

/// Tauri 命令：删除拦截规则
#[tauri::command]
fn remove_intercept_rule(rule_id: String) -> Result<(), String> {
    let state = PROXY_STATE.lock().map_err(|_| "无法锁定代理状态")?;
    state.interceptor.remove_rule(&rule_id);
    Ok(())
}

/// Tauri 命令：获取所有拦截规则
#[tauri::command]
fn get_intercept_rules() -> Result<Vec<InterceptRule>, String> {
    let state = PROXY_STATE.lock().map_err(|_| "无法锁定代理状态")?;
    Ok(state.interceptor.get_rules())
}

/// Tauri 命令：更新拦截规则
#[tauri::command]
fn update_intercept_rule(rule: InterceptRule) -> Result<(), String> {
    let state = PROXY_STATE.lock().map_err(|_| "无法锁定代理状态")?;
    state.interceptor.update_rule(rule);
    Ok(())
}

/// Tauri 命令：清空所有拦截规则
#[tauri::command]
fn clear_intercept_rules() -> Result<(), String> {
    let state = PROXY_STATE.lock().map_err(|_| "无法锁定代理状态")?;
    state.interceptor.clear_rules();
    Ok(())
}

// ========== 进程过滤命令 ==========

/// Tauri 命令：设置进程过滤器配置
#[tauri::command]
fn set_process_filter(filter: ProcessFilter) -> Result<(), String> {
    let state = PROXY_STATE.lock().map_err(|_| "无法锁定代理状态")?;
    state.process_filter.set_filter(filter);
    Ok(())
}

/// Tauri 命令：获取进程过滤器配置
#[tauri::command]
fn get_process_filter() -> Result<ProcessFilter, String> {
    let state = PROXY_STATE.lock().map_err(|_| "无法锁定代理状态")?;
    Ok(state.process_filter.get_filter())
}

/// Tauri 命令：添加允许的进程
#[tauri::command]
fn add_allowed_process(process_name: String) -> Result<(), String> {
    let state = PROXY_STATE.lock().map_err(|_| "无法锁定代理状态")?;
    state.process_filter.add_process(process_name);
    Ok(())
}

/// Tauri 命令：移除允许的进程
#[tauri::command]
fn remove_allowed_process(process_name: String) -> Result<(), String> {
    let state = PROXY_STATE.lock().map_err(|_| "无法锁定代理状态")?;
    state.process_filter.remove_process(&process_name);
    Ok(())
}

/// Tauri 命令：清空所有允许的进程
#[tauri::command]
fn clear_allowed_processes() -> Result<(), String> {
    let state = PROXY_STATE.lock().map_err(|_| "无法锁定代理状态")?;
    state.process_filter.clear_processes();
    Ok(())
}

/// Tauri 命令：启用/禁用进程过滤
#[tauri::command]
fn set_process_filter_enabled(enabled: bool) -> Result<(), String> {
    let state = PROXY_STATE.lock().map_err(|_| "无法锁定代理状态")?;
    state.process_filter.set_enabled(enabled);
    Ok(())
}

/// Tauri 命令：设置黑名单/白名单模式
#[tauri::command]
fn set_process_filter_blacklist_mode(blacklist: bool) -> Result<(), String> {
    let state = PROXY_STATE.lock().map_err(|_| "无法锁定代理状态")?;
    state.process_filter.set_blacklist_mode(blacklist);
    Ok(())
}

/// Tauri 命令：获取系统中所有正在运行的进程
#[tauri::command]
fn get_system_processes() -> Result<Vec<(u32, String)>, String> {
    Ok(get_running_processes())
}

/// Tauri 命令：获取系统中所有正在运行的进程（包含完整信息）
#[tauri::command]
fn get_system_processes_with_info() -> Result<Vec<ProcessInfo>, String> {
    Ok(get_running_processes_with_info())
}

/// Tauri 命令：提取应用程序图标
#[tauri::command]
fn get_app_icon(exe_path: String) -> Option<String> {
    app_icon::extract_app_icon(&exe_path)
}

/// Tauri 命令：启用透明代理
#[tauri::command]
fn enable_transparent_proxy(proxy_port: u16) -> Result<(), String> {
    let transparent_proxy = TransparentProxy::new(proxy_port);
    transparent_proxy.enable()
}

/// Tauri 命令：禁用透明代理
#[tauri::command]
fn disable_transparent_proxy(proxy_port: u16) -> Result<(), String> {
    let transparent_proxy = TransparentProxy::new(proxy_port);
    transparent_proxy.disable()
}

/// Tauri 命令：检查透明代理状态
#[tauri::command]
fn is_transparent_proxy_enabled(proxy_port: u16) -> bool {
    let transparent_proxy = TransparentProxy::new(proxy_port);
    transparent_proxy.is_enabled()
}

/// Tauri 命令：获取透明代理规则
#[tauri::command]
fn get_transparent_proxy_rules(proxy_port: u16) -> Option<String> {
    let transparent_proxy = TransparentProxy::new(proxy_port);
    transparent_proxy.get_rules()
}

fn main() {
    let app = Builder::default()
        .invoke_handler(generate_handler![
            set_system_proxy,
            restore_system_proxy,
            get_saved_proxy,
            get_current_proxy,
            start_proxy_server,
            stop_proxy_server,
            is_proxy_server_running,
            install_ca_certificate,
            uninstall_ca_certificate,
            is_certificate_installed,
            get_ca_cert_path,
            open_cert_folder,
            add_intercept_rule,
            remove_intercept_rule,
            get_intercept_rules,
            update_intercept_rule,
            clear_intercept_rules,
            set_process_filter,
            get_process_filter,
            add_allowed_process,
            remove_allowed_process,
            clear_allowed_processes,
            set_process_filter_enabled,
            set_process_filter_blacklist_mode,
            get_system_processes,
            get_system_processes_with_info,
            get_app_icon,
            enable_transparent_proxy,
            disable_transparent_proxy,
            is_transparent_proxy_enabled,
            get_transparent_proxy_rules,
        ])
        .setup(|app| {
            // 在应用启动时，启动一个后台线程来监听系统代理的变化
            start_proxy_change_listener(app.handle().clone());

            // Start log forwarding in a background thread
            let app_handle = app.handle().clone();
            std::thread::spawn(move || {
                let runtime = tokio::runtime::Runtime::new().unwrap();
                runtime.block_on(async {
                    loop {
                        tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;

                        let mut logs = Vec::new();
                        {
                            if let Ok(mut state) = PROXY_STATE.lock() {
                                if let Some(receiver) = &mut state.log_receiver {
                                    while let Ok(log) = receiver.try_recv() {
                                        logs.push(log);
                                    }
                                }
                            }
                        }

                        for log in logs {
                            let _ = app_handle.emit("proxy-log", log);
                        }
                    }
                });
            });

            Ok(())
        })
        .build(generate_context!())
        .expect("error while building tauri application");

    app.run(|_, event| {
        // 监听应用退出事件
        match event {
            RunEvent::Exit { .. } | RunEvent::ExitRequested { .. } => {
                // 在应用退出前，自动调用恢复代理的逻辑，确保不会污染用户的系统设置
                let _ = restore_system_proxy();

                // 停止代理服务器
                if let Ok(mut state) = PROXY_STATE.lock() {
                    // 发送停止信号
                    if let Some(shutdown_sender) = state.shutdown_sender.take() {
                        println!("应用退出：发送停止信号到代理服务器...");
                        let _ = shutdown_sender.send(());
                    }

                    // 中止任务（应用退出时不等待）
                    if let Some(handle) = state.handle.take() {
                        handle.abort();
                    }
                }
            }
            _ => {}
        }
    });
}

/// 向前端发送当前的代理配置事件。
///
/// 此函数会先获取当前代理状态，然后与上一次发送的状态进行比较。
/// 只有当状态发生变化时，才会真正发送 `PROXY_CHANGED_EVENT` 事件给前端。
fn emit_current_proxy_event(handle: &tauri::AppHandle) {
    match get_current_proxy() {
        Ok(proxy) => {
            // 去重逻辑：如果与上次发送的代理配置相同，则跳过
            let should_emit = {
                let mut last = LAST_EMITTED_PROXY.lock().unwrap();
                let is_different = last.as_ref() != Some(&proxy);
                if is_different {
                    *last = Some(proxy.clone());
                }
                is_different
            };

            if should_emit {
                eprintln!("emitting proxy change event: {:?}", proxy);
                match handle.emit(PROXY_CHANGED_EVENT, proxy) {
                    Ok(_) => eprintln!("proxy change event emitted successfully"),
                    Err(e) => eprintln!("failed to emit proxy change event: {e}"),
                }
            } else {
                eprintln!("skipping duplicate proxy event");
            }
        }
        Err(err) => {
            eprintln!("failed to get current proxy: {err}");
        }
    }
}

/// 启动一个后台线程来监听系统代理设置的变化（Windows 特定实现）。
///
/// Windows 上的代理设置存储在注册表中，此函数通过监听注册表键值的变化来实现。
#[cfg(target_os = "windows")]
fn start_proxy_change_listener(app_handle: tauri::AppHandle) {
    use std::thread;
    use windows::core::w;
    use windows::Win32::Foundation::ERROR_SUCCESS;
    use windows::Win32::System::Registry::{
        RegCloseKey, RegNotifyChangeKeyValue, RegOpenKeyExW, HKEY, HKEY_CURRENT_USER, KEY_NOTIFY,
        REG_NOTIFY_CHANGE_LAST_SET,
    };

    thread::spawn(move || unsafe {
        let mut key = HKEY::default();
        // 打开注册表项 HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings
        let status = RegOpenKeyExW(
            HKEY_CURRENT_USER,
            w!("SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Internet Settings"),
            Some(0),
            KEY_NOTIFY,
            &mut key,
        );

        if status != ERROR_SUCCESS {
            eprintln!("failed to open registry for proxy changes: {status:?}");
            return;
        }

        // 首次启动监听时，立即发送一次当前代理状态
        emit_current_proxy_event(&app_handle);

        // 无限循环，等待注册表变化通知
        loop {
            // 阻塞线程，直到指定的注册表键发生变化
            let wait_status = RegNotifyChangeKeyValue(
                key,
                false,
                REG_NOTIFY_CHANGE_LAST_SET,
                None,
                false,
            );

            if wait_status != ERROR_SUCCESS {
                eprintln!("proxy change notifications stopped: {wait_status:?}");
                break;
            }
            
            // 注册表发生变化后，向前端发送事件
            emit_current_proxy_event(&app_handle);
        }

        // 清理资源
        let _ = RegCloseKey(key);
    });
}

/// 启动一个后台线程来监听系统代理设置的变化（macOS 特定实现）。
///
/// macOS 使用 SystemConfiguration 框架来管理网络设置。此函数通过注册一个动态存储（Dynamic Store）
/// 回调来监听网络代理相关的配置变更。
#[cfg(target_os = "macos")]
fn start_proxy_change_listener(app_handle: tauri::AppHandle) {
    use core_foundation::{
        array::CFArray,
        runloop::{kCFRunLoopCommonModes, CFRunLoop},
        string::CFString,
    };
    use std::thread;
    use system_configuration::dynamic_store::{
        SCDynamicStoreBuilder, SCDynamicStoreCallBackContext,
    };

    thread::spawn(move || {
        let callback_context = SCDynamicStoreCallBackContext {
            callout: macos_proxy_callback,
            info: app_handle.clone(),
        };

        let store = SCDynamicStoreBuilder::new("sysproxy-tauri-proxy-listener")
            .callback_context(callback_context)
            .build();
        
        // 定义要监听的配置键模式
        let observed_keys = CFArray::<CFString>::from_CFTypes(&[]);
        let observed_patterns = CFArray::from_CFTypes(&[
            CFString::from("(State|Setup):/Network/Global/Proxies"),
            CFString::from("(State|Setup):/Network/Service/.*/Proxies"),
        ]);

        if !store.set_notification_keys(&observed_keys, &observed_patterns) {
            eprintln!("failed to register proxy change notifications on macOS");
            emit_current_proxy_event(&app_handle);
            return;
        }

        // 发送初始代理信息
        emit_current_proxy_event(&app_handle);
        
        // 将动态存储的通知源添加到当前线程的 RunLoop 中
        let run_loop_source = store.create_run_loop_source();
        let run_loop = CFRunLoop::get_current();
        unsafe {
            run_loop.add_source(&run_loop_source, kCFRunLoopCommonModes);
        }
        // 启动 RunLoop，开始监听事件
        CFRunLoop::run_current();
    });
}

/// macOS 代理变化时的回调函数。
#[cfg(target_os = "macos")]
fn macos_proxy_callback(
    _store: system_configuration::dynamic_store::SCDynamicStore,
    _changed: core_foundation::array::CFArray<core_foundation::string::CFString>,
    handle: &mut tauri::AppHandle,
) {
    emit_current_proxy_event(handle);
}

/// 启动一个后台线程来监听系统代理设置的变化（Linux 特定实现）。
///
/// 此实现假设用户使用基于 dconf/gsettings 的桌面环境（如 GNOME）。
/// 它通过 `notify` crate 监听 dconf 配置文件（`~/.config/dconf/user`）的变化。
/// **注意：** 此方法不适用于不使用 dconf 的桌面环境（如 KDE）。
#[cfg(target_os = "linux")]
fn start_proxy_change_listener(app_handle: tauri::AppHandle) {
    use notify::{Config, RecommendedWatcher, RecursiveMode, Watcher};
    use std::path::PathBuf;
    use std::thread;

    let config_file = match proxy_config_file_path() {
        Some(path) => path,
        None => {
            eprintln!("proxy watch path not found, cannot listen for changes");
            return;
        }
    };

    let watch_dir = config_file
        .parent()
        .map(PathBuf::from)
        .unwrap_or_else(|| config_file.clone());

    thread::spawn(move || {
        let callback_handle = app_handle.clone();
        let emit_handle = app_handle.clone();
        
        // 创建一个文件系统观察者
        let mut watcher = match RecommendedWatcher::new(
            move |res: Result<notify::Event, notify::Error>| match res {
                Ok(_) => {
                    // 文件发生变化时，发送代理变更事件
                    emit_current_proxy_event(&callback_handle);
                }
                Err(err) => {
                    eprintln!("proxy watcher error: {err}");
                }
            },
            Config::default(),
        ) {
            Ok(watcher) => watcher,
            Err(err) => {
                eprintln!("failed to create proxy watcher: {err}");
                return;
            }
        };

        if let Err(err) = watcher.watch(watch_dir.as_path(), RecursiveMode::NonRecursive) {
            eprintln!("failed to watch proxy directory: {err}");
            return;
        }
        
        // 首次启动时发送一次当前代理状态
        emit_current_proxy_event(&emit_handle);
        
        // 阻塞线程，使其保持活动状态以持续监听
        loop {
            thread::park();
        }
    });
}

/// 获取 Linux 上 dconf 配置文件的路径。
#[cfg(target_os = "linux")]
fn proxy_config_file_path() -> Option<std::path::PathBuf> {
    let home = std::env::var_os("HOME")?;
    Some(std::path::PathBuf::from(home).join(".config/dconf/user"))
}

/// 为其他不支持的平台提供一个空实现。
#[cfg(not(any(target_os = "windows", target_os = "macos", target_os = "linux")))]
fn start_proxy_change_listener(_app_handle: tauri::AppHandle) {
    // 当前平台不支持代理变化监听
}
