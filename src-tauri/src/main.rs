#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use once_cell::sync::Lazy;
use serde::Serialize;
use std::sync::Mutex;
use sysproxy::{Autoproxy, Sysproxy};
use tauri::{generate_context, generate_handler, Builder, RunEvent};

#[derive(Clone)]
#[derive(Serialize)]
struct SavedProxy {
    sys_enable: bool,
    sys_host: String,
    sys_port: u16,
    sys_bypass: String,
    auto_enable: bool,
    auto_url: String,
}

static SAVED_PROXY: Lazy<Mutex<Option<SavedProxy>>> = Lazy::new(|| Mutex::new(None));

#[cfg(target_os = "windows")]
const DEFAULT_BYPASS: &str = "localhost;127.*;192.168.*;10.*;172.16.*;172.17.*;172.18.*;172.19.*;172.20.*;172.21.*;172.22.*;172.23.*;172.24.*;172.25.*;172.26.*;172.27.*;172.28.*;172.29.*;172.30.*;172.31.*;<local>";
#[cfg(target_os = "linux")]
const DEFAULT_BYPASS: &str =
    "localhost,127.0.0.1,192.168.0.0/16,10.0.0.0/8,172.16.0.0/12,172.29.0.0/16,::1";
#[cfg(target_os = "macos")]
const DEFAULT_BYPASS: &str = "127.0.0.1,192.168.0.0/16,10.0.0.0/8,172.16.0.0/12,172.29.0.0/16,localhost,*.local,*.crashlytics.com,<local>";

#[tauri::command]
fn set_system_proxy(host: String, port: u16) -> Result<(), String> {
    let host = host.trim();
    if host.is_empty() {
        return Err("代理地址不能为空".into());
    }

    // 仅首次保存当前系统代理配置，供后续还原
    {
        let mut saved = SAVED_PROXY
            .lock()
            .map_err(|_| "无法锁定保存的代理配置".to_string())?;
        if saved.is_none() {
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

    // 关闭 PAC，改用直接系统代理
    if let Ok(mut auto) = Autoproxy::get_auto_proxy() {
        auto.enable = false;
        let _ = auto.set_auto_proxy();
    }

    let proxy = Sysproxy {
        enable: true,
        host: host.into(),
        port,
        bypass: DEFAULT_BYPASS.into(),
    };

    proxy
        .set_system_proxy()
        .map_err(|e| format!("设置系统代理失败: {e}"))
}

#[tauri::command]
fn reset_system_proxy() -> Result<(), String> {
    let mut sysproxy = Sysproxy::get_system_proxy().unwrap_or_default();
    let mut autoproxy = Autoproxy::get_auto_proxy().unwrap_or_default();

    sysproxy.enable = false;
    autoproxy.enable = false;

    autoproxy
        .set_auto_proxy()
        .map_err(|e| format!("关闭自动代理失败: {e}"))?;
    sysproxy
        .set_system_proxy()
        .map_err(|e| format!("关闭系统代理失败: {e}"))
}

#[tauri::command]
fn restore_system_proxy() -> Result<(), String> {
    let saved = {
        let saved = SAVED_PROXY
            .lock()
            .map_err(|_| "无法锁定保存的代理配置".to_string())?;
        saved.clone()
    };

    if let Some(saved) = saved {
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
        Ok(())
    } else {
        // 没有记录则说明未改动系统代理，直接跳过
        Ok(())
    }
}

#[tauri::command]
fn get_saved_proxy() -> Option<SavedProxy> {
    SAVED_PROXY.lock().ok().and_then(|s| s.clone())
}

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

fn main() {
    let app = Builder::default()
        .invoke_handler(generate_handler![
            set_system_proxy,
            reset_system_proxy,
            restore_system_proxy,
            get_saved_proxy,
            get_current_proxy
        ])
        .build(generate_context!())
        .expect("error while building tauri application");

    app.run(|_, event| {
        match event {
            RunEvent::Exit { .. } | RunEvent::ExitRequested { .. } => {
                let _ = restore_system_proxy();
            }
            _ => {}
        }
    });
}
