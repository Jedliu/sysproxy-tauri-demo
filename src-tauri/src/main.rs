#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use once_cell::sync::Lazy;
use serde::Serialize;
use std::sync::Mutex;
use sysproxy::{Autoproxy, Sysproxy};
use tauri::{generate_context, generate_handler, Builder, Emitter, RunEvent};

#[derive(Clone, Serialize, Debug, PartialEq)]
struct SavedProxy {
    sys_enable: bool,
    sys_host: String,
    sys_port: u16,
    sys_bypass: String,
    auto_enable: bool,
    auto_url: String,
}

static SAVED_PROXY: Lazy<Mutex<Option<SavedProxy>>> = Lazy::new(|| Mutex::new(None));
static LAST_EMITTED_PROXY: Lazy<Mutex<Option<SavedProxy>>> = Lazy::new(|| Mutex::new(None));
const PROXY_CHANGED_EVENT: &str = "proxy-changed";

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
        .setup(|app| {
            start_proxy_change_listener(app.handle().clone());
            Ok(())
        })
        .build(generate_context!())
        .expect("error while building tauri application");

    app.run(|_, event| match event {
        RunEvent::Exit { .. } | RunEvent::ExitRequested { .. } => {
            let _ = restore_system_proxy();
        }
        _ => {}
    });
}

fn emit_current_proxy_event(handle: &tauri::AppHandle) {
    match get_current_proxy() {
        Ok(proxy) => {
            // 去重：如果与上次发送的代理配置相同，则跳过
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

#[cfg(target_os = "windows")]
fn start_proxy_change_listener(app_handle: tauri::AppHandle) {
    use std::thread;
    use windows::core::w;
    use windows::Win32::Foundation::{ERROR_SUCCESS, HANDLE};
    use windows::Win32::System::Registry::{
        RegCloseKey, RegNotifyChangeKeyValue, RegOpenKeyExW, HKEY, HKEY_CURRENT_USER, KEY_NOTIFY,
        REG_NOTIFY_CHANGE_LAST_SET,
    };

    thread::spawn(move || unsafe {
        let mut key = HKEY::default();
        let status = RegOpenKeyExW(
            HKEY_CURRENT_USER,
            w!("SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Internet Settings"),
            0,
            KEY_NOTIFY,
            &mut key,
        );

        if status != ERROR_SUCCESS {
            eprintln!("failed to open registry for proxy changes: {status:?}");
            return;
        }

        emit_current_proxy_event(&app_handle);

        loop {
            let wait_status = RegNotifyChangeKeyValue(
                key,
                false,
                REG_NOTIFY_CHANGE_LAST_SET,
                HANDLE::default(),
                false,
            );

            if wait_status != ERROR_SUCCESS {
                eprintln!("proxy change notifications stopped: {wait_status:?}");
                break;
            }

            emit_current_proxy_event(&app_handle);
        }

        let _ = RegCloseKey(key);
    });
}

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

        // 发送初始代理信息（去重逻辑会避免重复发送）
        emit_current_proxy_event(&app_handle);

        let run_loop_source = store.create_run_loop_source();
        let run_loop = CFRunLoop::get_current();
        unsafe {
            run_loop.add_source(&run_loop_source, kCFRunLoopCommonModes);
        }
        CFRunLoop::run_current();
    });
}

#[cfg(target_os = "macos")]
fn macos_proxy_callback(
    _store: system_configuration::dynamic_store::SCDynamicStore,
    _changed: core_foundation::array::CFArray<core_foundation::string::CFString>,
    handle: &mut tauri::AppHandle,
) {
    emit_current_proxy_event(handle);
}

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

        let mut watcher = match RecommendedWatcher::new(
            move |res: Result<notify::Event, notify::Error>| match res {
                Ok(_) => {
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

        emit_current_proxy_event(&emit_handle);

        loop {
            thread::park();
        }
    });
}

#[cfg(target_os = "linux")]
fn proxy_config_file_path() -> Option<std::path::PathBuf> {
    let home = std::env::var_os("HOME")?;
    Some(std::path::PathBuf::from(home).join(".config/dconf/user"))
}

#[cfg(not(any(target_os = "windows", target_os = "macos", target_os = "linux")))]
fn start_proxy_change_listener(_app_handle: tauri::AppHandle) {}
