/// 进程过滤模块
///
/// 提供根据进程名称或PID过滤网络流量的功能

use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::sync::Arc;

/// 进程过滤器配置
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProcessFilter {
    /// 是否启用进程过滤
    pub enabled: bool,
    /// 允许的进程名称列表（例如：["chrome", "firefox"]）
    pub allowed_processes: HashSet<String>,
    /// 是否为黑名单模式（true=黑名单，false=白名单）
    pub blacklist_mode: bool,
}

impl Default for ProcessFilter {
    fn default() -> Self {
        Self {
            enabled: false,
            allowed_processes: HashSet::new(),
            blacklist_mode: false,
        }
    }
}

/// 进程过滤管理器
pub struct ProcessFilterManager {
    filter: Arc<RwLock<ProcessFilter>>,
}

impl ProcessFilterManager {
    pub fn new() -> Self {
        Self {
            filter: Arc::new(RwLock::new(ProcessFilter::default())),
        }
    }

    /// 设置过滤器配置
    pub fn set_filter(&self, filter: ProcessFilter) {
        *self.filter.write() = filter;
    }

    /// 获取当前过滤器配置
    pub fn get_filter(&self) -> ProcessFilter {
        self.filter.read().clone()
    }

    /// 添加允许的进程
    pub fn add_process(&self, process_name: String) {
        self.filter.write().allowed_processes.insert(process_name);
    }

    /// 移除允许的进程
    pub fn remove_process(&self, process_name: &str) {
        self.filter.write().allowed_processes.remove(process_name);
    }

    /// 清空所有允许的进程
    pub fn clear_processes(&self) {
        self.filter.write().allowed_processes.clear();
    }

    /// 启用/禁用过滤
    pub fn set_enabled(&self, enabled: bool) {
        self.filter.write().enabled = enabled;
    }

    /// 设置黑名单/白名单模式
    pub fn set_blacklist_mode(&self, blacklist: bool) {
        self.filter.write().blacklist_mode = blacklist;
    }

    /// 检查指定进程名是否应该被允许
    #[allow(dead_code)]
    pub fn should_allow(&self, process_name: &str) -> bool {
        let filter = self.filter.read();

        // 如果过滤器未启用，允许所有流量
        if !filter.enabled {
            return true;
        }

        // 检查进程名是否在列表中（支持部分匹配）
        let in_list = filter.allowed_processes.iter().any(|allowed| {
            let process_lower = process_name.to_lowercase();
            let allowed_lower = allowed.to_lowercase();
            process_lower.contains(&allowed_lower) || allowed_lower.contains(&process_lower)
        });

        // 黑名单模式：列表中的拒绝
        // 白名单模式：只允许列表中的
        if filter.blacklist_mode {
            !in_list
        } else {
            in_list
        }
    }
}

impl Default for ProcessFilterManager {
    fn default() -> Self {
        Self::new()
    }
}

/// 从 PID 获取进程名称 (macOS/Linux)
#[cfg(any(target_os = "macos", target_os = "linux"))]
#[allow(dead_code)]
pub fn get_process_name_by_pid(pid: u32) -> Option<String> {
    use sysinfo::{ProcessesToUpdate, System};

    let mut sys = System::new();
    let pid_obj = sysinfo::Pid::from_u32(pid);
    sys.refresh_processes(ProcessesToUpdate::Some(&[pid_obj]));

    sys.process(pid_obj)
        .and_then(|process| {
            process.exe()
                .and_then(|path| path.file_name())
                .and_then(|name| name.to_str())
                .map(|s| s.to_string())
        })
}

/// 从 PID 获取进程名称 (Windows)
#[cfg(target_os = "windows")]
#[allow(dead_code)]
pub fn get_process_name_by_pid(pid: u32) -> Option<String> {
    use sysinfo::{ProcessesToUpdate, System};

    let mut sys = System::new();
    let pid_obj = sysinfo::Pid::from_u32(pid);
    sys.refresh_processes(ProcessesToUpdate::Some(&[pid_obj]));

    sys.process(pid_obj)
        .and_then(|process| {
            process.exe()
                .and_then(|path| path.file_name())
                .and_then(|name| name.to_str())
                .map(|s| s.to_string())
        })
}

/// 进程信息结构（包含图标路径）
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProcessInfo {
    pub pid: u32,
    pub name: String,
    pub exe_path: String,
}

/// 获取系统中所有正在运行的进程列表（包含完整路径）
pub fn get_running_processes_with_info() -> Vec<ProcessInfo> {
    use sysinfo::{ProcessesToUpdate, System};

    let mut sys = System::new();
    sys.refresh_processes(ProcessesToUpdate::All);

    sys.processes()
        .iter()
        .filter_map(|(pid, process)| {
            let pid_u32 = pid.as_u32();
            process.exe().and_then(|path| {
                let name = path
                    .file_name()
                    .and_then(|n| n.to_str())
                    .map(|s| s.to_string())?;
                let exe_path = path.to_str().map(|s| s.to_string())?;

                Some(ProcessInfo {
                    pid: pid_u32,
                    name,
                    exe_path,
                })
            })
        })
        .collect()
}

/// 获取系统中所有正在运行的进程列表（仅名称，保持向后兼容）
pub fn get_running_processes() -> Vec<(u32, String)> {
    use sysinfo::{ProcessesToUpdate, System};

    let mut sys = System::new();
    sys.refresh_processes(ProcessesToUpdate::All);

    sys.processes()
        .iter()
        .filter_map(|(pid, process)| {
            let pid_u32 = pid.as_u32();
            process.exe()
                .and_then(|path| path.file_name())
                .and_then(|name| name.to_str())
                .map(|name| (pid_u32, name.to_string()))
        })
        .collect()
}
