/// 权限管理模块
///
/// 提供跨平台的权限检查和提权功能

use std::io;

/// 检查当前进程是否有管理员权限
///
/// # 平台差异
/// - Windows: 检查是否有 elevated token
/// - macOS/Linux: 检查 effective user ID 是否为 0 (root)
pub fn has_admin_privileges() -> bool {
    #[cfg(target_os = "windows")]
    {
        has_admin_privileges_windows()
    }

    #[cfg(unix)]
    {
        has_admin_privileges_unix()
    }
}

/// Windows 平台权限检查
#[cfg(target_os = "windows")]
fn has_admin_privileges_windows() -> bool {
    use windows::Win32::Foundation::{CloseHandle, HANDLE};
    use windows::Win32::Security::{
        GetTokenInformation, OpenProcessToken, TokenElevation, TOKEN_ELEVATION, TOKEN_QUERY,
    };
    use windows::Win32::System::Threading::GetCurrentProcess;

    unsafe {
        let mut token_handle: HANDLE = HANDLE::default();

        // 打开当前进程的 token
        if OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token_handle).is_err() {
            return false;
        }

        // 查询 token 的 elevation 状态
        let mut elevation = TOKEN_ELEVATION::default();
        let mut return_length = 0u32;

        let result = GetTokenInformation(
            token_handle,
            TokenElevation,
            Some(&mut elevation as *mut _ as *mut _),
            std::mem::size_of::<TOKEN_ELEVATION>() as u32,
            &mut return_length,
        );

        CloseHandle(token_handle).ok();

        if result.is_ok() {
            elevation.TokenIsElevated != 0
        } else {
            false
        }
    }
}

/// Unix 平台权限检查 (macOS, Linux)
#[cfg(unix)]
fn has_admin_privileges_unix() -> bool {
    // 检查 effective user ID 是否为 0 (root)
    unsafe { libc::geteuid() == 0 }
}

/// 以管理员权限重启当前应用程序
///
/// # 平台差异
/// - Windows: 使用 ShellExecuteW 的 "runas" 动作触发 UAC
/// - macOS/Linux: 返回错误，提示用户使用 sudo 手动重启
///
/// # 返回
/// - Ok(()): Windows 上成功启动管理员进程（当前进程应退出）
/// - Err: 启动失败或不支持的平台
pub fn request_admin_restart() -> Result<(), Box<dyn std::error::Error>> {
    #[cfg(target_os = "windows")]
    {
        request_admin_restart_windows()
    }

    #[cfg(unix)]
    {
        Err("请使用 sudo 运行此应用程序以获得管理员权限".into())
    }
}

/// Windows 平台自动提权重启
#[cfg(target_os = "windows")]
fn request_admin_restart_windows() -> Result<(), Box<dyn std::error::Error>> {
    use std::os::windows::ffi::OsStrExt;
    use std::ffi::OsStr;
    use windows::core::PCWSTR;
    use windows::Win32::UI::Shell::{ShellExecuteW, SW_SHOWNORMAL};
    use windows::Win32::UI::WindowsAndMessaging::HWND;

    // 获取当前可执行文件路径
    let exe_path = std::env::current_exe()?;
    let exe_path_str = exe_path.to_str().ok_or("无效的可执行文件路径")?;

    // 转换为 Windows wide string
    let operation: Vec<u16> = OsStr::new("runas")
        .encode_wide()
        .chain(Some(0))
        .collect();
    let file: Vec<u16> = OsStr::new(exe_path_str)
        .encode_wide()
        .chain(Some(0))
        .collect();

    unsafe {
        let result = ShellExecuteW(
            HWND::default(),
            PCWSTR(operation.as_ptr()),
            PCWSTR(file.as_ptr()),
            PCWSTR::null(),
            PCWSTR::null(),
            SW_SHOWNORMAL,
        );

        // ShellExecuteW 返回值 > 32 表示成功
        if result.0 as i32 > 32 {
            // 成功启动管理员进程，应该退出当前进程
            std::process::exit(0);
        } else {
            Err(io::Error::last_os_error().into())
        }
    }
}

/// 获取权限提示消息
///
/// 返回适合当前平台的权限提示文本
pub fn get_privilege_prompt() -> String {
    if has_admin_privileges() {
        "已拥有管理员权限".to_string()
    } else {
        #[cfg(target_os = "windows")]
        {
            "TUN 模式需要管理员权限\n\n应用程序将以管理员身份重启。".to_string()
        }

        #[cfg(target_os = "macos")]
        {
            "TUN 模式需要管理员权限\n\n请使用以下命令重启应用：\nsudo ./sysproxy-tauri-demo".to_string()
        }

        #[cfg(target_os = "linux")]
        {
            "TUN 模式需要管理员权限\n\n请使用以下命令重启应用：\nsudo ./sysproxy-tauri-demo".to_string()
        }
    }
}

/// macOS: 使用 osascript 弹出权限对话框并执行命令
///
/// 这个方法不需要重启整个应用，只需要用户输入管理员密码
#[cfg(target_os = "macos")]
pub fn execute_with_admin_prompt(command: &str, prompt: &str) -> Result<(), Box<dyn std::error::Error>> {
    let osascript_command = format!(
        r#"do shell script "{}" with administrator privileges with prompt "{}""#,
        command.replace("\"", "\\\""),  // 转义内部的引号
        prompt
    );

    let output = std::process::Command::new("osascript")
        .args(&["-e", &osascript_command])
        .output()?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(format!("执行失败: {}", stderr).into());
    }

    Ok(())
}

/// 非 macOS 平台的占位实现
#[cfg(not(target_os = "macos"))]
pub fn execute_with_admin_prompt(_command: &str, _prompt: &str) -> Result<(), Box<dyn std::error::Error>> {
    Err("此功能仅支持 macOS".into())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_has_admin_privileges() {
        // 这个测试只是验证函数能够调用，不验证返回值
        // 因为返回值取决于运行环境
        let has_admin = has_admin_privileges();
        println!("当前进程是否有管理员权限: {}", has_admin);
    }

    #[test]
    fn test_get_privilege_prompt() {
        let prompt = get_privilege_prompt();
        println!("权限提示消息:\n{}", prompt);
        assert!(!prompt.is_empty());
    }

    #[test]
    #[cfg(unix)]
    fn test_request_admin_restart_unix_returns_error() {
        // Unix 平台应该返回错误
        let result = request_admin_restart();
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("sudo"));
    }
}
