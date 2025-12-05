/// Socket 到进程映射模块
///
/// 根据客户端 socket 地址查找发起连接的进程名称

use std::net::SocketAddr;
use std::process::Command;

/// 从客户端 socket 地址获取进程名称 (macOS)
///
/// 使用 lsof 命令查找使用指定端口的进程
///
/// # 参数
/// - `client_addr`: 客户端的 socket 地址
///
/// # 返回
/// 进程名称（如果找到）
#[cfg(target_os = "macos")]
pub fn get_process_name_from_socket(client_addr: &SocketAddr) -> Option<String> {
    let client_port = client_addr.port();
    let client_ip = client_addr.ip().to_string();

    // 使用 lsof 查找所有 TCP 连接
    // 然后在结果中查找匹配的客户端地址
    let output = Command::new("lsof")
        .args(&[
            "-iTCP",
            "-sTCP:ESTABLISHED",
            "-n",
            "-P",
            "-F",
            "cn",  // 输出格式：c=命令名, n=网络地址
        ])
        .output()
        .ok()?;

    if !output.status.success() {
        return None;
    }

    let output_str = String::from_utf8_lossy(&output.stdout);

    // 解析 lsof 输出
    // 格式：
    // c<command>
    // n<network-address>
    let mut current_command = None;

    for line in output_str.lines() {
        if line.starts_with('c') {
            current_command = Some(line[1..].to_string());
        } else if line.starts_with('n') {
            // 检查是否匹配客户端地址
            let addr = &line[1..];
            // lsof 输出格式: 127.0.0.1:12345->127.0.0.1:8888
            // 我们需要找到 source port 匹配客户端端口的连接

            // 解析地址格式 local_ip:local_port->remote_ip:remote_port
            if let Some(arrow_pos) = addr.find("->") {
                let local_part = &addr[..arrow_pos];
                // 检查本地端口是否匹配客户端端口
                if local_part.ends_with(&format!(":{}", client_port)) &&
                   local_part.starts_with(&client_ip) {
                    return current_command;
                }
            }
        }
    }

    None
}

/// 从客户端 socket 地址获取进程名称 (Linux)
///
/// 使用 lsof 命令查找使用指定端口的进程
#[cfg(target_os = "linux")]
pub fn get_process_name_from_socket(client_addr: &SocketAddr) -> Option<String> {
    let client_port = client_addr.port();
    let client_ip = client_addr.ip().to_string();

    let output = Command::new("lsof")
        .args(&[
            "-iTCP",
            "-sTCP:ESTABLISHED",
            "-n",
            "-P",
            "-F",
            "cn",
        ])
        .output()
        .ok()?;

    if !output.status.success() {
        return None;
    }

    let output_str = String::from_utf8_lossy(&output.stdout);
    let mut current_command = None;

    for line in output_str.lines() {
        if line.starts_with('c') {
            current_command = Some(line[1..].to_string());
        } else if line.starts_with('n') {
            let addr = &line[1..];
            if let Some(arrow_pos) = addr.find("->") {
                let local_part = &addr[..arrow_pos];
                if local_part.ends_with(&format!(":{}", client_port)) &&
                   local_part.starts_with(&client_ip) {
                    return current_command;
                }
            }
        }
    }

    None
}

/// 从客户端 socket 地址获取进程名称 (Windows)
///
/// 使用 netstat 命令查找使用指定端口的进程
#[cfg(target_os = "windows")]
pub fn get_process_name_from_socket(client_addr: &SocketAddr) -> Option<String> {
    let port = client_addr.port();
    let client_ip = client_addr.ip().to_string();

    // 使用 netstat -ano 查找端口对应的 PID
    // 使用 chcp 65001 确保输出是 UTF-8 编码
    let output = Command::new("cmd")
        .args(&["/C", "chcp 65001 >nul && netstat -ano"])
        .output()
        .ok()?;

    if !output.status.success() {
        return None;
    }

    let output_str = String::from_utf8_lossy(&output.stdout);

    // 查找匹配的行
    // netstat 输出格式：
    // TCP    127.0.0.1:54321        127.0.0.1:8888         ESTABLISHED     12345
    // 我们需要匹配本地端口（source port）
    for line in output_str.lines() {
        // 只处理 TCP 连接
        if !line.trim().starts_with("TCP") {
            continue;
        }

        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() < 5 {
            continue;
        }

        // parts[1] 是本地地址 (127.0.0.1:54321)
        // parts[2] 是远程地址 (127.0.0.1:8888)
        // parts[3] 是状态 (ESTABLISHED)
        // parts[4] 是 PID
        let local_addr = parts[1];
        let state = parts[3];
        let pid_str = parts[4];

        // 检查是否是 ESTABLISHED 状态
        if state != "ESTABLISHED" {
            continue;
        }

        // 检查本地地址是否匹配客户端地址
        // 本地地址格式：127.0.0.1:54321 或 [::1]:54321
        if local_addr.ends_with(&format!(":{}", port)) {
            // 进一步检查 IP 是否匹配（如果不是 IPv6）
            if !client_ip.contains(':') && !local_addr.starts_with(&client_ip) {
                continue;
            }

            // 提取 PID
            if let Ok(pid) = pid_str.parse::<u32>() {
                // 使用 tasklist 获取进程名
                let task_output = Command::new("tasklist")
                    .args(&["/FI", &format!("PID eq {}", pid), "/FO", "CSV", "/NH"])
                    .output()
                    .ok()?;

                if task_output.status.success() {
                    let task_str = String::from_utf8_lossy(&task_output.stdout);
                    if let Some(first_line) = task_str.lines().next() {
                        // CSV 格式：\"name\",\"pid\",\"session\",\"memory\"
                        if let Some(name) = first_line.split(',').next() {
                            let name = name.trim_matches('"').trim();
                            if !name.is_empty() {
                                return Some(name.to_string());
                            }
                        }
                    }
                }
            }
        }
    }

    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::IpAddr;

    #[test]
    fn test_get_process_name() {
        let addr = SocketAddr::new(IpAddr::from([127, 0, 0, 1]), 12345);
        let result = get_process_name_from_socket(&addr);
        println!("Process name: {:?}", result);
    }
}
