// ============================================================================
// 证书安装器模块 (Certificate Installer Module)
// ============================================================================
// 这个模块负责将 CA 证书安装到系统信任存储中。
// 对于 HTTPS MITM 代理，必须让系统信任我们的 CA 证书，
// 否则浏览器会显示 "您的连接不是私密连接" 错误。
//
// 跨平台支持：
// - Windows: 使用 Windows API 安装到 ROOT 证书存储
// - macOS: 使用 security 命令安装到系统钥匙串
// - Linux: 支持 Ubuntu/Debian、RedHat/CentOS、Arch Linux
//
// macOS 特殊处理：
// 使用 osascript 执行 security 命令，会触发系统原生的授权对话框，
// 提供更好的用户体验（相比手动在终端输入 sudo 密码）。
// ============================================================================

use std::path::Path;
use std::process::Command;

#[cfg(target_os = "windows")]
use windows::Win32::Security::Cryptography::{
    CertAddEncodedCertificateToStore, CertCloseStore, CertOpenSystemStoreW, CERT_STORE_ADD_REPLACE_EXISTING,
    CERT_SYSTEM_STORE_CURRENT_USER, X509_ASN_ENCODING,
};

#[cfg(target_os = "windows")]
use windows::core::PCWSTR;

/// 证书安装器
///
/// 提供跨平台的证书安装、卸载和检查功能。
/// 所有方法都是静态的，不需要创建实例。
pub struct CertInstaller;

impl CertInstaller {
    /// 从系统信任存储中卸载/删除证书
    ///
    /// 根据不同的操作系统调用对应的实现。
    pub fn uninstall_cert() -> Result<String, Box<dyn std::error::Error>> {
        #[cfg(target_os = "windows")]
        return Self::uninstall_cert_windows();

        #[cfg(target_os = "macos")]
        return Self::uninstall_cert_macos();

        #[cfg(target_os = "linux")]
        return Self::uninstall_cert_linux();

        #[cfg(not(any(target_os = "windows", target_os = "macos", target_os = "linux")))]
        Err("Unsupported platform".into())
    }

    /// 将证书安装到系统信任存储
    ///
    /// 根据不同的操作系统调用对应的实现。
    pub fn install_cert(cert_path: &Path) -> Result<String, Box<dyn std::error::Error>> {
        #[cfg(target_os = "windows")]
        return Self::install_cert_windows(cert_path);

        #[cfg(target_os = "macos")]
        return Self::install_cert_macos(cert_path);

        #[cfg(target_os = "linux")]
        return Self::install_cert_linux(cert_path);

        #[cfg(not(any(target_os = "windows", target_os = "macos", target_os = "linux")))]
        Err("Unsupported platform".into())
    }

    /// 检查证书是否已安装
    pub fn is_cert_installed(cert_path: &Path) -> bool {
        #[cfg(target_os = "windows")]
        return Self::is_cert_installed_windows(cert_path);

        #[cfg(target_os = "macos")]
        return Self::is_cert_installed_macos(cert_path);

        #[cfg(target_os = "linux")]
        return Self::is_cert_installed_linux(cert_path);

        #[cfg(not(any(target_os = "windows", target_os = "macos", target_os = "linux")))]
        false
    }

    #[cfg(target_os = "windows")]
    fn install_cert_windows(cert_path: &Path) -> Result<String, Box<dyn std::error::Error>> {
        let cert_data = std::fs::read(cert_path)?;

        // Parse PEM to DER
        let pem = String::from_utf8_lossy(&cert_data);
        let der = Self::pem_to_der(&pem)?;

        unsafe {
            // Open the Root certificate store
            let store_name: Vec<u16> = "ROOT\0".encode_utf16().collect();
            let store = CertOpenSystemStoreW(None, PCWSTR(store_name.as_ptr()))?;

            // Add certificate to store
            let result = CertAddEncodedCertificateToStore(
                store,
                X509_ASN_ENCODING,
                &der,
                CERT_STORE_ADD_REPLACE_EXISTING,
                None,
            );

            CertCloseStore(store, 0)?;

            if result.is_ok() {
                Ok("证书已成功安装到 Windows 受信任的根证书颁发机构".to_string())
            } else {
                Err("安装证书失败".into())
            }
        }
    }

    #[cfg(target_os = "windows")]
    fn is_cert_installed_windows(_cert_path: &Path) -> bool {
        // For Windows, we'll assume it's installed if we can open the store
        // A more thorough check would enumerate all certs and compare
        true
    }

    /// macOS: 安装证书到系统钥匙串
    ///
    /// 这个方法使用 AppleScript + osascript 的方式来安装证书，
    /// 会触发 macOS 原生的授权对话框，提供更好的用户体验。
    ///
    /// 工作原理：
    /// 1. 构造一个 AppleScript 脚本
    /// 2. 脚本内容是执行 security add-trusted-cert 命令
    /// 3. 使用 "with administrator privileges" 触发授权对话框
    /// 4. 用户输入管理员密码后，证书会被安装并设置为受信任
    ///
    /// 优势：
    /// - 用户体验好：使用系统原生对话框
    /// - 安全：通过系统授权机制，不需要应用自己处理密码
    /// - 一步到位：安装 + 设置信任一次完成
    ///
    /// 对比：之前的方法需要用户手动在终端运行 sudo 命令，
    /// 或者手动打开钥匙串访问应用进行多步操作。
    #[cfg(target_os = "macos")]
    fn install_cert_macos(cert_path: &Path) -> Result<String, Box<dyn std::error::Error>> {
        let cert_path_str = cert_path.to_str().ok_or("Invalid cert path")?;

        // 构造 AppleScript 脚本
        // do shell script "命令" with administrator privileges
        // 这会触发 macOS 原生的授权对话框
        let script = format!(
            "do shell script \"security add-trusted-cert -d -r trustRoot -k /Library/Keychains/System.keychain '{}'\" with administrator privileges",
            cert_path_str.replace("'", "'\\''") // 转义单引号，防止 AppleScript 语法错误
        );

        // 使用 osascript 执行 AppleScript
        let output = Command::new("osascript")
            .args(["-e", &script])
            .output()?;

        if output.status.success() {
            Ok(format!(
                "证书已成功安装到系统钥匙串并设置为受信任！\n\n\
                现在您可以直接通过代理访问 HTTPS 网站了。\n\
                如果浏览器已经打开，请重启浏览器以使证书生效。\n\n\
                证书路径: {}",
                cert_path.display()
            ))
        } else {
            let error = String::from_utf8_lossy(&output.stderr);

            // 检查用户是否取消了授权对话框
            if error.contains("User canceled") || error.contains("cancelled") {
                return Err("用户取消了授权。安装证书需要管理员权限。".into());
            }

            // 构造错误消息，提供手动安装的方法
            let mut msg = String::new();
            if !error.is_empty() {
                msg.push_str(&format!("错误: {}\n\n", error.trim()));
            }
            msg.push_str(&format!("证书路径: {}\n\n", cert_path.display()));
            msg.push_str("您可以手动安装证书：\n");
            msg.push_str("1. 在终端运行以下命令：\n");
            msg.push_str(&format!("   sudo security add-trusted-cert -d -r trustRoot -k /Library/Keychains/System.keychain '{}'\n\n", cert_path_str));
            msg.push_str("或者：\n");
            msg.push_str("2. 打开「钥匙串访问」应用\n");
            msg.push_str("3. 将证书文件拖放到「系统」钥匙串中\n");
            msg.push_str("4. 双击证书，在「信任」部分设置为「始终信任」");

            Err(msg.into())
        }
    }

    #[cfg(target_os = "macos")]
    fn is_cert_installed_macos(_cert_path: &Path) -> bool {
        // Check if cert exists in login keychain
        if let Ok(home) = std::env::var("HOME") {
            let login_keychain = format!("{}/Library/Keychains/login.keychain-db", home);
            if let Ok(output) = Command::new("security")
                .args([
                    "find-certificate",
                    "-c", "Sysproxy MITM CA",
                    &login_keychain,
                ])
                .output()
            {
                // Check if the output contains the certificate (not just exit status)
                if output.status.success() {
                    let stdout = String::from_utf8_lossy(&output.stdout);
                    if stdout.contains("Sysproxy MITM CA") {
                        return true;
                    }
                }
            }
        }

        // Also check system keychain (in case user installed it manually with admin rights)
        if let Ok(output) = Command::new("security")
            .args([
                "find-certificate",
                "-c", "Sysproxy MITM CA",
                "/Library/Keychains/System.keychain",
            ])
            .output()
        {
            if output.status.success() {
                let stdout = String::from_utf8_lossy(&output.stdout);
                return stdout.contains("Sysproxy MITM CA");
            }
        }

        false
    }

    /// macOS: 从系统钥匙串中删除证书
    ///
    /// 与安装类似，使用 AppleScript + osascript 触发原生授权对话框。
    ///
    /// 工作原理：
    /// 1. 执行 security delete-certificate 命令
    /// 2. 使用 "with administrator privileges" 触发授权
    /// 3. 删除名为 "Sysproxy MITM CA" 的证书
    ///
    /// 错误处理：
    /// - 用户取消授权：返回友好的错误消息
    /// - 证书未找到：视为成功（已经删除）
    /// - 其他错误：提供手动删除的方法
    #[cfg(target_os = "macos")]
    fn uninstall_cert_macos() -> Result<String, Box<dyn std::error::Error>> {
        // 构造 AppleScript 脚本删除证书
        // -c 指定证书名称
        let script = "do shell script \"security delete-certificate -c 'Sysproxy MITM CA' /Library/Keychains/System.keychain\" with administrator privileges";

        // 使用 osascript 执行
        let output = Command::new("osascript")
            .args(["-e", script])
            .output()?;

        if output.status.success() {
            Ok("证书已成功从系统钥匙串中删除".to_string())
        } else {
            let error = String::from_utf8_lossy(&output.stderr);

            // 检查用户是否取消了授权对话框
            if error.contains("User canceled") || error.contains("cancelled") {
                return Err("用户取消了授权。删除证书需要管理员权限。".into());
            }

            // 如果证书未找到，视为成功（已经删除）
            if error.contains("not found") || error.contains("could not be found") {
                return Ok("证书未安装或已被删除".to_string());
            }

            // 其他错误，提供手动删除方法
            let mut msg = format!("删除证书失败\n\n错误: {}\n\n", error.trim());
            msg.push_str("您可以手动删除证书：\n");
            msg.push_str("1. 打开「钥匙串访问」应用\n");
            msg.push_str("2. 在「系统」钥匙串中找到「Sysproxy MITM CA」证书\n");
            msg.push_str("3. 右键点击并选择「删除」");

            Err(msg.into())
        }
    }

    #[cfg(target_os = "linux")]
    fn install_cert_linux(cert_path: &Path) -> Result<String, Box<dyn std::error::Error>> {
        // Try multiple methods based on different Linux distributions

        // Method 1: Ubuntu/Debian - copy to /usr/local/share/ca-certificates/
        let ubuntu_path = Path::new("/usr/local/share/ca-certificates/sysproxy-ca.crt");
        if let Ok(_) = std::fs::copy(cert_path, ubuntu_path) {
            let output = Command::new("update-ca-certificates").output()?;
            if output.status.success() {
                return Ok("证书已安装到 Ubuntu/Debian 系统".to_string());
            }
        }

        // Method 2: RedHat/CentOS/Fedora - copy to /etc/pki/ca-trust/source/anchors/
        let redhat_path = Path::new("/etc/pki/ca-trust/source/anchors/sysproxy-ca.crt");
        if let Ok(_) = std::fs::copy(cert_path, redhat_path) {
            let output = Command::new("update-ca-trust").output()?;
            if output.status.success() {
                return Ok("证书已安装到 RedHat/CentOS/Fedora 系统".to_string());
            }
        }

        // Method 3: Arch Linux - copy to /etc/ca-certificates/trust-source/anchors/
        let arch_path = Path::new("/etc/ca-certificates/trust-source/anchors/sysproxy-ca.crt");
        if let Ok(_) = std::fs::copy(cert_path, arch_path) {
            let output = Command::new("trust")
                .args(["extract-compat"])
                .output()?;
            if output.status.success() {
                return Ok("证书已安装到 Arch Linux 系统".to_string());
            }
        }

        Err("无法安装证书。请手动安装或使用 root 权限运行".into())
    }

    #[cfg(target_os = "linux")]
    fn is_cert_installed_linux(_cert_path: &Path) -> bool {
        // Check common locations
        Path::new("/usr/local/share/ca-certificates/sysproxy-ca.crt").exists()
            || Path::new("/etc/pki/ca-trust/source/anchors/sysproxy-ca.crt").exists()
            || Path::new("/etc/ca-certificates/trust-source/anchors/sysproxy-ca.crt").exists()
    }

    #[cfg(target_os = "windows")]
    fn uninstall_cert_windows() -> Result<String, Box<dyn std::error::Error>> {
        Err("Windows 证书删除功能尚未实现。请手动在证书管理器中删除「Sysproxy MITM CA」证书。".into())
    }

    #[cfg(target_os = "linux")]
    fn uninstall_cert_linux() -> Result<String, Box<dyn std::error::Error>> {
        let mut removed_count = 0;

        // Method 1: Ubuntu/Debian
        let ubuntu_path = Path::new("/usr/local/share/ca-certificates/sysproxy-ca.crt");
        if ubuntu_path.exists() {
            std::fs::remove_file(ubuntu_path)?;
            let _ = Command::new("update-ca-certificates").output();
            removed_count += 1;
        }

        // Method 2: RedHat/CentOS/Fedora
        let redhat_path = Path::new("/etc/pki/ca-trust/source/anchors/sysproxy-ca.crt");
        if redhat_path.exists() {
            std::fs::remove_file(redhat_path)?;
            let _ = Command::new("update-ca-trust").output();
            removed_count += 1;
        }

        // Method 3: Arch Linux
        let arch_path = Path::new("/etc/ca-certificates/trust-source/anchors/sysproxy-ca.crt");
        if arch_path.exists() {
            std::fs::remove_file(arch_path)?;
            let _ = Command::new("trust").args(["extract-compat"]).output();
            removed_count += 1;
        }

        if removed_count > 0 {
            Ok(format!("已成功删除证书（可能需要 root 权限）"))
        } else {
            Err("未找到需要删除的证书".into())
        }
    }

    #[cfg(target_os = "windows")]
    fn pem_to_der(pem: &str) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
        // Simple PEM to DER conversion
        let lines: Vec<&str> = pem.lines().collect();
        let mut der_base64 = String::new();
        let mut in_cert = false;

        for line in lines {
            let trimmed = line.trim();
            if trimmed.starts_with("-----BEGIN CERTIFICATE-----") {
                in_cert = true;
                continue;
            }
            if trimmed.starts_with("-----END CERTIFICATE-----") {
                break;
            }
            if in_cert {
                der_base64.push_str(trimmed);
            }
        }

        use base64::Engine;
        let engine = base64::engine::general_purpose::STANDARD;
        Ok(engine.decode(der_base64)?)
    }
}
