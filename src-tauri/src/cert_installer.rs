use std::path::Path;
use std::process::Command;

#[cfg(target_os = "windows")]
use windows::Win32::Security::Cryptography::{
    CertAddEncodedCertificateToStore, CertCloseStore, CertOpenSystemStoreW, CERT_STORE_ADD_REPLACE_EXISTING,
    CERT_SYSTEM_STORE_CURRENT_USER, X509_ASN_ENCODING,
};

#[cfg(target_os = "windows")]
use windows::core::PCWSTR;

pub struct CertInstaller;

impl CertInstaller {
    /// Uninstall/remove a certificate from the system trust store
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

    /// Install a certificate to the system trust store
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

    /// Check if a certificate is installed
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

    #[cfg(target_os = "macos")]
    fn install_cert_macos(cert_path: &Path) -> Result<String, Box<dyn std::error::Error>> {
        // First try installing to the user's login keychain (no admin required)
        let home = std::env::var("HOME").map_err(|_| "无法获取用户主目录")?;
        let login_keychain = format!("{}/Library/Keychains/login.keychain-db", home);

        let output = Command::new("security")
            .args([
                "add-trusted-cert",
                "-d",           // Add to admin cert store
                "-r", "trustRoot",  // Set trust settings for SSL
                "-k", &login_keychain,
                cert_path.to_str().ok_or("Invalid cert path")?,
            ])
            .output()?;

        if output.status.success() {
            Ok(format!(
                "证书已成功安装到用户钥匙串\n\n如果浏览器仍然提示不受信任，请：\n\
                1. 打开「钥匙串访问」应用\n\
                2. 找到「Sysproxy MITM CA」证书\n\
                3. 双击打开，展开「信任」选项\n\
                4. 将「使用此证书时」设置为「始终信任」\n\n\
                证书路径: {}",
                cert_path.display()
            ))
        } else {
            let error = String::from_utf8_lossy(&output.stderr);
            let stdout = String::from_utf8_lossy(&output.stdout);

            let mut msg = String::new();
            if !error.is_empty() {
                msg.push_str(&format!("错误: {}\n\n", error.trim()));
            }
            if !stdout.is_empty() {
                msg.push_str(&format!("输出: {}\n\n", stdout.trim()));
            }
            msg.push_str(&format!("证书路径: {}\n\n", cert_path.display()));
            msg.push_str("您可以手动安装证书：\n");
            msg.push_str("1. 打开「钥匙串访问」应用\n");
            msg.push_str("2. 选择「登录」钥匙串\n");
            msg.push_str("3. 拖放证书文件到窗口中\n");
            msg.push_str("4. 双击证书，设置「信任」为「始终信任」");

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

    #[cfg(target_os = "macos")]
    fn uninstall_cert_macos() -> Result<String, Box<dyn std::error::Error>> {
        let mut removed_count = 0;
        let mut errors = Vec::new();

        // Try to remove from login keychain
        if let Ok(home) = std::env::var("HOME") {
            let login_keychain = format!("{}/Library/Keychains/login.keychain-db", home);

            // Delete certificate from login keychain
            let output = Command::new("security")
                .args([
                    "delete-certificate",
                    "-c", "Sysproxy MITM CA",
                    &login_keychain,
                ])
                .output()?;

            if output.status.success() {
                removed_count += 1;
            } else {
                let stderr = String::from_utf8_lossy(&output.stderr);
                if !stderr.contains("not found") && !stderr.is_empty() {
                    errors.push(format!("登录钥匙串: {}", stderr.trim()));
                }
            }
        }

        // Try to remove from system keychain
        let output = Command::new("security")
            .args([
                "delete-certificate",
                "-c", "Sysproxy MITM CA",
                "/Library/Keychains/System.keychain",
            ])
            .output()?;

        if output.status.success() {
            removed_count += 1;
        } else {
            let stderr = String::from_utf8_lossy(&output.stderr);
            if !stderr.contains("not found") && !stderr.is_empty() {
                errors.push(format!("系统钥匙串: {}", stderr.trim()));
            }
        }

        if removed_count > 0 {
            Ok(format!("已成功删除 {} 个证书", removed_count))
        } else if !errors.is_empty() {
            Err(format!("删除证书时遇到错误:\n{}", errors.join("\n")).into())
        } else {
            Err("未找到需要删除的证书".into())
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
