/// 应用图标提取模块
///
/// 提供从应用程序路径提取图标并转换为 base64 的功能

#[cfg(target_os = "macos")]
use {
    std::path::Path,
    std::process::Command,
};

#[cfg(target_os = "windows")]
use {
    std::ffi::OsStr,
    std::os::windows::ffi::OsStrExt,
    std::{ffi::c_void, io::Cursor, mem},
    base64::{engine::general_purpose::STANDARD, Engine as _},
    image::{codecs::png::PngEncoder, ColorType, ImageEncoder},
    windows::core::PCWSTR,
    windows::Win32::Foundation::HWND,
    windows::Win32::Graphics::Gdi::{
        DeleteObject, GetDC, GetDIBits, GetObjectW, ReleaseDC, BITMAP, BITMAPINFO, BITMAPINFOHEADER, BI_RGB,
        DIB_RGB_COLORS, HBITMAP,
    },
    windows::Win32::UI::Shell::ExtractIconExW,
    windows::Win32::UI::WindowsAndMessaging::{DestroyIcon, GetIconInfo, HICON, ICONINFO},
};

/// 从应用程序路径提取图标 (macOS)
#[cfg(target_os = "macos")]
pub fn extract_app_icon(exe_path: &str) -> Option<String> {
    // 检查是否是 .app bundle
    if !exe_path.contains(".app/Contents/") {
        return None;
    }

    // 提取 .app 路径
    let app_path = if let Some(pos) = exe_path.find(".app/Contents/") {
        &exe_path[..pos + 4] // 包含 ".app"
    } else {
        return None;
    };

    // 尝试提取当前应用的图标
    if let Some(icon) = try_extract_icon_from_app(app_path) {
        return Some(icon);
    }

    // 如果当前路径是 Helper 或 Framework 内的应用，尝试查找父应用
    // 例如: /Applications/Google Chrome.app/Contents/Frameworks/.../Helpers/Google Chrome Helper.app
    // 应该使用 Google Chrome.app 的图标
    if exe_path.contains("/Frameworks/") || exe_path.contains("/Helpers/") {
        // 查找第一个 .app 路径（主应用）
        if let Some(first_app_pos) = exe_path.find(".app/") {
            let main_app_path = &exe_path[..first_app_pos + 4];
            if let Some(icon) = try_extract_icon_from_app(main_app_path) {
                return Some(icon);
            }
        }
    }

    None
}

/// 尝试从指定的 .app 路径提取图标
#[cfg(target_os = "macos")]
fn try_extract_icon_from_app(app_path: &str) -> Option<String> {
    // 尝试多个可能的图标文件位置
    let possible_icon_paths = vec![
        format!("{}/Contents/Resources/AppIcon.icns", app_path),
        format!("{}/Contents/Resources/app.icns", app_path),
        format!("{}/Contents/Resources/icon.icns", app_path),
    ];

    // 查找第一个存在的图标文件
    for icon_path in possible_icon_paths {
        if Path::new(&icon_path).exists() {
            if let Some(icon) = convert_icns_to_base64(&icon_path) {
                return Some(icon);
            }
        }
    }

    // 如果没有找到，尝试从 Info.plist 读取图标名称
    let plist_path = format!("{}/Contents/Info.plist", app_path);
    if let Ok(icon_name) = get_icon_name_from_plist(&plist_path) {
        let icon_path = format!("{}/Contents/Resources/{}", app_path, icon_name);
        if Path::new(&icon_path).exists() {
            if let Some(icon) = convert_icns_to_base64(&icon_path) {
                return Some(icon);
            }
        }
    }

    None
}

/// 从 Info.plist 读取图标文件名
#[cfg(target_os = "macos")]
fn get_icon_name_from_plist(plist_path: &str) -> Result<String, String> {
    let output = Command::new("defaults")
        .arg("read")
        .arg(plist_path)
        .arg("CFBundleIconFile")
        .output()
        .map_err(|e| e.to_string())?;

    if output.status.success() {
        let mut icon_name = String::from_utf8_lossy(&output.stdout).trim().to_string();
        // 添加 .icns 扩展名（如果没有）
        if !icon_name.ends_with(".icns") {
            icon_name.push_str(".icns");
        }
        Ok(icon_name)
    } else {
        Err("Failed to read plist".to_string())
    }
}

/// 将 .icns 文件转换为 base64 PNG 数据
#[cfg(target_os = "macos")]
fn convert_icns_to_base64(icns_path: &str) -> Option<String> {
    use std::fs;

    // 创建临时目录
    let temp_dir = std::env::temp_dir().join("sysproxy_icons");
    let _ = fs::create_dir_all(&temp_dir);

    // 生成临时 PNG 文件路径
    let temp_png = temp_dir.join(format!("{}.png",
        Path::new(icns_path)
            .file_stem()?
            .to_str()?));

    // 使用 sips 命令将 .icns 转换为 PNG
    let output = Command::new("sips")
        .arg("-s")
        .arg("format")
        .arg("png")
        .arg(icns_path)
        .arg("--out")
        .arg(&temp_png)
        .arg("--resampleWidth")
        .arg("32") // 调整为 32x32 像素
        .output()
        .ok()?;

    if !output.status.success() {
        return None;
    }

    // 读取 PNG 文件并转换为 base64
    let png_data = fs::read(&temp_png).ok()?;
    use base64::{Engine as _, engine::general_purpose::STANDARD};
    let base64_data = STANDARD.encode(&png_data);

    // 清理临时文件
    let _ = fs::remove_file(&temp_png);

    Some(format!("data:image/png;base64,{}", base64_data))
}

/// Windows 平台的应用图标提取
#[cfg(target_os = "windows")]
pub fn extract_app_icon(exe_path: &str) -> Option<String> {
    // 将 Windows 路径转换为 UTF-16 并结尾 0
    let wide_path: Vec<u16> = OsStr::new(exe_path).encode_wide().chain(Some(0)).collect();

    // 使用 ExtractIconExW 从 EXE 路径中拷贝大图标句柄
    let mut hicon = HICON::default();
    let extracted = unsafe { ExtractIconExW(PCWSTR(wide_path.as_ptr()), 0, Some(&mut hicon), None, 1) };
    if extracted == 0 || hicon.is_invalid() {
        return None;
    }

    // 转换为 base64 PNG 数据URL
    let data_url = unsafe { icon_handle_to_data_url(hicon) };

    // 释放图标句柄资源
    unsafe {
        let _ = DestroyIcon(hicon);
    }

    data_url
}

#[cfg(target_os = "windows")]
unsafe fn icon_handle_to_data_url(hicon: HICON) -> Option<String> {
    let mut icon_info = ICONINFO::default();
    if GetIconInfo(hicon, &mut icon_info).is_err() {
        return None;
    }
    let hbm_color = icon_info.hbmColor;
    let hbm_mask = icon_info.hbmMask;

    // 获取图标尺寸和位深
    let mut bmp = BITMAP::default();
    if GetObjectW(
        hbm_color.into(),
        mem::size_of::<BITMAP>() as i32,
        Some(&mut bmp as *mut _ as *mut c_void),
    ) == 0
    {
        cleanup_bitmaps(hbm_color, hbm_mask);
        return None;
    }

    let width = bmp.bmWidth.unsigned_abs();
    let height = bmp.bmHeight.unsigned_abs();
    if width == 0 || height == 0 {
        cleanup_bitmaps(hbm_color, hbm_mask);
        return None;
    }

    // 使用 GetDIBits 抽取 BGRA 像素
    let mut bmi: BITMAPINFO = mem::zeroed();
    bmi.bmiHeader = BITMAPINFOHEADER {
        biSize: mem::size_of::<BITMAPINFOHEADER>() as u32,
        biWidth: bmp.bmWidth,
        biHeight: -(bmp.bmHeight.abs()), // 让扫描行从上到下
        biPlanes: 1,
        biBitCount: 32,
        biCompression: BI_RGB.0,
        ..Default::default()
    };

    let hdc = GetDC(Some(HWND::default()));
    if hdc.0.is_null() {
        cleanup_bitmaps(hbm_color, hbm_mask);
        return None;
    }

    let mut pixels = vec![0u8; (width as usize) * (height as usize) * 4];
    let lines = GetDIBits(
        hdc,
        hbm_color,
        0,
        height,
        Some(pixels.as_mut_ptr() as *mut c_void),
        &mut bmi,
        DIB_RGB_COLORS,
    );
    ReleaseDC(Some(HWND::default()), hdc);

    if lines == 0 {
        cleanup_bitmaps(hbm_color, hbm_mask);
        return None;
    }

    // BGRA -> RGBA
    for chunk in pixels.chunks_exact_mut(4) {
        chunk.swap(0, 2);
    }

    cleanup_bitmaps(hbm_color, hbm_mask);

    // 直接用 PNG 编码器输出 RGBA 缓冲区
    let mut png_buf = Vec::new();
    {
        let mut cursor = Cursor::new(&mut png_buf);
        let encoder = PngEncoder::new(&mut cursor);
        encoder
            .write_image(&pixels, width, height, ColorType::Rgba8.into())
            .ok()?;
    }

    Some(format!("data:image/png;base64,{}", STANDARD.encode(png_buf)))
}

#[cfg(target_os = "windows")]
unsafe fn cleanup_bitmaps(hbm_color: HBITMAP, hbm_mask: HBITMAP) {
    if !hbm_color.is_invalid() {
        let _ = DeleteObject(hbm_color.into());
    }
    if !hbm_mask.is_invalid() {
        let _ = DeleteObject(hbm_mask.into());
    }
}

/// Linux 平台的图标提取实现（占位）
#[cfg(target_os = "linux")]
pub fn extract_app_icon(_exe_path: &str) -> Option<String> {
    // TODO: 实现 Linux 图标提取
    // 可以从 .desktop 文件或 icon theme 中查找
    None
}
