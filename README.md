# sysproxy-tauri-demo

一个最小可运行的 Tauri 2 示例，只有两个输入框即可设置/关闭系统代理，后端逻辑复用本仓库的 `sysproxy-rs`。

## 运行

```bash
cd examples/sysproxy-tauri-demo
pnpm install
pnpm dev    # 开发模式
# 或 pnpm build 打包
```

> Windows 如遇 `set_system_proxy` 失败，可在 `src-tauri` 同级放置从 sysproxy-rs 编译得到的 `sysproxy.exe` 并以管理员运行。

## 代码要点

- `src-tauri/src/main.rs`：`set_system_proxy`/`reset_system_proxy` 命令，非 Windows 直接调用 `sysproxy` 写系统代理，Windows 默认也直接调用 crate。
- `src/index.html`：两个输入框+两个按钮，通过 `window.__TAURI__.core.invoke` 调用上面的命令。

默认绕过列表与本项目一致，可按需调整 `DEFAULT_BYPASS` 常量。
