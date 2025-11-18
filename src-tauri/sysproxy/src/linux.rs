use crate::{Autoproxy, Error, Result, Sysproxy};
use std::{env, process::Command, str::from_utf8, sync::LazyLock};

const CMD_KEY: &str = "org.gnome.system.proxy";

static IS_APPIMAGE: LazyLock<bool> = LazyLock::new(|| std::env::var("APPIMAGE").is_ok());

impl Sysproxy {
    #[inline]
    pub fn get_system_proxy() -> Result<Sysproxy> {
        let enable = Sysproxy::get_enable()?;

        let mut socks = get_proxy("socks")?;
        let https = get_proxy("https")?;
        let http = get_proxy("http")?;

        if socks.host.is_empty() {
            if !http.host.is_empty() {
                socks.host = http.host;
                socks.port = http.port;
            }
            if !https.host.is_empty() {
                socks.host = https.host;
                socks.port = https.port;
            }
        }

        socks.enable = enable;
        socks.bypass = Sysproxy::get_bypass().unwrap_or_else(|_| "".into());

        Ok(socks)
    }

    #[inline]
    pub fn set_system_proxy(&self) -> Result<()> {
        self.set_enable()?;

        if self.enable {
            self.set_socks()?;
            self.set_https()?;
            self.set_http()?;
            self.set_bypass()?;
        }

        Ok(())
    }

    #[inline]
    pub fn get_enable() -> Result<bool> {
        match env::var("XDG_CURRENT_DESKTOP").unwrap_or_default().as_str() {
            "KDE" => {
                let config_path = kioslaverc_path()?;

                let mode = kreadconfig()
                    .args([
                        "--file",
                        config_path.as_str(),
                        "--group",
                        "Proxy Settings",
                        "--key",
                        "ProxyType",
                    ])
                    .output()?;
                let mode = from_utf8(&mode.stdout)
                    .map_err(|_| Error::ParseStr("mode".into()))?
                    .trim();
                Ok(mode == "1")
            }
            _ => {
                let mode = gsettings().args(["get", CMD_KEY, "mode"]).output()?;
                let mode = from_utf8(&mode.stdout)
                    .map_err(|_| Error::ParseStr("mode".into()))?
                    .trim();
                Ok(mode == "'manual'")
            }
        }
    }

    #[inline]
    pub fn get_bypass() -> Result<String> {
        match env::var("XDG_CURRENT_DESKTOP").unwrap_or_default().as_str() {
            "KDE" => {
                let config_path = kioslaverc_path()?;

                let bypass = kreadconfig()
                    .args([
                        "--file",
                        config_path.as_str(),
                        "--group",
                        "Proxy Settings",
                        "--key",
                        "NoProxyFor",
                    ])
                    .output()?;
                let bypass = from_utf8(&bypass.stdout)
                    .map_err(|_| Error::ParseStr("bypass".into()))?
                    .trim();

                let bypass = bypass
                    .split(',')
                    .map(|h| strip_str(h.trim()))
                    .collect::<Vec<&str>>()
                    .join(",");

                Ok(bypass)
            }
            _ => {
                let bypass = gsettings()
                    .args(["get", CMD_KEY, "ignore-hosts"])
                    .output()?;
                let bypass = from_utf8(&bypass.stdout)
                    .map_err(|_| Error::ParseStr("bypass".into()))?
                    .trim();

                let bypass = bypass.strip_prefix('[').unwrap_or(bypass);
                let bypass = bypass.strip_suffix(']').unwrap_or(bypass);

                let bypass = bypass
                    .split(',')
                    .map(|h| strip_str(h.trim()))
                    .collect::<Vec<&str>>()
                    .join(",");

                Ok(bypass)
            }
        }
    }

    #[inline]
    pub fn get_http() -> Result<Sysproxy> {
        get_proxy("http")
    }

    #[inline]
    pub fn get_https() -> Result<Sysproxy> {
        get_proxy("https")
    }

    #[inline]
    pub fn get_socks() -> Result<Sysproxy> {
        get_proxy("socks")
    }

    #[inline]
    pub fn set_enable(&self) -> Result<()> {
        match env::var("XDG_CURRENT_DESKTOP").unwrap_or_default().as_str() {
            "KDE" => {
                let config_path = kioslaverc_path()?;
                let mode = if self.enable { "1" } else { "0" };
                kwriteconfig()
                    .args([
                        "--file",
                        config_path.as_str(),
                        "--group",
                        "Proxy Settings",
                        "--key",
                        "ProxyType",
                        mode,
                    ])
                    .status()?;
                let gmode = if self.enable { "'manual'" } else { "'none'" };
                gsettings().args(["set", CMD_KEY, "mode", gmode]).status()?;
                write_dconf("/system/proxy/mode", gmode);
                Ok(())
            }
            _ => {
                let mode = if self.enable { "'manual'" } else { "'none'" };
                gsettings().args(["set", CMD_KEY, "mode", mode]).status()?;
                write_dconf("/system/proxy/mode", mode);
                Ok(())
            }
        }
    }

    #[inline]
    pub fn set_bypass(&self) -> Result<()> {
        match env::var("XDG_CURRENT_DESKTOP").unwrap_or_default().as_str() {
            "KDE" => {
                let config_path = kioslaverc_path()?;

                let bypass = self
                    .bypass
                    .split(',')
                    .map(|h| {
                        let mut host = String::from(h.trim());
                        if !host.starts_with('\'') && !host.starts_with('"') {
                            host = String::from("'") + &host;
                        }
                        if !host.ends_with('\'') && !host.ends_with('"') {
                            host += "'";
                        }
                        host
                    })
                    .collect::<Vec<String>>()
                    .join(", ");

                let bypass = format!("[{bypass}]");

                gsettings()
                    .args(["set", CMD_KEY, "ignore-hosts", bypass.as_str()])
                    .status()?;
                write_dconf("/system/proxy/ignore-hosts", bypass.as_str());

                kwriteconfig()
                    .args([
                        "--file",
                        config_path.as_str(),
                        "--group",
                        "Proxy Settings",
                        "--key",
                        "NoProxyFor",
                        self.bypass.as_str(),
                    ])
                    .status()?;
                Ok(())
            }
            _ => {
                let bypass = self
                    .bypass
                    .split(',')
                    .map(|h| {
                        let mut host = String::from(h.trim());
                        if !host.starts_with('\'') && !host.starts_with('"') {
                            host = String::from("'") + &host;
                        }
                        if !host.ends_with('\'') && !host.ends_with('"') {
                            host += "'";
                        }
                        host
                    })
                    .collect::<Vec<String>>()
                    .join(", ");

                let bypass = format!("[{bypass}]");

                gsettings()
                    .args(["set", CMD_KEY, "ignore-hosts", bypass.as_str()])
                    .status()?;
                write_dconf("/system/proxy/ignore-hosts", bypass.as_str());
                Ok(())
            }
        }
    }

    #[inline]
    pub fn set_http(&self) -> Result<()> {
        set_proxy(self, "http")
    }

    #[inline]
    pub fn set_https(&self) -> Result<()> {
        set_proxy(self, "https")
    }

    #[inline]
    pub fn set_socks(&self) -> Result<()> {
        set_proxy(self, "socks")
    }
}

#[inline]
fn gsettings() -> Command {
    let mut command = Command::new("gsettings");
    if *IS_APPIMAGE {
        command.env_remove("LD_LIBRARY_PATH");
    }
    command
}

#[inline]
fn dconf() -> Command {
    let mut command = Command::new("dconf");
    if *IS_APPIMAGE {
        command.env_remove("LD_LIBRARY_PATH");
    }
    command
}

#[inline]
fn write_dconf(path: &str, value: &str) {
    let _ = dconf().arg("write").arg(path).arg(value).status();
}

#[inline]
fn kioslaverc_path() -> Result<String> {
    let xdg_dir = xdg::BaseDirectories::new();
    let config = xdg_dir
        .get_config_file("kioslaverc")
        .ok_or_else(|| Error::ParseStr("config".into()))?;
    config
        .to_str()
        .map(|value| value.to_owned())
        .ok_or_else(|| Error::ParseStr("config".into()))
}

#[inline]
fn quoted(value: &str) -> String {
    if value.starts_with('\'') && value.ends_with('\'') {
        value.to_string()
    } else {
        format!("'{}'", value)
    }
}

#[inline]
fn kreadconfig() -> Command {
    let command = match env::var("KDE_SESSION_VERSION").unwrap_or_default().as_str() {
        "6" => "kreadconfig6",
        _ => "kreadconfig5",
    };
    let mut command = Command::new(command);
    if *IS_APPIMAGE {
        command.env_remove("LD_LIBRARY_PATH");
    }
    command
}

#[inline]
fn kwriteconfig() -> Command {
    let command = match env::var("KDE_SESSION_VERSION").unwrap_or_default().as_str() {
        "6" => "kwriteconfig6",
        _ => "kwriteconfig5",
    };
    let mut command = Command::new(command);
    if *IS_APPIMAGE {
        command.env_remove("LD_LIBRARY_PATH");
    }
    command
}

#[inline]
fn set_proxy(proxy: &Sysproxy, service: &str) -> Result<()> {
    match env::var("XDG_CURRENT_DESKTOP").unwrap_or_default().as_str() {
        "KDE" => {
            let schema = format!("{CMD_KEY}.{service}");
            let schema = schema.as_str();

            let host = format!("'{}'", proxy.host);
            let host = host.as_str();
            let port = format!("{}", proxy.port);
            let port = port.as_str();
            let dconf_service = service;

            gsettings().args(["set", schema, "host", host]).status()?;
            gsettings().args(["set", schema, "port", port]).status()?;
            let host_path = format!("/system/proxy/{dconf_service}/host");
            let port_path = format!("/system/proxy/{dconf_service}/port");
            write_dconf(host_path.as_str(), host);
            write_dconf(port_path.as_str(), port);

            let config_path = kioslaverc_path()?;

            let key = format!("{service}Proxy");
            let key = key.as_str();

            let service = match service {
                "socks" => "socks",
                _ => "http",
            };

            let host = proxy.host.to_string();
            let host = host.as_str();

            let schema = format!("{service}://{host} {port}");
            let schema = schema.as_str();

            kwriteconfig()
                .args([
                    "--file",
                    config_path.as_str(),
                    "--group",
                    "Proxy Settings",
                    "--key",
                    key,
                    schema,
                ])
                .status()?;

            Ok(())
        }
        _ => {
            let schema = format!("{CMD_KEY}.{service}");
            let schema = schema.as_str();

            let host = format!("'{}'", proxy.host);
            let host = host.as_str();
            let port = format!("{}", proxy.port);
            let port = port.as_str();
            let dconf_service = service;

            gsettings().args(["set", schema, "host", host]).status()?;
            gsettings().args(["set", schema, "port", port]).status()?;
            let host_path = format!("/system/proxy/{dconf_service}/host");
            let port_path = format!("/system/proxy/{dconf_service}/port");
            write_dconf(host_path.as_str(), host);
            write_dconf(port_path.as_str(), port);

            Ok(())
        }
    }
}

#[inline]
fn get_proxy(service: &str) -> Result<Sysproxy> {
    match env::var("XDG_CURRENT_DESKTOP").unwrap_or_default().as_str() {
        "KDE" => {
            let config_path = kioslaverc_path()?;

            let key = format!("{service}Proxy");
            let key = key.as_str();

            let schema = kreadconfig()
                .args([
                    "--file",
                    config_path.as_str(),
                    "--group",
                    "Proxy Settings",
                    "--key",
                    key,
                ])
                .output()?;
            let schema = from_utf8(&schema.stdout)
                .map_err(|_| Error::ParseStr("schema".into()))?
                .trim();
            let schema = schema
                .trim_start_matches("http://")
                .trim_start_matches("socks://");
            let schema = schema
                .split_once(' ')
                .ok_or_else(|| Error::ParseStr("schema".into()))?;

            let host = strip_str(schema.0);
            let port = schema.1.parse().unwrap_or(80u16);

            Ok(Sysproxy {
                enable: false,
                host: String::from(host),
                port,
                bypass: "".into(),
            })
        }
        _ => {
            let schema = format!("{CMD_KEY}.{service}");
            let schema = schema.as_str();

            let host = gsettings().args(["get", schema, "host"]).output()?;
            let host = from_utf8(&host.stdout)
                .map_err(|_| Error::ParseStr("host".into()))?
                .trim();
            let host = strip_str(host);

            let port = gsettings().args(["get", schema, "port"]).output()?;
            let port = from_utf8(&port.stdout)
                .map_err(|_| Error::ParseStr("port".into()))?
                .trim();
            let port = port.parse().unwrap_or(80u16);

            Ok(Sysproxy {
                enable: false,
                host: String::from(host),
                port,
                bypass: "".into(),
            })
        }
    }
}

#[inline]
fn strip_str(text: &str) -> &str {
    text.strip_prefix('\'')
        .unwrap_or(text)
        .strip_suffix('\'')
        .unwrap_or(text)
}

impl Autoproxy {
    #[inline]
    pub fn get_auto_proxy() -> Result<Autoproxy> {
        let (enable, url) = match env::var("XDG_CURRENT_DESKTOP").unwrap_or_default().as_str() {
            "KDE" => {
                let config_path = kioslaverc_path()?;

                let mode = kreadconfig()
                    .args([
                        "--file",
                        config_path.as_str(),
                        "--group",
                        "Proxy Settings",
                        "--key",
                        "ProxyType",
                    ])
                    .output()?;
                let mode = from_utf8(&mode.stdout)
                    .map_err(|_| Error::ParseStr("mode".into()))?
                    .trim();
                let url = kreadconfig()
                    .args([
                        "--file",
                        config_path.as_str(),
                        "--group",
                        "Proxy Settings",
                        "--key",
                        "Proxy Config Script",
                    ])
                    .output()?;
                let url = from_utf8(&url.stdout)
                    .map_err(|_| Error::ParseStr("url".into()))?
                    .trim();
                (mode == "2", url.to_string())
            }
            _ => {
                let mode = gsettings().args(["get", CMD_KEY, "mode"]).output()?;
                let mode = from_utf8(&mode.stdout)
                    .map_err(|_| Error::ParseStr("mode".into()))?
                    .trim();
                let url = gsettings()
                    .args(["get", CMD_KEY, "autoconfig-url"])
                    .output()?;
                let url: &str = from_utf8(&url.stdout)
                    .map_err(|_| Error::ParseStr("url".into()))?
                    .trim();
                let url = strip_str(url);
                (mode == "'auto'", url.to_string())
            }
        };

        Ok(Autoproxy { enable, url })
    }
    
    #[inline]
    pub fn set_auto_proxy(&self) -> Result<()> {
        match env::var("XDG_CURRENT_DESKTOP").unwrap_or_default().as_str() {
            "KDE" => {
                let config_path = kioslaverc_path()?;
                let mode = if self.enable { "2" } else { "0" };
                kwriteconfig()
                    .args([
                        "--file",
                        config_path.as_str(),
                        "--group",
                        "Proxy Settings",
                        "--key",
                        "ProxyType",
                        mode,
                    ])
                    .status()?;
                kwriteconfig()
                    .args([
                        "--file",
                        config_path.as_str(),
                        "--group",
                        "Proxy Settings",
                        "--key",
                        "Proxy Config Script",
                        &self.url,
                    ])
                    .status()?;
                let gmode = if self.enable { "'auto'" } else { "'none'" };
                gsettings().args(["set", CMD_KEY, "mode", gmode]).status()?;
                write_dconf("/system/proxy/mode", gmode);
                let autoconfig = quoted(&self.url);
                gsettings()
                    .args(["set", CMD_KEY, "autoconfig-url", autoconfig.as_str()])
                    .status()?;
                write_dconf("/system/proxy/autoconfig-url", autoconfig.as_str());
            }
            _ => {
                let mode = if self.enable { "'auto'" } else { "'none'" };
                gsettings().args(["set", CMD_KEY, "mode", mode]).status()?;
                write_dconf("/system/proxy/mode", mode);
                let autoconfig = quoted(&self.url);
                gsettings()
                    .args(["set", CMD_KEY, "autoconfig-url", autoconfig.as_str()])
                    .status()?;
                write_dconf("/system/proxy/autoconfig-url", autoconfig.as_str());
            }
        }

        Ok(())
    }
}
