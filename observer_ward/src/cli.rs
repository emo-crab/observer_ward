use crate::input::{read_file_to_target, read_from_stdio};
use crate::parse_yaml;
use argh::FromArgs;
use console::Emoji;
use engine::find_yaml_file;
use engine::slinger::http::header::HeaderValue;
use engine::slinger::http::Uri;
use engine::slinger::http_serde;
use engine::slinger::redirect::Policy;
use engine::slinger::{openssl, ClientBuilder, ConnectorBuilder, Proxy};
use engine::template::Template;
use log::{error, warn};
use serde::{Deserialize, Serialize};
use std::env::current_dir;
use std::fmt::{Display, Formatter};
use std::fs::File;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::str::FromStr;
use std::time::Duration;

#[derive(Debug, Clone, Default)]
pub enum OutputFormat {
  #[default]
  STD,
  JSON,
  CSV,
}

impl FromStr for OutputFormat {
  type Err = std::io::Error;
  fn from_str(s: &str) -> Result<Self, Self::Err> {
    let f = match s {
      "json" => OutputFormat::JSON,
      "csv" => OutputFormat::CSV,
      "txt" => OutputFormat::STD,
      _ => {
        return Err(std::io::Error::new(
          std::io::ErrorKind::InvalidInput,
          "invalid format",
        ));
      }
    };
    Ok(f)
  }
}

#[derive(Debug, Clone, Default, PartialEq)]
pub enum Mode {
  #[default]
  ALL,
  HTTP,
  TCP,
}

impl FromStr for Mode {
  type Err = std::io::Error;
  fn from_str(s: &str) -> Result<Self, Self::Err> {
    let f = match s {
      "all" => Mode::ALL,
      "http" => Mode::HTTP,
      "tcp" => Mode::TCP,
      _ => {
        return Err(std::io::Error::new(
          std::io::ErrorKind::InvalidInput,
          "invalid mode",
        ));
      }
    };
    Ok(f)
  }
}

#[derive(Debug, Clone, PartialEq)]
pub enum UnixSocketAddr {
  #[cfg(unix)]
  Unix(PathBuf),
  SocketAddr(SocketAddr),
}

impl Display for UnixSocketAddr {
  fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
    match self {
      #[cfg(unix)]
      UnixSocketAddr::Unix(p) => f.write_str(&p.to_string_lossy()),
      UnixSocketAddr::SocketAddr(s) => f.write_str(&s.to_string()),
    }
  }
}

impl FromStr for UnixSocketAddr {
  type Err = std::io::Error;
  fn from_str(s: &str) -> Result<Self, Self::Err> {
    if let Ok(socket_addr) = SocketAddr::from_str(s) {
      Ok(Self::SocketAddr(socket_addr))
    } else {
      #[cfg(unix)]
      return PathBuf::from_str(s)
        .map(Self::Unix)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidInput, e));
      #[cfg(not(unix))]
      return Err(std::io::Error::new(
        std::io::ErrorKind::Unsupported,
        "only unix support unix-socket",
      ));
    }
  }
}

#[derive(Debug, Serialize, Deserialize, Clone, FromArgs)]
#[argh(description = "observer_ward version")]
#[serde(rename_all = "kebab-case")]
pub struct ObserverWardConfig {
  /// multiple targets from file path
  #[argh(option, short = 'l')]
  #[serde(skip)]
  pub list: Option<PathBuf>,
  /// the target (required)
  #[argh(option, short = 't')]
  pub target: Vec<String>,
  /// customized fingerprint file path
  #[argh(option, short = 'p')]
  #[serde(skip)]
  pub probe_path: Option<PathBuf>,
  /// customized fingerprint yaml file dir
  #[argh(option)]
  #[serde(skip)]
  pub probe_dir: Vec<PathBuf>,
  /// customized ua
  #[argh(option, default = "default_ua()")]
  #[serde(default = "default_ua")]
  pub ua: String,
  /// mode probes option[tcp,http,all] default: all
  #[argh(option)]
  #[serde(skip)]
  pub mode: Option<Mode>,
  /// set request timeout.
  #[argh(option, default = "default_timeout()")]
  #[serde(default = "default_timeout")]
  pub timeout: u64,
  /// number of concurrent threads.
  #[argh(option, default = "default_thread()")]
  #[serde(default = "default_thread")]
  pub thread: usize,
  /// proxy to use for requests (ex:[http(s)|socks5(h)]://host:port)
  #[argh(option, from_str_fn(proxy))]
  #[serde(skip)]
  pub proxy: Option<Proxy>,
  /// include request/response pairs in output
  #[argh(switch)]
  #[serde(default)]
  pub ir: bool,
  /// include certificate pairs in output
  #[argh(switch)]
  #[serde(default)]
  pub ic: bool,
  /// customized template dir
  #[argh(option)]
  #[serde(skip)]
  pub plugin: Option<PathBuf>,
  /// export to the file
  #[argh(option, short = 'o')]
  #[serde(skip)]
  pub output: Option<PathBuf>,
  /// output format option[json,csv,txt] default: txt
  #[argh(option)]
  #[serde(skip)]
  pub format: Option<OutputFormat>,
  /// disable output content coloring
  #[argh(switch)]
  #[serde(skip)]
  pub no_color: bool,
  /// poc nuclei engine additional args
  #[argh(option)]
  #[serde(skip)]
  pub nuclei_args: Vec<String>,
  /// silent mode
  #[argh(switch)]
  #[serde(skip)]
  pub silent: bool,
  /// debug mode
  #[argh(switch)]
  #[serde(skip)]
  pub debug: bool,
  /// customized template dir
  #[argh(option, default = "default_config()")]
  #[serde(skip)]
  pub config_dir: PathBuf,
  /// update self
  #[argh(switch)]
  #[serde(skip)]
  pub update_self: bool,
  /// update fingerprint
  #[argh(switch, short = 'u')]
  #[serde(default)]
  pub update_fingerprint: bool,
  /// update plugin
  #[argh(switch)]
  #[serde(default)]
  pub update_plugin: bool,
  #[cfg(not(target_os = "windows"))]
  /// api background service
  #[argh(switch)]
  #[serde(skip)]
  pub daemon: bool,
  /// api Bearer authentication
  #[argh(option)]
  #[serde(skip)]
  pub token: Option<String>,
  /// send results to webhook server (ex:https://host:port/webhook)
  #[argh(option, from_str_fn(uri))]
  #[serde(default, with = "http_serde::option::uri")]
  pub webhook: Option<Uri>,
  /// the auth will be set to the webhook request header AUTHORIZATION
  #[argh(option)]
  #[serde(default)]
  pub webhook_auth: Option<String>,
  /// start a web API service (ex:127.0.0.1:8080)
  #[argh(option)]
  #[serde(skip)]
  pub api_server: Option<UnixSocketAddr>,
}

fn default_token() -> Option<String> {
  let hasher = openssl::hash::Hasher::new(openssl::hash::MessageDigest::md5());
  if let Ok(mut h) = hasher {
    let mut test_bytes = vec![0u8; 32];
    openssl::rand::rand_bytes(&mut test_bytes).unwrap_or_default();
    h.update(&test_bytes).unwrap_or_default();
    if let Ok(bytes) = h.finish() {
      let hex: String = bytes
        .iter()
        .map(|b| format!("{:02x}", b))
        .collect::<Vec<String>>()
        .join("");
      return Some(hex);
    }
  }
  None
}

pub fn default_config() -> PathBuf {
  if let Some(cp) = dirs::config_dir() {
    let observer_ward = cp.join("observer_ward");
    if !observer_ward.is_dir() || !observer_ward.exists() {
      std::fs::create_dir_all(&observer_ward).unwrap_or_default();
    }
    observer_ward
  } else {
    std::env::current_dir().expect("config path err")
  }
}

fn default_thread() -> usize {
  std::thread::available_parallelism().map_or(12, |x| x.get() * 4)
}

fn uri(value: &str) -> Result<Uri, String> {
  Uri::from_str(value).map_err(|x| x.to_string())
}

fn proxy(value: &str) -> Result<Proxy, String> {
  Proxy::parse(value).map_err(|x| x.to_string())
}

fn default_ua() -> String {
  String::from("Mozilla/5.0 (X11; Linux x86_64; rv:94.0) Gecko/20100101 Firefox/94.0")
}

fn default_timeout() -> u64 {
  10
}

impl Default for ObserverWardConfig {
  fn default() -> Self {
    let mut default: ObserverWardConfig = argh::from_env();
    if let Some(_api) = &default.api_server {
      if default.token.is_none() {
        default.token = default_token();
      }
    }
    // 补充默认输出格式
    if let Some(path) = &default.output {
      if let Some(ext) = path.extension() {
        default.format = Some(OutputFormat::from_str(&ext.to_string_lossy()).unwrap_or_default());
      }
    }
    if let Some(mut plugin) = default.plugin {
      if !has_nuclei_app() {
        println!(
          "{}please install nuclei to the environment path!",
          Emoji("💢", ""),
        );
        std::process::exit(0);
      }
      if plugin.to_string_lossy() == "default" {
        plugin = default.config_dir.join("plugins");
      }
      if plugin.is_dir() {
        default.plugin = Some(plugin.to_path_buf());
      } else {
        println!(
          "{}please update plugins to {} use `--update-plugin`!",
          Emoji("💢", ""),
          plugin.to_string_lossy()
        );
        std::process::exit(0);
      }
    }
    default
  }
}

impl ObserverWardConfig {
  pub fn tcp_client_builder(&self) -> ConnectorBuilder {
    let timeout = Duration::from_secs(self.timeout);

    ConnectorBuilder::default()
      .nodelay(true)
      .proxy(self.proxy.clone())
      .connect_timeout(Some(timeout))
      .read_timeout(Some(timeout))
      .write_timeout(Some(timeout))
  }
  pub fn http_client_builder(&self) -> ClientBuilder {
    let mut client_builder = ClientBuilder::new()
      .danger_accept_invalid_certs(true)
      .danger_accept_invalid_hostnames(true)
      .min_tls_version(Some(engine::slinger::native_tls::Protocol::Tlsv10))
      .redirect(Policy::Custom(engine::common::http::js_redirect))
      .timeout(Some(Duration::from_secs(self.timeout)));
    if let Ok(ua) = HeaderValue::from_str(&self.ua) {
      client_builder = client_builder.user_agent(ua);
    }
    if let Some(proxy) = &self.proxy {
      client_builder = client_builder.proxy(proxy.clone());
    }
    client_builder
  }
  pub fn yaml_probes(&self) -> Option<Vec<Template>> {
    if self.probe_dir.is_empty() {
      return None;
    }
    let mut templates = Vec::new();
    for fd in &self.probe_dir {
      let yaml_paths = find_yaml_file(fd, true);
      for path in yaml_paths {
        match parse_yaml(&path) {
          Ok(t) => templates.push(t),
          Err(err) => {
            warn!(
              "{}load template {} err: {}",
              Emoji("⚠️", ""),
              path.to_string_lossy(),
              err
            );
          }
        }
      }
    }
    if templates.is_empty() {
      None
    } else {
      Some(templates)
    }
  }
  pub fn input(&self) -> Vec<Uri> {
    let i = if !self.target.is_empty() {
      self.target.clone()
    } else if let Some(f) = &self.list {
      read_file_to_target(f)
    } else {
      read_from_stdio().unwrap_or_default()
    };
    i.iter()
      .filter_map(|target| match Uri::from_str(target.trim()) {
        Ok(u) => Some(u),
        Err(err) => {
          error!("{}uri: {}, err: {}", Emoji("💢", ""), target, err);
          None
        }
      })
      .collect()
  }
  pub fn templates(&self) -> Vec<Template> {
    let mut templates = Vec::new();
    if let Some(ts) = self.yaml_probes() {
      return ts;
    }
    if let Some(fp) = &self.probe_path {
      if let Ok(f) = std::fs::File::open(fp) {
        let ext = fp.extension().and_then(|x| x.to_str()).unwrap_or_default();
        match ext {
          "json" => {
            templates = serde_json::from_reader(f).expect("load fingerprint err");
          }
          "yaml" | "yml" => match parse_yaml(fp) {
            Ok(t) => {
              templates.push(t);
            }
            Err(err) => {
              error!(
                "{}load template {} err {}",
                Emoji("💢", ""),
                fp.to_string_lossy(),
                err
              );
            }
          },
          _ => {}
        }
      };
    } else {
      for path in ["web_fingerprint_v4.json", "service_fingerprint_v4.json"] {
        let fingerprint_path = current_dir().map_or(self.config_dir.join(path), |x| {
          let p = x.join(path);
          if p.exists() {
            p
          } else {
            self.config_dir.join(path)
          }
        });
        if let Ok(f) = std::fs::File::open(&fingerprint_path) {
          match serde_json::from_reader::<File, Vec<_>>(f) {
            Ok(t) => {
              templates.extend(t);
            }
            Err(err) => {
              error!(
                "{}load template {} err {}",
                Emoji("💢", ""),
                fingerprint_path.to_string_lossy(),
                err
              );
            }
          }
        }
      }
    }
    templates
  }
}

fn has_nuclei_app() -> bool {
  return if cfg!(target_os = "windows") {
    Command::new("nuclei.exe")
      .args(["-version"])
      .stdin(Stdio::null())
      .output()
      .is_ok()
  } else {
    Command::new("nuclei")
      .args(["-version"])
      .stdin(Stdio::null())
      .output()
      .is_ok()
  };
}
