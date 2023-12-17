use crate::OBSERVER_WARD_PATH;
use argh::FromArgs;
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use std::process;
use std::process::{Command, Stdio};

#[derive(Debug, Serialize, Deserialize, Clone, FromArgs, Default)]
#[argh(description = "observer_ward")]
pub struct ObserverWardConfig {
    /// multiple targets from the API
    #[argh(option)]
    #[serde(default)]
    pub targets: Vec<String>,
    /// the target (required, unless --stdin used)
    #[argh(option, short = 't')]
    pub target: Option<String>,
    /// read target(s) from STDIN
    #[argh(switch)]
    #[serde(skip)]
    pub stdin: bool,
    /// customized fingerprint file path
    #[argh(option)]
    #[serde(skip)]
    pub fpath: Option<PathBuf>,
    /// customized fingerprint yaml directory (slow)
    #[argh(option)]
    #[serde(skip)]
    pub yaml: Option<PathBuf>,
    /// generate json format fingerprint library from yaml format(requires yaml parameter)
    #[argh(option)]
    #[serde(skip)]
    pub gen: Option<PathBuf>,
    /// customized nuclei template file path
    #[argh(option)]
    #[serde(skip)]
    pub path: Option<String>,
    /// validate the specified yaml file or grep keyword
    #[argh(option)]
    #[serde(skip)]
    pub verify: Option<String>,
    /// read the target from the file
    #[argh(option, short = 'f')]
    #[serde(skip)]
    pub file: Option<String>,
    /// update web fingerprint
    #[argh(switch, short = 'u')]
    #[serde(default)]
    pub update_fingerprint: bool,
    /// export to the csv file or Import form the csv file
    #[argh(option, short = 'c')]
    #[serde(skip)]
    pub csv: Option<String>,
    /// export to the json file or Import form the json file
    #[argh(option, short = 'j')]
    #[serde(skip)]
    pub json: Option<String>,
    /// proxy to use for requests (ex:[http(s)|socks5(h)]://host:port)
    #[argh(option)]
    #[serde(default)]
    pub proxy: Option<String>,
    /// set request timeout.
    #[argh(option, default = "default_timeout()")]
    #[serde(default = "default_timeout")]
    pub timeout: u64,
    /// the 'plugins' directory is used when the parameter is the default
    #[argh(option)]
    #[serde(default)]
    pub plugins: Option<String>,
    /// update nuclei plugins
    #[argh(switch)]
    #[serde(default)]
    pub update_plugins: bool,
    /// update self
    #[argh(switch)]
    #[serde(skip)]
    pub update_self: bool,
    /// number of concurrent threads.
    #[argh(option, default = "default_thread()")]
    #[serde(default = "default_thread")]
    pub thread: u32,
    /// send results to webhook server (ex:https://host:port/webhook)
    #[argh(option)]
    #[serde(default)]
    pub webhook: Option<String>,
    /// the auth will be set to the webhook request header AUTHORIZATION
    #[argh(option)]
    #[serde(default)]
    pub webhook_auth: Option<String>,
    /// using nmap fingerprint identification service (slow)
    #[argh(switch)]
    #[serde(default)]
    pub service: bool,
    /// start a web API service (ex:127.0.0.1:8080)
    #[argh(option, short = 's')]
    #[serde(skip)]
    pub api_server: Option<String>,
    /// api Bearer authentication
    #[argh(option, default = "default_token()")]
    #[serde(skip)]
    pub token: String,
    /// customized ua
    #[argh(option, default = "default_ua()")]
    #[serde(skip)]
    pub ua: String,
    /// api background service
    #[argh(switch)]
    #[serde(skip)]
    pub daemon: bool,
    /// danger mode
    #[argh(switch)]
    #[serde(skip)]
    pub danger: bool,
    /// silent mode
    #[argh(switch)]
    #[serde(skip)]
    pub silent: bool,
    /// filter mode,Display only the fingerprint that is not empty
    #[argh(switch)]
    #[serde(skip)]
    pub filter: bool,
    /// include request/response pairs in the JSONL output
    #[argh(switch)]
    #[serde(skip)]
    pub irr: bool,
    /// nuclei args
    #[argh(option)]
    #[serde(skip)]
    pub nargs: Option<String>,
}

fn default_thread() -> u32 {
    32_u32
}

// fn default_targets() -> Vec<String> {
//     Vec::new()
// }
fn default_token() -> String {
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
            return hex;
        }
    }
    String::new()
}

fn default_ua() -> String {
    String::from("Mozilla/5.0 (X11; Linux x86_64; rv:94.0) Gecko/20100101 Firefox/94.0")
}

fn default_timeout() -> u64 {
    10
}

impl ObserverWardConfig {
    pub fn new() -> Self {
        let mut default: ObserverWardConfig = argh::from_env();
        if let Some(mut nuclei_path) = default.plugins {
            if !has_nuclei_app() {
                println!("Please install nuclei to the environment variable!");
                process::exit(0);
            }
            if nuclei_path == "default" {
                nuclei_path = OBSERVER_WARD_PATH
                    .join("plugins")
                    .to_str()
                    .unwrap_or_default()
                    .to_string();
            }
            if !Path::new(&nuclei_path).exists() {
                println!("The '{}' directory does not exist!", nuclei_path);
                process::exit(0);
            } else {
                default.plugins = Some(nuclei_path);
            }
        }
        default
    }
    pub fn use_nuclei(&self) -> bool {
        self.path.is_some() || self.plugins.is_some()
    }
}

pub fn has_nuclei_app() -> bool {
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
