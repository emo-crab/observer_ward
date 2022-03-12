extern crate clap;

use std::collections::HashSet;
use std::path::Path;
use std::process;
use std::process::{Command, Stdio};
use crate::OBSERVER_WARD_PATH;
use clap::{App, Arg};
use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct ObserverWardConfig {
    #[serde(skip)]
    pub target: String,
    #[serde(default)]
    pub targets: HashSet<String>,
    #[serde(skip)]
    pub stdin: bool,
    #[serde(skip)]
    pub verify: String,
    #[serde(skip)]
    pub file: String,
    #[serde(default)]
    pub update_fingerprint: bool,
    #[serde(skip)]
    pub csv: String,
    #[serde(skip)]
    pub json: String,
    #[serde(default)]
    pub proxy: String,
    #[serde(default = "default_timeout")]
    pub timeout: u64,
    #[serde(default)]
    pub plugins: String,
    #[serde(default)]
    pub update_plugins: bool,
    #[serde(skip)]
    pub update_self: bool,
    #[serde(default = "default_thread")]
    pub thread: u32,
    #[serde(default)]
    pub webhook: String,
    #[serde(default)]
    pub service: bool,
    #[serde(skip)]
    pub api_server: String,
    #[serde(skip)]
    pub daemon: bool,
}

fn default_thread() -> u32 {
    100 as u32
}

fn default_timeout() -> u64 {
    10
}

impl Default for ObserverWardConfig {
    fn default() -> Self {
        Self {
            target: String::new(),
            targets: Default::default(),
            stdin: false,
            verify: String::new(),
            file: String::new(),
            update_fingerprint: false,
            csv: String::new(),
            json: String::new(),
            proxy: String::new(),
            timeout: 10,
            plugins: String::new(),
            update_plugins: false,
            update_self: false,
            thread: 100,
            webhook: String::new(),
            service: false,
            api_server: String::new(),
            daemon: false,
        }
    }
}

impl ObserverWardConfig {
    pub fn new() -> Self {
        let app = App::new("ObserverWard")
            .version("0.0.1")
            // .about("about: Community based web fingerprint analysis tool.")
            .author("author: Kali-Team")
            .arg(
                Arg::with_name("target")
                    .short("t")
                    .long("target")
                    .value_name("TARGET")
                    .help("The target URL(s) (required, unless --stdin used)"),
            )
            .arg(
                Arg::with_name("rest_api")
                    .short("s")
                    .long("rest_api")
                    .value_name("SERVER")
                    .help("Start a web API service (ex: 127.0.0.1:8080)"),
            )
            .arg(
                Arg::with_name("stdin")
                    .long("stdin")
                    .takes_value(false)
                    .help("Read url(s) from STDIN")
                    .conflicts_with("url"),
            )
            .arg(
                Arg::with_name("file")
                    .short("f")
                    .long("file")
                    .value_name("FILE")
                    .help("Read the target from the file"),
            )
            .arg(
                Arg::with_name("daemon")
                    .long("daemon")
                    .takes_value(false)
                    .help("API background service")
                    .conflicts_with("url"),
            )
            .arg(
                Arg::with_name("csv")
                    .short("c")
                    .long("csv")
                    .value_name("CSV")
                    .help("Export to the csv file or Import form the csv file"),
            )
            .arg(
                Arg::with_name("json")
                    .short("j")
                    .long("json")
                    .value_name("JSON")
                    .help("Export to the json file or Import form the json file"),
            )
            .arg(
                Arg::with_name("proxy")
                    .long("proxy")
                    .takes_value(true)
                    .value_name("PROXY")
                    .help("Proxy to use for requests (ex: [http(s)|socks5(h)]://host:port)"),
            )
            .arg(
                Arg::with_name("webhook")
                    .long("webhook")
                    .takes_value(true)
                    .value_name("WEBHOOK")
                    .help("Send results to webhook server (ex: https://host:port/webhook)"),
            )
            .arg(
                Arg::with_name("timeout")
                    .long("timeout")
                    .takes_value(true)
                    .default_value("10")
                    .value_name("TIMEOUT")
                    .help("Set request timeout."),
            )
            .arg(
                Arg::with_name("thread")
                    .long("thread")
                    .takes_value(true)
                    .default_value("100")
                    .value_name("THREAD")
                    .help("Number of concurrent threads."),
            )
            .arg(
                Arg::with_name("verify")
                    .long("verify")
                    .takes_value(true)
                    .help("Validate the specified yaml file"),
            )
            .arg(
                Arg::with_name("service")
                    .long("service")
                    .help("Using nmap fingerprint identification service (slow)"),
            )
            .arg(
                Arg::with_name("plugins")
                    .long("plugins")
                    .takes_value(true)
                    .help("The 'plugins' directory is used when the parameter is the 'default'"),
            )
            .arg(
                Arg::with_name("update_plugins")
                    .long("update_plugins")
                    .takes_value(false)
                    .help("Update nuclei plugins"),
            )
            .arg(
                Arg::with_name("update_self")
                    .long("update_self")
                    .takes_value(false)
                    .help("Update self"),
            )
            .arg(
                Arg::with_name("update_fingerprint")
                    .short("u")
                    .long("update_fingerprint")
                    .takes_value(false)
                    .help("Update web fingerprint"),
            );
        let args = app.get_matches();
        let mut default = ObserverWardConfig::default();
        if args.is_present("stdin") {
            default.stdin = true;
        }
        if args.is_present("service") {
            default.service = true;
        }
        if args.is_present("daemon") {
            default.daemon = true;
        }
        if args.is_present("update_plugins") {
            default.update_plugins = true;
        }
        if args.is_present("update_self") {
            default.update_self = true;
        }
        if args.is_present("update_fingerprint") {
            default.update_fingerprint = true;
        }
        if let Some(nuclei) = args.value_of("plugins") {
            if !has_nuclei_app() {
                println!("Please install nuclei to the environment variable!");
                process::exit(0);
            }
            default.plugins = nuclei.to_string();
            if default.plugins == "default" {
                default.plugins = OBSERVER_WARD_PATH.join("plugins").to_str().unwrap_or_default().to_string();
            }
            if !Path::new(&default.plugins).exists() {
                println!("The '{}' directory does not exist!", default.plugins);
                process::exit(0);
            }
        }
        if let Some(target) = args.value_of("target") {
            default.target = target.to_string();
        };
        if let Some(webhook) = args.value_of("webhook") {
            default.webhook = webhook.to_string();
        };
        if let Some(server) = args.value_of("rest_api") {
            default.api_server = server.to_string();
        };
        if let Some(file) = args.value_of("file") {
            default.file = file.to_string();
        };
        if let Some(verify) = args.value_of("verify") {
            default.verify = verify.to_string();
        };
        if let Some(file) = args.value_of("csv") {
            default.csv = file.to_string();
        };
        if let Some(file) = args.value_of("json") {
            default.json = file.to_string();
        };
        if let Some(proxy) = args.value_of("proxy") {
            default.proxy = proxy.to_string();
        };
        if let Some(timeout) = args.value_of("timeout") {
            default.timeout = timeout.parse().unwrap_or(10);
        };
        if let Some(thread) = args.value_of("thread") {
            default.thread = thread.parse().unwrap_or(100);
        };
        return default;
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
