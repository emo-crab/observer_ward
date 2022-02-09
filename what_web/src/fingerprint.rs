use std::collections::HashMap;
use std::env;
use std::fs::File;
use std::io::Read;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct VerifyWebFingerPrint {
    name: String,
    priority: u32,
    fingerprint: Vec<WebFingerPrint>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct WebFingerPrintRequest {
    pub path: String,
    pub request_method: String,
    pub request_headers: HashMap<String, String>,
    pub request_data: String,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct WebFingerPrintMatch {
    pub status_code: u16,
    #[serde(default)]
    pub favicon_hash: Vec<String>,
    pub headers: HashMap<String, String>,
    pub keyword: Vec<String>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct V3WebFingerPrint {
    #[serde(default)]
    pub name: String,
    #[serde(default)]
    pub priority: u32,
    pub request: WebFingerPrintRequest,
    pub match_rules: WebFingerPrintMatch,
}

//TODO 整理lib文件
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct WebFingerPrint {
    #[serde(default)]
    name: String,
    path: String,
    status_code: u16,
    headers: HashMap<String, String>,
    keyword: Vec<String>,
    #[serde(default)]
    priority: u32,
    request_method: String,
    request_headers: HashMap<String, String>,
    request_data: String,
    #[serde(default)]
    favicon_hash: Vec<String>,
}

impl WebFingerPrint {
    pub fn new() -> Self {
        Self {
            path: String::new(),
            name: String::new(),
            status_code: 0,
            headers: HashMap::new(),
            keyword: vec![],
            priority: 1,
            request_method: String::new(),
            request_headers: HashMap::new(),
            request_data: String::new(),
            favicon_hash: vec![],
        }
    }
}

// 将指纹分成首页识别，特殊请求识别和favicon的哈希识别
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct WebFingerPrintLib {
    pub index: Vec<V3WebFingerPrint>,
    pub special: Vec<V3WebFingerPrint>,
    pub favicon: Vec<V3WebFingerPrint>,
}

impl WebFingerPrintLib {
    pub fn new(web_fingerprint: Vec<WebFingerPrint>) -> Self {
        let mut index: Vec<V3WebFingerPrint> = vec![];
        let mut special: Vec<V3WebFingerPrint> = vec![];
        let mut favicon: Vec<V3WebFingerPrint> = vec![];
        for f_rule in web_fingerprint {
            let request = WebFingerPrintRequest {
                path: f_rule.path.clone(),
                request_method: f_rule.request_method.clone(),
                request_headers: f_rule.request_headers.clone(),
                request_data: f_rule.request_data.clone(),
            };
            let match_rules = WebFingerPrintMatch {
                status_code: f_rule.status_code,
                favicon_hash: f_rule.favicon_hash.clone(),
                headers: f_rule.headers,
                keyword: f_rule.keyword,
            };
            let v3_web_fingerprint = V3WebFingerPrint {
                name: f_rule.name,
                priority: f_rule.priority,
                request,
                match_rules,
            };
            if f_rule.path == "/"
                && f_rule.request_headers.is_empty()
                && f_rule.request_method == "get"
                && f_rule.request_data.is_empty()
                && f_rule.favicon_hash.is_empty()
            {
                index.push(v3_web_fingerprint);
            } else if !f_rule.favicon_hash.is_empty() {
                favicon.push(v3_web_fingerprint);
            } else {
                special.push(v3_web_fingerprint);
            }
        }
        Self {
            index,
            special,
            favicon,
        }
    }
}

pub fn read_form_file(verify: &String) -> Vec<WebFingerPrint> {
    let self_path: PathBuf = env::current_exe().unwrap_or(PathBuf::new());
    let path = Path::new(&self_path).parent().unwrap_or(Path::new(""));
    return if !verify.is_empty() {
        let mut file = match File::open(verify.clone()) {
            Err(_) => {
                println!("The verification file cannot be found in the current directory!");
                std::process::exit(0);
            }
            Ok(file) => file,
        };
        let mut data = String::new();
        file.read_to_string(&mut data).ok();
        let mut web_fingerprint: Vec<WebFingerPrint> = vec![];
        let verify_fingerprints: VerifyWebFingerPrint =
            serde_yaml::from_str(&data).expect("BAD YAML");
        for mut verify_fingerprint in verify_fingerprints.fingerprint {
            verify_fingerprint.name = verify_fingerprints.name.clone();
            verify_fingerprint.priority = verify_fingerprints.priority.clone();
            web_fingerprint.push(verify_fingerprint);
        }
        web_fingerprint
    } else {
        let mut file = match File::open(path.join("web_fingerprint_v3.json")) {
            Err(_) => {
                println!("The fingerprint library cannot be found in the current directory!");
                println!("Update fingerprint library with `-u` parameter!");
                std::process::exit(0);
            }
            Ok(file) => file,
        };
        let mut data = String::new();
        file.read_to_string(&mut data).ok();
        let web_fingerprint: Vec<WebFingerPrint> = serde_json::from_str(&data).expect("BAD JSON");
        web_fingerprint
    };
}
