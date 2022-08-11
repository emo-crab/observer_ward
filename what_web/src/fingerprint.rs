use std::collections::HashMap;

use serde::{Deserialize, Serialize};

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
    pub name: String,
    path: String,
    status_code: u16,
    headers: HashMap<String, String>,
    keyword: Vec<String>,
    #[serde(default)]
    pub priority: u32,
    request_method: String,
    request_headers: HashMap<String, String>,
    request_data: String,
    #[serde(default)]
    favicon_hash: Vec<String>,
}

impl Default for WebFingerPrint {
    fn default() -> Self {
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
            let is_index = || {
                f_rule.path == "/"
                    && f_rule.request_headers.is_empty()
                    && f_rule.request_method.to_uppercase() == "GET"
                    && f_rule.request_data.is_empty()
                    && f_rule.favicon_hash.is_empty()
            };
            // 首页请求，有FaviconHash
            if is_index() {
                index.push(v3_web_fingerprint);
            } else if !f_rule.favicon_hash.is_empty() {
                favicon.push(v3_web_fingerprint.clone());
                // 固定路径的FaviconHash
                if f_rule.path != "/" {
                    special.push(v3_web_fingerprint);
                }
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
