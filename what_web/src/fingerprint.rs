use reqwest::header::{HeaderMap, HeaderName, HeaderValue};
use reqwest::{Body, Method};
use std::collections::HashMap;
use std::str::FromStr;

use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct WebFingerPrintRequest {
    /// 请求路径
    pub path: String,
    /// 请求方法
    pub request_method: String,
    /// 请求头
    pub request_headers: HashMap<String, String>,
    /// 请求数据，base64编码后的
    pub request_data: String,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct WebFingerPrintMatch {
    /// 匹配状态码
    pub status_code: u16,
    /// 匹配favicon的hash列表
    #[serde(default)]
    pub favicon_hash: Vec<String>,
    /// 匹配的请求头
    pub headers: HashMap<String, String>,
    /// 匹配的关键词列表
    pub keyword: Vec<String>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct V3WebFingerPrint {
    /// 组件名称
    #[serde(default)]
    pub name: String,
    /// 权重
    #[serde(default)]
    pub priority: u32,
    /// 指纹的自定义请求
    pub request: WebFingerPrintRequest,
    /// 匹配部分
    pub match_rules: WebFingerPrintMatch,
}

/// 单个指纹结构
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
    /// 首页的指纹
    pub index: Vec<V3WebFingerPrint>,
    /// 特殊自定义请求的指纹
    pub special: Vec<V3WebFingerPrint>,
    /// 存在favicon的指纹
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

impl WebFingerPrintRequest {
    pub fn get_method(&self) -> Method {
        Method::from_str(&self.request_method.to_uppercase()).unwrap_or(Method::GET)
    }
    pub fn get_body(&self) -> Body {
        Body::from(base64::decode(self.request_data.clone()).unwrap_or_default())
    }
    pub fn set_header(&self, headers: &mut HeaderMap) {
        if !self.request_headers.is_empty() {
            for (k, v) in self.request_headers.clone() {
                if let (Ok(k), Ok(v)) = (HeaderName::from_str(&k), HeaderValue::from_str(&v)) {
                    headers.insert(k, v);
                }
            }
        }
    }
}
