use std::collections::{HashMap, HashSet};
use std::iter::FromIterator;
use std::marker::PhantomData;
use std::path::PathBuf;
use std::str;
use std::sync::Arc;
use std::{fmt, process};
use url::Url;

use fingerprint::{WebFingerPrintLib, WebFingerPrintRequest};
use request::{get_title, index_fetch};
use serde::{de, Deserialize, Deserializer, Serialize};
use ward::check;

use crate::fingerprint::WebFingerPrint;

pub mod fingerprint;
mod request;
mod ward;

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct WhatWebResult {
    /// URL
    pub url: String,
    /// 组件列表
    #[serde(deserialize_with = "string_to_hashset")]
    pub name: HashSet<String>,
    /// 权重，状态码200,有标题，有指纹，有漏洞都会累加一
    pub priority: u32,
    /// 响应长度
    pub length: usize,
    /// 标题
    pub title: String,
    /// 状态码
    pub status_code: u16,
    /// 是否为Web
    #[serde(default)]
    pub is_web: bool,
    /// nuclei的template-id
    #[serde(default)]
    pub plugins: HashSet<String>,
    /// nuclei部分数据，在`--irr`参数开启就会保存到json
    #[serde(skip_serializing_if = "Option::is_none")]
    pub plugins_result: Option<Vec<TemplateResult>>,
}

impl WhatWebResult {
    pub fn new(url: String) -> Self {
        Self {
            url,
            name: HashSet::new(),
            priority: 0,
            length: 0,
            status_code: 0,
            title: String::new(),
            plugins: HashSet::new(),
            plugins_result: None,
            is_web: true,
        }
    }
}

#[derive(Debug, Clone)]
pub struct RequestOption {
    /// 请求的超时
    timeout: u64,
    /// 请求代理
    pub proxy: Option<Url>,
    /// 验证规则的关键词
    verify_keyword: String,
    /// 验证参数是否为文件路径
    is_path: bool,
    /// 静默模式，不打印
    silent: bool,
    // danger mode
    danger: bool,
    // ua
    ua: String,
}

impl RequestOption {
    pub fn new(
        timeout: &u64,
        proxy: &Option<String>,
        verify_keyword: &Option<String>,
        silent: bool,
        danger: bool,
        ua: &str,
    ) -> Self {
        let mut is_exists = false;
        let mut default_verify_path = String::new();
        if let Some(verify_path) = verify_keyword {
            is_exists = PathBuf::from(&verify_path).exists();
            default_verify_path = verify_path.clone();
        }
        if let Some(proxy_url) = proxy {
            match Url::parse(proxy_url) {
                Ok(u) => {
                    let proxy_url = Some(u);
                    Self {
                        timeout: *timeout,
                        proxy: proxy_url,
                        verify_keyword: default_verify_path,
                        is_path: is_exists,
                        silent,
                        danger,
                        ua: ua.to_string(),
                    }
                }
                Err(err) => {
                    println!("Invalid Proxy Uri {}", err);
                    process::exit(0);
                }
            }
        } else {
            Self {
                timeout: *timeout,
                proxy: None,
                verify_keyword: default_verify_path,
                is_path: is_exists,
                silent,
                danger,
                ua: ua.to_string(),
            }
        }
    }
}

#[derive(Clone)]
pub struct WhatWeb {
    /// 指纹规则库
    fingerprint: Arc<WebFingerPrintLib>,
    /// 请求配置
    config: RequestOption,
}

impl WhatWeb {
    pub fn new(config: RequestOption, web_fingerprint: Vec<WebFingerPrint>) -> Self {
        let fingerprint: Arc<WebFingerPrintLib> = Arc::new(WebFingerPrintLib::new(web_fingerprint));
        Self {
            fingerprint,
            config,
        }
    }
    pub async fn scan(&self, url: String) -> WhatWebResult {
        let mut name: HashSet<String> = HashSet::new();
        let mut what_web_result: WhatWebResult = WhatWebResult::new(url.clone());
        let default_request = WebFingerPrintRequest {
            path: String::from("/"),
            request_method: String::from("get"),
            request_headers: Default::default(),
            request_data: String::new(),
        };
        // https和http都可以访问的情况下，在特殊路径都要请求
        let mut http_https_set = HashSet::new();
        if let Ok(rdl) = index_fetch(&url, &default_request, true, self.config.clone(), false).await
        {
            if rdl.is_empty() {
                what_web_result.is_web = false;
            }
            //首页请求允许跳转
            for raw_data in rdl {
                http_https_set.insert(raw_data.url.scheme().to_lowercase());
                let web_name_set =
                    check(&raw_data, &self.fingerprint.to_owned(), &self.config).await;
                for (k, v) in web_name_set {
                    name.insert(k);
                    what_web_result.priority = v;
                }
                if url.starts_with("http://") || url.starts_with("https://") {
                    // 本来有的协议
                    what_web_result.url = url.clone();
                } else if what_web_result.url.starts_with("http://")
                    || what_web_result.url.starts_with("https://")
                {
                } else {
                    what_web_result.url = raw_data.url.as_str().to_string();
                }
                what_web_result.length = raw_data.text.len();
                if what_web_result.status_code == 0 || raw_data.status_code.is_success() {
                    what_web_result.status_code = raw_data.status_code.as_u16();
                }
                if (raw_data.next_url.is_none() && what_web_result.title.is_empty())
                    || raw_data.status_code.is_success()
                {
                    what_web_result.title = get_title(&raw_data.text);
                    what_web_result.priority += 1;
                    if what_web_result.url.starts_with("http://")
                        && raw_data.url.as_str().starts_with("https://")
                    {
                        what_web_result.url = what_web_result.url.replace("http://", "https://");
                    } else if what_web_result.url.starts_with("https://")
                        && raw_data.url.as_str().starts_with("http://")
                    {
                        what_web_result.url = what_web_result.url.replace("https://", "http://");
                    }
                }
                if raw_data.status_code.is_success() {
                    what_web_result.priority += 1;
                }
            }
        };
        // 在首页请求时不是Web也没必要跑特殊请求了
        if !what_web_result.is_web {
            return what_web_result;
        }
        for special_wfp in self.fingerprint.to_owned().special.iter() {
            if let Ok(rdl) = index_fetch(
                &what_web_result.url,
                &special_wfp.request,
                false,
                self.config.clone(),
                http_https_set.len() == 2,
            )
            .await
            {
                for raw_data in rdl {
                    let web_name_set =
                        check(&raw_data, &self.fingerprint.to_owned(), &self.config).await;
                    for (k, v) in web_name_set {
                        name.insert(k);
                        what_web_result.priority = v;
                    }
                }
            }
        }
        if name.len() > 10 {
            let count = name.len();
            name.clear();
            name.insert(format!("Honeypot 蜜罐{}", count));
        }
        what_web_result.name = name.clone();
        what_web_result
    }
}

/// 部分nuclei的数据结构
#[derive(Debug, Serialize, Deserialize, Clone, Default)]
pub struct TemplateResult {
    #[serde(default)]
    pub template: String,
    #[serde(rename = "template-id")]
    pub template_id: String,
    #[serde(rename = "matched-at")]
    pub matched_at: String,
    #[serde(default)]
    pub meta: HashMap<String, String>,
    #[serde(default)]
    pub info: TemplateInfo,
    #[serde(rename = "curl-command")]
    pub curl_command: String,
    #[serde(rename = "type", default)]
    pub p_type: String,
    #[serde(default)]
    pub host: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub request: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub response: Option<String>,
    #[serde(default)]
    pub ip: String,
}

#[derive(Debug, Serialize, Deserialize, Clone, Default)]
pub struct TemplateInfo {
    #[serde(default)]
    pub severity: String,
    #[serde(default)]
    pub name: String,
    #[serde(default)]
    pub description: String,
}

/// 字符串转set
fn string_to_hashset<'de, D>(deserializer: D) -> Result<HashSet<String>, D::Error>
where
    D: Deserializer<'de>,
{
    struct StringToHashSet(PhantomData<HashSet<String>>);
    impl<'de> de::Visitor<'de> for StringToHashSet {
        type Value = HashSet<String>;
        fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
            formatter.write_str("string or list of strings")
        }
        fn visit_str<E>(self, value: &str) -> Result<Self::Value, E>
        where
            E: de::Error,
        {
            let name: Vec<String> = value.split_terminator('\n').map(String::from).collect();
            Ok(HashSet::from_iter(name))
        }
        fn visit_seq<S>(self, visitor: S) -> Result<Self::Value, S::Error>
        where
            S: de::SeqAccess<'de>,
        {
            Deserialize::deserialize(de::value::SeqAccessDeserializer::new(visitor))
        }
    }
    deserializer.deserialize_any(StringToHashSet(PhantomData))
}
