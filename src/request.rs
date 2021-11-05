use serde::{Deserialize, Serialize};
use reqwest::header::{HeaderMap, HeaderName, HeaderValue, LOCATION};
use reqwest::redirect::Policy;
use reqwest::{Body, header, Method, Proxy, Response};
use encoding_rs::{Encoding, UTF_8};
use mime::Mime;
use regex::Regex;
use url::Url;
use scraper::{Html, Selector};
use cached::proc_macro::cached;
use cached::SizedCache;
use std::{fmt, process};
use std::collections::{HashMap, HashSet};
use std::iter::FromIterator;
use std::str::FromStr;
use std::time::Duration;
use std::sync::Arc;
use md5::{Digest, Md5};
use super::CONFIG;
use crate::fingerprint::WebFingerPrintRequest;
use crate::ward::RawData;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum WardError {
    Fetch(String),
    Analyze(String),
    Other(String),
}

impl fmt::Display for WardError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}",
            match self {
                WardError::Fetch(err) => format!("Fetch/{}", err),
                WardError::Analyze(err) => format!("Analyze/{}", err),
                WardError::Other(err) => format!("Other/{}", err),
            }
        )
    }
}

impl std::convert::From<std::io::Error> for WardError {
    fn from(err: std::io::Error) -> Self {
        WardError::Other(err.to_string())
    }
}

impl From<&dyn std::error::Error> for WardError {
    fn from(err: &dyn std::error::Error) -> Self {
        WardError::Other(err.to_string())
    }
}

impl From<reqwest::Error> for WardError {
    fn from(err: reqwest::Error) -> Self {
        WardError::Other(err.to_string())
    }
}

impl From<std::str::Utf8Error> for WardError {
    fn from(err: std::str::Utf8Error) -> Self {
        WardError::Other(err.to_string())
    }
}

impl From<url::ParseError> for WardError {
    fn from(err: url::ParseError) -> Self {
        WardError::Other(err.to_string())
    }
}

async fn send_requests(
    mut url: Url,
    fingerprint: &WebFingerPrintRequest,
) -> Result<Response, reqwest::Error> {
    let mut headers = header::HeaderMap::new();
    let ua = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/92.0.4515.107 Safari/537.36";
    headers.insert(header::USER_AGENT, header::HeaderValue::from_static(ua));
    let method = Method::from_str(&fingerprint.request_method.to_uppercase()).unwrap_or(Method::GET);
    let body_data = Body::from(base64::decode(fingerprint.request_data.clone()).unwrap_or_default());
    if !fingerprint.request_headers.is_empty() {
        for (k, v) in fingerprint.request_headers.clone() {
            headers.insert(
                HeaderName::from_str(&k).unwrap(),
                HeaderValue::from_str(&v).unwrap(),
            );
        }
    }
    if fingerprint.path != "/" {
        url.set_path(fingerprint.path.as_str());
    }

    let client = reqwest::Client::builder()
        .danger_accept_invalid_certs(true)
        .default_headers(headers.clone())
        .redirect(Policy::none())
        .timeout(Duration::new(CONFIG.timeout, 0));

    if !CONFIG.proxy.is_empty() {
        match Url::parse(CONFIG.proxy.clone().as_str()) {
            Ok(proxy_uri) => {
                let proxy_obj = Proxy::all(proxy_uri).unwrap();
                return client
                    .proxy(proxy_obj)
                    .build()
                    .unwrap()
                    .request(method, url.as_ref())
                    .body(body_data)
                    .send()
                    .await;
            }
            Err(_) => {
                println!("Invalid Proxy Uri");
                process::exit(0);
            }
        };
    }
    return client.build()
        .unwrap()
        .request(method, url.as_ref())
        .body(body_data)
        .send().await;
}
lazy_static! {
    static ref RE_COMPILE_BY_CHARSET: Regex = Regex::new(r#"(?im)charset="(.*?)"|charset=(.*?)""#).unwrap() ;
}
fn get_default_encoding(byte: &[u8], headers: HeaderMap) -> String {
    let (html, _, _) = UTF_8.decode(byte);
    let mut default_encoding = "utf-8";
    for charset in RE_COMPILE_BY_CHARSET.captures(&html) {
        for cs in charset.iter() {
            if let Some(c) = cs {
                default_encoding = c.as_str();
            }
        }
    }
    let content_type = headers
        .get(header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.parse::<Mime>().ok());
    let encoding_name = content_type
        .as_ref()
        .and_then(|mime| mime.get_param("charset").map(|charset| charset.as_str()))
        .unwrap_or(default_encoding);
    let encoding = Encoding::for_label(encoding_name.as_bytes()).unwrap_or(UTF_8);
    let (text, _, _) = encoding.decode(byte);
    text.to_lowercase()
}

async fn fetch_raw_data(res: Response, is_index: bool) -> Result<Arc<RawData>, WardError> {
    let path: String = res.url().path().to_string();
    let url = res.url().join("/").unwrap();
    let status_code = res.status();
    let headers = res.headers().clone();
    let base_url = res.url().clone();
    let text = match res.bytes().await {
        Ok(byte) => get_default_encoding(&byte, headers.clone()),
        Err(_) => String::from(""),
    };
    let mut favicon: HashMap<String, String> = HashMap::new();
    if is_index && !status_code.is_server_error() {
        // 只有在首页的时候提取favicon图标链接
        favicon = find_favicon_tag(base_url, &text).await;
    }
    let lang_set: HashSet<String> = get_lang(&headers);
    let raw_data = Arc::new(RawData {
        url,
        path,
        headers,
        status_code,
        text,
        favicon,
        lang_set,
    });
    Ok(raw_data)
}

// favicon的URL到Hash
#[cached(
type = "SizedCache<String, String>",
create = "{ SizedCache::with_size(100) }",
result = true,
convert = r#"{ format!("{}", url.as_str().to_owned()) }"#
)]
async fn get_favicon_hash(url: Url) -> Result<String, WardError> {
    let default_request = WebFingerPrintRequest {
        path: "/".to_string(),
        request_method: "get".to_string(),
        request_headers: Default::default(),
        request_data: "".to_string(),
    };
    match send_requests(url, &default_request).await {
        Ok(res) => {
            let status_code = res.status();
            if !res.status().is_success() {
                return Err(WardError::Fetch(format!(
                    "Non-200 status code: {}",
                    status_code
                )));
            }
            let content = res.bytes().await?;
            let mut hasher = Md5::new();
            hasher.update(content);
            let result = hasher.finalize();
            let favicon_md5: String = format!("{:x}", (&result));
            Ok(favicon_md5)
        }
        Err(err) => {
            Err(WardError::Fetch(format!("{}", err)))
        }
    }
}

// 从HTML标签中提取favicon的链接
async fn find_favicon_tag(
    base_url: reqwest::Url,
    text: &String,
) -> HashMap<String, String> {
    let parsed_html = Html::parse_fragment(&text);
    let selector = Selector::parse("link").unwrap();
    let mut link_tags = HashMap::new();
    let path_list = parsed_html.select(&selector);
    for link in path_list.into_iter() {
        if let (Some(href), Some(rel)) = (link.value().attr("href"), link.value().attr("rel")) {
            if ["icon", "shortcut icon"].contains(&rel) {
                let favicon_url = base_url.join(href).unwrap();
                if let Ok(favicon_md5) = get_favicon_hash(favicon_url.clone()).await {
                    link_tags.insert(String::from(favicon_url.clone()), favicon_md5);
                };
            }
        }
    }
    // 补充默认路径
    let favicon_url = base_url.join("/favicon.ico").unwrap();
    if !link_tags.contains_key(&String::from(favicon_url.clone())) {
        if let Ok(favicon_md5) = get_favicon_hash(favicon_url.clone()).await {
            link_tags.insert(String::from(favicon_url.clone()), favicon_md5);
        };
    }
    return link_tags;
}
lazy_static! {
    static ref RE_COMPILE_BY_JUMP: Vec<Regex> = {
        let js_reg = vec![
            r#"(?im)[ |.|:]location\.href=['|"](?P<name>.*?)['|"]"#,
            r#"(?im)window\.open\(['|"](?P<name>.*?)['|"]"#,
            r#"(?im)<meta.*?http-equiv=.*?refresh.*?url=(?P<name>.*?)['|"]>"#];
        let re_list:Vec<Regex> = js_reg.iter().map(|reg|Regex::new(reg).unwrap()).collect();
        re_list
    };
}
//首页请求
#[cached(
type = "SizedCache<String, Vec<Arc<RawData>>>",
create = "{ SizedCache::with_size(100) }",
result = true,
convert = r#"{ format!("{}{:?}", url_str.to_owned(), special_wfp) }"#
)]
pub async fn index_fetch(
    url_str: &String,
    special_wfp: &WebFingerPrintRequest,
    is_index: bool,
    is_special: bool,
) -> Result<Vec<Arc<RawData>>, WardError> {
    let mut is_index: bool = is_index;
    let mut is_start_with_http: bool = true;
    let mut raw_data_list: Vec<Arc<RawData>> = vec![];
    let schemes: [String; 2] = ["https://".to_string(), "http://".to_string()];
    for mut scheme in schemes {
        //最大重定向跳转次数
        let mut max_redirect = 3;
        let mut scheme_url = url_str.clone();
        if !url_str.to_lowercase().starts_with("http://")
            && !url_str.to_lowercase().starts_with("https://")
        {
            scheme.push_str(url_str.as_str());
            scheme_url = scheme;
            is_start_with_http = false;
        }
        let mut url = match Url::parse(scheme_url.as_str()) {
            Ok(url) => url,
            Err(err) => {
                return Err(WardError::Other(format!("{:?}", err)));
            }
        };
        let get_next_url = |headers: &HeaderMap, url: &Url, text: &String, is_index: bool| {
            let mut next_url = headers
                .get(LOCATION)
                .and_then(|location| location.to_str().ok())
                .and_then(|location| url.join(location).ok());
            if next_url.is_none() && is_index && text.len() <= 1024 {
                for reg in RE_COMPILE_BY_JUMP.iter() {
                    if let Some(x) = reg.captures(&text) {
                        let u = x.name("name").map_or("", |m| m.as_str());
                        if u.starts_with("http://") || u.starts_with("https://") {
                            next_url = Some(Url::parse(u).unwrap_or(url.clone()));
                            break;
                        }
                        next_url = Some(url.join(u).unwrap_or(url.clone()));
                        break;
                    }
                }
            }
            return next_url;
        };
        loop {
            let mut next_url: Option<Url> = Option::None;
            if let Ok(res) = send_requests(url.clone(), special_wfp).await {
                if let Ok(raw_data) = fetch_raw_data(res, is_index).await {
                    next_url = get_next_url(&raw_data.headers, &url, &raw_data.text, is_index);
                    raw_data_list.push(raw_data);
                };
                is_index = false;
            };
            if is_special {
                break;
            }
            match next_url.clone() {
                Some(next_jump_url) => {
                    url = next_jump_url;
                }
                None => {
                    break;
                }
            }
            max_redirect -= 1;
            if max_redirect <= 0 {
                break;
            }
        }
        if is_start_with_http {
            break;
        }
    }
    return Ok(raw_data_list);
}

pub fn get_title(raw_data: &Arc<RawData>) -> String {
    let parsed_html = Html::parse_fragment(&raw_data.text);
    let selector = Selector::parse("title").unwrap();
    for title in parsed_html.select(&selector).into_iter() {
        let title: String = title.inner_html().trim().to_string();
        return title;
    }
    return String::new();
}

fn get_lang(headers: &HeaderMap) -> HashSet<String> {
    let headers = format!("{:?}", headers.clone());
    let cookie_to_lang_map: HashMap<&str, &str> = HashMap::from_iter(
        [("phpsessid", ".php"), ("jsessionid", ".jsp"), ("aspsession", ".asp"), ]
    );
    let mut lang_set: HashSet<String> = HashSet::new();
    for (header_flag, lang) in cookie_to_lang_map.into_iter() {
        if headers.contains(header_flag) {
            lang_set.insert(lang.to_string());
        }
    }
    return lang_set;
}