#[macro_use]
extern crate lazy_static;

mod cli;
pub mod ward;

use cli::WardArgs;
use colored::Colorize;
use encoding_rs::{Encoding, UTF_8};
use mime::Mime;
use regex::Regex;
use reqwest::header::{HeaderMap, HeaderName, HeaderValue, LOCATION};
use reqwest::redirect::Policy;
use reqwest::{Body, header, Method, Proxy, Response};
use scraper::{Html, Selector};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::collections::HashSet;
use std::fs::File;
use std::io::Cursor;
use std::io::Read;
use std::io::{self, BufRead};
use std::iter::FromIterator;
use std::path::{Path, PathBuf};
use std::str;
use std::str::FromStr;
use std::sync::Arc;
use std::time::Duration;
use std::{env, fmt, process};
use url::Url;
use ward::{check, RawData};
use md5::{Digest, Md5};
use std::sync::RwLock;

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct VerifyWebFingerPrint {
    name: String,
    priority: u32,
    fingerprint: Vec<WebFingerPrint>,
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
            path: String::from(""),
            name: String::from(""),
            status_code: 0,
            headers: HashMap::new(),
            keyword: vec![],
            priority: 1,
            request_method: String::from(""),
            request_headers: HashMap::new(),
            request_data: String::from(""),
            favicon_hash: vec![],
        }
    }
}

// 将指纹分成首页识别，特殊请求识别和favicon的哈希识别
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct WebFingerPrintLib {
    index: Vec<WebFingerPrint>,
    special: Vec<WebFingerPrint>,
    favicon: Vec<WebFingerPrint>,

}

impl WebFingerPrintLib {
    pub fn new() -> Self {
        Self {
            index: vec![],
            special: vec![],
            favicon: vec![],
        }
    }
    fn read_form_file(&self) -> Vec<WebFingerPrint> {
        let self_path: PathBuf = env::current_exe().unwrap_or(PathBuf::new());
        let path = Path::new(&self_path).parent().unwrap_or(Path::new(""));
        return if !CONFIG.verify.is_empty() {
            let mut file = match File::open(CONFIG.verify.clone()) {
                Err(_) => {
                    println!("The verification file cannot be found in the current directory!");
                    std::process::exit(0);
                }
                Ok(file) => file,
            };
            let mut data = String::new();
            file.read_to_string(&mut data).unwrap();
            let mut web_fingerprint: Vec<WebFingerPrint> = vec![];
            let verify_fingerprints: VerifyWebFingerPrint = serde_yaml::from_str(&data).expect("Bad Yaml");
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
                    std::process::exit(0);
                }
                Ok(file) => file,
            };
            let mut data = String::new();
            file.read_to_string(&mut data).unwrap();
            let web_fingerprint: Vec<WebFingerPrint> = serde_json::from_str(&data).expect("Bad Json");
            web_fingerprint
        };
    }
    pub fn init(&mut self) {
        self.index.clear();
        self.special.clear();
        self.favicon.clear();
        let web_fingerprint: Vec<WebFingerPrint> = self.read_form_file();
        for f_rule in web_fingerprint {
            if f_rule.path == "/"
                && f_rule.request_headers.is_empty()
                && f_rule.request_method == "get"
                && f_rule.request_data.is_empty()
                && f_rule.favicon_hash.is_empty()
            {
                self.index.push(f_rule);
            } else if !f_rule.favicon_hash.is_empty() {
                self.favicon.push(f_rule);
            } else {
                self.special.push(f_rule);
            }
        }
    }
}
// 加载指纹库到常量，防止在文件系统反复加载
lazy_static! {
    static ref WEB_FINGERPRINT_LIB_DATA: RwLock<WebFingerPrintLib> =  RwLock::new({
        let mut web_fingerprint_lib = WebFingerPrintLib::new();
        web_fingerprint_lib.init();
        web_fingerprint_lib
    });
}
pub fn update_fingerprint() {
    WEB_FINGERPRINT_LIB_DATA.write().unwrap().init();
}
lazy_static! {
    static ref CONFIG: WardArgs = {
        let config = WardArgs::new();
        config
    };
}
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
    fingerprint: Option<&WebFingerPrint>,
) -> Result<Response, reqwest::Error> {
    let mut headers = header::HeaderMap::new();
    let mut method: Method = Method::GET;
    let mut body_data = Body::from("");
    let ua = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/92.0.4515.107 Safari/537.36";
    headers.insert(header::USER_AGENT, header::HeaderValue::from_static(ua));
    if let Some(fingerprint) = fingerprint {
        method = Method::from_str(&fingerprint.request_method.to_uppercase()).unwrap_or(Method::GET);
        body_data = Body::from(base64::decode(fingerprint.request_data.clone()).unwrap_or_default());
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

fn get_default_encoding(byte: &[u8], headers: HeaderMap) -> String {
    let (html, _, _) = UTF_8.decode(byte);
    let charset_re = Regex::new(r#"(?im)charset="(.*?)"|charset=(.*?)""#).unwrap();
    let mut default_encoding = "utf-8";
    for charset in charset_re.captures(&html) {
        for cs in charset.iter() {
            if let Some(c) = cs {
                default_encoding = c.as_str();
            }
        }
    }
    let content_type = headers
        .get(crate::header::CONTENT_TYPE)
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
    if is_index && !status_code.is_server_error() && is_index {
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
pub async fn get_favicon_hash(url: Url) -> Result<String, WardError> {
    match send_requests(url, None).await {
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

//首页请求
async fn index_fetch(
    url_str: &String,
    special_wfp: Option<&WebFingerPrint>,
) -> Result<Vec<Response>, WardError> {
    let mut res_list: Vec<Response> = vec![];
    let schemes: [String; 2] = ["https://".to_string(), "http://".to_string()];
    for mut scheme in schemes {
        //最大重定向跳转次数
        let mut max_redirect = 5;
        let mut is_right_scheme: bool = false;
        let mut scheme_url = url_str.clone();
        if !url_str.to_lowercase().starts_with("http://")
            && !url_str.to_lowercase().starts_with("https://")
        {
            scheme.push_str(url_str.as_str());
            scheme_url = scheme;
        }
        let mut url = match Url::parse(scheme_url.as_str()) {
            Ok(url) => url,
            Err(err) => {
                return Err(WardError::Other(format!("{:?}", err)));
            }
        };
        let get_next_url = |response: &Response| {
            response
                .headers()
                .get(LOCATION)
                .and_then(|location| location.to_str().ok())
                .and_then(|location| response.url().join(location).ok())
        };
        loop {
            let mut next_url: Option<Url> = Option::None;
            if let Ok(res) = send_requests(url, special_wfp).await {
                next_url = get_next_url(&res);
                res_list.push(res);
                is_right_scheme = true;
            };
            match next_url.clone() {
                Some(next_jump_url) => {
                    url = next_jump_url;
                }
                None => {
                    break;
                }
            }
            max_redirect -= 1;
            if max_redirect == 0 {
                break;
            }
        }
        if is_right_scheme {
            break;
        }
    }
    return Ok(res_list);
}

#[derive(Debug, Serialize, Deserialize)]
pub struct WhatWebResult {
    pub url: String,
    pub what_web_name: HashSet<String>,
    pub priority: u32,
    pub length: usize,
    pub title: String,
}

impl WhatWebResult {
    pub fn new(url: String) -> Self {
        Self {
            url,
            what_web_name: HashSet::new(),
            priority: 0,
            length: 0,
            title: String::new(),
        }
    }
}

fn get_title(raw_data: &Arc<RawData>) -> String {
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

pub async fn scan(url: String) -> WhatWebResult {
    let mut what_web_name: HashSet<String> = HashSet::new();
    let mut what_web_result: WhatWebResult = WhatWebResult::new(url.clone());
    if let Ok(res_list) = index_fetch(&url, None).await {
        //首页请求允许跳转
        for res in res_list {
            if let Ok(raw_data) = fetch_raw_data(res, true).await {
                let web_name_set = check(&raw_data, &WEB_FINGERPRINT_LIB_DATA.read().unwrap().to_owned(), false).await;
                for (k, v) in web_name_set {
                    what_web_name.insert(k);
                    what_web_result.priority = v;
                }
                what_web_result.url = String::from(raw_data.url.clone());
                what_web_result.title = get_title(&raw_data);
                what_web_result.length = raw_data.text.len();
            }
        }
    };
    for special_wfp in WEB_FINGERPRINT_LIB_DATA.read().unwrap().to_owned().special.iter() {
        if let Ok(res_list) =
        index_fetch(&url, Some(special_wfp)).await
        {
            for res in res_list {
                if let Ok(raw_data) = fetch_raw_data(res, false).await {
                    let web_name_set = check(&raw_data, &WEB_FINGERPRINT_LIB_DATA.read().unwrap().to_owned(), true).await;
                    for (k, v) in web_name_set {
                        what_web_name.insert(k);
                        what_web_result.priority = v;
                    }
                }
            }
            // if !what_web_name.is_empty() {
            //     break;
            // }
        }
    }
    if what_web_name.len() > 5 {
        let count = what_web_name.len();
        what_web_name.clear();
        what_web_name.insert(format!("Honeypot 蜜罐{}", count));
    }
    what_web_result.what_web_name = what_web_name.clone();
    let color_web_name: Vec<String> = what_web_name.iter().map(String::from).collect();
    if !what_web_name.is_empty() {
        println!(
            "[ {} | {} | {} | {} ]",
            what_web_result.url,
            format!("{:?}", color_web_name).red(),
            what_web_result.length,
            what_web_result.title
        );
    } else {
        println!(
            "[ {} | {:?} | {} | {} ]",
            what_web_result.url, color_web_name, what_web_result.length, what_web_result.title
        );
    }
    what_web_result
}

// 去重
pub fn strings_to_urls(domains: String) -> HashSet<String> {
    let target_list: Vec<String> = domains
        .split_terminator('\n')
        .map(|s| s.to_string())
        .collect();
    HashSet::from_iter(target_list)
}

pub fn read_file_to_target(file_path: String) -> HashSet<String> {
    if let Ok(lines) = read_lines(file_path) {
        let target_list: Vec<String> = lines.filter_map(Result::ok).collect();
        return HashSet::from_iter(target_list);
    }
    return HashSet::from_iter([]);
}

fn read_lines<P>(filename: P) -> io::Result<io::Lines<io::BufReader<File>>>
    where
        P: AsRef<Path>,
{
    let file = File::open(filename)?;
    Ok(io::BufReader::new(file).lines())
}

pub async fn download_fingerprints_from_github() {
    let update_url = "https://0x727.github.io/FingerprintHub/web_fingerprint_v3.json";
    match reqwest::get(update_url).await {
        Ok(response) => {
            let self_path: PathBuf = env::current_exe().unwrap_or(PathBuf::new());
            let path = Path::new(&self_path).parent().unwrap_or(Path::new(""));
            let mut file = std::fs::File::create(path.join("web_fingerprint_v3.json")).unwrap();
            let mut content = Cursor::new(response.bytes().await.unwrap());
            std::io::copy(&mut content, &mut file).unwrap();
            println!(
                "Complete fingerprint update: web_fingerprint_v3.json file size => {:?}",
                file.metadata().unwrap().len()
            );
        }
        Err(_) => {
            println!(
                "Update failed, please download {} to local directory manually.",
                update_url
            );
        }
    };
}
