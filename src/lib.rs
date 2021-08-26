#[macro_use]
extern crate lazy_static;

pub mod favicon_hash_lib;
pub mod ward;

use std::collections::HashMap;
use std::collections::HashSet;
use std::fmt;
use std::sync::Arc;
use std::fs::File;
use std::path::Path;
use std::io::Cursor;
use std::io::{self, BufRead};
use std::iter::FromIterator;
use url::Url;
use ward::{check, RawData};
use favicon_hash_lib::{get_md5, murmurhash3_x86_32};
use reqwest::header::{LOCATION, HeaderValue, HeaderName};
use reqwest::redirect::Policy;
use reqwest::{header, Response};
use scraper::{Html, Selector};
use std::time::Duration;
use colored::Colorize;
use std::io::Read;
use serde::{Deserialize, Serialize};
use std::str::FromStr;

#[derive(Debug, Serialize, Deserialize)]
pub struct WebFingerPrint {
    path: String,
    name: String,
    status_code: u16,
    headers: HashMap<String, String>,
    keyword: Vec<String>,
    favicon_hash: Vec<String>,
    priority: u32,
    request_method: String,
    request_headers: HashMap<String, String>,
    request_data: String,
}

impl WebFingerPrint {
    pub fn new() -> Self {
        Self {
            path: String::from(""),
            name: String::from(""),
            status_code: 0,
            headers: HashMap::new(),
            keyword: vec![],
            favicon_hash: vec![],
            priority: 1,
            request_method: String::from(""),
            request_headers: HashMap::new(),
            request_data: String::from(""),
        }
    }
}

#[derive(Debug, Serialize, Deserialize)]
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
}
// 加载指纹库到常量，防止在文件系统反复加载
lazy_static! {
    static ref WEB_FINGERPRINT_LIB_DATA: WebFingerPrintLib = {
        let mut web_fingerprint_lib = WebFingerPrintLib::new();
        let mut file = match File::open("web_fingerprint_v2.json") {
            Err(_) => {
                println!("The fingerprint library cannot be found in the current directory!");
                std::process::exit(0);
            }
            Ok(file) => file,
        };
        let mut data = String::new();
        file.read_to_string(&mut data).unwrap();
        let web_fingerprint: Vec<WebFingerPrint> =serde_json::from_str(&data).expect("Bad Yaml");
        for f_rule in web_fingerprint{
            if f_rule.path =="/"&&f_rule.request_headers.is_empty()&&f_rule.request_method=="get"&&f_rule.request_data.is_empty(){
                web_fingerprint_lib.index.push(f_rule);
            }else if !f_rule.favicon_hash.is_empty() {
                web_fingerprint_lib.favicon.push(f_rule);
            }else {
                web_fingerprint_lib.special.push(f_rule);
            }
        }
        web_fingerprint_lib
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

// the trait `std::convert::From<page::reqwest::Error>` is not implemented for `WardError`
impl From<reqwest::Error> for WardError {
    fn from(err: reqwest::Error) -> Self {
        WardError::Other(err.to_string())
    }
}

// the trait `std::convert::From<std::str::Utf8Error>` is not implemented for `WardError`
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

async fn send_requests(mut url: Url, fingerprint: Option<&WebFingerPrint>) -> Result<Response, reqwest::Error> {
    let mut headers = header::HeaderMap::new();
    let ua = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/92.0.4515.107 Safari/537.36";
    headers.insert(header::USER_AGENT, header::HeaderValue::from_static(ua));
    if let Some(fingerprint) = fingerprint {
        if !fingerprint.request_headers.is_empty() {
            for (k, v) in fingerprint.request_headers.clone() {
                headers.insert(HeaderName::from_str(&k).unwrap(), HeaderValue::from_str(&v).unwrap());
            }
        }
        url.set_path(fingerprint.path.as_str());
    }
    return reqwest::Client::builder()
        .danger_accept_invalid_certs(true)
        .default_headers(headers.clone())
        .redirect(Policy::none())
        .build()
        .unwrap()
        .get(url.as_ref())
        .timeout(Duration::new(10, 0))
        .send()
        .await;
}

// favicon的URL到Hash
pub async fn get_favicon_hash(url: Url) -> Result<HashMap<String, String>, WardError> {
    let mut favicon_hash = HashMap::new();
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
            let bs64 = base64::encode(&content);
            let favicon_mmh3 = format!("{}", murmurhash3_x86_32(&bs64.as_bytes(), 0));
            let favicon_md5: String = get_md5(&content);
            favicon_hash.insert(String::from("md5"), favicon_md5);
            favicon_hash.insert(String::from("mmh3"), favicon_mmh3);
            Ok(favicon_hash)
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
) -> HashMap<String, HashMap<String, String>> {
    let parsed_html = Html::parse_fragment(&text);
    let selector = Selector::parse("link").unwrap();
    let mut link_tags = HashMap::new();
    let path_list = parsed_html.select(&selector);
    for link in path_list.into_iter() {
        if let (Some(href), Some(rel)) = (link.value().attr("href"), link.value().attr("rel")) {
            if ["icon", "shortcut icon"].contains(&rel) {
                let favicon_url = base_url.join(href).unwrap();
                match get_favicon_hash(favicon_url.clone()).await {
                    Ok(md5_mmh3) => {
                        let md5_mmh3_hash = md5_mmh3;
                        link_tags.insert(String::from(favicon_url.clone()), md5_mmh3_hash);
                    }
                    Err(_) => {}
                };
            }
        }
    }
    // 补充默认路径
    let favicon_url = base_url.join("/favicon.ico").unwrap();
    if !link_tags.contains_key(&String::from(favicon_url.clone())) {
        match get_favicon_hash(favicon_url.clone()).await {
            Ok(md5_mmh3) => {
                let md5_mmh3_hash = md5_mmh3;
                link_tags.insert(String::from(favicon_url.clone()), md5_mmh3_hash);
            }
            Err(_) => {}
        };
    }
    return link_tags;
}

async fn fetch_raw_data(res: Response, is_icon: bool) -> Result<Arc<RawData>, WardError> {
    let path: String = res.url().path().to_string();
    let url = res.url().join("/").unwrap();
    let status_code = res.status();
    let mut is_index = false;
    if let "/" = res.url().path() {
        is_index = true;
    };
    let mut favicon_hash = HashMap::new();
    let headers = res.headers().clone();
    let base_url = res.url().clone();
    let text = match res.text().await {
        Ok(text) => text.to_lowercase(),
        Err(_) => String::from(""),
    };
    if is_index && !status_code.is_server_error() && is_icon {
        // 只有在首页的时候提取favicon图标链接
        favicon_hash = find_favicon_tag(base_url, &text).await;
    }
    let raw_data = Arc::new(RawData {
        url,
        path,
        headers,
        status_code,
        favicon_hash,
        text,
    });
    Ok(raw_data)
}

//首页请求
async fn index_fetch(url_str: &String, special_wfp: Option<&WebFingerPrint>) -> Result<Vec<Response>, WardError> {
    let mut res_list: Vec<Response> = vec![];
    let schemes: [String; 2] = ["https://".to_string(), "http://".to_string()];
    for mut scheme in schemes {
        //最大重定向跳转次数
        let mut max_redirect = 5;
        let mut is_right_scheme: bool = false;
        let mut scheme_url = url_str.clone();
        if !url_str.to_lowercase().starts_with("http://") && !url_str.to_lowercase().starts_with("https://") {
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
            match send_requests(url, special_wfp).await
            {
                Ok(res) => {
                    next_url = get_next_url(&res);
                    res_list.push(res);
                    is_right_scheme = true;
                }
                Err(_) => {}
            };
            match next_url.clone() {
                Some(next_jump_url) => {
                    url = next_jump_url;
                }
                None => { break; }
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
    pub fn new(
        url: String,
    ) -> Self {
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
        // if title.bytes().all(|b| b.is_()) {
        return title;
        // }
        // TODO 解码
    }
    return String::new();
}

pub async fn scan(url: String) -> WhatWebResult {
    let mut what_web_name: HashSet<String> = HashSet::new();
    let mut what_web_result: WhatWebResult = WhatWebResult::new(url.clone());
    let mut is_200 = false;
    if let Ok(res_list) = index_fetch(&url, None).await { //首页请求允许跳转
        for res in res_list {
            if let Ok(raw_data) = fetch_raw_data(res, true).await {
                let web_name_set = check(&raw_data, &WEB_FINGERPRINT_LIB_DATA, false).await;
                for (k, v) in web_name_set {
                    what_web_name.insert(k);
                    what_web_result.priority = v;
                }
                what_web_result.url = String::from(raw_data.url.clone());
                what_web_result.title = get_title(&raw_data);
                what_web_result.length = raw_data.text.len();
            }
            is_200 = true;
        }
    };
    //如果首页识别不出来就跑特定请求
    if what_web_name.is_empty() && is_200 {
        for special_wfp in WEB_FINGERPRINT_LIB_DATA.special.iter() {
            if let Ok(res_list) = index_fetch(&what_web_result.url.to_string(), Some(special_wfp)).await {
                for res in res_list {
                    if let Ok(raw_data) = fetch_raw_data(res, false).await {
                        let web_name_set = check(&raw_data, &WEB_FINGERPRINT_LIB_DATA, true).await;
                        for (k, v) in web_name_set {
                            what_web_name.insert(k);
                            what_web_result.priority = v;
                        }
                        what_web_result.url = String::from(raw_data.url.clone());
                        what_web_result.title = get_title(&raw_data);
                        what_web_result.length = raw_data.text.len();
                    }
                }
                if !what_web_name.is_empty() {
                    break;
                }
            }
        }
    }
    what_web_result.what_web_name = what_web_name.clone();
    let color_web_name: Vec<String> = what_web_name.iter().map(String::from).collect();
    if !what_web_name.is_empty() {
        println!("[ {} | {} | {} | {} |", what_web_result.url, format!("{:?}", color_web_name).red(), what_web_result.length, what_web_result.title);
    } else {
        println!("[ {} | {:?} | {} | {} |", what_web_result.url, color_web_name, what_web_result.length, what_web_result.title);
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
    where P: AsRef<Path>, {
    let file = File::open(filename)?;
    Ok(io::BufReader::new(file).lines())
}

pub async fn update_web_fingerprint() {
    let update_url = "https://0x727.github.io/FingerprintHub/web_fingerprint_v2.json";
    match reqwest::get(update_url).await {
        Ok(response) => {
            let mut file = std::fs::File::create("web_fingerprint_v2.json").unwrap();
            let mut content = Cursor::new(response.bytes().await.unwrap());
            std::io::copy(&mut content, &mut file).unwrap();
            println!("Complete fingerprint update: web_fingerprint_v2.json file size => {:?}", file.metadata().unwrap().len());
        }
        Err(_) => {
            println!("Update failed, please download {} to local directory manually.", update_url);
        }
    };
}