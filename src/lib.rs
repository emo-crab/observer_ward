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
use reqwest::header::LOCATION;
use reqwest::redirect::Policy;
use reqwest::{header, Response};
use scraper::{Html, Selector};
use serde::{Deserialize, Serialize};
use std::time::Duration;
use colored::Colorize;

/// Possible Errors in the domain_info lib
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

async fn send_requests(url: &Url) -> Result<Response, reqwest::Error> {
    let mut headers = header::HeaderMap::new();
    headers.insert(header::USER_AGENT, header::HeaderValue::from_static("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/92.0.4515.107 Safari/537.36"));
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
pub async fn get_favicon_hash(url: &Url) -> Result<HashMap<String, String>, WardError> {
    let mut favicon_hash = HashMap::new();
    match send_requests(url).await {
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
                match get_favicon_hash(&favicon_url).await {
                    Ok(md5_mmh3) => {
                        let md5_mmh3_hash = md5_mmh3;
                        link_tags.insert(String::from(favicon_url), md5_mmh3_hash);
                    }
                    Err(_) => {}
                };
            }
        }
    }
    // 补充默认路径
    let favicon_url = base_url.join("/favicon.ico").unwrap();
    if !link_tags.contains_key(&String::from(favicon_url.clone())) {
        match get_favicon_hash(&favicon_url).await {
            Ok(md5_mmh3) => {
                let md5_mmh3_hash = md5_mmh3;
                link_tags.insert(String::from(favicon_url), md5_mmh3_hash);
            }
            Err(_) => {}
        };
    }
    return link_tags;
}

async fn fetch_raw_data(res: Response) -> Result<Arc<RawData>, WardError> {
    let path: String = res.url().path().to_string();
    let url = res.url().join("/").unwrap().to_string();
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
    if is_index && !status_code.is_server_error() {
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
async fn index_fetch(url_str: String) -> Result<Vec<Response>, WardError> {
    let mut res_list: Vec<Response> = vec![];
    let mut headers = header::HeaderMap::new();
    headers.insert(header::USER_AGENT, header::HeaderValue::from_static("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/92.0.4515.107 Safari/537.36"));
    let schemes: [String; 2] = ["https://".to_string(), "http://".to_string()];
    let mut next_url: Option<Url> = Option::None;
    //最大重定向跳转次数
    let mut max_redirect = 5;
    for mut scheme in schemes {
        let mut scheme_url = url_str.clone();
        if !url_str.to_lowercase().starts_with("http") {
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
            match send_requests(&url).await
            {
                Ok(res) => {
                    next_url = get_next_url(&res);
                    res_list.push(res);
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
    // TODO 整理,应该是请求完两个请求，放回raw_data后再匹配规则
    let mut what_web_name: HashSet<String> = HashSet::new();
    let mut what_web_result: WhatWebResult = WhatWebResult { url: url.clone(), what_web_name: HashSet::new(), priority: 0, length: 0, title: String::new() };
    match index_fetch(url.clone()).await { //首页请求允许跳转
        Ok(res_list) => {
            for res in res_list {
                match fetch_raw_data(res).await {
                    Ok(raw_data) => {
                        let web_name_set = check(&raw_data).await;
                        for (k, v) in web_name_set {
                            what_web_name.insert(k);
                            what_web_result.priority = v;
                        }
                        what_web_result.url = raw_data.url.clone();
                        what_web_result.title = get_title(&raw_data);
                        what_web_result.length = raw_data.text.len();
                    }
                    Err(_) => {}
                };
            }
        }
        Err(_) => {}
    };
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

// 从文件的中读取文件
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
    let target = "https://cdn.jsdelivr.net/gh/0x727/FingerprintHub/web_fingerprint.json";
    let response = reqwest::get(target).await.unwrap();
    let mut file = std::fs::File::create("web_fingerprint.json").unwrap();
    let mut content = Cursor::new(response.bytes().await.unwrap());
    std::io::copy(&mut content, &mut file).unwrap();
    println!("Complete fingerprint update: web_fingerprint.json file size => {:?}", file.metadata().unwrap().len());
}