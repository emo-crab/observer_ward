#[macro_use]
extern crate lazy_static;

use std::collections::HashSet;
use std::env;
use std::fs::File;
use std::io::Cursor;
use std::io::{self, BufRead};
use std::iter::FromIterator;
use std::path::{Path, PathBuf};
use std::str;
use std::sync::RwLock;

use colored::Colorize;
use serde::{Deserialize, Serialize};

use cli::WardArgs;
use fingerprint::{WebFingerPrintLib, WebFingerPrintRequest};
use request::{get_title, index_fetch};
use ward::check;

mod cli;
pub mod fingerprint;
mod request;
mod ward;

lazy_static! {
    static ref CONFIG: WardArgs = {
        let config = WardArgs::new();
        config
    };
}
// 加载指纹库到常量，防止在文件系统反复加载
lazy_static! {
    static ref WEB_FINGERPRINT_LIB_DATA: RwLock<WebFingerPrintLib> = RwLock::new({
        let mut web_fingerprint_lib = WebFingerPrintLib::new();
        web_fingerprint_lib.init();
        web_fingerprint_lib
    });
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

pub async fn scan(url: String) -> WhatWebResult {
    let mut what_web_name: HashSet<String> = HashSet::new();
    let mut what_web_result: WhatWebResult = WhatWebResult::new(url.clone());
    let default_request = WebFingerPrintRequest {
        path: "/".to_string(),
        request_method: "get".to_string(),
        request_headers: Default::default(),
        request_data: "".to_string(),
    };
    if let Ok(raw_data_list) = index_fetch(&url, &default_request, true, false).await {
        //首页请求允许跳转
        for raw_data in raw_data_list {
            let web_name_set = check(
                &raw_data,
                &WEB_FINGERPRINT_LIB_DATA.read().unwrap().to_owned(),
                false,
            )
            .await;
            for (k, v) in web_name_set {
                what_web_name.insert(k);
                what_web_result.priority = v;
            }
            what_web_result.url = String::from(raw_data.url.clone());
            if what_web_result.title.is_empty() {
                what_web_result.title = get_title(&raw_data);
                what_web_result.priority = what_web_result.priority + 1;
            }
            what_web_result.length = raw_data.text.len();
        }
    };
    for special_wfp in WEB_FINGERPRINT_LIB_DATA
        .read()
        .unwrap()
        .to_owned()
        .special
        .iter()
    {
        if let Ok(raw_data_list) = index_fetch(&url, &special_wfp.request, false, true).await {
            for raw_data in raw_data_list {
                let web_name_set = check(
                    &raw_data,
                    &WEB_FINGERPRINT_LIB_DATA.read().unwrap().to_owned(),
                    true,
                )
                .await;
                for (k, v) in web_name_set {
                    what_web_name.insert(k);
                    what_web_result.priority = v;
                }
            }
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
            what_web_result.title,
        );
    } else {
        println!(
            "[ {} | {:?} | {} | {} ]",
            what_web_result.url, color_web_name, what_web_result.length, what_web_result.title,
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

pub async fn download_file_from_github(update_url: &str, filename: &str) {
    match reqwest::get(update_url).await {
        Ok(response) => {
            let self_path: PathBuf = env::current_exe().unwrap_or(PathBuf::new());
            let path = Path::new(&self_path).parent().unwrap_or(Path::new(""));
            let mut file = std::fs::File::create(path.join(filename)).unwrap();
            let mut content = Cursor::new(response.bytes().await.unwrap());
            std::io::copy(&mut content, &mut file).unwrap();
            println!(
                "Complete {} update: {} file size => {:?}",
                filename,
                filename,
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
