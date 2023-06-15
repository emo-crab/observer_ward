use crate::fingerprint::{V3WebFingerPrint, WebFingerPrintLib};
use crate::RequestOption;
use crossterm::style::Stylize;
use futures::future::join_all;
use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use url::Url;

#[derive(Debug)]
pub struct RawData {
    pub url: Url,
    pub path: String,
    pub headers: reqwest::header::HeaderMap,
    pub status_code: reqwest::StatusCode,
    pub text: String,
    pub favicon: HashMap<String, String>,
    pub next_url: Option<Url>,
}

impl RawData {
    fn grep(&self, kw: &str, is_path: bool, silent: bool) {
        let grep_color = |text: &str| {
            if is_path || silent {
                println!("{}", text);
                return;
            }
            let mut color_grep = text.to_string();
            color_grep = color_grep.replace(kw, &kw.red().to_string());
            println!("{}", color_grep);
        };
        if let Ok(u) = self.url.join(&self.path) {
            println!("URL: {}", u.to_string().green());
        }
        println!("HEADERS:");
        for (k, v) in self.headers.clone() {
            if let Some(n) = k {
                print!("{}: ", n);
                grep_color(v.to_str().unwrap_or_default());
            }
        }
        println!("COOKIES:");
        let cookies = self.headers.get_all(reqwest::header::SET_COOKIE);
        for v in cookies.iter() {
            grep_color(v.to_str().unwrap_or_default());
        }
        // println!(&header_to_string(&self.headers));
        println!("STATUS_CODE: {}", self.status_code.as_u16());
        println!("TEXT:");
        grep_color(&self.text);
        if !self.favicon.is_empty() {
            println!("{}", format!("FAVICON: {:#?}", self.favicon).red());
        }
        if let Some(next_url) = &self.next_url {
            println!("NEXT_URL: {}", next_url);
        }
    }
}

pub async fn check(
    raw_data: &Arc<RawData>,
    fingerprint_lib: &WebFingerPrintLib,
    config: &RequestOption,
) -> HashMap<String, u32> {
    let is_debug = !config.verify_keyword.is_empty();
    if is_debug {
        raw_data.grep(&config.verify_keyword, config.is_path, config.silent);
    }
    let mut futures_e = vec![];
    let mut web_name_set: HashMap<String, u32> = HashMap::new();
    for fingerprint in fingerprint_lib.special.iter() {
        futures_e.push(what_web(raw_data.clone(), fingerprint, is_debug));
    }
    for fingerprint in fingerprint_lib.index.iter() {
        futures_e.push(what_web(raw_data.clone(), fingerprint, is_debug));
    }
    if !raw_data.favicon.is_empty() {
        for fingerprint in fingerprint_lib.favicon.iter() {
            futures_e.push(what_web(raw_data.clone(), fingerprint, is_debug));
        }
    }
    let results = join_all(futures_e).await;
    for res in results {
        let (is_match, match_web_fingerprint) = res;
        if is_match {
            web_name_set.insert(
                match_web_fingerprint.name.clone(),
                match_web_fingerprint.priority,
            );
        }
    }
    web_name_set
}

pub async fn what_web(
    raw_data: Arc<RawData>,
    fingerprint: &V3WebFingerPrint,
    debug: bool,
) -> (bool, &V3WebFingerPrint) {
    // 默认匹配不到
    let mut default_result = (false, fingerprint);
    // 匹配FaviconHash
    if !fingerprint.match_rules.favicon_hash.is_empty() {
        let mut hash_set = HashSet::new();
        for (_key, value) in raw_data.favicon.iter() {
            hash_set.insert(value);
        }
        // 规则中有，但是请求中没有找到FaviconHash
        if hash_set.is_empty() {
            return default_result;
        }
        let mut fph_set = HashSet::new();
        for fph in fingerprint.match_rules.favicon_hash.iter() {
            fph_set.insert(fph);
        }
        // 规则和请求数据没有交集
        if hash_set.intersection(&fph_set).count() == 0 {
            return default_result;
        }
    }
    // 关键词匹配
    let not_match_status_code = || {
        fingerprint.match_rules.status_code != 0
            && raw_data.status_code.as_u16() != fingerprint.match_rules.status_code
    };
    // 匹配了状态码，规则中状态码不为0,并且和请求的状态码不相等
    if not_match_status_code() {
        return default_result;
    }
    for (k, v) in &fingerprint.match_rules.headers {
        let matcher_part = header_to_cookies(&raw_data.headers);
        if k.to_lowercase() == "set-cookie" {
            if !matcher_part.contains(&v.to_lowercase()) {
                return default_result;
            }
        } else if let Some(vv) = raw_data.headers.get(k.to_lowercase()) {
            let is_match = vv
                .to_str()
                .unwrap_or_default()
                .to_lowercase()
                .find(&v.to_lowercase());
            if is_match.is_none() && v != "*" {
                return default_result;
            }
        } else {
            return default_result;
        }
    }
    for keyword in &fingerprint.match_rules.keyword {
        if !raw_data.text.contains(&keyword.to_lowercase()) {
            return default_result;
        }
    }
    default_result.0 = true;
    if debug {
        println!("Matching fingerprint{:#?}", fingerprint);
    }
    default_result
}

fn header_to_cookies(headers: &reqwest::header::HeaderMap) -> String {
    let cookies: Vec<&str> = headers
        .get_all(reqwest::header::SET_COOKIE)
        .iter()
        .map(|v| v.to_str().unwrap_or_default())
        .collect();

    cookies.join(";").to_lowercase()
}
