use std::collections::{HashMap, HashSet};
use std::str::FromStr;
use std::sync::Arc;
use std::time::Duration;

use cached::proc_macro::cached;
use cached::SizedCache;
use encoding_rs::{Encoding, UTF_8};
use md5::{Digest, Md5};
use mime::Mime;
use once_cell::sync::Lazy;
use regex::Regex;
use reqwest::header::{HeaderMap, HeaderName, HeaderValue, LOCATION};
use reqwest::redirect::Policy;
use reqwest::{header, Body, Method, Proxy, Response};
use scraper::{Html, Selector};
use url::Url;

use crate::fingerprint::WebFingerPrintRequest;
use crate::ward::RawData;
use crate::RequestOption;

async fn send_requests(
    url: &Url,
    fingerprint: &WebFingerPrintRequest,
    config: &RequestOption,
) -> anyhow::Result<Response> {
    let mut url = url.clone();
    let mut headers = header::HeaderMap::new();
    let ua = "Mozilla/5.0 (X11; Linux x86_64; rv:94.0) Gecko/20100101 Firefox/94.0";
    headers.insert(header::USER_AGENT, header::HeaderValue::from_static(ua));
    let method =
        Method::from_str(&fingerprint.request_method.to_uppercase()).unwrap_or(Method::GET);
    let body_data =
        Body::from(base64::decode(fingerprint.request_data.clone()).unwrap_or_default());
    if !fingerprint.request_headers.is_empty() {
        for (k, v) in fingerprint.request_headers.clone() {
            headers.insert(HeaderName::from_str(&k)?, HeaderValue::from_str(&v)?);
        }
    }
    if fingerprint.path != "/" {
        url.set_path(fingerprint.path.as_str());
    }
    let client = reqwest::Client::builder()
        .pool_max_idle_per_host(0)
        .danger_accept_invalid_certs(true)
        .danger_accept_invalid_hostnames(true)
        .default_headers(headers.clone())
        .redirect(Policy::none())
        .timeout(Duration::new(config.timeout, 0));
    let config_proxy = config.proxy.clone();
    let proxy_obj = Proxy::custom(move |_| config_proxy.clone());
    return Ok(client
        .proxy(proxy_obj)
        .build()?
        .request(method, url.as_ref())
        .body(body_data)
        .send()
        .await?);
}

static RE_COMPILE_BY_CHARSET: Lazy<Regex> = Lazy::new(|| -> Regex {
    Regex::new(r#"(?im)charset="(.*?)"|charset=(.*?)""#).expect("RE_COMPILE_BY_CHARSET")
});

fn get_default_encoding(byte: &[u8], headers: HeaderMap) -> String {
    let (html, _, _) = UTF_8.decode(byte);
    let mut default_encoding = "utf-8";
    if let Some(charset) = RE_COMPILE_BY_CHARSET.captures(&html) {
        for cs in charset.iter().flatten() {
            default_encoding = cs.as_str();
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
    text.to_string()
}

async fn fetch_raw_data(
    res: Response,
    is_index: bool,
    config: RequestOption,
) -> anyhow::Result<Arc<RawData>> {
    let path: String = res.url().path().to_string();
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
        favicon = find_favicon_tag(&base_url, &text, config).await;
    }
    // 在请求头和正文里匹配下一跳URL
    let get_next_url = |headers: &HeaderMap, url: &Url, text: &String| {
        let mut next_url = headers
            .get(LOCATION)
            .and_then(|location| location.to_str().ok())
            .and_then(|location| {
                if location.starts_with("http://") || location.starts_with("https://") {
                    Some(Url::parse(location).unwrap_or_else(|_| url.clone()))
                } else {
                    url.join(location).ok()
                }
            });
        if next_url.is_none() && text.len() <= 1024 {
            for reg in RE_COMPILE_BY_JUMP.iter() {
                if let Some(x) = reg.captures(text) {
                    let mut u = x.name("name").map_or("", |m| m.as_str()).to_string();
                    u = u.replace('\'', "").replace('\"', "");
                    if u.starts_with("http://") || u.starts_with("https://") {
                        next_url = Some(Url::parse(&u).unwrap_or_else(|_| url.clone()));
                        break;
                    }
                    next_url = Some(url.join(&u).unwrap_or_else(|_| url.clone()));
                    break;
                }
            }
        }
        next_url
    };
    let next_url = get_next_url(&headers, &base_url, &text);
    let raw_data = Arc::new(RawData {
        url: base_url,
        path,
        headers,
        status_code,
        text: text.to_lowercase(),
        favicon,
        next_url,
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
async fn get_favicon_hash(url: &Url, config: &RequestOption) -> anyhow::Result<String> {
    let default_request = WebFingerPrintRequest {
        path: String::from("/"),
        request_method: String::from("get"),
        request_headers: Default::default(),
        request_data: String::new(),
    };
    let res = send_requests(url, &default_request, config).await?;
    let content_type = res.headers().get(reqwest::header::CONTENT_TYPE);

    if let Some(content_type) = content_type {
        let content_type = Mime::from_str(content_type.to_str()?)?;
        if content_type.type_() != mime::IMAGE {
            return Err(anyhow::Error::from(std::io::Error::last_os_error()));
        }
    }
    if res.status().as_u16() != 200 {
        return Err(anyhow::Error::from(std::io::Error::last_os_error()));
    }
    let content = res.bytes().await?;
    let mut hasher = Md5::new();
    hasher.update(content);
    let result = hasher.finalize();
    let favicon_md5: String = format!("{:x}", &result);
    Ok(favicon_md5)
}

fn get_favicon_link(text: &str, base_url: &Url) -> HashSet<Url> {
    let parsed_html = Html::parse_fragment(text);
    let selector = Selector::parse("link").unwrap();
    let mut icon_links = HashSet::new();
    let path_list = parsed_html.select(&selector);
    for link in path_list {
        if let (Some(href), Some(rel)) = (link.value().attr("href"), link.value().attr("rel")) {
            if ["icon", "shortcut icon"].contains(&rel) {
                if href.starts_with("http://") || href.starts_with("https://") {
                    let favicon_url = Url::parse(href).unwrap_or_else(|_| base_url.clone());
                    icon_links.insert(favicon_url);
                } else {
                    let favicon_url = base_url.join(href).unwrap_or_else(|_| base_url.clone());
                    icon_links.insert(favicon_url);
                }
            }
        }
    }
    if let Ok(favicon_url) = base_url.join("/favicon.ico") {
        icon_links.insert(favicon_url);
    }
    icon_links
}

// 从HTML标签中提取favicon的链接
async fn find_favicon_tag(
    base_url: &Url,
    text: &str,
    config: RequestOption,
) -> HashMap<String, String> {
    // 补充默认路径
    let mut link_tags = HashMap::new();
    let icon_sets = get_favicon_link(text, base_url);
    for link in icon_sets {
        if let Ok(favicon_md5) = get_favicon_hash(&link, &config).await {
            link_tags.insert(link.to_string(), favicon_md5);
        };
    }
    link_tags
}
// 支持部分正文跳转
static RE_COMPILE_BY_JUMP: Lazy<Vec<Regex>> = Lazy::new(|| -> Vec<Regex> {
    let js_reg = vec![
        r#"(?im)[ |.|:]location\.href.*?=.*?['|"](?P<name>.*?)['|"]"#,
        r#"(?im)window.*?\.(open|replace)\(['|"](?P<name>.*?)['|"]"#,
        r#"(?im)window.*?\.location=['|"](?P<name>.*?)['|"]"#,
        r#"(?im)<meta.*?http-equiv=.*?refresh.*?url=['" ]?(?P<name>.*?)['"]/?>"#,
    ];
    let re_list: Vec<Regex> = js_reg
        .iter()
        .map(|reg| Regex::new(reg).expect("RE_COMPILE_BY_JUMP"))
        .collect();
    re_list
});

static RE_COMPILE_BY_TITLE: Lazy<Vec<Regex>> = Lazy::new(|| -> Vec<Regex> {
    let js_reg = vec![
        r#"(?im)<title>(?P<name>.*?)</title>"#,
        r#"(?im)<meta property="title" content="(?P<name>.*?)">"#,
    ];
    let re_list: Vec<Regex> = js_reg
        .iter()
        .map(|reg| Regex::new(reg).expect("RE_COMPILE_BY_TITLE"))
        .collect();
    re_list
});

pub fn get_title(raw_data: &Arc<RawData>) -> String {
    for reg in RE_COMPILE_BY_TITLE.iter() {
        if let Some(x) = reg.captures(&raw_data.text) {
            let title = x.name("name").map_or("", |m| m.as_str()).to_string();
            if !title.is_empty() {
                return title;
            }
        }
    }
    String::new()
}

// 首页请求
#[cached(
    type = "SizedCache<String, Vec<Arc<RawData>>>",
    create = "{ SizedCache::with_size(100) }",
    result = true,
    convert = r#"{ format!("{}{:?}", url_str.to_owned(), special_wfp) }"#
)]
pub async fn index_fetch(
    url_str: &str,
    special_wfp: &WebFingerPrintRequest,
    is_index: bool,
    is_special: bool,
    config: RequestOption,
) -> anyhow::Result<Vec<Arc<RawData>>> {
    let mut is_index: bool = is_index;
    let mut is_start_with_http: bool = true;
    let mut raw_data_list: Vec<Arc<RawData>> = vec![];
    let schemes: [String; 2] = [String::from("https://"), String::from("http://")];
    for mut scheme in schemes {
        //最大重定向跳转次数
        let mut max_redirect = 5;
        let mut scheme_url = url_str;
        if !url_str.to_lowercase().starts_with("http://")
            && !url_str.to_lowercase().starts_with("https://")
        {
            scheme.push_str(url_str);
            scheme_url = scheme.as_str();
            is_start_with_http = false;
        }
        let mut url = Url::parse(scheme_url)?;
        loop {
            let mut next_url: Option<Url> = None;
            if let Ok(res) = send_requests(&url, special_wfp, &config).await {
                if let Ok(raw_data) = fetch_raw_data(res, is_index, config.clone()).await {
                    next_url = raw_data.next_url.clone();
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
        // 已经有协议的没必要请求两次
        if is_start_with_http {
            break;
        }
    }
    Ok(raw_data_list)
}

#[cfg(test)]
mod tests {
    use crate::request::{get_favicon_link, send_requests, RE_COMPILE_BY_JUMP};
    use crate::{RequestOption, WebFingerPrintRequest};
    use std::collections::HashMap;
    use url::Url;

    // https://docs.rs/tokio/latest/tokio/attr.test.html
    #[tokio::test]
    async fn test_send_requests() {
        let test_url = Url::parse("https://httpbin.org/").unwrap();
        let fingerprint = WebFingerPrintRequest {
            path: String::from("/"),
            request_method: String::from("GET"),
            request_headers: Default::default(),
            request_data: String::from(""),
        };
        let timeout = 10_u64;
        let request_config = RequestOption::new(&timeout, "");
        let res = send_requests(&test_url, &fingerprint, &request_config)
            .await
            .unwrap();
        assert!(res.text().await.unwrap().contains("swagger-ui"));
    }

    #[tokio::test]
    async fn test_bad_ssl_send_requests() {
        let test_url = Url::parse("https://expired.badssl.com/").unwrap();
        let fingerprint = WebFingerPrintRequest {
            path: String::from("/"),
            request_method: String::from("GET"),
            request_headers: Default::default(),
            request_data: String::from(""),
        };
        let timeout = 10_u64;
        let request_config = RequestOption::new(&timeout, "");
        let res = send_requests(&test_url, &fingerprint, &request_config)
            .await
            .unwrap();
        assert!(res
            .text()
            .await
            .unwrap()
            .contains("<title>expired.badssl.com</title>"));
    }
    #[test]
    fn test_regex_icon() {
        let test_text_list = vec![
            (
                r#"<link rel="icon" href=/uistyle/themes/default/images/favicon.ico type="image/x-icon" />"#,
                "/uistyle/themes/default/images/favicon.ico",
            ),
            (r#"<link rel=icon href=/logo.png>"#, "/logo.png"),
        ];
        let test_test_verify_map: HashMap<&str, &str> = HashMap::from_iter(test_text_list);
        let base_url = Url::parse("https://kali-team.cn").unwrap();
        let mut flag = false;
        for (text, verify) in test_test_verify_map {
            for link in get_favicon_link(text, &base_url) {
                if link.path() == verify {
                    flag = true;
                }
            }
        }
        assert!(flag);
    }
    #[test]
    fn test_js_jump() {
        let test_text_list = vec![(
            r#"<script> window.location.replace("login.jsp?up=1");</script>"#.to_string(),
            "login.jsp?up=1".to_string(),
        )];
        let test_test_verify_map: HashMap<String, String> = HashMap::from_iter(test_text_list);
        let mut flag = false;
        for (text, verify) in test_test_verify_map {
            for reg in RE_COMPILE_BY_JUMP.iter() {
                if let Some(x) = reg.captures(&text) {
                    let u = x.name("name").map_or("", |m| m.as_str()).to_string();
                    if u == verify {
                        flag = true;
                    }
                }
            }
        }
        assert!(flag);
    }
}
