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
use reqwest::header::{HeaderMap, HeaderValue, LOCATION};
use reqwest::redirect::Policy;
use reqwest::tls::Version;
use reqwest::{header, Proxy, Response};
use select::document::Document;
use select::predicate::Name;
use url::Url;

use crate::fingerprint::WebFingerPrintRequest;
use crate::ward::RawData;
use crate::RequestOption;

/// 发送请求，并带上apache-shiro的请求头
async fn send_requests(
    url: &Url,
    fingerprint: &WebFingerPrintRequest,
    config: &RequestOption,
    redirect: Policy,
) -> anyhow::Result<Response> {
    let mut url = url.clone();
    let mut headers = HeaderMap::new();
    let default_ua = HeaderValue::from_static(
        "Mozilla/5.0 (X11; Linux x86_64; rv:94.0) Gecko/20100101 Firefox/94.0",
    );
    headers.insert(
        header::USER_AGENT,
        HeaderValue::from_str(&config.ua).unwrap_or(default_ua),
    );
    if config.danger {
        headers.insert(
            header::COOKIE,
            HeaderValue::from_static("rememberMe=admin;rememberMe-K=admin"),
        );
    }
    headers.insert(
        header::ACCEPT,
        HeaderValue::from_static(
            "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
        ),
    );
    let method = fingerprint.get_method();
    let body_data = fingerprint.get_body();
    fingerprint.set_header(&mut headers);
    if fingerprint.path != "/" {
        url.set_path(fingerprint.path.as_str());
    }
    let client = reqwest::Client::builder()
        .pool_max_idle_per_host(0)
        .danger_accept_invalid_certs(true)
        .danger_accept_invalid_hostnames(true)
        .min_tls_version(Version::TLS_1_0)
        .default_headers(headers.clone())
        .redirect(redirect)
        .cookie_store(true)
        .timeout(Duration::new(config.timeout, 0));
    let config_proxy = config.proxy.clone();
    let proxy_obj = Proxy::custom(move |_| config_proxy.clone());
    Ok(client
        .proxy(proxy_obj)
        .build()?
        .request(method, url.as_ref())
        .body(body_data)
        .send()
        .await?)
}

/// reqwest的内部只有从请求头提取编码，这里需要在html里再提取
fn get_charset_from_html(text: &str) -> String {
    for metas in Document::from(text).find(Name("meta")) {
        if let Some(charset) = metas.attr("charset") {
            let charset = charset.trim_matches('"').trim_matches('\'');
            return charset.to_lowercase();
        }
        if let Some(content) = metas.attr("content") {
            if let Ok(mime) = Mime::from_str(content) {
                if let Some(charset) = mime.get_param("charset") {
                    return charset.to_string();
                }
            }
        }
    }
    String::from("utf-8")
}

/// 获取编码并且尝试解码，返回解码后字符串和是否解码成功
fn get_default_encoding(byte: &[u8], headers: HeaderMap) -> (String, bool) {
    let (html, _, _) = UTF_8.decode(byte);
    let default_encoding = get_charset_from_html(&html);
    let content_type = headers
        .get(header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.parse::<Mime>().ok());
    let header_encoding = content_type
        .as_ref()
        .and_then(|mime| mime.get_param("charset").map(|charset| charset.as_str()))
        .unwrap_or(&default_encoding);
    for encoding_name in &[header_encoding, &default_encoding] {
        let encoding = Encoding::for_label(encoding_name.as_bytes()).unwrap_or(UTF_8);
        let (text, _, is_errors) = encoding.decode(byte);
        if !is_errors {
            return (text.to_string(), false);
        }
    }
    if let Ok(text) = String::from_utf8(byte.to_vec()) {
        return (text, false);
    }
    return (String::from_utf8_lossy(byte).to_string(), true);
}

/// 获取下一跳的地址，302请求头，meta标签，和正则匹配
fn get_next_jump(headers: &HeaderMap, url: &Url, text: &str) -> Option<Url> {
    let mut next_url_list = Vec::new();
    if let Some(location) = headers
        .get(LOCATION)
        .and_then(|location| location.to_str().ok())
    {
        next_url_list.push(location.to_string());
    }
    if next_url_list.is_empty() {
        for metas in Document::from(text).find(Name("meta")) {
            if let (Some(http_equiv), Some(content)) =
                (metas.attr("http-equiv"), metas.attr("content"))
            {
                if http_equiv.to_lowercase() == "refresh" {
                    if let Some((_, u)) = content.split_once('=') {
                        let n = u.replace(['\'', '\"'], "");
                        next_url_list.push(n);
                    }
                }
            }
        }
    }
    if next_url_list.is_empty() && text.len() <= 1024 {
        for reg in RE_COMPILE_BY_JUMP.iter() {
            if let Some(x) = reg.captures(text) {
                let mut u = x.name("name").map_or("", |m| m.as_str()).to_string();
                u = u.replace(['\'', '\"'], "");
                next_url_list.push(u);
            }
        }
    }
    if let Some(next_url) = next_url_list.into_iter().next() {
        return if next_url.starts_with("http://") || next_url.starts_with("https://") {
            match Url::parse(&next_url) {
                Ok(next_path) => Some(next_path),
                Err(_) => None,
            }
        } else if let Ok(next_path) = url.join(&next_url) {
            Some(next_path)
        } else {
            None
        };
    };
    None
}

/// 判断是否为图片，如果是图片直接算hash就可以了
fn is_image(headers: &HeaderMap, body: &[u8]) -> bool {
    let ct = headers
        .get(header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| Mime::from_str(value).ok())
        .map(|value| value.type_() == mime::IMAGE)
        .unwrap_or_default();
    let encode_error = String::from_utf8(body.to_vec()).is_err();
    if encode_error {
        let text = String::from_utf8_lossy(body).to_lowercase();
        let is_html = vec!["html", "head", "script", "div", "title", "xml", "svg"]
            .into_iter()
            .any(|c| text.contains(c));
        ct || !is_html
    } else {
        false
    }
}

async fn fetch_raw_data(res: Response, config: RequestOption) -> anyhow::Result<Arc<RawData>> {
    let path: String = res.url().path().to_string();
    let status_code = res.status();
    let headers = res.headers().clone();
    let base_url = res.url().clone();
    let mut favicon: HashMap<String, String> = HashMap::new();
    let text_byte = res.bytes().await.unwrap_or_default();
    let (mut text, _) = get_default_encoding(&text_byte, headers.clone());
    if is_image(&headers, &text_byte) {
        favicon.insert(base_url.to_string(), favicon_hash(&text_byte));
        text = String::from("响应内容为图片");
    } else {
        // 只有在首页的时候提取favicon图标链接
        favicon.extend(find_favicon_tag(&base_url, &text, config).await);
    }
    // 在请求头和正文里匹配下一跳URL
    let next_url = get_next_jump(&headers, &base_url, &text);
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
    let res = send_requests(url, &default_request, config, Policy::default()).await?;
    let status_code = res.status().as_u16();
    let headers = res.headers().clone();
    let content = res.bytes().await?;
    if status_code != 200 || !is_image(&headers, &content) {
        return Ok(String::new());
    }
    Ok(favicon_hash(&content))
}

fn favicon_hash(content: &[u8]) -> String {
    let mut hasher = Md5::new();
    hasher.update(content);
    let result = hasher.finalize();
    let favicon_md5: String = format!("{:x}", &result);
    favicon_md5
}

fn get_favicon_link(text: &str, base_url: &Url) -> HashSet<Url> {
    let mut icon_links = HashSet::new();
    for links in Document::from(text).find(Name("link")) {
        if let (Some(rel), Some(href)) = (links.attr("rel"), links.attr("href")) {
            if RE_COMPILE_BY_SIZE.is_match(href) {
                continue;
            }
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

/// 从HTML标签中提取favicon的链接
async fn find_favicon_tag(
    base_url: &Url,
    text: &str,
    config: RequestOption,
) -> HashMap<String, String> {
    // 补充默认路径
    let mut link_tags = HashMap::new();
    let icon_sets = get_favicon_link(text, base_url);
    for link in icon_sets {
        // 当图标404时，没有命中缓存，默认返回空字符串，需要判断一下
        if let Ok(favicon_md5) = get_favicon_hash(&link, &config).await {
            if favicon_md5.is_empty() {
                continue;
            }
            link_tags.insert(link.to_string(), favicon_md5);
        };
    }
    link_tags
}

static RE_COMPILE_BY_SIZE: Lazy<Regex> =
    Lazy::new(|| -> Regex { Regex::new(r"(?im)-\d{1,3}x\d{1,3}").expect("RE_COMPILE_BY_SIZE") });
/// 支持部分正文跳转
static RE_COMPILE_BY_JUMP: Lazy<Vec<Regex>> = Lazy::new(|| -> Vec<Regex> {
    let js_reg = [r#"(?im)\.location.*?=\s*?['"](?P<name>.*?)['"]"#,
        r"(?im)\.location\.(open|replace)\((?P<name>.*?)\)"];
    let re_list: Vec<Regex> = js_reg
        .iter()
        .map(|reg| Regex::new(reg).expect("RE_COMPILE_BY_JUMP"))
        .collect();
    re_list
});
static RE_TITLE: Lazy<Regex> = Lazy::new(|| -> Regex {
    Regex::new(r#"(?im)<title>(?P<title>.*?)</title>"#).expect("RE_TITLE")
});

/// 获取标题
pub fn get_title(text: &str) -> String {
    for titles in Document::from(text).find(Name("title")) {
        if !titles.text().is_empty() {
            return titles.text().trim().to_string();
        }
        if let Some(title) = titles.attr("_html") {
            return title.trim().to_string();
        }
    }
    for titles in Document::from(text).find(Name("meta")) {
        if titles.attr("property") == Some("title") {
            return titles
                .attr("content")
                .unwrap_or_default()
                .trim()
                .to_string();
        }
    }
    if let Some(m) = RE_TITLE.captures(text) {
        return m
            .name("title")
            .map_or("", |m| m.as_str())
            .trim()
            .to_string();
    }
    String::new()
}

/// 首页请求
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
    config: RequestOption,
    http_https: bool,
) -> anyhow::Result<Vec<Arc<RawData>>> {
    let mut is_start_with_http: bool = true;
    let mut raw_data_list: Vec<Arc<RawData>> = vec![];
    let schemes: [String; 2] = [String::from("https://"), String::from("http://")];
    for mut scheme in schemes {
        //最大重定向跳转次数
        let mut max_redirect = 5;
        let mut scheme_url = url_str.to_string();
        if http_https {
            scheme_url = scheme_url.replace("http://", "").replace("https://", "");
        }
        if !scheme_url.to_lowercase().starts_with("http://")
            && !scheme_url.to_lowercase().starts_with("https://")
        {
            scheme.push_str(&scheme_url);
            scheme_url = scheme;
            is_start_with_http = false;
        }
        let mut url = Url::parse(&scheme_url)?;
        loop {
            let mut next_url: Option<Url> = None;
            if let Ok(res) = send_requests(&url, special_wfp, &config, Policy::none()).await {
                if let Ok(raw_data) = fetch_raw_data(res, config.clone()).await {
                    next_url = raw_data.next_url.clone();
                    raw_data_list.push(raw_data);
                };
            };
            if !is_index {
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
    use std::collections::HashMap;

    use reqwest::header::HeaderMap;
    use reqwest::redirect::Policy;
    use url::Url;

    use crate::request::{get_charset_from_html, get_favicon_link, get_next_jump, send_requests};
    use crate::{RequestOption, WebFingerPrintRequest};

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
        let request_config = RequestOption::new(&timeout, &None, &None, false, false, "");
        let res = send_requests(&test_url, &fingerprint, &request_config, Policy::none())
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
        let request_config = RequestOption::new(&timeout, &None, &None, false, false, "");
        let res = send_requests(&test_url, &fingerprint, &request_config, Policy::none())
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
        for (text, verify) in test_test_verify_map {
            let mut flag = false;
            for link in get_favicon_link(text, &base_url) {
                if link.path() == verify {
                    flag = true;
                }
            }
            assert!(flag);
        }
    }

    #[test]
    fn test_get_charset() {
        let charset_tests = [
            (r#"<meta charset="gb2312" />"#, "gb2312"),
            (
                r#"<meta http-equiv="Content-Type" content="text/html; charset=gbk" />"#,
                "gbk",
            ),
            (
                r#"<meta http-equiv="Content-Type" content="text/html;" />"#,
                "utf-8",
            ),
        ];
        for (text, verify) in charset_tests.iter() {
            assert_eq!(get_charset_from_html(text), verify.to_string());
        }
    }

    #[test]
    fn test_js_jump() {
        let test_text_list = vec![
            (
                r#"<script> window.location.replace("login.jsp?up=1");</script>"#,
                "login.jsp?up=1",
            ),
            (
                r#"<html><meta charset='utf-8'/><style>body{background:white}</style><script>self.location='/index.php?m=user&f=login&referer=lw==';</script>"#,
                "/index.php?m=user&f=login&referer=lw==",
            ),
            (
                r#"window.location.href = "../cgi-bin/login.cgi?requestname=2&cmd=0";"#,
                "/cgi-bin/login.cgi?requestname=2&cmd=0",
            ),
        ];
        let test_test_verify_map: HashMap<&str, &str> = HashMap::from_iter(test_text_list);
        let base_url = Url::parse("https://kali-team.cn").unwrap();
        for (text, verify) in test_test_verify_map {
            if let Some(next_url) = get_next_jump(&HeaderMap::new(), &base_url, text) {
                let verify_url = base_url.join(verify).unwrap();
                assert_eq!(next_url, verify_url);
            } else {
                assert_eq!(verify, "");
            };
        }
    }
}
