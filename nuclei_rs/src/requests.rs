use std::collections::HashMap;
use std::fmt;
use std::iter::FromIterator;
use std::marker::PhantomData;
use std::str::FromStr;
use std::time::Duration;

use encoding_rs::{Encoding, UTF_8};
use lazy_static::lazy_static;
use mime::Mime;
use rand::distributions::Alphanumeric;
use rand::{thread_rng, Rng};
use regex::Regex;
use reqwest::blocking::{Body, Client, Response};
use reqwest::header::{HeaderMap, HeaderName, HeaderValue};
use reqwest::redirect::Policy;
use reqwest::{header, Method};
use serde::{de, Deserialize, Deserializer, Serialize};
use tera::{Context, Template};
use url::Url;

use crate::err::BuildRequestError;
use crate::operators::Matcher;

use super::operators::Extractor;

#[derive(Debug, Default, Clone)]
pub struct ResponseRaw {
    pub raw: Vec<u8>,
    pub html: String,
    pub headers: reqwest::header::HeaderMap,
    pub status_code: u16,
}
lazy_static! {
    static ref RE_COMPILE_BY_CHARSET: Regex =
        Regex::new(r#"(?im)charset="(.*?)"|charset=(.*?)""#).unwrap();
}
pub fn get_default_encoding(byte: &[u8], headers: HeaderMap) -> String {
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

impl ResponseRaw {
    pub fn new(resp: Response) -> Self {
        let resp_headers = resp.headers().clone();
        let status_code = resp.status().clone();
        let bytes = resp.bytes().unwrap_or_default().to_vec();
        let text: String = get_default_encoding(&bytes, resp_headers.clone());
        Self {
            raw: bytes,
            html: text,
            headers: resp_headers,
            status_code: status_code.as_u16(),
        }
    }
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct HttpRequest {
    #[serde(default)]
    path: Vec<String>,
    #[serde(default)]
    raw: Vec<String>,
    #[serde(default)]
    method: String,
    #[serde(default)]
    body: String,
    #[serde(default)]
    headers: HashMap<String, String>,
    #[serde(default)]
    max_redirects: usize,
    #[serde(default)]
    cookie_reuse: bool,
    #[serde(default)]
    redirects: bool,
    #[serde(default)]
    req_condition: bool,
    #[serde(default)]
    stop_at_first_match: bool,
    #[serde(default)]
    skip_variables_check: bool,
    #[serde(default)]
    metadata: HashMap<String, String>,
    #[serde(default)]
    matchers: Vec<Matcher>,
    #[serde(default)]
    extractors: Vec<Extractor>,
    #[serde(default)]
    #[serde(deserialize_with = "string_to_is_and")]
    #[serde(rename = "matchers-condition")]
    matchers_condition_is_and: bool,
    #[serde(skip)]
    response_raw: Vec<ResponseRaw>,
    #[serde(skip)]
    client: Client,
    #[serde(skip)]
    #[serde(default = "default_url")]
    target: Url,
    #[serde(skip)]
    context: Context,
}

fn default_url() -> Url {
    Url::parse("https://www.example.com/").unwrap()
}

#[derive(Debug, Clone)]
struct BuildRequest {
    method: Method,
    url: Url,
    headers: HeaderMap,
    body: String,
}
lazy_static! {
    static ref RE_COMPILE_BY_BLOCK: Regex = Regex::new(r#"(?im)Ident\("(?P<name>.*?)"\)"#).unwrap();
}
#[derive(Debug, Clone)]
struct PartBlock {
    patched_template: String,
    block_list: Vec<String>,
}

impl BuildRequest {
    fn fetch_all_block(template_string: String) -> PartBlock {
        let mut patched_template = template_string;
        let replace_map: HashMap<&str, &str> = HashMap::from_iter([
            ("{{BaseURL}}/", "{{BaseURL}}"),
            ("interactsh-url", "interactsh_url"),
            ("url_encode(", "url_encode(string="),
            ("{{base64(", "{{base64(string="),
            ("{{hex_decode(", "{{hex_decode(string="),
            ("{{base64_decode(", "{{base64_decode(string="),
        ]);
        for (from_key, to_value) in replace_map.into_iter() {
            patched_template = patched_template.replace(from_key, to_value);
        }
        let mut block_list: Vec<String> = vec![];
        match Template::new("path.yaml", None, &patched_template) {
            Ok(template) => {
                for charset in RE_COMPILE_BY_BLOCK.captures_iter(&format!("{:?}", template.ast)) {
                    let u = charset.name("name").map_or("", |m| m.as_str());
                    block_list.push(u.to_string());
                }
            }
            Err(_err) => {
                // println!("{:?}", err)
            }
        };
        return PartBlock {
            patched_template,
            block_list,
        };
    }

    fn fetch_extractor_by_name(
        name: &String,
        extractors: Vec<Extractor>,
        last_response_raw: Vec<ResponseRaw>,
    ) -> HashMap<String, String> {
        for mut extractor in extractors.into_iter() {
            if &extractor.name == name {
                if let Some(rq) = last_response_raw.last() {
                    return extractor.extract(&rq);
                }
            }
        }
        let resulted = HashMap::new();
        return resulted;
    }
}

impl BuildRequest {
    pub fn parse(raw_string: String, target: Url) -> Self {
        let mut headers = HeaderMap::new();
        let mut body = String::new();
        let mut method = Method::GET;
        let mut req_url = target.clone();
        let mut headers_lines: Vec<String> = raw_string
            .split_terminator("\n")
            .map(|s| s.to_string())
            .collect();
        match raw_string.split_once("\n\n") {
            None => {}
            Some((headers_string, data)) => {
                body = data.to_string();
                headers_lines = headers_string
                    .split_terminator("\n")
                    .map(|s| s.to_string())
                    .collect();
            }
        };
        if !headers_lines.is_empty() {
            let method_path: Vec<String> = headers_lines
                .remove(0)
                .split_whitespace()
                .map(|s| s.to_string())
                .collect();
            let method_string: String = method_path
                .get(0)
                .unwrap_or(&String::from("get"))
                .to_string();
            let path = method_path.get(1).unwrap_or(&String::from("/")).to_string();
            req_url = target.join(&path).unwrap_or(req_url);
            if let Ok(m) = Method::from_str(&method_string.to_uppercase()) {
                method = m;
            };
            for header_line in headers_lines.into_iter() {
                if let Some((name, value)) = header_line.split_once(": ") {
                    if !name.is_empty() {
                        headers.insert(
                            HeaderName::from_str(name).unwrap(),
                            HeaderValue::from_str(value).unwrap(),
                        );
                    }
                }
            }
        }
        let hrp = Self {
            method,
            url: req_url,
            headers,
            body,
        };
        hrp
    }
}

impl HttpRequest {
    fn default_ctx(&self) -> Context {
        let mut ctx = Context::new();
        let rand_string: String = thread_rng()
            .sample_iter(&Alphanumeric)
            .take(6)
            .map(char::from)
            .collect();
        let hostname = format!(
            "{}:{}",
            self.target.host_str().unwrap(),
            self.target.port_or_known_default().unwrap_or_default()
        );
        ctx.insert("BaseURL", self.target.as_str());
        ctx.insert("interactsh_url", "http://interactsh.com/");
        ctx.insert("randstr", rand_string.as_str());
        ctx.insert("Hostname", hostname.as_str());
        return ctx;
    }
    fn raw_to_br(&mut self, raw: String) -> Result<BuildRequest, BuildRequestError> {
        let text = self.make_template(raw)?;
        let br = BuildRequest::parse(text, self.target.clone());
        Ok(br)
    }
    fn make_url(&mut self, path: String) -> Result<Url, BuildRequestError> {
        let text = self.make_template(path)?;
        let path_url = Url::parse(&text).unwrap();
        return Ok(path_url);
    }
    fn make_body(&mut self, path: String) -> Result<String, BuildRequestError> {
        let text = self.make_template(path)?;
        return Ok(text);
    }
    fn make_template(&mut self, template_string: String) -> Result<String, BuildRequestError> {
        let mut tera_c = tera::Tera::default();
        let part_block = BuildRequest::fetch_all_block(template_string.clone());
        for block_name in part_block.block_list.into_iter() {
            if !self.context.contains_key(&block_name) {
                let ctx_extractor = BuildRequest::fetch_extractor_by_name(
                    &block_name,
                    self.extractors.clone(),
                    self.response_raw.clone(),
                );
                if ctx_extractor.contains_key(&block_name) {
                    self.context
                        .insert(&block_name, ctx_extractor.get(&block_name).unwrap());
                } else {
                    return Err(BuildRequestError::Other(format!(
                        "{} not found in context",
                        block_name
                    )));
                }
            }
        }
        let text = tera_c.render_str(&part_block.patched_template, &self.context);
        match text {
            Ok(text) => Ok(text),
            Err(err) => Err(BuildRequestError::Other(format!("{}", err))),
        }
    }
    fn path_to_br(&mut self, path: String) -> Result<BuildRequest, BuildRequestError> {
        let req_url = self.make_url(path).unwrap();
        let req_body = self.make_body(self.body.clone()).unwrap();
        let mut req_headers = header::HeaderMap::new();
        let req_method = Method::from_str(&self.method.to_uppercase()).unwrap_or(Method::GET);
        for (k, v) in self.headers.clone() {
            req_headers.insert(
                HeaderName::from_str(&k).unwrap(),
                HeaderValue::from_str(&v).unwrap(),
            );
        }
        let br = BuildRequest {
            method: req_method,
            url: req_url,
            headers: req_headers,
            body: req_body,
        };
        Ok(br)
    }
}

impl HttpRequest {
    fn init(&mut self, target: Url) {
        self.target = target;
        self.client = self.new_client();
        self.context = self.default_ctx();
    }
    // 执行全部请求
    pub fn execute_request(&mut self, target: String) -> bool {
        let target = Url::parse(&target).unwrap();
        self.init(target);
        for (_index, path) in self.path.clone().into_iter().enumerate() {
            // 根据提取器和上次的请求数据生成这次的请求
            if let Ok(build_request) = self.path_to_br(path) {
                let resp_result = self.send_requests(build_request.clone());
                if let Ok(resp) = resp_result {
                    let raw_resp = ResponseRaw::new(resp);
                    if self.match_raw_resp(&raw_resp) {
                        // self.matchers_condition_is_and 和请求没有关系，只和matcher有关系
                        // 不管是那个请求都去匹配，匹配到了再返回match的url
                        // println!("{:#?}", build_request)
                        return true;
                    };
                    self.response_raw.push(raw_resp.clone());
                }
            };
        }
        for (_index, raw) in self.raw.clone().into_iter().enumerate() {
            if let Ok(build_request) = self.raw_to_br(raw) {
                let resp_result = self.send_requests(build_request.clone());
                if let Ok(resp) = resp_result {
                    let raw_resp = ResponseRaw::new(resp);
                    if self.match_raw_resp(&raw_resp) {
                        // self.matchers_condition_is_and 和请求没有关系，只和matcher有关系
                        // 不管是那个请求都去匹配，匹配到了再返回match的url
                        // println!("{:#?}", build_request)
                        return true;
                    };
                    self.response_raw.push(raw_resp.clone());
                }
            };
        }
        return false;
    }
    // 根据 path或者raw生成的build_request发送请求，返回原始数据
    fn send_requests(&self, build_request: BuildRequest) -> Result<Response, reqwest::Error> {
        let body_data = Body::from(build_request.body.clone());
        return self
            .client
            .request(build_request.method, build_request.url.as_ref())
            .body(body_data)
            .headers(build_request.headers)
            .send();
    }
    // 新建一个HTTP客户端，用于保存会话
    pub fn new_client(&self) -> Client {
        let mut headers = header::HeaderMap::new();
        let ua = "Mozilla/5.0 (X11; Linux x86_64; rv:94.0) Gecko/20100101 Firefox/94.0";
        headers.insert(header::USER_AGENT, header::HeaderValue::from_static(ua));
        if !self.headers.is_empty() {
            for (k, v) in self.headers.clone() {
                headers.insert(
                    HeaderName::from_str(&k).unwrap(),
                    HeaderValue::from_str(&v).unwrap(),
                );
            }
        }
        let client = reqwest::blocking::Client::builder()
            .danger_accept_invalid_certs(true)
            .default_headers(headers.clone())
            .redirect(Policy::limited(self.max_redirects))
            .cookie_store(self.cookie_reuse)
            .timeout(Duration::new(10, 0));
        return client.build().unwrap();
    }
    // 匹配全部后根据matchers_condition返回match-url
    fn match_raw_resp(&self, raw_resp: &ResponseRaw) -> bool {
        for (index, mut match_item) in self.matchers.clone().into_iter().enumerate() {
            if !match_item.match_item(raw_resp.clone()) {
                if self.matchers_condition_is_and {
                    return false;
                }
                continue;
            }
            if !self.matchers_condition_is_and {
                return true;
            }
            if self.matchers.len() - 1 == index {
                return true;
            }
        }
        return false;
    }
}

// 将and or 转为 bool
pub fn string_to_is_and<'de, D>(deserializer: D) -> Result<bool, D::Error>
where
    D: Deserializer<'de>,
{
    struct StringOrVec(PhantomData<bool>);
    impl<'de> de::Visitor<'de> for StringOrVec {
        type Value = bool;
        fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
            formatter.write_str("string or list of strings")
        }
        fn visit_str<E>(self, value: &str) -> Result<Self::Value, E>
        where
            E: de::Error,
        {
            if value == "and" {
                Ok(true)
            } else {
                Ok(false)
            }
        }

        fn visit_seq<S>(self, visitor: S) -> Result<Self::Value, S::Error>
        where
            S: de::SeqAccess<'de>,
        {
            Deserialize::deserialize(de::value::SeqAccessDeserializer::new(visitor))
        }
    }
    deserializer.deserialize_any(StringOrVec(PhantomData))
}
