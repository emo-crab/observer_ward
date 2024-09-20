mod code;
mod dns;
mod headless;
mod http;
mod tcp;

use crate::operators::Operators;
use crate::request::code::CodeRequest;
use crate::request::headless::HeadlessRequest;
pub use crate::request::http::{HTTPRequest, Http, HttpRaw, Raw, RequestGenerator};
pub use crate::request::tcp::{Input, PortRange, TCPRequest};
use crate::serde_format::is_default;
use rustc_lexer::unescape;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
#[serde(rename_all = "lowercase")]
#[serde(deny_unknown_fields)]
pub struct Requests {
  // description: |
  //   HTTP contains the http request to make in the template.
  // examples:
  //   - value: exampleNormalHTTPRequest
  // RequestsWithHTTP is placeholder(internal) only, and should not be used instead use RequestsHTTP
  // Deprecated: Use RequestsHTTP instead.
  #[serde(alias = "requests", default, skip_serializing_if = "is_default")]
  pub http: Vec<HTTPRequest>,
  // description: |
  //   DNS contains the dns request to make in the template
  // examples:
  //   - value: exampleNormalDNSRequest
  // DNS(),
  // description: |
  //   File contains the file request to make in the template
  // examples:
  //   - value: exampleNormalFileRequest
  // FILE(),
  // description: |
  //   TCP contains the network request to make in the template
  // examples:
  //   - value: exampleNormalNetworkRequest
  // RequestsWithTCP is placeholder(internal) only, and should not be used instead use RequestsNetwork
  // Deprecated: Use RequestsNetwork instead.
  #[serde(default, skip_serializing_if = "is_default")]
  pub tcp: Vec<TCPRequest>,
  // description: |
  //   Headless contains the headless request to make in the template.
  #[serde(default, skip_serializing_if = "is_default")]
  pub headless: Vec<HeadlessRequest>,
  // description: |
  //   SSL contains the SSL request to make in the template.
  // SSL(),
  // description: |
  //   Websocket contains the Websocket request to make in the template.
  // WEBSOCKET(),
  // description: |
  //   WHOIS contains the WHOIS request to make in the template.
  // WHOIS(),
  // description: |
  //   Code contains code snippets.
  #[serde(default, skip_serializing_if = "is_default")]
  pub code: Vec<CodeRequest>,
  // description: |
  //   Javascript contains the javascript request to make in the template.
  // JAVASCRIPT(),
}

impl Requests {
  // 判断是否可以优化请求
  pub fn can_cluster(&self, other: &Requests) -> bool {
    if self.http.len() == 1 && other.http.len() == 1 {
      let self_http = &self.http[0];
      let other_http = &other.http[0];
      // 存在请求探针名称并且相同，直接合并优化
      if let (Some(sn), Some(on)) = (&self_http.name, &other_http.name) {
        return sn == on;
      }
      // 存在相同的情况上面已经返回了
      if self_http.name.is_some() || other_http.name.is_some() {
        return false;
      }
      if self_http.http_option != other_http.http_option {
        return false;
      }
      if self_http.payload_attack.is_some() || other_http.payload_attack.is_some() {
        return false;
      }
      if let (HttpRaw::Path(sp), HttpRaw::Path(op)) = (&self_http.http_raw, &other_http.http_raw) {
        if sp == op {
          return true;
        }
      }
    }
    if self.tcp.len() == 1 && other.tcp.len() == 1 {
      let self_tcp = &self.tcp[0];
      let other_tcp = &other.tcp[0];
      // 存在请求探针名称并且相同，直接合并优化
      if let (Some(sn), Some(on)) = (&self_tcp.name, &other_tcp.name) {
        return sn == on;
      }
    }
    false
  }
  pub fn is_web_default(&self) -> bool {
    if self.http.len() == 1 {
      if let HttpRaw::Path(path) = &self.http[0].http_raw {
        if path.path.len() == 1 && path.method.is_safe() {
          return path.path[0] == "{{BaseURL}}/";
        }
      };
    }
    false
  }
  pub fn is_web(&self) -> Option<&HTTPRequest> {
    self.http.first()
  }
  pub fn is_tcp(&self) -> Option<&TCPRequest> {
    self.tcp.first()
  }
  pub fn is_tcp_default(&self) -> bool {
    if self.tcp.len() == 1 {
      return self.tcp[0].name == Some("null".to_string());
    }
    false
  }
  pub fn operators(&self) -> Vec<Operators> {
    let mut all = Vec::new();
    all.extend(
      self
        .http
        .iter()
        .map(|h| h.operators.clone())
        .collect::<Vec<_>>(),
    );
    all.extend(
      self
        .tcp
        .iter()
        .map(|t| t.operators.clone())
        .collect::<Vec<_>>(),
    );
    all
  }

  pub fn default_web_index() -> Self {
    Self {
      http: vec![HTTPRequest {
        http_raw: HttpRaw::Path(Http {
          method: Default::default(),
          path: vec!["{{BaseURL}}/".to_string()],
          body: Default::default(),
          headers: Default::default(),
        }),
        id: None,
        name: None,
        payload_attack: None,
        skip_variables_check: false,
        stop_at_first_match: false,
        http_option: Default::default(),
        operators: Default::default(),
      }],
      tcp: vec![],
      headless: vec![],
      code: vec![],
    }
  }
}
// yaml字符串转字节
fn input_to_byte(payload: &str) -> Vec<u8> {
  let mut buf = Vec::new();
  if !payload.is_empty() {
    unescape::unescape_byte_str(payload, &mut |_x, y| {
      if let Ok(c) = y {
        buf.push(c)
      }
    });
  }
  buf
}
