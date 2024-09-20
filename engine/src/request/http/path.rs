use crate::request::input_to_byte;
use crate::serde_format::is_default;
use crate::serde_format::Value;
use serde::{Deserialize, Serialize};
use slinger::http::Method;
use slinger::http_serde;
use slinger::Request;
use std::collections::{BTreeMap, VecDeque};
use std::path::PathBuf;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "kebab-case")]
pub struct Http {
  // description: |
  //   Method is the HTTP Request Method.
  #[serde(with = "http_serde::method", default)]
  pub method: Method,
  // description: |
  //   Path contains the path/s for the HTTP requests. It supports variables
  //   as placeholders.
  // examples:
  //   - name: Some example path values
  //     value: >
  //       []string{"{{BaseURL}}", "{{BaseURL}}/+CSCOU+/../+CSCOE+/files/file_list.json?path=/sessions"}
  #[serde(default)]
  pub path: Vec<String>,
  // description: |
  //   Body is an optional parameter which contains HTTP Request body.
  // examples:
  //   - name: Same Body for a Login POST request
  //     value: "\"username=test&password=test\""
  #[serde(default, skip_serializing_if = "is_default")]
  pub body: Option<String>,
  // description: |
  //   Headers contains HTTP Headers to send with the request.
  // examples:
  //   - value: |
  //       map[string]string{"Content-Type": "application/x-www-form-urlencoded", "Content-Length": "1", "Any-Header": "Any-Value"}
  #[serde(default, skip_serializing_if = "is_default")]
  pub headers: BTreeMap<String, Value>,
}

fn join(cur_uri: &slinger::http::uri::Uri, val: String) -> Option<slinger::http::uri::Uri> {
  let path = val.trim_start_matches("{{BaseURL}}");
  let path = PathBuf::from(cur_uri.path()).join(path);
  slinger::http::uri::Uri::builder()
    .scheme(cur_uri.scheme_str().unwrap_or_default())
    .authority(cur_uri.authority()?.as_str())
    .path_and_query(path.to_string_lossy().as_ref())
    .build()
    .ok()
}

impl Http {
  pub(crate) fn to_requests(&self, target: &slinger::http::uri::Uri) -> VecDeque<Request> {
    let mut requests = VecDeque::new();
    for path in self.path.clone().into_iter() {
      let target = join(target, path).unwrap_or(target.clone());
      let mut builder = Request::builder()
        .method(self.method.clone())
        .uri(target.clone())
        .header(
          "Accept",
          "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
        );
      for (key, value) in self.headers.clone().into_iter() {
        builder = builder.header(key, &value);
      }
      let body = slinger::Body::from(input_to_byte(&self.body.clone().unwrap_or_default()));
      if let Ok(request) = builder.body(body) {
        requests.push_back(Request::from(request));
      };
    }
    requests
  }
}
