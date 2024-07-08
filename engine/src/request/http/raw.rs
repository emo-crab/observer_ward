use crate::serde_format::is_default;
use serde::{Deserialize, Serialize};
use slinger::Request;
use std::collections::VecDeque;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "kebab-case")]
pub struct Raw {
  // description: |
  //   Raw contains HTTP Requests in Raw format.
  // examples:
  //   - name: Some example raw requests
  //     value: |
  //       []string{"GET /etc/passwd HTTP/1.1\nHost:\nContent-Length: 4", "POST /.%0d./.%0d./.%0d./.%0d./bin/sh HTTP/1.1\nHost: {{Hostname}}\nUser-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:71.0) Gecko/20100101 Firefox/71.0\nContent-Length: 1\nConnection: close\n\necho\necho\ncat /etc/passwd 2>&1"}
  #[serde(default, skip_serializing_if = "is_default")]
  pub raw: Vec<String>,
  #[serde(default, skip_serializing_if = "is_default")]
  pub r#unsafe: bool,
}
impl Raw {
  pub(crate) fn to_requests(&self, target: &slinger::http::uri::Uri) -> VecDeque<Request> {
    let mut requests = VecDeque::new();
    for raw in self.raw.clone().into_iter() {
      let r = Request::raw(target.clone(), raw, true);
      requests.push_back(r);
    }
    requests
  }
}
