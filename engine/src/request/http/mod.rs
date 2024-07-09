mod option;
mod path;
mod raw;

use crate::operators::Operators;
use std::collections::VecDeque;
use std::fmt::Debug;

use crate::common::{PayloadAttack, PayloadIterator};
use crate::request::http::option::HttpOption;
pub use crate::request::http::path::Http;
pub use crate::request::http::raw::Raw;
use crate::serde_format::is_default;
use serde::{Deserialize, Serialize};
use slinger::Request;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "kebab-case")]
pub struct HTTPRequest {
  #[serde(flatten)]
  pub http_raw: HttpRaw,
  // ID is the optional id of the request
  #[serde(default, skip_serializing_if = "is_default")]
  pub id: Option<String>,
  // description: |
  //  Name is the optional name of the request.
  //
  //  If a name is specified, all the named request in a template can be matched upon
  //  in a combined manner allowing multi-request based matchers.
  #[serde(default, skip_serializing_if = "is_default")]
  pub name: Option<String>,
  #[serde(flatten, skip_serializing_if = "is_default")]
  pub payload_attack: Option<PayloadAttack>,
  #[serde(default, skip_serializing_if = "is_default")]
  pub skip_variables_check: bool,
  #[serde(default, skip_serializing_if = "is_default")]
  pub stop_at_first_match: bool,
  // Operators for the current request go here.
  #[serde(flatten)]
  pub http_option: HttpOption,
  #[serde(flatten)]
  pub operators: Operators,
}

#[derive(Debug)]
pub struct RequestGenerator {
  requests: VecDeque<Request>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(untagged)]
pub enum HttpRaw {
  Path(Http),
  Raw(Raw),
}

impl RequestGenerator {
  pub fn new(value: &HTTPRequest, uri: slinger::http::uri::Uri) -> Self {
    let _payload = value.payload_attack.as_ref().map(PayloadIterator::from);
    let requests = match &value.http_raw {
      HttpRaw::Path(paths) => paths.to_requests(&uri),
      HttpRaw::Raw(raws) => raws.to_requests(&uri),
    };
    RequestGenerator { requests }
  }
}

impl Iterator for RequestGenerator {
  type Item = Request;

  fn next(&mut self) -> Option<Self::Item> {
    self.requests.pop_front()
  }
}
