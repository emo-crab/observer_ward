use crate::info::Info;
use crate::operators::OperatorResult;
use crate::serde_format::Value;
use serde::{Deserialize, Serialize};
use slinger::http::uri::Uri;
use slinger::http_serde;
use slinger::record::HTTPRecord;
use slinger::Response;
use std::collections::{BTreeMap, HashSet};

// 指纹匹配结果
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
#[serde(deny_unknown_fields)]
pub struct FingerprintResult {
  // 当前请求所命中的全面规则
  matcher_results: Vec<MatcherResult>,
  #[serde(with = "http_serde::uri")]
  // 当前URI
  matched_at: Uri,
  // 当前请求和响应记录
  #[serde(skip_serializing_if = "Option::is_none")]
  record: Option<HTTPRecord>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
#[serde(deny_unknown_fields)]
pub struct MatcherResult {
  pub template: String,
  pub info: Info,
  pub matcher_name: Vec<String>,
  pub extractor: BTreeMap<String, HashSet<String>>,
}

impl FingerprintResult {
  pub fn push(&mut self, template: &String, info: &Info, ops: OperatorResult) {
    self.matcher_results.push(MatcherResult {
      template: template.to_string(),
      info: info.clone(),
      matcher_name: ops.matcher_word(),
      extractor: ops.extract_result(),
    });
  }
  pub fn new(response: &Response) -> Self {
    let request = response.request().cloned().unwrap_or_default();
    let uri = request.uri().clone();
    Self {
      matcher_results: vec![],
      matched_at: uri,
      record: Some(HTTPRecord {
        request,
        raw_request: Default::default(),
        response: response.clone(),
        raw_response: Default::default(),
      }),
    }
  }
  pub fn matched_at(&self) -> &Uri {
    &self.matched_at
  }
  pub fn response(&self) -> Option<Response> {
    self.record.clone().map(|http| http.response.clone())
  }
  pub fn omit_raw(&mut self) {
    self.record = None;
  }
  pub fn matcher_result(&self) -> &Vec<MatcherResult> {
    &self.matcher_results
  }
  pub fn name(&self) -> HashSet<String> {
    self
      .matcher_results
      .iter()
      .map(|x| x.template.clone())
      .collect()
  }
  pub fn matcher_result_mut(&mut self) -> &mut Vec<MatcherResult> {
    &mut self.matcher_results
  }
  pub fn extractor(&self) -> BTreeMap<String, HashSet<String>> {
    let mut em: BTreeMap<String, HashSet<String>> = BTreeMap::new();
    for mr in self.matcher_results.iter() {
      for (k, h) in mr.extractor.iter() {
        if let Some(e) = em.get_mut(k) {
          e.extend(h.iter().map(|x| x.trim().to_string()).collect::<Vec<_>>());
        } else {
          em.insert(
            k.clone(),
            h.iter()
              .map(|x| x.trim().to_string())
              .collect::<HashSet<_>>(),
          );
        }
      }
    }
    em
  }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct NucleiResult {
  pub template_id: String,
  pub matched_at: String,
  #[serde(default, skip_serializing_if = "Option::is_none")]
  pub extracted_results: Option<Vec<String>>,
  #[serde(default)]
  pub meta: BTreeMap<String, Value>,
  pub info: Info,
  #[serde(default)]
  pub curl_command: String,
  #[serde(default, skip_serializing_if = "Option::is_none")]
  pub request: Option<String>,
  #[serde(default, skip_serializing_if = "Option::is_none")]
  pub response: Option<String>,
}
