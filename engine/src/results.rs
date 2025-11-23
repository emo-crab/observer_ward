use crate::info::Info;
use crate::operators::OperatorResult;
use crate::serde_format::Value;
use serde::{Deserialize, Serialize};
use slinger::Response;
use slinger::http::uri::Uri;
use slinger::http_serde;
use slinger::record::HTTPRecord;
use std::collections::{BTreeMap, HashSet};
use std::sync::Arc;

// 指纹/匹配结果 (更通用的命名)
#[cfg_attr(feature = "mcp", derive(schemars::JsonSchema))]
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
#[serde(deny_unknown_fields)]
pub struct MatchEvent {
  // 当前请求所命中的全面规则
  /// Collection of all matched fingerprint rules
  #[cfg_attr(
    feature = "mcp",
    schemars(
      title = "matcher results",
      description = "Detailed results of all matched fingerprinting rules",
      example = r#"[{
            "name": "nginx-version",
            "matched": "server header",
            "confidence": 90
        }]"#
    )
  )]
  matcher_results: Vec<MatcherResult>,
  #[serde(with = "http_serde::uri")]
  #[cfg_attr(feature = "mcp", schemars(with = "String"))]
  // 当前URI
  matched_at: Uri,
  // 当前请求和响应记录
  #[serde(skip_serializing_if = "Option::is_none")]
  record: Option<Arc<HTTPRecord>>,
}
#[cfg_attr(feature = "mcp", derive(schemars::JsonSchema))]
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
#[serde(deny_unknown_fields)]
pub struct MatcherResult {
  pub template: String,
  pub info: Arc<Info>,
  pub matcher_name: Vec<String>,
  pub extractor: BTreeMap<String, HashSet<String>>,
}

impl MatchEvent {
  pub fn push(&mut self, template: &Arc<str>, info: &Arc<Info>, ops: OperatorResult) {
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
      record: Some(Arc::new(HTTPRecord {
        request,
        raw_request: Default::default(),
        response: response.clone(),
        raw_response: Default::default(),
      })),
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
#[cfg_attr(feature = "mcp", derive(schemars::JsonSchema))]
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct NucleiResult {
  /// Unique identifier of the template that produced this result
  #[cfg_attr(
    feature = "mcp",
    schemars(
      title = "template identifier",
      description = "Unique identifier of the template that produced this result"
    )
  )]
  pub template_id: String,
  /// Timestamp when the match occurred
  #[cfg_attr(
    feature = "mcp",
    schemars(
      title = "match timestamp",
      description = "Timestamp indicating when the template matched the target"
    )
  )]
  pub matched_at: String,
  /// Results extracted from the target using extractors
  #[serde(default, skip_serializing_if = "Option::is_none")]
  #[cfg_attr(
    feature = "mcp",
    schemars(
      title = "extracted results",
      description = "Values extracted from the target using the template's extractors"
    )
  )]
  pub extracted_results: Option<Vec<String>>,
  /// Additional metadata associated with the result
  #[serde(default)]
  #[cfg_attr(
    feature = "mcp",
    schemars(
      title = "result metadata",
      description = "Additional metadata associated with the scan result"
    )
  )]
  pub meta: BTreeMap<String, Value>,
  /// Information about the template that produced this result
  #[cfg_attr(
    feature = "mcp",
    schemars(
      title = "template information",
      description = "Detailed information about the template that generated this result"
    )
  )]
  pub info: Arc<Info>,
  /// cURL command that could reproduce this request
  #[serde(default)]
  #[cfg_attr(
    feature = "mcp",
    schemars(
      title = "curl command",
      description = "cURL command that could reproduce the request that led to this result"
    )
  )]
  pub curl_command: String,
  /// The raw request that was sent (if enabled in configuration)
  #[serde(default, skip_serializing_if = "Option::is_none")]
  #[cfg_attr(
    feature = "mcp",
    schemars(
      title = "raw request",
      description = "The complete request that was sent to the target (if request logging is enabled)"
    )
  )]
  pub request: Option<String>,
  /// The raw response received (if enabled in configuration)
  #[serde(default, skip_serializing_if = "Option::is_none")]
  #[cfg_attr(
    feature = "mcp",
    schemars(
      title = "raw response",
      description = "The complete response received from the target (if response logging is enabled)"
    )
  )]
  pub response: Option<String>,
}
