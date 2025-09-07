use crate::error::{Result, new_regex_error};
use crate::info::Info;
use crate::operators::matchers::MatcherType;
use crate::request::{HttpRaw, Requests};
use crate::serde_format::is_default;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::sync::Arc;

pub mod cluster;
/// Template is a YAML input file which defines all the requests and
/// other metadata for a template.
#[cfg_attr(feature = "mcp", derive(schemars::JsonSchema))]
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
#[serde(deny_unknown_fields)]
pub struct Template {
  /// description: |
  ///   ID is the unique id for the template.
  ///
  ///   #### Good IDs
  ///
  ///   A good ID uniquely identifies what the requests in the template
  ///   are doing. Let's say you have a template that identifies a git-config
  ///   file on the webservers, a good name would be `git-config-exposure`. Another
  ///   example name is `azure-apps-nxdomain-takeover`.
  /// examples:
  ///   - name: ID Example
  ///     value: "\"CVE-2021-19520\""
  #[cfg_attr(
    feature = "mcp",
    schemars(
      title = "id of the template",
      description = "The Unique ID for the template",
      example = &"cve-2021-19520",
      pattern("^([a-zA-Z0-9]+[-_])*[a-zA-Z0-9]+$")
    )
  )]
  pub id: String,
  /// description: |
  ///   Info contains metadata information about the template.
  /// examples:
  ///   - value: exampleInfoStructure
  #[cfg_attr(
    feature = "mcp",
    schemars(
      title = "info for the template",
      description = "Info contains metadata for the template"
    )
  )]
  pub info: Arc<Info>,
  /// description: |
  ///   Flow contains the execution flow for the template.
  /// examples:
  /// ```yaml
  /// - flow: |
  ///   for region in regions {
  ///    http(0)
  ///  }
  ///  for vpc in vpcs {
  ///   http(1)
  /// }
  ///```
  #[serde(skip_serializing_if = "is_default")]
  #[cfg_attr(
    feature = "mcp",
    schemars(
      title = "template execution flow in js",
      description = "Flow contains js code which defines how the template should be executed",
      example = &"flow: http(0) && http(1)"
    )
  )]
  pub flow: Option<String>,
  #[serde(flatten)]
  pub requests: Arc<Requests>,
  /// description: |
  ///   Self Contained marks Requests for the template as self-contained
  #[serde(default, skip_serializing_if = "is_default")]
  #[cfg_attr(
    feature = "mcp",
    schemars(
      title = "mark requests as self-contained",
      description = "Mark Requests for the template as self-contained"
    )
  )]
  pub self_contained: bool,
  /// description: |
  ///  Stop execution once first match is found
  #[serde(default, skip_serializing_if = "is_default")]
  #[cfg_attr(
    feature = "mcp",
    schemars(
      title = "stop at first match",
      description = "Stop at first match for the template"
    )
  )]
  pub stop_at_first_match: bool,
  /// Variables contains any variables for the current request.
  #[serde(default, skip_serializing_if = "is_default")]
  #[cfg_attr(
    feature = "mcp",
    schemars(
      title = "variables for the http request",
      description = "Variables contains any variables for the current request"
    )
  )]
  pub variables: BTreeMap<String, String>,
}

impl Template {
  pub fn compile(&mut self) -> Result<()> {
    let requests = Arc::make_mut(&mut self.requests);
    for http in requests.http.iter_mut() {
      let mutable_http = Arc::make_mut(http);
      let mutable_operators = Arc::make_mut(&mut mutable_http.operators);
      mutable_operators.compile().map_err(new_regex_error)?;
    }
    for tcp in requests.tcp.iter_mut() {
      let mutable_tcp = Arc::make_mut(tcp);
      let mutable_operators = Arc::make_mut(&mut mutable_tcp.operators);
      mutable_operators.compile().map_err(new_regex_error)?;
    }
    Ok(())
  }
  pub fn find_favicon(&mut self) -> Option<Template> {
    let mut new_template = self.clone();
    let new_requests = Arc::make_mut(&mut new_template.requests);

    let mut found = false;

    for i in 0..self.requests.http.len() {
      if self.process_favicon_for_request(i, new_requests) {
        found = true;
      }
    }
    found.then_some(new_template)
  }
  fn process_favicon_for_request(&self, index: usize, new_requests: &mut Requests) -> bool {
    let request = &self.requests.http[index];
    let mut has_favicon = false;

    // 检查路径
    if let HttpRaw::Path(ref http) = request.http_raw {
      let favicon_paths: Vec<_> = http
        .path
        .iter()
        .filter(|p| p.ends_with("favicon.ico"))
        .cloned()
        .collect();

      if !favicon_paths.is_empty() {
        has_favicon = true;
        let new_http = Arc::make_mut(&mut new_requests.http[index]);

        if let HttpRaw::Path(ref mut new_http_raw) = new_http.http_raw {
          new_http_raw.path = favicon_paths;
        }
      }
    }

    // 检查匹配器
    let favicon_matchers: Vec<_> = request
      .operators
      .matchers
      .iter()
      .filter(|m| matches!(m.matcher_type, MatcherType::Favicon(..)))
      .cloned()
      .collect();

    if !favicon_matchers.is_empty() {
      has_favicon = true;
      let new_http = Arc::make_mut(&mut new_requests.http[index]);
      let new_operators = Arc::make_mut(&mut new_http.operators);
      new_operators.matchers = favicon_matchers;
    }
    has_favicon
  }
}
