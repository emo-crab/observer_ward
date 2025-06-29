use crate::error::{Result, new_regex_error};
use crate::info::Info;
use crate::matchers::MatcherType;
use crate::request::{HttpRaw, Requests};
use crate::serde_format::is_default;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

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
  pub info: Info,
  /// description: |
  ///   Flow contains the execution flow for the template.
  /// examples:
  ///   - flow: |
  /// 		for region in regions {
  ///  	    http(0)
  ///  	 }
  ///  	 for vpc in vpcs {
  ///  	    http(1)
  ///  	 }
  ///
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
  pub requests: Requests,
  /// description: |
  ///   Self Contained marks Requests for the template as self-contained
  #[serde(default, skip_serializing_if = "is_default")]
  #[cfg_attr(feature = "mcp", schemars(
    title = "mark requests as self-contained",
    description = "Mark Requests for the template as self-contained"
  ))]
  pub self_contained: bool,
  /// description: |
  ///  Stop execution once first match is found
  #[serde(default, skip_serializing_if = "is_default")]
  #[cfg_attr(feature = "mcp", schemars(
    title = "stop at first match",
    description = "Stop at first match for the template"
  ))]
  pub stop_at_first_match: bool,
  /// Variables contains any variables for the current request.
  #[serde(default, skip_serializing_if = "is_default")]
  #[cfg_attr(feature = "mcp", schemars(
    title = "variables for the http request",
    description = "Variables contains any variables for the current request"
  ))]
  pub variables: BTreeMap<String, String>,
}

impl Template {
  pub fn compile(&mut self) -> Result<()> {
    for http in self.requests.http.iter_mut() {
      http.operators.compile().map_err(new_regex_error)?;
    }
    for tcp in self.requests.tcp.iter_mut() {
      tcp.operators.compile().map_err(new_regex_error)?;
    }
    Ok(())
  }
  pub fn find_favicon(&mut self) -> Option<Template> {
    let mut new_template = self.clone();
    let mut flag = false;
    for (request_index, request) in self.requests.http.iter_mut().enumerate() {
      let mut favicon = Vec::new();
      if let HttpRaw::Path(ref mut http) = request.http_raw {
        let mut remove_path = Vec::new();
        let mut new_http = http.clone();
        while let Some(index) = http
          .path
          .iter_mut()
          .position(|p| p.ends_with("favicon.ico"))
        {
          remove_path.push(http.path.remove(index));
        }
        if !remove_path.is_empty() {
          new_http.path = remove_path;
          new_template.requests.http[request_index].http_raw = HttpRaw::Path(new_http);
        }
      }
      let mut new_operators = request.operators.clone();
      while let Some(index) = request
        .operators
        .matchers
        .iter_mut()
        .position(|m| matches!(m.matcher_type, MatcherType::Favicon(..)))
      {
        favicon.push(request.operators.matchers.remove(index));
      }
      if !favicon.is_empty() {
        flag = true;
        new_operators.matchers = favicon;
        new_template.requests.http[request_index].operators = new_operators;
      }
    }
    if flag { Some(new_template) } else { None }
  }
}
