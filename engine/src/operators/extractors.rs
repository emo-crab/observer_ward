use crate::error::Result;
use crate::info::Version;
use crate::operators::matchers::Part;
use crate::operators::regex::RegexPattern;
use crate::serde_format::is_default;
use jsonpath_rust::JsonPath;
use log::error;
use once_cell::sync::OnceCell;
use serde::{Deserialize, Serialize};
use slinger::Body;
use std::collections::{BTreeMap, HashSet};

/// Extractor defines a mechanism to extract data from protocol responses
#[cfg_attr(feature = "mcp", derive(schemars::JsonSchema))]
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct Extractor {
  /// Name of the extractor. Should be lowercase and must not contain spaces or underscores.
  #[serde(default, skip_serializing_if = "is_default")]
  #[cfg_attr(
    feature = "mcp",
    schemars(
      title = "name of the extractor",
      description = "Name of the extractor. Name should be lowercase and must not contain spaces or underscores (_)"
    )
  )]
  pub name: Option<String>,
  /// Part of the request response to extract data from.
  #[serde(default, skip_serializing_if = "is_default")]
  #[cfg_attr(
    feature = "mcp",
    schemars(
      title = "part of response to extract data from",
      description = "Part of the request response to extract data from. Each protocol exposes different parts documented in request type docs"
    )
  )]
  pub part: Part,
  #[serde(flatten)]
  pub extractor_type: ExtractorType,
  /// When true, allows using extracted value in next request for some protocols
  #[serde(default, skip_serializing_if = "is_default")]
  #[cfg_attr(
    feature = "mcp",
    schemars(
      title = "mark extracted value for internal variable use",
      description = "Internal when set to true will allow using the value extracted in the next request for some protocols"
    )
  )]
  pub internal: bool,
  /// Enables case-insensitive extractions (default: false)
  #[serde(default, skip_serializing_if = "is_default")]
  #[cfg_attr(
    feature = "mcp",
    schemars(
      title = "use case insensitive extract",
      description = "CaseInsensitive enables case-insensitive extractions. Default is false"
    )
  )]
  pub case_insensitive: bool,
}

impl PartialEq for Extractor {
  fn eq(&self, other: &Self) -> bool {
    self.name == other.name
      && self.part == other.part
      && self.extractor_type == other.extractor_type
      && self.internal == other.internal
      && self.case_insensitive == other.case_insensitive
  }
}

impl Extractor {
  pub(crate) fn compile(&mut self) -> Result<()> {
    if let ExtractorType::Regex(regexps) = &mut self.extractor_type {
      regexps.compiled_regex = vec![OnceCell::new(); regexps.regex.len()]
    }
    Ok(())
  }
  pub fn extract_json(
    &self,
    json_path: &JsonPathQuery,
    corpus: String,
  ) -> (HashSet<String>, BTreeMap<String, String>) {
    let mut extract_result = HashSet::new();
    let json: serde_json::Value = if let Ok(x) = serde_json::from_str(&corpus) {
      x
    } else {
      return (extract_result, BTreeMap::new());
    };
    for path in json_path.json.iter() {
      if let Ok(array) = json.query(path) {
        for v in array {
          extract_result.insert(v.to_string());
        }
      }
    }
    (extract_result, BTreeMap::new())
  }
  pub(crate) fn extract_regex(
    &self,
    regex_list: &RegexPattern,
    corpus: String,
    body: Body,
    version: &Option<Version>,
  ) -> (HashSet<String>, BTreeMap<String, String>) {
    let mut extract_result = HashSet::new();
    let mut version_map = BTreeMap::new();
    let group = regex_list.group.unwrap_or(0);
    for (i, _) in regex_list.regex.iter().enumerate() {
      let re = match regex_list.get_compiled(i) {
        Ok(re) => re,
        Err(err) => {
          error!("extract regex compiled error: {:?}", err);
          continue;
        } // 如果编译失败，跳过这个正则
      };
      re.captures(&corpus, &body)
        .map(|e| {
          if let Some(eg) = e.get(group) {
            extract_result.insert(eg);
          }
          if let Some(ver) = version {
            version_map.extend(ver.captures(e));
          }
        })
        .unwrap_or_default();
    }
    (extract_result, version_map)
  }
}
/// Defines the type of extraction to perform
#[cfg_attr(feature = "mcp", derive(schemars::JsonSchema))]
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "lowercase", tag = "type")]
pub enum ExtractorType {
  /// Regex extractor using regular expression patterns
  #[cfg_attr(feature = "mcp", schemars(title = "regex extractor"))]
  Regex(RegexPattern),
  // name:kval
  KVal(KVal),
  // name:xpath
  XPath(XPath),
  // name:json
  JSON(JsonPathQuery),
  // name:dsl
  DSL(DSL),
}

#[cfg_attr(feature = "mcp", derive(schemars::JsonSchema))]
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "kebab-case")]
#[serde(deny_unknown_fields)]
#[cfg_attr(
  feature = "mcp",
  schemars(description = "Key-value extractor for headers and cookies")
)]
pub struct KVal {
  /// Optional group identifier
  pub group: Option<u8>,
  /// Key-value pairs to extract from response
  #[cfg_attr(
    feature = "mcp",
    schemars(
      title = "kval pairs to extract from response",
      description = "kval contains the key-value pairs present in the HTTP response header/cookies. Inputs are case-insensitive and use underscores instead of dashes"
    )
  )]
  pub kval: HashSet<String>,
}
/// JSON extractor using jq-style syntax
#[cfg_attr(feature = "mcp", derive(schemars::JsonSchema))]
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "kebab-case")]
#[serde(deny_unknown_fields)]
pub struct JsonPathQuery {
  /// Optional group identifier
  pub group: Option<u8>,
  /// JQ expressions to evaluate on JSON response
  #[cfg_attr(
    feature = "mcp",
    schemars(
      title = "json jq expressions to extract data",
      description = "JSON allows using jq-style syntax to extract items from json response"
    )
  )]
  pub json: HashSet<String>,
}
/// XPath extractor for HTML responses
#[cfg_attr(feature = "mcp", derive(schemars::JsonSchema))]
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "kebab-case")]
#[serde(deny_unknown_fields)]
pub struct XPath {
  /// XPath expressions to extract from HTML
  #[cfg_attr(
    feature = "mcp",
    schemars(
      title = "html xpath expressions to extract data",
      description = "XPath allows using xpath expressions to extract items from html response"
    )
  )]
  pub xpath: HashSet<String>,
  /// Optional attribute to extract from matched elements
  #[cfg_attr(
    feature = "mcp",
    schemars(
      title = "optional attribute to extract from xpath",
      description = "Attribute is an optional attribute to extract from response XPath"
    )
  )]
  pub attribute: Option<String>,
}
/// DSL extractor using expression evaluation
#[cfg_attr(feature = "mcp", derive(schemars::JsonSchema))]
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "kebab-case")]
#[serde(deny_unknown_fields)]
pub struct DSL {
  /// DSL expressions to evaluate
  #[cfg_attr(
    feature = "mcp",
    schemars(
      title = "dsl expressions to extract",
      description = "Optional attribute to extract from response dsl"
    )
  )]
  pub dsl: HashSet<String>,
}
