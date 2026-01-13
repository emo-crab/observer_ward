//! MITM (Man-in-the-Middle) operation definitions for intercepting and modifying
//! HTTP/HTTPS traffic.
//!
//! This module provides structures for defining interception rules that can:
//! - Match requests/responses by Domain, IP, Protocol, URL, file extension, headers, body
//! - Support keyword and regex matching with AND/OR conditions
//! - Support negation (inverse matching)
//! - Define replacement operations for matched content

use crate::operators::matchers::Condition;
use crate::serde_format::is_default;
use log::error;
use once_cell::sync::OnceCell;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::sync::Arc;

/// MITM Request defines a complete MITM interception rule.
///
/// Similar to `HTTPRequest`, this struct defines how to intercept and handle
/// man-in-the-middle proxy traffic.
#[cfg_attr(feature = "mcp", derive(schemars::JsonSchema))]
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "kebab-case")]
pub struct MitmRequest {
  /// Optional ID for the MITM rule
  #[serde(default, skip_serializing_if = "is_default")]
  #[cfg_attr(
    feature = "mcp",
    schemars(
      title = "id of the mitm rule",
      description = "ID of the MITM interception rule"
    )
  )]
  pub id: Option<String>,

  /// Optional name for the MITM rule
  #[serde(default, skip_serializing_if = "is_default")]
  #[cfg_attr(
    feature = "mcp",
    schemars(
      title = "name of the mitm rule",
      description = "Name of the MITM interception rule"
    )
  )]
  pub name: Option<String>,

  /// Match configuration for determining when to apply this rule
  #[serde(flatten)]
  pub match_config: MitmMatchConfig,

  /// Action to take when the rule matches
  #[serde(default)]
  #[cfg_attr(
    feature = "mcp",
    schemars(
      title = "action to take",
      description = "Action to take when the rule matches (allow, block, modify)"
    )
  )]
  pub action: MitmAction,

  /// Replacement operations to apply when action is Modify
  #[serde(default, skip_serializing_if = "is_default")]
  #[cfg_attr(
    feature = "mcp",
    schemars(
      title = "replacement operations",
      description = "Replacement operations to apply when action is Modify"
    )
  )]
  pub replacements: Vec<MitmReplacement>,
}

/// Configuration for matching MITM traffic
#[cfg_attr(feature = "mcp", derive(schemars::JsonSchema))]
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
#[serde(rename_all = "kebab-case")]
pub struct MitmMatchConfig {
  /// Matchers to apply to the traffic
  #[serde(default, skip_serializing_if = "is_default")]
  #[cfg_attr(
    feature = "mcp",
    schemars(
      title = "matchers for traffic",
      description = "Matchers to apply to the traffic for interception"
    )
  )]
  pub matchers: Vec<Arc<MitmMatcher>>,

  /// Condition between matchers (AND/OR)
  #[serde(default, skip_serializing_if = "is_default")]
  #[cfg_attr(
    feature = "mcp",
    schemars(
      title = "condition between matchers",
      description = "Condition between the matchers (and/or)"
    )
  )]
  pub matchers_condition: Condition,
}

/// A single matcher for MITM traffic
#[cfg_attr(feature = "mcp", derive(schemars::JsonSchema))]
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "kebab-case")]
pub struct MitmMatcher {
  /// Optional name for the matcher
  #[serde(default, skip_serializing_if = "is_default")]
  #[cfg_attr(
    feature = "mcp",
    schemars(
      title = "name of the matcher",
      description = "Name of the matcher for identification"
    )
  )]
  pub name: Option<String>,

  /// Target part of the request/response to match
  #[serde(default)]
  #[cfg_attr(
    feature = "mcp",
    schemars(
      title = "target to match",
      description = "Target part of the traffic to match against"
    )
  )]
  pub target: MitmTarget,

  /// Type of match to perform
  #[serde(flatten)]
  pub match_type: MitmMatchType,

  /// Condition between match values (AND/OR)
  #[serde(default, skip_serializing_if = "is_default")]
  #[cfg_attr(
    feature = "mcp",
    schemars(
      title = "condition between values",
      description = "Condition between the match values (and/or)"
    )
  )]
  pub condition: Condition,

  /// Whether to negate/invert the match result
  #[serde(default, skip_serializing_if = "is_default")]
  #[cfg_attr(
    feature = "mcp",
    schemars(
      title = "negate match result",
      description = "When true, inverts the match result (matches when condition is NOT met)"
    )
  )]
  pub negative: bool,

  /// Enable case-insensitive matching
  #[serde(default, skip_serializing_if = "is_default")]
  #[cfg_attr(
    feature = "mcp",
    schemars(
      title = "case insensitive matching",
      description = "Enable case-insensitive matching for keywords"
    )
  )]
  pub case_insensitive: bool,
}

impl PartialEq for MitmMatcher {
  fn eq(&self, other: &Self) -> bool {
    self.name == other.name
      && self.target == other.target
      && self.match_type == other.match_type
      && self.condition == other.condition
      && self.negative == other.negative
      && self.case_insensitive == other.case_insensitive
  }
}

/// Target part of the request/response to match against
#[cfg_attr(feature = "mcp", derive(schemars::JsonSchema))]
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
#[serde(rename_all = "lowercase")]
pub enum MitmTarget {
  /// Match against the domain/hostname
  #[default]
  Domain,
  /// Match against the IP address
  Ip,
  /// Match against the protocol (http/https/tcp)
  Protocol,
  /// Match against the full URL
  Url,
  /// Match against the URL path
  Path,
  /// Match against the file extension
  Extension,
  /// Match against the HTTP method
  Method,
  /// Match against request headers
  RequestHeader,
  /// Match against response headers
  ResponseHeader,
  /// Match against request body
  RequestBody,
  /// Match against response body
  ResponseBody,
  /// Match against status code
  StatusCode,
  /// Match against a specific header by name
  #[serde(rename = "header")]
  Header(String),
}

/// Type of match to perform
#[cfg_attr(feature = "mcp", derive(schemars::JsonSchema))]
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
#[serde(rename_all = "lowercase", tag = "type")]
pub enum MitmMatchType {
  /// Match using keywords (substring match)
  #[default]
  None,
  #[serde(rename = "word")]
  Word(MitmWordMatch),
  /// Match using regular expressions
  #[serde(rename = "regex")]
  Regex(MitmRegexMatch),
  /// Match exact values
  #[serde(rename = "exact")]
  Exact(MitmExactMatch),
  /// Match status codes
  #[serde(rename = "status")]
  Status(MitmStatusMatch),
}

/// Word/keyword matching configuration
#[cfg_attr(feature = "mcp", derive(schemars::JsonSchema))]
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "kebab-case")]
pub struct MitmWordMatch {
  /// Keywords to match against
  #[cfg_attr(
    feature = "mcp",
    schemars(
      title = "keywords to match",
      description = "Keywords to match against the target",
      example = r#"&["example.com", "api.example.com"]"#
    )
  )]
  pub words: Vec<String>,
}

/// Regular expression matching configuration
#[cfg_attr(feature = "mcp", derive(schemars::JsonSchema))]
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct MitmRegexMatch {
  /// Regular expression patterns to match against
  #[cfg_attr(
    feature = "mcp",
    schemars(
      title = "regex patterns to match",
      description = "Regular expression patterns to match against the target",
      example = r#"&["^api\\..*\\.com$", "\\.(jpg|png|gif)$"]"#
    )
  )]
  pub regex: Vec<String>,

  /// Pre-compiled regex patterns
  #[serde(skip)]
  pub compiled_regex: Vec<OnceCell<fancy_regex::Regex>>,
}

impl PartialEq for MitmRegexMatch {
  fn eq(&self, other: &Self) -> bool {
    self.regex == other.regex
  }
}

impl MitmRegexMatch {
  /// Compile all regex patterns
  pub fn compile(&mut self) {
    self.compiled_regex = vec![OnceCell::new(); self.regex.len()];
  }

  /// Get a compiled regex pattern at the given index
  pub fn get_compiled(&self, index: usize) -> Option<&fancy_regex::Regex> {
    if index >= self.regex.len() {
      return None;
    }
    self.compiled_regex[index]
      .get_or_try_init(|| {
        fancy_regex::Regex::new(&self.regex[index]).map_err(|e| {
          error!(
            "Failed to compile regex pattern '{}': {}",
            self.regex[index], e
          );
          e
        })
      })
      .ok()
  }
}

/// Exact value matching configuration
#[cfg_attr(feature = "mcp", derive(schemars::JsonSchema))]
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "kebab-case")]
pub struct MitmExactMatch {
  /// Exact values to match against
  #[cfg_attr(
    feature = "mcp",
    schemars(
      title = "exact values to match",
      description = "Exact values to match against the target",
      example = r#"&["example.com", "GET"]"#
    )
  )]
  pub values: Vec<String>,
}

/// Status code matching configuration
#[cfg_attr(feature = "mcp", derive(schemars::JsonSchema))]
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "kebab-case")]
pub struct MitmStatusMatch {
  /// Status codes to match against
  #[cfg_attr(
    feature = "mcp",
    schemars(
      title = "status codes to match",
      description = "HTTP status codes to match against",
      example = r#"&[200, 301, 302]"#
    )
  )]
  pub status: Vec<u16>,
}

/// Action to take when a MITM rule matches
#[cfg_attr(feature = "mcp", derive(schemars::JsonSchema))]
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
#[serde(rename_all = "lowercase")]
pub enum MitmAction {
  /// Allow the traffic to pass through unchanged
  #[default]
  Allow,
  /// Block the traffic (drop the connection)
  Block,
  /// Modify the traffic using replacement rules
  Modify,
}

/// Replacement operation for modifying MITM traffic
#[cfg_attr(feature = "mcp", derive(schemars::JsonSchema))]
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "kebab-case")]
pub struct MitmReplacement {
  /// Target part to replace
  #[serde(default)]
  #[cfg_attr(
    feature = "mcp",
    schemars(
      title = "target to replace",
      description = "Target part of the traffic to replace"
    )
  )]
  pub target: MitmReplacementTarget,

  /// Type of replacement to perform
  #[serde(flatten)]
  pub replacement_type: MitmReplacementType,
}

/// Target part of the request/response to replace
#[cfg_attr(feature = "mcp", derive(schemars::JsonSchema))]
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
#[serde(rename_all = "lowercase")]
pub enum MitmReplacementTarget {
  /// Replace in the URL/path
  #[default]
  Url,
  /// Replace in the URL path only
  Path,
  /// Replace in the query string
  Query,
  /// Replace the HTTP method
  Method,
  /// Replace a request header (specify header name)
  #[serde(rename = "request-header")]
  RequestHeader(String),
  /// Replace a response header (specify header name)
  #[serde(rename = "response-header")]
  ResponseHeader(String),
  /// Replace in the request body
  RequestBody,
  /// Replace in the response body
  ResponseBody,
  /// Replace the status code
  StatusCode,
}

/// Type of replacement to perform
#[cfg_attr(feature = "mcp", derive(schemars::JsonSchema))]
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "lowercase", tag = "replace-type")]
pub enum MitmReplacementType {
  /// Replace using a simple string substitution
  #[serde(rename = "string")]
  String(StringReplacement),
  /// Replace using a regular expression
  #[serde(rename = "regex")]
  Regex(RegexReplacement),
  /// Set a value (overwrites the entire target)
  #[serde(rename = "set")]
  Set(SetReplacement),
  /// Append a value to the target
  #[serde(rename = "append")]
  Append(AppendReplacement),
  /// Prepend a value to the target
  #[serde(rename = "prepend")]
  Prepend(PrependReplacement),
  /// Remove the target entirely
  #[serde(rename = "remove")]
  Remove,
}

/// Simple string replacement
#[cfg_attr(feature = "mcp", derive(schemars::JsonSchema))]
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "kebab-case")]
pub struct StringReplacement {
  /// String to search for
  #[cfg_attr(
    feature = "mcp",
    schemars(
      title = "string to find",
      description = "String to search for in the target"
    )
  )]
  pub find: String,
  /// String to replace with
  #[cfg_attr(
    feature = "mcp",
    schemars(
      title = "replacement string",
      description = "String to replace the found string with"
    )
  )]
  pub replace: String,
  /// Replace all occurrences (default: true)
  #[serde(default = "default_true", skip_serializing_if = "is_true")]
  #[cfg_attr(
    feature = "mcp",
    schemars(
      title = "replace all occurrences",
      description = "Replace all occurrences of the string (default: true)"
    )
  )]
  pub all: bool,
}

/// Regex-based replacement
#[cfg_attr(feature = "mcp", derive(schemars::JsonSchema))]
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct RegexReplacement {
  /// Regex pattern to search for
  #[cfg_attr(
    feature = "mcp",
    schemars(
      title = "regex pattern",
      description = "Regular expression pattern to search for"
    )
  )]
  pub pattern: String,
  /// Replacement string (can use capture groups like $1, $2)
  #[cfg_attr(
    feature = "mcp",
    schemars(
      title = "replacement string",
      description = "Replacement string (can use capture groups like $1, $2)"
    )
  )]
  pub replace: String,
  /// Replace all occurrences (default: true)
  #[serde(default = "default_true", skip_serializing_if = "is_true")]
  #[cfg_attr(
    feature = "mcp",
    schemars(
      title = "replace all occurrences",
      description = "Replace all occurrences of the pattern (default: true)"
    )
  )]
  pub all: bool,

  /// Pre-compiled regex pattern
  #[serde(skip)]
  pub compiled: OnceCell<fancy_regex::Regex>,
}

impl PartialEq for RegexReplacement {
  fn eq(&self, other: &Self) -> bool {
    self.pattern == other.pattern && self.replace == other.replace && self.all == other.all
  }
}

impl RegexReplacement {
  /// Get the compiled regex pattern
  pub fn get_compiled(&self) -> Option<&fancy_regex::Regex> {
    self
      .compiled
      .get_or_try_init(|| {
        fancy_regex::Regex::new(&self.pattern).map_err(|e| {
          error!(
            "Failed to compile replacement regex pattern '{}': {}",
            self.pattern, e
          );
          e
        })
      })
      .ok()
  }
}

/// Set a value replacement (overwrites entire target)
#[cfg_attr(feature = "mcp", derive(schemars::JsonSchema))]
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "kebab-case")]
pub struct SetReplacement {
  /// Value to set
  #[cfg_attr(
    feature = "mcp",
    schemars(
      title = "value to set",
      description = "Value to set as the new content"
    )
  )]
  pub value: String,
}

/// Append a value to the target
#[cfg_attr(feature = "mcp", derive(schemars::JsonSchema))]
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "kebab-case")]
pub struct AppendReplacement {
  /// Value to append
  #[cfg_attr(
    feature = "mcp",
    schemars(
      title = "value to append",
      description = "Value to append to the target"
    )
  )]
  pub value: String,
}

/// Prepend a value to the target
#[cfg_attr(feature = "mcp", derive(schemars::JsonSchema))]
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "kebab-case")]
pub struct PrependReplacement {
  /// Value to prepend
  #[cfg_attr(
    feature = "mcp",
    schemars(
      title = "value to prepend",
      description = "Value to prepend to the target"
    )
  )]
  pub value: String,
}

fn default_true() -> bool {
  true
}

fn is_true(v: &bool) -> bool {
  *v
}

impl MitmMatcher {
  /// Compile any regex patterns in the matcher
  pub fn compile(&mut self) {
    if let MitmMatchType::Regex(ref mut regex_match) = self.match_type {
      regex_match.compile();
    }
  }

  /// Match against a string value
  pub fn matches(&self, value: &str) -> bool {
    let result = match &self.match_type {
      MitmMatchType::None => true,
      MitmMatchType::Word(word_match) => self.match_words(&word_match.words, value),
      MitmMatchType::Regex(regex_match) => self.match_regex(regex_match, value),
      MitmMatchType::Exact(exact_match) => self.match_exact(&exact_match.values, value),
      MitmMatchType::Status(_) => false, // Status matching is handled separately
    };

    if self.negative { !result } else { result }
  }

  /// Match status code
  pub fn matches_status(&self, status_code: u16) -> bool {
    let result = match &self.match_type {
      MitmMatchType::Status(status_match) => status_match.status.contains(&status_code),
      _ => false,
    };

    if self.negative { !result } else { result }
  }

  fn match_words(&self, words: &[String], value: &str) -> bool {
    // Optimize: only convert value to lowercase if needed, use Cow to avoid allocation when not needed
    let value_cow: std::borrow::Cow<'_, str> = if self.case_insensitive {
      std::borrow::Cow::Owned(value.to_lowercase())
    } else {
      std::borrow::Cow::Borrowed(value)
    };

    match self.condition {
      Condition::And => words.iter().all(|w| {
        if self.case_insensitive {
          // Pre-computed lowercase during compile() would be better for repeated matching
          value_cow.contains(&w.to_lowercase())
        } else {
          value_cow.contains(w.as_str())
        }
      }),
      Condition::Or => words.iter().any(|w| {
        if self.case_insensitive {
          value_cow.contains(&w.to_lowercase())
        } else {
          value_cow.contains(w.as_str())
        }
      }),
    }
  }

  fn match_regex(&self, regex_match: &MitmRegexMatch, value: &str) -> bool {
    match self.condition {
      Condition::And => {
        for (i, _) in regex_match.regex.iter().enumerate() {
          if let Some(re) = regex_match.get_compiled(i) {
            if !re.is_match(value).unwrap_or(false) {
              return false;
            }
          } else {
            return false;
          }
        }
        true
      }
      Condition::Or => {
        for (i, _) in regex_match.regex.iter().enumerate() {
          if let Some(re) = regex_match.get_compiled(i)
            && re.is_match(value).unwrap_or(false)
          {
            return true;
          }
        }
        false
      }
    }
  }

  fn match_exact(&self, values: &[String], value: &str) -> bool {
    // Optimize: only convert value to lowercase if needed, use Cow to avoid allocation when not needed
    let value_cow: std::borrow::Cow<'_, str> = if self.case_insensitive {
      std::borrow::Cow::Owned(value.to_lowercase())
    } else {
      std::borrow::Cow::Borrowed(value)
    };

    match self.condition {
      Condition::And => values.iter().all(|v| {
        if self.case_insensitive {
          value_cow.as_ref() == v.to_lowercase()
        } else {
          value_cow.as_ref() == v
        }
      }),
      Condition::Or => values.iter().any(|v| {
        if self.case_insensitive {
          value_cow.as_ref() == v.to_lowercase()
        } else {
          value_cow.as_ref() == v
        }
      }),
    }
  }
}

impl MitmRequest {
  /// Compile all regex patterns in the MITM request
  pub fn compile(&mut self) {
    for matcher in self.match_config.matchers.iter_mut() {
      Arc::make_mut(matcher).compile();
    }
    for replacement in self.replacements.iter_mut() {
      if let MitmReplacementType::Regex(ref mut regex_rep) = replacement.replacement_type {
        // Trigger compilation
        let _ = regex_rep.get_compiled();
      }
    }
  }
}

impl MitmReplacement {
  /// Apply the replacement to a string value
  pub fn apply(&self, value: &str) -> String {
    match &self.replacement_type {
      MitmReplacementType::String(string_rep) => {
        if string_rep.all {
          value.replace(&string_rep.find, &string_rep.replace)
        } else {
          value.replacen(&string_rep.find, &string_rep.replace, 1)
        }
      }
      MitmReplacementType::Regex(regex_rep) => {
        if let Some(re) = regex_rep.get_compiled() {
          if regex_rep.all {
            re.replace_all(value, &regex_rep.replace).to_string()
          } else {
            re.replace(value, &regex_rep.replace).to_string()
          }
        } else {
          value.to_string()
        }
      }
      MitmReplacementType::Set(set_rep) => set_rep.value.clone(),
      MitmReplacementType::Append(append_rep) => format!("{}{}", value, append_rep.value),
      MitmReplacementType::Prepend(prepend_rep) => format!("{}{}", prepend_rep.value, value),
      MitmReplacementType::Remove => String::new(),
    }
  }
}

/// Result of matching a request against MITM rules
#[derive(Debug, Clone, PartialEq)]
pub enum MitmMatchResult {
  /// No rule matched, allow the traffic
  NoMatch,
  /// A rule matched with the specified action
  Matched {
    /// The name of the matching rule
    rule_name: Option<String>,
    /// The action to take
    action: MitmAction,
    /// The replacements to apply (if action is Modify)
    replacements: Vec<MitmReplacement>,
  },
}

/// Rule-based MITM matcher that applies MitmRequest rules to traffic
#[derive(Debug, Clone, Default)]
pub struct MitmRuleMatcher {
  /// The rules to match against
  pub rules: Vec<Arc<MitmRequest>>,
}

/// Context for matching a request (grouped parameters to avoid too many arguments)
pub struct MitmRequestContext {
  pub destination: String,
  pub uri: String,
  pub path: String,
  pub method: String,
  pub protocol: String,
  /// All headers joined as a single string for header-based matching
  pub headers: String,
  /// Body as string
  pub body: String,
  /// Headers map for lookup by name
  pub headers_map: std::collections::BTreeMap<String, String>,
  /// Precomputed file extension (e.g. ".jpg") (to avoid computing on every match)
  pub extension: Option<String>,
}

impl MitmRequestContext {
  /// Build a MitmRequestContext from a `slinger_mitm::MitmRequest`
  pub fn from_slinger_mitm_request(req: &crate::slinger_mitm::MitmRequest) -> Self {
    let headers_map: std::collections::BTreeMap<String, String> = req
      .request()
      .headers()
      .iter()
      .filter_map(|(k, v)| v.to_str().ok().map(|s| (k.to_string(), s.to_string())))
      .collect();
    let headers = headers_map
      .iter()
      .map(|(k, v)| format!("{}: {}", k, v))
      .collect::<Vec<_>>()
      .join("\n");
    let body = req
      .body()
      .map(|b| String::from_utf8_lossy(b).to_string())
      .unwrap_or_default();

    // Precompute extension from the path to avoid repeated rsplit and allocation
    let path = req.request().uri().path().to_string();
    let extension = path
      .rsplit('.')
      .next()
      .filter(|s| !s.is_empty())
      .map(|e| format!(".{}", e));

    MitmRequestContext {
      destination: req.destination().to_string(),
      uri: req.request().uri().to_string(),
      path,
      method: req.request().method().as_str().to_string(),
      protocol: req
        .request()
        .uri()
        .scheme_str()
        .unwrap_or("http")
        .to_string(),
      headers,
      body,
      headers_map,
      extension,
    }
  }
}

/// Context for matching a response
pub struct MitmResponseContext {
  pub source: String,
  pub uri: Option<String>,
  pub path: Option<String>,
  pub status_code: u16,
  pub headers: String,
  pub body: String,
  pub headers_map: std::collections::BTreeMap<String, String>,
  /// Precomputed extension derived from request URI path if available
  pub extension: Option<String>,
}

impl MitmResponseContext {
  /// Build a MitmResponseContext from a `slinger_mitm::MitmResponse`
  pub fn from_slinger_mitm_response(resp: &crate::slinger_mitm::MitmResponse) -> Self {
    // Pull request URI from response extensions if present
    let request_uri = resp
      .response
      .extensions()
      .get::<crate::slinger::Request>()
      .map(|r| r.uri().clone());

    let headers_map: std::collections::BTreeMap<String, String> = resp
      .response()
      .headers()
      .iter()
      .filter_map(|(k, v)| v.to_str().ok().map(|s| (k.to_string(), s.to_string())))
      .collect();
    let headers = headers_map
      .iter()
      .map(|(k, v)| format!("{}: {}", k, v))
      .collect::<Vec<_>>()
      .join("\n");
    let body = resp
      .body()
      .map(|b| String::from_utf8_lossy(b).to_string())
      .unwrap_or_default();

    // Precompute extension from request_uri path if present
    let (uri_clone, path_clone, extension) = if let Some(ref u) = request_uri {
      let p = u.path().to_string();
      let ext = p
        .rsplit('.')
        .next()
        .filter(|s| !s.is_empty())
        .map(|e| format!(".{}", e));
      (Some(u.to_string()), Some(p), ext)
    } else {
      (None, None, None)
    };

    MitmResponseContext {
      source: resp.source().to_string(),
      uri: uri_clone,
      path: path_clone,
      status_code: resp.response().status_code().as_u16(),
      headers,
      body,
      headers_map,
      extension,
    }
  }
}

impl MitmRuleMatcher {
  /// Create a new rule matcher with the given rules
  pub fn new(rules: Vec<Arc<MitmRequest>>) -> Self {
    Self { rules }
  }

  /// Check if there are any rules
  pub fn has_rules(&self) -> bool {
    !self.rules.is_empty()
  }

  /// Get the number of rules
  pub fn len(&self) -> usize {
    self.rules.len()
  }

  /// Check if the rule matcher is empty
  pub fn is_empty(&self) -> bool {
    self.rules.is_empty()
  }

  /// Match a request against all rules using a context struct
  pub fn match_request(&self, ctx: &MitmRequestContext) -> MitmMatchResult {
    for rule in &self.rules {
      let mut all_matched = true;
      let mut any_matched = false;

      for matcher in &rule.match_config.matchers {
        let value_to_match: &str = match &matcher.target {
          MitmTarget::Domain => ctx.destination.as_str(),
          MitmTarget::Url => ctx.uri.as_str(),
          MitmTarget::Path => ctx.path.as_str(),
          MitmTarget::Method => ctx.method.as_str(),
          MitmTarget::Protocol => ctx.protocol.as_str(),
          MitmTarget::Extension => ctx.extension.as_deref().unwrap_or_default(),
          MitmTarget::RequestHeader => ctx.headers.as_str(),
          MitmTarget::RequestBody => ctx.body.as_str(),
          MitmTarget::Header(name) => ctx
            .headers_map
            .get(name)
            .map(|s| s.as_str())
            .unwrap_or_default(),
          // Response-only targets don't apply to requests
          _ => continue,
        };

        let matched = matcher.matches(value_to_match);

        if matched {
          any_matched = true;
        } else {
          all_matched = false;
        }
      }

      // Check condition
      let rule_matched = match rule.match_config.matchers_condition {
        crate::operators::matchers::Condition::And => all_matched,
        crate::operators::matchers::Condition::Or => any_matched,
      };

      if rule_matched {
        return MitmMatchResult::Matched {
          rule_name: rule.name.clone(),
          action: rule.action.clone(),
          replacements: rule.replacements.clone(),
        };
      }
    }

    MitmMatchResult::NoMatch
  }

  /// Match a response against all rules
  pub fn match_response(&self, ctx: &MitmResponseContext) -> MitmMatchResult {
    for rule in &self.rules {
      let mut all_matched = true;
      let mut any_matched = false;

      for matcher in &rule.match_config.matchers {
        let value_to_match: &str = match &matcher.target {
          MitmTarget::Domain => ctx.source.as_str(),
          MitmTarget::Url => ctx.uri.as_deref().unwrap_or_default(),
          MitmTarget::Path => ctx.path.as_deref().unwrap_or_default(),
          MitmTarget::StatusCode => {
            // Status code matching is handled separately
            if matcher.matches_status(ctx.status_code) {
              any_matched = true;
              if matches!(
                rule.match_config.matchers_condition,
                crate::operators::matchers::Condition::Or
              ) {
                continue;
              }
            } else {
              all_matched = false;
            }
            continue;
          }
          MitmTarget::ResponseHeader => ctx.headers.as_str(),
          MitmTarget::ResponseBody => ctx.body.as_str(),
          MitmTarget::Header(name) => ctx
            .headers_map
            .get(name)
            .map(|s| s.as_str())
            .unwrap_or_default(),
          // Request-only targets - skip for responses
          _ => continue,
        };

        let matched = matcher.matches(value_to_match);

        if matched {
          any_matched = true;
        } else {
          all_matched = false;
        }
      }

      let rule_matched = match rule.match_config.matchers_condition {
        crate::operators::matchers::Condition::And => all_matched,
        crate::operators::matchers::Condition::Or => any_matched,
      };

      if rule_matched {
        return MitmMatchResult::Matched {
          rule_name: rule.name.clone(),
          action: rule.action.clone(),
          replacements: rule.replacements.clone(),
        };
      }
    }

    MitmMatchResult::NoMatch
  }
}

/// Collection of MITM headers for matching/replacement
#[cfg_attr(feature = "mcp", derive(schemars::JsonSchema))]
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
pub struct MitmHeaders(pub BTreeMap<String, String>);

impl MitmHeaders {
  /// Get a header value by name (case-insensitive)
  pub fn get(&self, name: &str) -> Option<&String> {
    let name_lower = name.to_lowercase();
    self.0.iter().find_map(|(k, v)| {
      if k.to_lowercase() == name_lower {
        Some(v)
      } else {
        None
      }
    })
  }

  /// Set a header value
  pub fn set(&mut self, name: String, value: String) {
    self.0.insert(name, value);
  }

  /// Remove a header by name (case-insensitive)
  /// Uses a two-pass approach: first find the exact key, then remove it directly
  pub fn remove(&mut self, name: &str) {
    let name_lower = name.to_lowercase();
    // First, find the exact key to remove
    let key_to_remove: Option<String> = self
      .0
      .keys()
      .find(|k| k.to_lowercase() == name_lower)
      .cloned();
    // Then remove it directly
    if let Some(key) = key_to_remove {
      self.0.remove(&key);
    }
  }
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn test_word_match() {
    let mut matcher = MitmMatcher {
      name: None,
      target: MitmTarget::Domain,
      match_type: MitmMatchType::Word(MitmWordMatch {
        words: vec!["example.com".to_string(), "test.com".to_string()],
      }),
      condition: Condition::Or,
      negative: false,
      case_insensitive: false,
    };
    matcher.compile();

    assert!(matcher.matches("api.example.com"));
    assert!(matcher.matches("test.com.cn"));
    assert!(!matcher.matches("other.com"));
  }

  #[test]
  fn test_word_match_and_condition() {
    let mut matcher = MitmMatcher {
      name: None,
      target: MitmTarget::Url,
      match_type: MitmMatchType::Word(MitmWordMatch {
        words: vec!["api".to_string(), "v1".to_string()],
      }),
      condition: Condition::And,
      negative: false,
      case_insensitive: false,
    };
    matcher.compile();

    assert!(matcher.matches("https://api.example.com/v1/users"));
    assert!(!matcher.matches("https://api.example.com/v2/users"));
    assert!(!matcher.matches("https://www.example.com/v1/users"));
  }

  #[test]
  fn test_regex_match() {
    let mut matcher = MitmMatcher {
      name: None,
      target: MitmTarget::Extension,
      match_type: MitmMatchType::Regex(MitmRegexMatch {
        regex: vec![r"\.(jpg|png|gif)$".to_string()],
        compiled_regex: vec![],
      }),
      condition: Condition::Or,
      negative: false,
      case_insensitive: false,
    };
    matcher.compile();

    assert!(matcher.matches("image.jpg"));
    assert!(matcher.matches("photo.png"));
    assert!(!matcher.matches("document.pdf"));
  }

  #[test]
  fn test_negative_match() {
    let mut matcher = MitmMatcher {
      name: None,
      target: MitmTarget::Domain,
      match_type: MitmMatchType::Word(MitmWordMatch {
        words: vec!["blocked.com".to_string()],
      }),
      condition: Condition::Or,
      negative: true,
      case_insensitive: false,
    };
    matcher.compile();

    assert!(!matcher.matches("blocked.com"));
    assert!(matcher.matches("allowed.com"));
  }

  #[test]
  fn test_case_insensitive_match() {
    let mut matcher = MitmMatcher {
      name: None,
      target: MitmTarget::Domain,
      match_type: MitmMatchType::Word(MitmWordMatch {
        words: vec!["Example.COM".to_string()],
      }),
      condition: Condition::Or,
      negative: false,
      case_insensitive: true,
    };
    matcher.compile();

    assert!(matcher.matches("EXAMPLE.com"));
    assert!(matcher.matches("example.com"));
    assert!(matcher.matches("Example.COM"));
  }

  #[test]
  fn test_status_match() {
    let mut matcher = MitmMatcher {
      name: None,
      target: MitmTarget::StatusCode,
      match_type: MitmMatchType::Status(MitmStatusMatch {
        status: vec![200, 301, 302],
      }),
      condition: Condition::Or,
      negative: false,
      case_insensitive: false,
    };
    matcher.compile();

    assert!(matcher.matches_status(200));
    assert!(matcher.matches_status(301));
    assert!(!matcher.matches_status(404));
  }

  #[test]
  fn test_string_replacement() {
    let replacement = MitmReplacement {
      target: MitmReplacementTarget::Url,
      replacement_type: MitmReplacementType::String(StringReplacement {
        find: "http://".to_string(),
        replace: "https://".to_string(),
        all: true,
      }),
    };

    assert_eq!(
      replacement.apply("http://example.com"),
      "https://example.com"
    );
  }

  #[test]
  fn test_regex_replacement() {
    let replacement = MitmReplacement {
      target: MitmReplacementTarget::ResponseBody,
      replacement_type: MitmReplacementType::Regex(RegexReplacement {
        pattern: r"password=\w+".to_string(),
        replace: "password=***".to_string(),
        all: true,
        compiled: OnceCell::new(),
      }),
    };

    assert_eq!(replacement.apply("password=secret123"), "password=***");
  }

  #[test]
  fn test_set_replacement() {
    let replacement = MitmReplacement {
      target: MitmReplacementTarget::RequestHeader("User-Agent".to_string()),
      replacement_type: MitmReplacementType::Set(SetReplacement {
        value: "Custom-Agent/1.0".to_string(),
      }),
    };

    assert_eq!(replacement.apply("Mozilla/5.0"), "Custom-Agent/1.0");
  }
}
