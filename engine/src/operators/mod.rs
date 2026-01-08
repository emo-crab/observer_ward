use crate::error::{Result, new_regex_error};
use crate::info::Version;
use crate::operators::extractors::{Extractor, ExtractorType};
use crate::operators::matchers::{Condition, FaviconMap, Matcher, MatcherType};
use crate::operators::target::OperatorTarget;
use crate::serde_format::is_default;
use serde::{Deserialize, Serialize};
use slinger::{Response, Body};
use std::collections::{BTreeMap, HashSet};
use std::sync::Arc;
use rayon::prelude::*;

pub mod extractors;
pub mod matchers;
pub mod regex;
pub mod target;

/// Operators for the current request go here.
#[cfg_attr(feature = "mcp", derive(schemars::JsonSchema))]
#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq)]
#[serde(rename_all = "kebab-case")]
pub struct Operators {
  // description: |
  //   StopAtFirstMatch stops the execution of the requests and template as soon as a match is found.
  #[serde(default, skip_serializing_if = "is_default")]
  #[cfg_attr(
    feature = "mcp",
    schemars(
      title = "stop at first match",
      description = "Stop the execution after a match is found"
    )
  )]
  pub stop_at_first_match: bool,
  // description: |
  //   MatchersCondition is the condition between the matchers. Default is OR.
  // values:
  //   - "and"
  //   - "or"
  #[serde(default, skip_serializing_if = "is_default")]
  #[cfg_attr(
    feature = "mcp",
    schemars(
      title = "condition between the matchers",
      description = "Conditions between the matchers",
    )
  )]
  pub matchers_condition: Condition,
  // description: |
  //   Matchers contains the detection mechanism for the request to identify
  //   whether the request was successful by doing pattern matching
  //   on request/responses.
  //
  //   Multiple matchers can be combined with `matcher-condition` flag
  //   which accepts either `and` or `or` as argument.
  #[serde(default, skip_serializing_if = "is_default")]
  #[cfg_attr(
    feature = "mcp",
    schemars(
      title = "matchers to run on response",
      description = "Detection mechanism to identify whether the request was successful by doing pattern matching"
    )
  )]
  pub matchers: Vec<Arc<Matcher>>,
  // description: |
  //   Extractors contains the extraction mechanism for the request to identify
  //   and extract parts of the response.
  #[serde(default, skip_serializing_if = "is_default")]
  #[cfg_attr(
    feature = "mcp",
    schemars(
      title = "extractors to run on response",
      description = "Extractors contains the extraction mechanism for the request to identify and extract parts of the response"
    )
  )]
  pub extractors: Vec<Arc<Extractor>>,
}

impl Operators {
  pub fn compile(&mut self) -> Result<()> {
    for matcher in self.matchers.iter_mut() {
      let mutable_matcher = Arc::make_mut(matcher);
      mutable_matcher.compile().map_err(new_regex_error)?;
    }
    for extractor in self.extractors.iter_mut() {
      let mutable_extractor = Arc::make_mut(extractor);
      mutable_extractor.compile().map_err(new_regex_error)?;
    }
    Ok(())
  }

  /// Generic extractor that works with any OperatorTarget (Response or Request)
  pub fn extractor_generic<T: OperatorTarget>(
    &self,
    version: Option<Version>,
    target: &T,
    result: &mut OperatorResult,
  ) {
    for (index, extractor) in self.extractors.iter().enumerate() {
      let (words, body) =
        if let Ok((words, body)) = extractor.part.get_matcher_word_from_part(target) {
          (words, body)
        } else {
          continue;
        };
      let (extract_result, version) = match &extractor.extractor_type {
        ExtractorType::Regex(re) => extractor.extract_regex(re, words, body, &version),
        ExtractorType::JSON(json) => extractor.extract_json(json, words),
        ExtractorType::KVal(..) | ExtractorType::XPath(..) | ExtractorType::DSL(..) => {
          (HashSet::new(), BTreeMap::new())
        }
      };
      if !extract_result.is_empty() {
        let key = extractor.name.clone().unwrap_or(index.to_string());
        if let Some(er) = result.extract_result.get_mut(&key) {
          er.extend(extract_result);
        } else {
          result.extract_result.insert(key.clone(), extract_result);
        }
      }
      for (k, v) in version {
        result.extract_result.insert(k, HashSet::from_iter([v]));
      }
    }
  }

  pub fn extractor(
    &self,
    version: Option<Version>,
    response: &Response,
    result: &mut OperatorResult,
  ) {
    self.extractor_generic(version, response, result)
  }

  /// Generic matcher that works with any OperatorTarget (Response or Request)
  /// For Response, it can access extensions for favicon and status code
  /// For Request, status code matching will be skipped
  pub fn matcher_generic<T: OperatorTarget>(
    &self,
    target: &T,
    response_for_extensions: Option<&Response>,
    result: &mut OperatorResult,
  ) -> Result<()> {
    if self.matchers.is_empty() {
      return Ok(());
    }
    let mut inputs: Vec<(Arc<Matcher>, String, Body, Option<u16>)> = Vec::with_capacity(self.matchers.len());
    for matcher in self.matchers.iter() {
      if let Ok((words, body)) = matcher.part.get_matcher_word_from_part(target) {
        let status = response_for_extensions.map(|r| r.status_code().as_u16());
        inputs.push((Arc::clone(matcher), words, body, status));
      } else {
        let status = response_for_extensions.map(|r| r.status_code().as_u16());
        inputs.push((Arc::clone(matcher), String::new(), Body::default(), status));
      }
    }
    let favicon_map: Option<BTreeMap<String, FaviconMap>> = response_for_extensions
      .and_then(|r| r.extensions().get::<BTreeMap<String, FaviconMap>>().cloned());
    let results: Vec<(bool, Vec<String>, Option<String>)> = inputs
      .into_par_iter()
      .map(|(matcher, words, body, status)| {
        let (is_match, mw) = match &matcher.matcher_type {
          MatcherType::Word(word) => matcher.match_word(word, words.clone()),
          MatcherType::Favicon(fav) => {
            if let Some(ref hm) = favicon_map {
              matcher.match_favicon(fav, hm)
            } else {
              (false, Vec::new())
            }
          }
          MatcherType::Status(status_pat) => {
            if let Some(code) = status {
              (matcher.match_status_code(status_pat, code), vec![code.to_string()])
            } else {
              (false, Vec::new())
            }
          }
          MatcherType::Regex(re) => matcher.match_regex(re, words.clone(), body.clone()),
          MatcherType::None
          | MatcherType::DSL(..)
          | MatcherType::Binary(..)
          | MatcherType::XPath(..) => (false, Vec::new()),
        };
        let is_match = matcher.negative(is_match);
        let name = matcher.name.clone();
        (is_match, mw, name)
      })
      .collect();
    let mut seen_any = Vec::new();
    for  (is_match, mw, name) in results.into_iter() {
      seen_any.push(is_match);
      if !is_match {
        match self.matchers_condition {
          Condition::Or => continue,
          Condition::And => {
            result.matched = false;
            break;
          }
        }
      } else {
        if let Some(n) = name {
          result.name.insert(n);
        }
        result.matcher_word.extend(mw);
        if matches!(self.matchers_condition, Condition::Or) {
          result.matched = true;
          if self.stop_at_first_match {
            break;
          }
        }
      }
    }
    if matches!(self.matchers_condition, Condition::And) && seen_any.iter().all(|x| *x) {
      result.matched = true;
    }
    Ok(())
  }

  /// 匹配接口统一为只接收 &Response，request 可通过 response.extensions().get::<Request>() 访问
  pub fn matcher(&self, response: &Response, result: &mut OperatorResult) -> Result<()> {
    self.matcher_generic(response, Some(response), result)
  }
}

#[cfg_attr(feature = "mcp", derive(schemars::JsonSchema))]
#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq)]
pub struct OperatorResult {
  /// Description: Indicates whether the template matched the response
  /// Example: true
  #[cfg_attr(
    feature = "mcp",
    schemars(
      title = "Match Status",
      description = "Boolean indicating if the template matched the response",
      example = "true"
    )
  )]
  matched: bool,
  /// Description: Set of names that matched during the operation
  /// Example: ["apache", "tomcat"]
  #[cfg_attr(
    feature = "mcp",
    schemars(
      title = "Matched Names",
      description = "Set of names that matched during the operation",
      example = r#"["apache", "tomcat"]"#
    )
  )]
  name: HashSet<String>,
  /// Description: List of words that triggered the matcher
  /// Example: ["server: apache", "x-powered-by: tomcat"]
  #[cfg_attr(
    feature = "mcp",
    schemars(
      title = "Matcher Words",
      description = "List of words that triggered the matcher",
      example = r#"["server: apache", "x-powered-by: tomcat"]"#
    )
  )]
  matcher_word: Vec<String>,
  /// Description: Key-value pairs of extracted data from the operation
  /// Example: {"user": ["admin"], "version": ["1.0"]}
  #[cfg_attr(
    feature = "mcp",
    schemars(
      title = "Extracted Results",
      description = "Key-value pairs of extracted data from the operation",
      example = r#"{"user": ["admin"], "version": ["1.0"]}"#
    )
  )]
  extract_result: BTreeMap<String, HashSet<String>>,
}

impl OperatorResult {
  pub fn is_matched(&self) -> bool {
    self.matched
  }
  pub fn is_extract(&self) -> bool {
    !self.extract_result.is_empty()
  }
  fn name(&self) -> Vec<String> {
    Vec::from_iter(&self.name)
      .iter()
      .map(|x| x.to_string())
      .collect()
  }
  pub fn matcher_word(&self) -> Vec<String> {
    let mut name = self.matcher_word.clone();
    name.extend(self.name());
    name
  }
  pub fn extract_result(&self) -> BTreeMap<String, HashSet<String>> {
    self.extract_result.clone()
  }
}
