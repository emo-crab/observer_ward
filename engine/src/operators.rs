use crate::error::{new_regex_error, Error, Result};
use crate::extractors::{Extractor, ExtractorType};
use crate::info::Version;
use crate::matchers::{Condition, FaviconMap, Matcher, MatcherType};
use crate::serde_format::is_default;
use serde::{Deserialize, Serialize};
use slinger::Response;
use std::collections::{BTreeMap, HashSet};

#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq)]
#[serde(rename_all = "kebab-case")]
pub struct Operators {
  #[serde(default, skip_serializing_if = "is_default")]
  pub stop_at_first_match: bool,
  #[serde(default, skip_serializing_if = "is_default")]
  pub matchers_condition: Condition,
  #[serde(default, skip_serializing_if = "is_default")]
  pub matchers: Vec<Matcher>,
  #[serde(default, skip_serializing_if = "is_default")]
  pub extractors: Vec<Extractor>,
}

impl Operators {
  pub(crate) fn compile(&mut self) -> Result<()> {
    for matcher in self.matchers.iter_mut() {
      matcher.compile().map_err(new_regex_error)?;
    }
    for extractor in self.extractors.iter_mut() {
      extractor.compile().map_err(new_regex_error)?;
    }
    Ok(())
  }
  pub fn extractor(
    &self,
    version: Option<Version>,
    response: &Response,
    result: &mut OperatorResult,
  ) {
    for (index, extractor) in self.extractors.iter().enumerate() {
      let words = if let Ok(w) = extractor.part.get_matcher_word_from_part(response) {
        w
      } else {
        continue;
      };
      let (extract_result, version) = match &extractor.extractor_type {
        ExtractorType::Regex(re) => extractor.extract_regex(re, words, &version),
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
  pub fn matcher(&self, response: &Response, result: &mut OperatorResult) -> Result<()> {
    let mut matchers = Vec::new();
    if self.matchers.is_empty() {
      return Ok(());
    }
    for matcher in self.matchers.iter() {
      let words = matcher.part.get_matcher_word_from_part(response)?;
      let (is_match, mw) = match &matcher.matcher_type {
        MatcherType::Word(word) => matcher.match_word(word, words),
        MatcherType::Favicon(fav) => {
          let hm = response
            .extensions()
            .get::<BTreeMap<String, FaviconMap>>()
            .ok_or(Error::IO(std::io::Error::new(
              std::io::ErrorKind::InvalidData,
              "not found favicon",
            )))?;
          matcher.match_favicon(fav, hm)
        }
        MatcherType::Status(status) => (
          matcher.match_status_code(status, response.status_code().as_u16()),
          vec![response.status_code().as_u16().to_string()],
        ),
        MatcherType::Regex(re) => matcher.match_regex(re, words),
        MatcherType::None
        | MatcherType::DSL(..)
        | MatcherType::Binary(..)
        | MatcherType::XPath(..) => (false, Vec::new()),
      };
      // 结果反取
      let is_match = matcher.negative(is_match);
      matchers.push(is_match);
      if !is_match {
        // 没有匹配到的
        match self.matchers_condition {
          Condition::Or => {
            continue;
          }
          Condition::And => {
            result.matched = false;
            break;
          }
        }
      } else {
        // 匹配到的
        if let Some(name) = &matcher.name {
          result.name.insert(name.clone());
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
    // 全部匹配到
    if matches!(self.matchers_condition, Condition::And) && matchers.iter().all(|x| *x) {
      result.matched = true;
    }
    Ok(())
  }
}

#[derive(Debug, Clone, Default, PartialEq)]
pub struct OperatorResult {
  matched: bool,
  name: HashSet<String>,
  matcher_word: Vec<String>,
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
