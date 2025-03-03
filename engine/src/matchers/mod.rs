use crate::error::{new_regex_error, Error, Result};
use crate::serde_format::is_default;
use serde::{de, ser, Deserialize, Deserializer, Serialize, Serializer};
use slinger::Response;
use std::collections::{BTreeMap, HashSet};
use std::fmt::{Display, Formatter};
use std::str::FromStr;

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "kebab-case")]
pub struct Matcher {
  #[serde(flatten)]
  pub matcher_type: MatcherType,
  #[serde(default, skip_serializing_if = "is_default")]
  pub name: Option<String>,
  #[serde(default, skip_serializing_if = "is_default")]
  pub part: Part,
  #[serde(default, skip_serializing_if = "is_default")]
  pub encoding: Option<String>,
  #[serde(default, skip_serializing_if = "is_default")]
  pub condition: Condition,
  #[serde(default, skip_serializing_if = "is_default")]
  pub match_all: bool,
  #[serde(default, skip_serializing_if = "is_default")]
  pub internal: bool,
  #[serde(default, skip_serializing_if = "is_default")]
  pub case_insensitive: bool,
  #[serde(default, skip_serializing_if = "is_default")]
  pub negative: bool,
  /// 预编译正则
  #[serde(skip)]
  pub regex: Vec<fancy_regex::Regex>,
}

impl PartialEq for Matcher {
  fn eq(&self, other: &Self) -> bool {
    self.name == other.name
  }
}

impl Matcher {
  pub(crate) fn compile(&mut self) -> Result<()> {
    if let MatcherType::Regex(regexps) = &self.matcher_type {
      for re in regexps.regex.iter() {
        let rec = fancy_regex::Regex::new(re).map_err(new_regex_error)?;
        self.regex.push(rec);
      }
    }
    if let MatcherType::Word(word) = &mut self.matcher_type {
      if self.case_insensitive {
        word.words = word.words.iter().map(|x| x.to_ascii_lowercase()).collect();
      }
    }
    Ok(())
  }
  pub(crate) fn match_favicon(
    &self,
    fav: &Favicon,
    corpus: &BTreeMap<String, FaviconMap>,
  ) -> (bool, Vec<String>) {
    let mut matched_words = Vec::new();
    for (u, map) in corpus.iter().map(|(k, v)| (k.to_string(), v.hash())) {
      for w in fav.hash.clone().into_iter() {
        if map.contains(&w) {
          matched_words.push(w);
          matched_words.push(u);
          return (true, matched_words);
        }
      }
    }
    (false, matched_words)
  }
  pub(crate) fn match_word(&self, word: &Word, corpus: String) -> (bool, Vec<String>) {
    let words = if self.case_insensitive {
      corpus.to_ascii_lowercase()
    } else {
      corpus
    };
    let mut matched_words = Vec::new();
    for (i, w) in word.words.clone().into_iter().enumerate() {
      // 如果没命中而且是and关系立即结束
      if !words.contains(&w) {
        match self.condition {
          Condition::Or => {
            continue;
          }
          Condition::And => {
            return (false, matched_words);
          }
        }
      }
      matched_words.push(w);
      // 有一个匹配到了而且不要求匹配全部
      if matches!(self.condition, Condition::Or) && !self.match_all {
        return (true, matched_words);
      }
      if word.words.len() - 1 == i && !self.match_all {
        return (true, matched_words);
      }
    }
    if !matched_words.is_empty() && self.match_all {
      return (true, matched_words);
    }
    (false, matched_words)
  }
  pub(crate) fn match_regex(&self, regexs: &MRegex, corpus: String) -> (bool, Vec<String>) {
    let mut matched_regexes = Vec::new();
    for re in self.regex.iter() {
      let matcher = if let Ok(matcher) = re.captures(&corpus) {
        matcher
      } else {
        continue;
      };
      match matcher {
        Some(c) => {
          if let Some(m) = c.get(regexs.group.unwrap_or(0)) {
            matched_regexes.push(m.as_str().to_string());
          }
          if matches!(self.condition, Condition::Or) && !self.match_all {
            return (true, matched_regexes);
          }
        }
        None => match self.condition {
          Condition::And => {
            return (false, matched_regexes);
          }
          Condition::Or => {
            continue;
          }
        },
      }
    }
    if !matched_regexes.is_empty() && !self.match_all {
      return (true, matched_regexes);
    }
    (false, matched_regexes)
  }
  pub(crate) fn match_status_code(&self, status: &Status, status_code: u16) -> bool {
    for code in status.status.iter() {
      if code != &status_code {
        continue;
      }
      return true;
    }
    false
  }

  pub(crate) fn negative(&self, is_match: bool) -> bool {
    if self.negative {
      !is_match
    } else {
      is_match
    }
  }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
#[serde(rename_all = "lowercase", tag = "type")]
pub enum MatcherType {
  #[default]
  None,
  Favicon(Favicon),
  Word(Word),
  Status(Status),
  Regex(MRegex),
  DSL(DSL),
  Binary(Binary),
  XPath(MatcherXPath),
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "kebab-case")]
#[serde(deny_unknown_fields)]
pub struct MatcherXPath {
  pub xpath: HashSet<String>,
  pub attribute: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "kebab-case")]
#[serde(deny_unknown_fields)]
pub struct Binary {
  pub binary: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "kebab-case")]
#[serde(deny_unknown_fields)]
pub struct Word {
  pub words: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct FaviconMap {
  md5: String,
  mmh3: String,
}

impl FaviconMap {
  pub fn new(md5: String, mmh3: String) -> Self {
    Self { md5, mmh3 }
  }
  pub fn hash(&self) -> Vec<String> {
    vec![self.md5.clone(), self.mmh3.clone()]
  }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "kebab-case")]
#[serde(deny_unknown_fields)]
pub struct Favicon {
  pub hash: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "kebab-case")]
#[serde(deny_unknown_fields)]
pub struct MRegex {
  pub regex: Vec<String>,
  #[serde(default, skip_serializing_if = "is_default")]
  pub group: Option<usize>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "kebab-case")]
#[serde(deny_unknown_fields)]
pub struct Status {
  pub status: Vec<u16>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "kebab-case")]
#[serde(deny_unknown_fields)]
pub struct DSL {
  pub dsl: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum Condition {
  #[default]
  Or,
  And,
}

#[derive(Debug, Clone, Default, PartialEq)]
pub enum Part {
  #[default]
  Body,
  Header,
  Response,
  Name(String),
}

impl Part {
  pub(crate) fn get_matcher_word_from_part(&self, response: &Response) -> Result<String> {
    let body = response.body().clone().unwrap_or_default();
    let body = match String::from_utf8(body.as_ref().to_vec()) {
      Ok(s) => s,
      Err(_) => format!("{}", body.escape_ascii()),
    };
    let mut header_string = String::new();
    for (k, v) in response.headers() {
      header_string.push_str(&format!("{}: {}\r\n", k, v.to_str().unwrap_or_default()));
    }
    let result = match &self {
      Part::Body => body.to_string(),
      Part::Header => header_string,
      Part::Response => {
        format!("{}\r\n\r\n{}", header_string, body)
      }
      Part::Name(name) => {
        if let Some(v) = response.headers().get(name) {
          v.to_str().unwrap_or_default().to_string()
        } else {
          return Err(Error::IO(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "not found part name",
          )));
        }
      }
    };
    Ok(result)
  }
}

impl FromStr for Part {
  type Err = Error;

  fn from_str(s: &str) -> Result<Self> {
    match s {
      "body" => Ok(Self::Body),
      "header" => Ok(Self::Header),
      "response" => Ok(Self::Response),
      name => Ok(Self::Name(name.to_string())),
    }
  }
}

impl Display for Part {
  fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
    let s = match self {
      Self::Body => "body".to_string(),
      Self::Header => "header".to_string(),
      Self::Response => "response".to_string(),
      Self::Name(name) => name.to_string(),
    };
    f.write_str(&s)
  }
}

impl<'de> de::Deserialize<'de> for Part {
  fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
  where
    D: Deserializer<'de>,
  {
    let s = String::deserialize(deserializer)?;
    match Part::from_str(&s) {
      Ok(p) => Ok(p),
      Err(err) => Err(de::Error::custom(err)),
    }
  }
}

impl ser::Serialize for Part {
  fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
  where
    S: Serializer,
  {
    serde::Serialize::serialize(&self.to_string().to_lowercase(), serializer)
  }
}
