use crate::error::{Error, Result};
use crate::operators::regex::RegexPattern;
use crate::operators::target::OperatorTarget;
use crate::serde_format::is_default;
use log::error;
use once_cell::sync::OnceCell;
use serde::{Deserialize, Deserializer, Serialize, Serializer, de, ser};
use slinger::Body;
use std::collections::{BTreeMap, HashSet};
use std::fmt::{Display, Formatter};
use std::str::FromStr;

#[cfg_attr(feature = "mcp", derive(schemars::JsonSchema))]
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "kebab-case")]
pub struct Matcher {
  // description: |
  //   Type is the type of the matcher.
  #[serde(flatten)]
  #[cfg_attr(
    feature = "mcp",
    schemars(title = "type of matcher", description = "Type of the matcher",)
  )]
  pub matcher_type: MatcherType,
  // description: |
  //   Name of the matcher. Name should be lowercase and must not contain
  //   spaces or underscores (_).
  // examples:
  //   - value: "\"cookie-matcher\""
  #[serde(default, skip_serializing_if = "is_default")]
  #[cfg_attr(
    feature = "mcp",
    schemars(
      title = "name of the matcher",
      description = "Name of the matcher. Should be lowercase and must not contain spaces or underscores",
      example = r#"&"cookie-matcher""#
    )
  )]
  pub name: Option<String>,
  // description: |
  //   Part is the part of the request response to match data from.
  //
  //   Each protocol exposes a lot of different parts which are well
  //   documented in docs for each request type.
  // examples:
  //   - value: "\"body\""
  //   - value: "\"raw\""
  #[serde(default, skip_serializing_if = "is_default")]
  #[cfg_attr(
    feature = "mcp",
    schemars(
      title = "part of response to match",
      description = "Part of response to match data from",
      example = r#"&"body""#
    )
  )]
  pub part: Part,
  // description: |
  //   Encoding specifies the encoding for the words field if any.
  // values:
  //   - "hex"
  #[serde(default, skip_serializing_if = "is_default")]
  #[cfg_attr(
    feature = "mcp",
    schemars(
      title = "encoding for word field",
      description = "Optional encoding for the word fields,enum: hex",
    )
  )]
  pub encoding: Option<String>,
  // description: |
  //   Condition is the optional condition between two matcher variables. By default,
  //   the condition is assumed to be OR.
  // values:
  //   - "and"
  //   - "or"
  #[serde(default, skip_serializing_if = "is_default")]
  #[cfg_attr(
    feature = "mcp",
    schemars(
      title = "condition between matcher variables",
      description = "Condition between the matcher variables",
    )
  )]
  pub condition: Condition,
  // description: |
  //   MatchAll enables matching for all matcher values. Default is false.
  // values:
  //   - false
  //   - true
  #[serde(default, skip_serializing_if = "is_default")]
  #[cfg_attr(
    feature = "mcp",
    schemars(
      title = "match all values",
      description = "match all matcher values ignoring condition"
    )
  )]
  pub match_all: bool,
  // description: |
  //  Internal when true hides the matcher from output. Default is false.
  // It is meant to be used in multiprotocol / flow templates to create internal matcher condition without printing it in output.
  // or other similar use cases.
  // values:
  //   - false
  //   - true
  #[serde(default, skip_serializing_if = "is_default")]
  #[cfg_attr(
    feature = "mcp",
    schemars(
      title = "hide matcher from output",
      description = "hide matcher from output"
    )
  )]
  pub internal: bool,
  // description: |
  //   CaseInsensitive enables case-insensitive matches. Default is false.
  // values:
  //   - false
  //   - true
  #[serde(default, skip_serializing_if = "is_default")]
  #[cfg_attr(
    feature = "mcp",
    schemars(
      title = "use case insensitive match",
      description = "use case insensitive match"
    )
  )]
  pub case_insensitive: bool,
  // description: |
  //   Negative specifies if the match should be reversed
  //   It will only match if the condition is not true.
  #[serde(default, skip_serializing_if = "is_default")]
  #[cfg_attr(
    feature = "mcp",
    schemars(
      title = "negative specifies if match reversed",
      description = "Negative specifies if the match should be reversed. It will only match if the condition is not true"
    )
  )]
  pub negative: bool,
}

impl PartialEq for Matcher {
  fn eq(&self, other: &Self) -> bool {
    self.name == other.name
  }
}

impl Matcher {
  pub(crate) fn compile(&mut self) -> Result<()> {
    if let MatcherType::Regex(regexps) = &mut self.matcher_type {
      regexps.compiled_regex = vec![OnceCell::new(); regexps.regex.len()]
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
  pub(crate) fn match_regex(
    &self,
    regex_list: &RegexPattern,
    corpus: String,
    body: Body,
  ) -> (bool, Vec<String>) {
    let mut matched_regexes = Vec::new();
    // 遍历所有正则表达式模式
    for (i, _) in regex_list.regex.iter().enumerate() {
      // 获取编译后的正则表达式（懒加载）
      let re = match regex_list.get_compiled(i) {
        Ok(re) => re,
        Err(err) => {
          error!("match regex compiled error: {err:?}",);
          continue;
        } // 如果编译失败，跳过这个正则
      };

      // 执行匹配
      match re.captures(&corpus, &body) {
        Some(c) => {
          // 处理匹配结果
          if let Some(m) = c.get(regex_list.group.unwrap_or(0)) {
            matched_regexes.push(m);
          }
          // 如果是 OR 条件且不需要匹配所有，提前返回
          if matches!(self.condition, Condition::Or) && !self.match_all {
            return (true, matched_regexes);
          }
        }
        None => match self.condition {
          Condition::And => {
            // AND 条件需要全部匹配，所以一旦有一个不匹配就返回失败
            return (false, matched_regexes);
          }
          Condition::Or => {
            // OR 条件继续尝试下一个正则
            continue;
          }
        },
      }
    }
    // 根据匹配结果和条件返回最终结果
    if !matched_regexes.is_empty() && !self.match_all {
      (true, matched_regexes)
    } else {
      (false, matched_regexes)
    }
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
    if self.negative { !is_match } else { is_match }
  }
}
#[cfg_attr(feature = "mcp", derive(schemars::JsonSchema))]
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
#[serde(rename_all = "lowercase", tag = "type")]
pub enum MatcherType {
  #[default]
  None,
  Favicon(Favicon),
  Word(Word),
  Status(Status),
  Regex(RegexPattern),
  DSL(DSL),
  Binary(Binary),
  XPath(MatcherXPath),
}
#[cfg_attr(feature = "mcp", derive(schemars::JsonSchema))]
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "kebab-case")]
#[serde(deny_unknown_fields)]
pub struct MatcherXPath {
  #[cfg_attr(
    feature = "mcp",
    schemars(
      title = "xpath queries to match in response",
      description = "xpath are the XPath queries that will be evaluated against the response part of nuclei matching rules",
      example = r#"&["/html/head/title[contains(text(), 'How to Find XPath')]", "//a[@target=\"_blank\"]"]"#
    )
  )]
  pub xpath: HashSet<String>,
  pub attribute: Option<String>,
}
#[cfg_attr(feature = "mcp", derive(schemars::JsonSchema))]
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "kebab-case")]
#[serde(deny_unknown_fields)]
pub struct Binary {
  #[cfg_attr(
    feature = "mcp",
    schemars(
      title = "binary patterns to match in response",
      description = "Binary are the binary patterns required to be present in the response part",
      example = r#"&["4a4156412050524f46494c45", "4850524f46", "1f8b080000000000"]"#
    )
  )]
  pub binary: Vec<String>,
}
#[cfg_attr(feature = "mcp", derive(schemars::JsonSchema))]
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "kebab-case")]
#[serde(deny_unknown_fields)]
pub struct Word {
  #[cfg_attr(
    feature = "mcp",
    schemars(
      title = "words to match in response",
      description = "Words contains word patterns required to be present in the response part",
      example = r#"&["mail.protection.outlook.com", "application/json"]"#
    )
  )]
  pub words: Vec<String>,
}
#[cfg_attr(feature = "mcp", derive(schemars::JsonSchema))]
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct FaviconMap {
  /// MD5 hash of the favicon in hexadecimal format
  ///
  /// This 128-bit hash is commonly used for favicon identification
  /// despite not being cryptographically secure for this purpose.
  #[cfg_attr(
    feature = "mcp",
    schemars(
      title = "MD5 hash",
      description = "MD5 hash of the favicon in hexadecimal format (32 characters)",
      example = &"d41d8cd98f00b204e9800998ecf8427e",
      pattern("^[a-f0-9]{32}$"),
      length(min = 32, max = 32)
    )
  )]
  md5: String,
  /// MurmurHash3 (MMH3) hash of the favicon in hexadecimal format
  ///
  /// This 32-bit hash is popular for favicon identification due to
  /// its speed and reasonable collision resistance for this use case.
  #[cfg_attr(feature = "mcp", schemars(
        with = "i32",
        title = "MurmurHash3",
        description = "MurmurHash3 32-bit signed integer value in decimal format",
        example = "-1205551036",
        // 32-bit signed int range: -2,147,483,648 to 2,147,483,647
  ))]
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
#[cfg_attr(feature = "mcp", derive(schemars::JsonSchema))]
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "kebab-case")]
#[serde(deny_unknown_fields)]
pub struct Favicon {
  #[cfg_attr(
    feature = "mcp",
    schemars(
      title = "hash to match in favicon",
      description = "The hash of the webpage icon supports mmh3 and md5, and if there is one in the collection, the match is successful",
      example = r#"&["3aa2067193b2ed83f24c30bd238a717c", "1165838194"]"#
    )
  )]
  pub hash: Vec<String>,
}
#[cfg_attr(feature = "mcp", derive(schemars::JsonSchema))]
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
#[serde(deny_unknown_fields)]
pub struct MRegex {
  #[cfg_attr(
    feature = "mcp",
    schemars(
      title = "regex to match in response",
      description = "Regex contains regex patterns required to be present in the response part",
      example = r#"&["(?mi)^Via\\s*?:.*?linkerd.*$", "(?m)^(?:Location\\s*?:\\s*?)(?:https?://|//)?(?:[a-zA-Z0-9\\-_\\.@]*)example\\.com.*$"]"#
    )
  )]
  pub regex: Vec<String>,
  #[serde(default, skip_serializing_if = "is_default")]
  pub group: Option<usize>,
  /// 预编译正则
  #[serde(skip)]
  pub compiled_regex: Vec<OnceCell<fancy_regex::Regex>>,
}
#[cfg_attr(feature = "mcp", derive(schemars::JsonSchema))]
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "kebab-case")]
#[serde(deny_unknown_fields)]
pub struct Status {
  #[cfg_attr(
    feature = "mcp",
    schemars(
      title = "status to match",
      description = "Status to match for the response",
      example = r#"&[200, 302]"#
    )
  )]
  pub status: Vec<u16>,
}
#[cfg_attr(feature = "mcp", derive(schemars::JsonSchema))]
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "kebab-case")]
#[serde(deny_unknown_fields)]
pub struct DSL {
  #[cfg_attr(
    feature = "mcp",
    schemars(
      title = "dsl expressions to match in response",
      description = "DSL are the dsl expressions that will be evaluated as part of nuclei matching rules",
      example = r#"&["contains(body, 'packages') && contains(tolower(all_headers), 'application/octet-stream') && status_code == 200"]"#
    )
  )]
  pub dsl: Vec<String>,
}
#[cfg_attr(feature = "mcp", derive(schemars::JsonSchema))]
#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum Condition {
  #[default]
  Or,
  And,
}
#[cfg_attr(feature = "mcp", derive(schemars::JsonSchema))]
#[derive(Debug, Clone, Default, PartialEq)]
pub enum Part {
  #[default]
  Body,
  Header,
  Response,
  Name(String),
}

impl Part {
  pub(crate) fn get_matcher_word_from_part<T: OperatorTarget>(&self, target: &T) -> Result<(String, Body)> {
    let body = target.get_body().unwrap_or_default();
    let body_string = match String::from_utf8(body.as_ref().to_vec()) {
      Ok(s) => s,
      Err(_) => format!("{}", body.escape_ascii()),
    };
    let header_string = target.get_headers();
    let result = match &self {
      Part::Body => body_string,
      Part::Header => header_string,
      Part::Response => {
        format!("{header_string}\r\n\r\n{body_string}")
      }
      Part::Name(name) => {
        target.get_header(name).ok_or_else(|| {
          Error::IO(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "not found part name",
          ))
        })?
      }
    };
    Ok((result, body))
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
