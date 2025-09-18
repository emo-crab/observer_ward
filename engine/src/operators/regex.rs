use crate::error::{Error, Result};
use crate::serde_format::is_default;
use log::error;
use once_cell::sync::OnceCell;
use serde::{Deserialize, Serialize};
use slinger::Body;

impl PartialEq for RegexPattern {
  fn eq(&self, other: &Self) -> bool {
    self.regex == other.regex && self.group == other.group
  }
}
#[cfg_attr(feature = "mcp", derive(schemars::JsonSchema))]
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
#[serde(deny_unknown_fields)]
pub struct RegexPattern {
  /// Regular expression patterns to extract from a part
  #[cfg_attr(
    feature = "mcp",
    schemars(
      title = "regex to extract from part",
      description = "Regex contains the regular expression patterns to extract from a part"
    )
  )]
  pub regex: Vec<String>,
  /// Numbered group to extract from the regex
  #[serde(default, skip_serializing_if = "is_default")]
  #[cfg_attr(
    feature = "mcp",
    schemars(
      title = "group to extract from regex",
      description = "Group specifies a numbered group to extract from the regex"
    )
  )]
  pub group: Option<usize>,
  /// 预编译正则
  #[serde(skip)]
  pub compiled_regex: Vec<OnceCell<Regexp>>,
}
#[derive(Debug, Clone)]
pub struct Regexp {
  fancy_regex: Option<fancy_regex::Regex>,
  bytes_regex: Option<regex::bytes::Regex>,
}
pub enum OneOfCaptures<'a> {
  FancyCaptures(fancy_regex::Captures<'a>),
  BytesCaptures(regex::bytes::Captures<'a>),
}
impl OneOfCaptures<'_> {
  pub fn get(&self, index: usize) -> Option<String> {
    match self {
      OneOfCaptures::FancyCaptures(r) => r.get(index).map(|x| x.as_str().to_string()),
      OneOfCaptures::BytesCaptures(r) => r.get(index).map(|x| {
        let b = x.as_bytes();
        String::from_utf8(b.to_vec())
          .unwrap_or(b.escape_ascii().to_string())
          .chars()
          .filter(|c| !c.is_whitespace())
          .collect()
      }),
    }
  }
}
impl Regexp {
  fn new(pattern: &str) -> Result<Self> {
    let fancy_regex = match fancy_regex::Regex::new(pattern) {
      Ok(r) => Some(r),
      Err(err) => {
        error!("new fancy regex pattern error:{err:?}");
        None
      }
    };
    let bytes_regex = match regex::bytes::Regex::new(pattern) {
      Ok(r) => Some(r),
      Err(err) => {
        error!("new bytes regex pattern error:{err:?}");
        None
      }
    };
    Ok(Regexp {
      fancy_regex,
      bytes_regex,
    })
  }

  pub fn captures<'a>(&self, corpus: &'a str, body: &'a Body) -> Option<OneOfCaptures<'a>> {
    match self.fancy_captures(corpus) {
      Some(captures) => Some(captures),
      None => self.bytes_captures(body),
    }
  }
  fn fancy_captures<'a>(&self, corpus: &'a str) -> Option<OneOfCaptures<'a>> {
    if let Some(fancy_regex) = &self.fancy_regex {
      match fancy_regex.captures(corpus) {
        Ok(Some(captures)) => Some(OneOfCaptures::FancyCaptures(captures)),
        Ok(None) => None,
        Err(_) => None,
      }
    } else {
      None
    }
  }
  fn bytes_captures<'a>(&self, corpus: &'a [u8]) -> Option<OneOfCaptures<'a>> {
    if let Some(bytes_regex) = &self.bytes_regex {
      bytes_regex
        .captures(corpus)
        .map(OneOfCaptures::BytesCaptures)
    } else {
      None
    }
  }
}
impl RegexPattern {
  pub fn get_compiled(&self, index: usize) -> Result<&Regexp> {
    if index >= self.regex.len() {
      return Err(Error::IO(std::io::Error::new(
        std::io::ErrorKind::InvalidData,
        format!(
          "Index out of bounds: {} >= {}",
          index,
          self.compiled_regex.len()
        ),
      )));
    }
    self.compiled_regex[index].get_or_try_init(|| Regexp::new(&self.regex[index]))
  }
}
