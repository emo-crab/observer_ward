use crate::matchers::{Favicon, MRegex, Matcher, MatcherType, Word};
use crate::serde_format::string_vec_serde;
use serde::{Deserialize, Serialize};
use std::collections::HashSet;

// 空间搜索引擎查询语法CyberspaceSearchEngineQuery
#[derive(Default, Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct CSE {
  #[serde(
    deserialize_with = "string_vec_serde::deserialize",
    skip_serializing_if = "Vec::is_empty",
    default
  )]
  pub zoomeye_query: Vec<String>,
  #[serde(
    deserialize_with = "string_vec_serde::deserialize",
    skip_serializing_if = "Vec::is_empty",
    default
  )]
  pub hunter_query: Vec<String>,
  #[serde(
    deserialize_with = "string_vec_serde::deserialize",
    skip_serializing_if = "Vec::is_empty",
    default
  )]
  pub shodan_query: Vec<String>,
  #[serde(
    deserialize_with = "string_vec_serde::deserialize",
    skip_serializing_if = "Vec::is_empty",
    default
  )]
  pub fofa_query: Vec<String>,
  #[serde(
    deserialize_with = "string_vec_serde::deserialize",
    skip_serializing_if = "Vec::is_empty",
    default
  )]
  pub google_query: Vec<String>,
}

fn or_and_split(query: &str) -> Vec<String> {
  let mut parts = Vec::new();

  let mut current_part = String::new();
  let mut in_double_and = false;
  let mut in_double_or = false;

  for c in query.chars() {
    match c {
      '&' => {
        if in_double_and {
          parts.push(current_part.trim().to_string());
          current_part = String::new();
          in_double_and = false;
        } else {
          in_double_and = true;
        }
      }
      '|' => {
        if in_double_or {
          parts.push(current_part.trim().to_string());
          current_part = String::new();
          in_double_or = false;
        } else {
          in_double_or = true;
        }
      }
      _ => {
        if in_double_and || in_double_or {
          continue;
        }
        current_part.push(c);
      }
    }
  }
  if !current_part.is_empty() {
    parts.push(current_part.trim().to_string());
  }
  parts
}

impl From<CSE> for Vec<Matcher> {
  fn from(val: CSE) -> Self {
    let mut mt = Vec::new();
    let mut keyword = HashSet::new();
    let mut title = HashSet::new();
    let mut hash = HashSet::new();
    let trim = &['"', '\'', '\\', ' '];
    for query in &val.shodan_query {
      if let Some((k, v)) = query.split_once(':') {
        let v = v
          .to_lowercase()
          .trim_matches(trim)
          .replace("\\\"", "")
          .to_string();
        for vv in or_and_split(&v) {
          match k {
            "title" | "http.title" => {
              title.insert(vv);
            }
            "http.html" | "html" => {
              keyword.insert(vv);
            }
            "http.favicon.hash" => {
              hash.extend(
                vv.split(',')
                  .map(|x| x.to_string())
                  .collect::<Vec<String>>(),
              );
            }
            _ => {}
          }
        }
      } else {
        // 都归关键词
        keyword.insert(query.to_lowercase().trim_matches(trim).to_string());
      }
    }
    for query in &val.fofa_query {
      let query = query.trim_matches(trim);
      for v in or_and_split(query) {
        if let Some((k, vv)) = v.split_once('=') {
          let vv = vv
            .to_lowercase()
            .trim_matches(trim)
            .replace("\\\"", "")
            .to_string();
          match k {
            "title" => {
              title.insert(vv);
            }
            "body" => {
              keyword.insert(vv);
            }
            "icon_hash" => {
              hash.extend(vv.split(',').map(|x| x.to_string()));
            }
            _ => {}
          }
        } else {
          // 都归关键词
          keyword.insert(v.to_lowercase().trim_matches(trim).to_string());
        }
      }
    }
    if !keyword.is_empty() {
      let mut k: Vec<String> = keyword.iter().map(|x| x.to_string()).collect();
      k.sort();
      let m = Matcher {
        matcher_type: MatcherType::Word(Word { words: k }),
        ..Matcher::default()
      };
      mt.push(m);
    }
    if !hash.is_empty() {
      let mut h: Vec<String> = hash.iter().map(|x| x.to_string()).collect();
      h.sort();
      let m = Matcher {
        matcher_type: MatcherType::Favicon(Favicon { hash: h }),
        ..Matcher::default()
      };
      mt.push(m);
    }
    if !title.is_empty() {
      let mut r: Vec<String> = title
        .iter()
        .filter(|x| !keyword.contains(*x))
        .map(|x| format!("(?mi)<title[^>]*>{}.*?</title>", x))
        .collect();
      r.sort();
      if !r.is_empty() {
        let m = Matcher {
          matcher_type: MatcherType::Regex(MRegex {
            regex: r,
            group: None,
          }),
          ..Matcher::default()
        };
        mt.push(m);
      }
    }
    mt
  }
}

#[cfg(test)]
mod tests {
  use crate::info::cse::or_and_split;

  #[test]
  fn it_works() {
    let o = or_and_split("icon_hash=\"160707013\" || icon_hash=\"-1815707560\"");
    println!("{:?}", o);
  }
}
