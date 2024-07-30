use crate::matchers::{Favicon, MRegex, MatcherType, Word};
use crate::serde_format::{is_default, string_vec_serde, Value};
use fancy_regex::Captures;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashSet};
const UNKNOWN_00: &str = "00_unknown";
#[derive(Default, Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
#[serde(deny_unknown_fields)]
pub struct Info {
  pub name: String,
  #[serde(with = "string_vec_serde", default)]
  pub author: Vec<String>,
  #[serde(with = "string_vec_serde", default)]
  pub tags: Vec<String>,
  #[serde(skip_serializing_if = "Option::is_none")]
  pub description: Option<String>,
  #[serde(skip_serializing_if = "Option::is_none")]
  pub impact: Option<String>,
  #[serde(
    deserialize_with = "string_vec_serde::deserialize",
    skip_serializing_if = "Vec::is_empty",
    default
  )]
  pub reference: Vec<String>,
  pub severity: Severity,
  #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
  pub metadata: BTreeMap<String, Value>,
  #[serde(skip_serializing_if = "Option::is_none")]
  pub classification: Option<Classification>,
  #[serde(skip_serializing_if = "Option::is_none")]
  pub remediation: Option<String>,
}

impl Info {
  pub fn get_version(&self) -> Option<Version> {
    let mut flag = false;
    let version = Version {
      product_name: self.metadata.get("product_name").map(|x| {
        flag = true;
        x.to_string()
      }),
      version: self.metadata.get("version").map(|x| {
        flag = true;
        x.to_string()
      }),
      info: self.metadata.get("info").map(|x| {
        flag = true;
        x.to_string()
      }),
      hostname: self.metadata.get("hostname").map(|x| {
        flag = true;
        x.to_string()
      }),
      operating_system: self.metadata.get("operating_system").map(|x| {
        flag = true;
        x.to_string()
      }),
      device_type: self.metadata.get("device_type").map(|x| {
        flag = true;
        x.to_string()
      }),
      cpe: self
        .metadata
        .get("cpe")
        .map(|x| {
          flag = true;
          x.to_vec()
        })
        .unwrap_or_default(),
    };
    if flag {
      return Some(version);
    }
    None
  }
  pub fn get_vpf(&self) -> Option<VPF> {
    if let (Some(product), Some(vendor)) =
      (self.metadata.get("product"), self.metadata.get("vendor"))
    {
      Some(VPF {
        product: product
          .to_string()
          .replacen('\\', "", 10)
          .replacen('/', "-", 10)
          .trim_start_matches('_')
          .trim_end_matches('_')
          .to_lowercase(),
        vendor: vendor
          .to_string()
          .replacen('\\', "", 10)
          .replacen('/', "-", 10)
          .trim_start_matches('_')
          .trim_end_matches('_')
          .to_lowercase(),
        framework: self.metadata.get("framework").map(|x| x.to_string()),
        verified: if let Some(Value::Bool(verified)) = self.metadata.get("verified") {
          *verified
        } else {
          false
        },
      })
    } else {
      None
    }
  }
  pub fn get_rarity(&self) -> Option<u8> {
    self.metadata.get("rarity").and_then(|x| {
      if let Value::Num(n) = x {
        Some(*n as u8)
      } else {
        None
      }
    })
  }
  pub fn get_cse(&self) -> Option<CSE> {
    let mut flag = false;
    let cse = CSE {
      zoomeye_query: self
        .metadata
        .get("zoomeye-query")
        .map(|x| {
          flag = true;
          x.to_vec()
        })
        .unwrap_or_default(),
      fofa_query: self
        .metadata
        .get("fofa-query")
        .map(|x| {
          flag = true;
          x.to_vec()
        })
        .unwrap_or_default(),
      hunter_query: self
        .metadata
        .get("hunter-query")
        .map(|x| {
          flag = true;
          x.to_vec()
        })
        .unwrap_or_default(),
      shodan_query: self
        .metadata
        .get("shodan-query")
        .map(|x| {
          flag = true;
          x.to_vec()
        })
        .unwrap_or_default(),
      google_query: self
        .metadata
        .get("google-query")
        .map(|x| {
          flag = true;
          x.to_vec()
        })
        .unwrap_or_default(),
    };
    if flag {
      return Some(cse);
    }
    None
  }
}

impl Info {
  pub fn set_vpf(&mut self, vpf: VPF) {
    self.metadata.insert(
      "verified".to_string(),
      Value::Bool(vpf.product.as_str() != UNKNOWN_00),
    );
    self
      .metadata
      .insert("vendor".to_string(), Value::String(vpf.vendor));
    self
      .metadata
      .insert("product".to_string(), Value::String(vpf.product));
    if let Some(framework) = vpf.framework {
      self
        .metadata
        .insert("framework".to_string(), Value::String(framework));
    } else {
      self.metadata.remove("framework");
    }
  }
  pub fn set_cse(&mut self, cse: CSE) {
    self.metadata.insert(
      "zoomeye-query".to_string(),
      Value::List(
        cse
          .zoomeye_query
          .iter()
          .map(|x| Value::String(x.to_string()))
          .collect(),
      ),
    );
    self.metadata.insert(
      "fofa-query".to_string(),
      Value::List(
        cse
          .fofa_query
          .iter()
          .map(|x| Value::String(x.to_string()))
          .collect(),
      ),
    );
    self.metadata.insert(
      "hunter-query".to_string(),
      Value::List(
        cse
          .hunter_query
          .iter()
          .map(|x| Value::String(x.to_string()))
          .collect(),
      ),
    );
    self.metadata.insert(
      "shodan-query".to_string(),
      Value::List(
        cse
          .shodan_query
          .iter()
          .map(|x| Value::String(x.to_string()))
          .collect(),
      ),
    );
    self.metadata.insert(
      "google-query".to_string(),
      Value::List(
        cse
          .google_query
          .iter()
          .map(|x| Value::String(x.to_string()))
          .collect(),
      ),
    );
  }
}
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

impl CSE {
  fn or_and_split(&self, query: &str) -> Vec<String> {
    let mut parts = Vec::new();

    let mut current_part = String::new();
    let mut in_double_and = false;
    let mut in_double_or = false;

    for c in query.chars() {
      match c {
        '&' => {
          if in_double_and {
            parts.push(current_part);
            current_part = String::new();
            in_double_and = false;
          } else {
            in_double_and = true;
          }
        }
        '|' => {
          if in_double_or {
            parts.push(current_part);
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
      parts.push(current_part);
    }
    parts
  }
}
impl Into<Vec<MatcherType>> for CSE {
  fn into(self) -> Vec<MatcherType> {
    let mut mt = Vec::new();
    let mut keyword = HashSet::new();
    let mut title = HashSet::new();
    let mut hash = HashSet::new();
    let trim = &['"', '\''];
    for query in &self.shodan_query {
      if let Some((k, v)) = query.split_once(":") {
        let v = v.to_lowercase().trim_matches(trim).to_string();
        match k {
          "title" | "http.title" => {
            title.insert(format!("<\\btitle\\b.*?>{}<\\/\\btitle\\b>", v));
          }
          "http.html" | "html" => {
            keyword.insert(v);
          }
          "http.favicon.hash" => {
            hash.insert(v);
          }
          _ => {}
        }
      } else {
        // 都归关键词
        keyword.insert(query.to_lowercase().trim_matches(trim).to_string());
      }
    }
    for query in &self.fofa_query {
      let query = query.trim_matches(trim);
      if let Some((k, v)) = query.split_once("=") {
        for vv in self.or_and_split(&v) {
          let vv = vv.to_lowercase().trim_matches(trim).to_string();
          match k {
            "title" => {
              title.insert(format!("<\\btitle\\b.*?>{}<\\/\\btitle\\b>", vv));
            }
            "body" => {
              keyword.insert(vv);
            }
            "icon_hash" => {
              hash.insert(vv);
            }
            _ => {}
          }
        }
      } else {
        // 都归关键词
        for vv in self.or_and_split(&query) {
          keyword.insert(vv.to_lowercase().trim_matches(trim).to_string());
        }
      }
    }
    if !keyword.is_empty() {
      let mut k: Vec<String> = keyword.iter().map(|x| x.to_string()).collect();
      k.sort();
      mt.push(MatcherType::Word(Word { words: k }));
    }
    if !hash.is_empty() {
      let mut h: Vec<String> = hash.iter().map(|x| x.to_string()).collect();
      h.sort();
      mt.push(MatcherType::Favicon(Favicon { hash: h }));
    }
    if !title.is_empty() {
      let mut r: Vec<String> = title.iter().map(|x| x.to_string()).collect();
      r.sort();
      mt.push(MatcherType::Regex(MRegex {
        regex: r,
        group: None,
      }))
    }
    mt
  }
}

// nmap的服务版本信息
#[derive(Default, Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
#[serde(deny_unknown_fields)]
pub struct Version {
  /// 产品名称
  pub product_name: Option<String>,
  /// 版本号
  pub version: Option<String>,
  /// 信息
  pub info: Option<String>,
  /// 主机名
  pub hostname: Option<String>,
  /// 操作系统
  pub operating_system: Option<String>,
  /// 设备类型
  pub device_type: Option<String>,
  /// 通用枚举
  pub cpe: Vec<String>,
}

impl Version {
  pub fn captures(&self, captures: Captures) -> BTreeMap<String, String> {
    let replace = |x: &str| {
      let mut x = x.to_string();
      for (index, value) in self.extract_parameters(&x) {
        if let Some(m) = captures.get(index) {
          x = x.replace(&value, m.as_str());
        }
      }
      x
    };
    let mut r: BTreeMap<String, String> = BTreeMap::new();
    if let Some(x) = &self.info {
      r.insert("info".to_string(), replace(x));
    }
    if let Some(x) = &self.version {
      r.insert("version".to_string(), replace(x));
    }
    if let Some(x) = &self.device_type {
      r.insert("device_type".to_string(), replace(x));
    }
    if let Some(x) = &self.product_name {
      r.insert("product_name".to_string(), replace(x));
    }
    if let Some(x) = &self.hostname {
      r.insert("hostname".to_string(), replace(x));
    }
    if let Some(x) = &self.operating_system {
      r.insert("operating_system".to_string(), replace(x));
    }
    if !self.cpe.is_empty() {
      r.insert(
        "cpe".to_string(),
        self
          .cpe
          .iter()
          .map(|x| replace(x))
          .collect::<Vec<_>>()
          .join(","),
      );
    }
    r
  }
  fn extract_parameters(&self, s: &str) -> BTreeMap<usize, String> {
    let mut parameters = BTreeMap::new();
    let mut chars = s.chars().peekable();
    while let Some(&c) = chars.peek() {
      if c == '$' {
        chars.next(); // 跳过 '$'
        if let Some(&next_c) = chars.peek() {
          let mut num_str = String::new();
          // 下一位是数字
          if next_c.is_ascii_digit() {
            while let Some(&c) = chars.peek() {
              if c.is_ascii_digit() {
                num_str.push(c);
                chars.next();
              } else {
                break;
              }
            }
            let mut num = 0;
            let mut multiplier = 1;
            for digit in num_str.chars().rev() {
              num += (digit as usize - '0' as usize) * multiplier;
              multiplier *= 10;
            }
            parameters.insert(num, format!("${}", num));
          }
        }
      }
      chars.next();
    }
    parameters
  }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
#[serde(deny_unknown_fields)]
pub struct VPF {
  pub vendor: String,
  pub product: String,
  pub framework: Option<String>,
  pub verified: bool,
}

impl VPF {
  pub fn name(&self) -> String {
    format!("{}:{}", self.vendor, self.product)
  }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
#[serde(deny_unknown_fields)]
pub struct Classification {
  #[serde(with = "string_vec_serde", default, skip_serializing_if = "is_default")]
  pub cve_id: Vec<String>,
  #[serde(with = "string_vec_serde", default, skip_serializing_if = "is_default")]
  pub cwe_id: Vec<String>,
  #[serde(default, skip_serializing_if = "is_default")]
  pub cvss_metrics: Option<String>,
  #[serde(default, skip_serializing_if = "is_default")]
  pub cvss_score: Option<f32>,
  #[serde(default, skip_serializing_if = "is_default")]
  pub epss_score: Option<f32>,
  #[serde(default, skip_serializing_if = "is_default")]
  pub epss_percentile: Option<f32>,
  #[serde(default, skip_serializing_if = "is_default")]
  pub cpe: Option<String>,
}

#[derive(Default, Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
  #[default]
  // name:unknown
  Unknown,
  // name:info
  Info,
  // name:low
  Low,
  // name:medium
  Medium,
  // name:high
  High,
  // name:critical
  Critical,
}
