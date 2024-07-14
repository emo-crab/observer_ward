use crate::serde_format::{is_default, string_vec_serde, Value};
use fancy_regex::Captures;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashMap};

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
          .to_string(),
        vendor: vendor
          .to_string()
          .replacen('\\', "", 10)
          .replacen('/', "-", 10)
          .trim_start_matches('_')
          .trim_end_matches('_')
          .to_string(),
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
  pub fn captures(&self, captures: Captures) -> HashMap<String, String> {
    let replace = |x: &str| {
      let mut x = x.to_string();
      for (index, value) in self.extract_parameters(&x) {
        if let Some(m) = captures.get(index) {
          x = x.replace(&value, m.as_str());
        }
      }
      x
    };
    let mut r: HashMap<String, String> = HashMap::new();
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
  fn extract_parameters(&self, s: &str) -> HashMap<usize, String> {
    let mut parameters = HashMap::new();
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
