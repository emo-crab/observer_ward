use fancy_regex::Captures;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

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
