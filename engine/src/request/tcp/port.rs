use crate::error::{Error, Result};
use serde::{de, ser, Deserializer, Serializer};
use std::ops::Range;
use std::str::FromStr;

// 端口，支持单个端口和范围：80，443-1024
#[derive(Debug, Clone, Eq, PartialEq, Default)]
pub struct PortRange {
  /// 单个端口列表
  single: Vec<u16>,
  /// 范围端口列表
  range: Vec<Range<u16>>,
}

impl PortRange {
  /// 判断是否存在给定端口
  pub fn contains(&self, other: u16) -> bool {
    self.single.contains(&other) || self.range.iter().any(|p| p.contains(&other))
  }
  fn all(&self) -> Vec<String> {
    let mut all: Vec<String> = self.single.iter().map(|s| s.to_string()).collect();
    all.extend(self.range.iter().map(|s| format!("{}-{}", s.start, s.end)));
    all
  }
  pub fn is_empty(&self) -> bool {
    self.single.is_empty() && self.range.is_empty()
  }
}

impl std::str::FromStr for PortRange {
  type Err = Error;

  /// Accepts '80-443', '80', '0-10'
  fn from_str(src: &str) -> Result<Self> {
    port_parser(src)
  }
}

pub fn port_parser(src: &str) -> Result<PortRange> {
  let port_list: Vec<&str> = src.split(',').collect();
  let mut single = Vec::new();
  let mut range = Vec::new();
  // Exclude 53,T:9100,U:30000-40000
  let m: &[_] = &['T', 'U', ':'];
  for port in port_list {
    if let Some((start, end)) = port.split_once('-') {
      range.push(
        start.trim_start_matches(m).parse::<u16>()?..end.trim_start_matches(m).parse::<u16>()?,
      )
    } else {
      single.push(port.trim_start_matches(m).parse::<u16>()?)
    }
  }
  Ok(PortRange { single, range })
}

impl<'de> de::Deserialize<'de> for PortRange {
  fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
  where
    D: Deserializer<'de>,
  {
    let s = String::deserialize(deserializer)?;
    match PortRange::from_str(&s) {
      Ok(p) => Ok(p),
      Err(err) => Err(serde::de::Error::custom(err)),
    }
  }
}

impl ser::Serialize for PortRange {
  fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
  where
    S: Serializer,
  {
    serde::Serialize::serialize(&self.all().join(","), serializer)
  }
}
