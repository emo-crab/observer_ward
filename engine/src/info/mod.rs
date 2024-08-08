mod cse;
mod severity;
mod version;
mod vpf;

pub use crate::info::cse::CSE;
pub use crate::info::severity::Severity;
pub use crate::info::version::Version;
pub use crate::info::vpf::VPF;
use crate::serde_format::{is_default, string_vec_serde, Value};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
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
      Value::Bool(vpf.vendor.as_str() != UNKNOWN_00),
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
    if !cse.zoomeye_query.is_empty() {
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
    }
    if !cse.fofa_query.is_empty() {
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
    }
    if !cse.hunter_query.is_empty() {
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
    }
    if !cse.shodan_query.is_empty() {
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
    }
    if !cse.google_query.is_empty() {
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
