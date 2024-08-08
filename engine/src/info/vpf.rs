use serde::{Deserialize, Serialize};

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
