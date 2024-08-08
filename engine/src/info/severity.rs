use serde::{Deserialize, Serialize};

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
