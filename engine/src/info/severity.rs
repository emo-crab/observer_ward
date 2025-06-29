use serde::{Deserialize, Serialize};
#[cfg_attr(feature = "mcp", derive(schemars::JsonSchema))]
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
