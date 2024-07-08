use crate::operators::Operators;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "kebab-case")]
pub struct CodeRequest {
  // Operators for the current request go here.
  #[serde(flatten)]
  pub operators: Operators,
  // ID is the optional id of the request
  pub id: Option<String>,
  pub engine: Vec<String>,
  #[serde(default)]
  pub args: Vec<String>,
  pub pattern: Option<String>,
  pub source: String,
}
