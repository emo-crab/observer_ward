use crate::common::PayloadAttack;
use crate::operators::Operators;
use crate::serde_format::is_default;
use serde::{Deserialize, Serialize};
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "kebab-case")]
pub struct TCPRequest {
  #[serde(default, skip_serializing_if = "is_default")]
  pub id: Option<String>,
  #[serde(default, skip_serializing_if = "is_default")]
  pub name: Option<String>,
  #[serde(default, skip_serializing_if = "is_default")]
  pub inputs: Vec<Input>,
  #[serde(default, skip_serializing_if = "is_default")]
  pub host: Vec<String>,
  // Operators for the current request go here.
  #[serde(flatten)]
  pub operators: Operators,
  // ID is the optional id of the request
  #[serde(flatten, skip_serializing_if = "is_default")]
  pub payload_attack: Option<PayloadAttack>,
  #[serde(default, skip_serializing_if = "is_default")]
  pub threads: Option<i32>,
  #[serde(default, skip_serializing_if = "is_default")]
  pub port: Option<Port>,
  #[serde(default, skip_serializing_if = "is_default")]
  pub exclude_ports: Option<String>,
  #[serde(default, skip_serializing_if = "is_default")]
  pub read_size: Option<usize>,
  #[serde(default, skip_serializing_if = "is_default")]
  pub read_all: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(untagged)]
pub enum Port {
  Port(u16),
  Ports(String),
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "kebab-case")]
pub struct Input {
  #[serde(default, skip_serializing_if = "is_default")]
  pub data: Option<String>,
  #[serde(default, skip_serializing_if = "is_default")]
  pub read: Option<usize>,
}
