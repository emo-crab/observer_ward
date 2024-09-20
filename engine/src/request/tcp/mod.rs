mod port;

use crate::common::PayloadAttack;
use crate::operators::Operators;
use crate::request::input_to_byte;
use crate::serde_format::is_default;
pub use port::PortRange;
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
  #[serde(default, skip_serializing_if = "is_default")]
  pub port: Option<PortRange>,
  // Operators for the current request go here.
  #[serde(flatten)]
  pub operators: Operators,
  // ID is the optional id of the request
  #[serde(flatten, skip_serializing_if = "is_default")]
  pub payload_attack: Option<PayloadAttack>,
  #[serde(default, skip_serializing_if = "is_default")]
  pub threads: Option<u8>,
  #[serde(default, skip_serializing_if = "is_default")]
  pub exclude_ports: Option<String>,
  #[serde(default, skip_serializing_if = "is_default")]
  pub read_size: Option<u16>,
  #[serde(default, skip_serializing_if = "is_default")]
  pub read_all: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "kebab-case")]
pub struct Input {
  #[serde(default, skip_serializing_if = "is_default")]
  pub data: Option<String>,
  #[serde(default, skip_serializing_if = "is_default")]
  pub read: Option<usize>,
}

impl Input {
  pub fn data(&self) -> Vec<u8> {
    input_to_byte(self.data.clone().unwrap_or_default().as_str())
  }
}
