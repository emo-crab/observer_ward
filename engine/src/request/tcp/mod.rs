mod port;

use crate::common::PayloadAttack;
use crate::operators::Operators;
use crate::request::input_to_byte;
use crate::serde_format::is_default;
pub use port::PortRange;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
#[cfg_attr(feature = "mcp", derive(schemars::JsonSchema))]
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "kebab-case")]
pub struct TCPRequest {
  #[serde(default, skip_serializing_if = "is_default")]
  #[cfg_attr(
    feature = "mcp",
    schemars(title = "id of the request", description = "ID of the network request")
  )]
  pub id: Option<String>,
  #[serde(default, skip_serializing_if = "is_default")]
  pub name: Option<String>,
  #[serde(default, skip_serializing_if = "is_default")]
  #[cfg_attr(
    feature = "mcp",
    schemars(
      title = "inputs for the network request",
      description = "Inputs contains any input/output for the current request"
    )
  )]
  pub inputs: Vec<Input>,
  #[serde(default, skip_serializing_if = "is_default")]
  #[cfg_attr(
    feature = "mcp",
    schemars(
      title = "host to send requests to",
      description = "Host to send network requests to. Usually set to `{{Hostname}}`. For TLS use `tls://{{Hostname}}`",
      example = r#"&["{{Hostname}}"]"#
    )
  )]
  pub host: Vec<String>,
  #[serde(default, skip_serializing_if = "is_default")]
  #[cfg_attr(
    feature = "mcp",
    schemars(
      title = "port to send requests to",
      description = "Port to send network requests to. Acts as default but overridden by target ports",
    )
  )]
  pub port: Option<PortRange>,
  // Operators for the current request go here.
  #[serde(flatten)]
  pub operators: Arc<Operators>,
  // ID is the optional id of the request
  #[serde(flatten, skip_serializing_if = "is_default")]
  pub payload_attack: Option<PayloadAttack>,
  #[serde(default, skip_serializing_if = "is_default")]
  #[cfg_attr(
    feature = "mcp",
    schemars(
      title = "threads for sending requests",
      description = "Threads specifies number of threads to use sending requests. This enables Connection Pooling",
      example = 10
    )
  )]
  pub threads: Option<u8>,
  #[serde(default, skip_serializing_if = "is_default")]
  #[cfg_attr(
    feature = "mcp",
    schemars(
      title = "exclude ports from being scanned",
      description = "Exclude ports from being scanned. Used with Port field"
    )
  )]
  pub exclude_ports: Option<String>,
  #[serde(default, skip_serializing_if = "is_default")]
  #[cfg_attr(
    feature = "mcp",
    schemars(
      title = "size of network response to read",
      description = "Size of response to read at the end. Default is 1024 bytes",
      example = 2048
    )
  )]
  pub read_size: Option<u16>,
  #[serde(default, skip_serializing_if = "is_default")]
  #[cfg_attr(
    feature = "mcp",
    schemars(
      title = "read all response stream",
      description = "Read all response stream till the server stops sending",
      example = false
    )
  )]
  pub read_all: bool,
}
#[cfg_attr(feature = "mcp", derive(schemars::JsonSchema))]
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
