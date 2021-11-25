use serde::{Deserialize, Serialize};

use requests::HttpRequest;

pub mod err;
pub mod operators;
pub mod requests;

#[derive(Debug, Serialize, Deserialize, Clone)]
struct NetInput {
    data: String,
    decode_type: String,
    read: u32,
    name: String,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
struct NetWorkRequest {
    host: Vec<String>,
    #[serde(default)]
    read_size: u32,
    #[serde(default)]
    input: Vec<NetInput>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct NucleiTemplate {
    pub id: String,
    #[serde(default)]
    pub requests: Vec<HttpRequest>,
    #[serde(default)]
    network: Vec<NetWorkRequest>,
}
