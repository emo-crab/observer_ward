use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct X509Certificate {
  text: String,
  pem: Vec<u8>,
  public_key: Option<Vec<u8>>,
  subject_name: BTreeMap<String, String>,
  issuer_name: BTreeMap<String, String>,
  subject_alt_names: Option<Vec<GeneralName>>,
  issuer_alt_names: Option<Vec<GeneralName>>,
  subject_name_hash: u32,
  signature: Vec<u8>,
  signature_algorithm: String,
  ocsp_responders: Vec<String>,
  serial_number: Option<String>,
  not_after: String,
  not_before: String,
  version: i32,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "kebab-case")]
pub struct GeneralName {
  email: Option<String>,
  dns_name: Option<String>,
  uri: Option<String>,
  ipaddress: Option<Vec<u8>>,
}

impl Default for X509Certificate {
    fn default() -> Self {
        Self::new()
    }
}

impl X509Certificate {
  pub fn new() -> X509Certificate {
    // X509Certificate {
    //   public_key: value
    //     .public_key()
    //     .ok()
    //     .map(|x| x.public_key_to_pem().unwrap_or_default()),
    //   text: String::from_utf8_lossy(&value.to_text().unwrap_or_default()).to_string(),
    //   pem: value.to_pem().unwrap_or_default(),
    //   not_after: value.not_after().to_string(),
    //   not_before: value.not_before().to_string(),
    //   version: value.version(),
    //   subject_name_hash: value.subject_name_hash(),
    //   serial_number: value.serial_number().to_bn().ok().map(|x| x.to_string()),
    //   ocsp_responders: value
    //     .ocsp_responders()
    //     .map_or(Vec::new(), |x| x.iter().map(|o| o.to_string()).collect()),
    //   signature_algorithm: value.signature_algorithm().object().to_string(),
    //   signature: value.signature().as_slice().to_vec(),
    //   subject_alt_names: value.subject_alt_names().map(|x| {
    //     x.into_iter()
    //       .map(|g| GeneralName {
    //         dns_name: g.dnsname().map(|d| d.to_string()),
    //         email: g.email().map(|e| e.to_string()),
    //         uri: g.uri().map(|u| u.to_string()),
    //         ipaddress: g.ipaddress().map(|i| i.to_vec()),
    //       })
    //       .collect()
    //   }),
    //   issuer_alt_names: value.issuer_alt_names().map(|x| {
    //     x.into_iter()
    //       .map(|g| GeneralName {
    //         dns_name: g.dnsname().map(|d| d.to_string()),
    //         email: g.email().map(|e| e.to_string()),
    //         uri: g.uri().map(|u| u.to_string()),
    //         ipaddress: g.ipaddress().map(|i| i.to_vec()),
    //       })
    //       .collect()
    //   }),
    //   subject_name: value
    //     .subject_name()
    //     .entries()
    //     .map(|e| {
    //       (
    //         kebab_case(&e.object().to_string()),
    //         String::from_utf8_lossy(e.data().as_slice()).to_string(),
    //       )
    //     })
    //     .collect(),
    //   issuer_name: value
    //     .issuer_name()
    //     .entries()
    //     .map(|e| {
    //       (
    //         kebab_case(&e.object().to_string()),
    //         String::from_utf8_lossy(e.data().as_slice()).to_string(),
    //       )
    //     })
    //     .collect(),
    // }
    X509Certificate{
      text: "".to_string(),
      pem: vec![],
      public_key: None,
      subject_name: Default::default(),
      issuer_name: Default::default(),
      subject_alt_names: None,
      issuer_alt_names: None,
      subject_name_hash: 0,
      signature: vec![],
      signature_algorithm: "".to_string(),
      ocsp_responders: vec![],
      serial_number: None,
      not_after: "".to_string(),
      not_before: "".to_string(),
      version: 0,
    }
  }
}

// fn kebab_case(name: &str) -> String {
//   let mut new_name = String::new();
//   let chars = name.chars().collect::<Vec<_>>();
//   let l = chars.len();
//   for (index, c) in chars.into_iter().enumerate() {
//     if c.is_uppercase() && (index != 0 || index != l - 1) {
//       new_name.push('_');
//       c.to_lowercase().for_each(|nc| new_name.push(nc));
//     } else {
//       new_name.push(c);
//     }
//   }
//   new_name
// }
