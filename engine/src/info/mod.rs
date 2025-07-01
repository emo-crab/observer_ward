mod cse;
mod severity;
mod version;
mod vpf;

pub use crate::info::cse::CSE;
pub use crate::info::severity::Severity;
pub use crate::info::version::Version;
pub use crate::info::vpf::VPF;
use crate::serde_format::{Value, is_default, string_vec_serde};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

const UNKNOWN_00: &str = "00_unknown";
#[cfg_attr(feature = "mcp", derive(schemars::JsonSchema))]
#[derive(Default, Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
#[serde(deny_unknown_fields)]
pub struct Info {
  /// description: |
  ///   Name should be good short summary that identifies what the template does.
  ///
  /// examples:
  ///   - value: "\"bower.json file disclosure\""
  ///   - value: "\"Nagios Default Credentials Check\""
  #[cfg_attr(
    feature = "mcp",
    schemars(
      title = "name of the template",
      description = "Name is a short summary of what the template does",
      example = &"Nagios Default Credentials Check"
    )
  )]
  pub name: String,
  /// description: |
  ///   Author of the template.
  ///
  ///   Multiple values can also be specified separated by commas.
  /// examples:
  ///   - value: "\"<username>\""
  #[serde(with = "string_vec_serde", default)]
  #[cfg_attr(
    feature = "mcp",
    schemars(
      with = "Vec<String>",
      title = "author of the template",
      description = "Author is the author of the template",
      example = &"username"
    )
  )]
  pub author: Vec<String>,
  /// description: |
  ///   Any tags for the template.
  ///
  ///   Multiple values can also be specified separated by commas.
  ///
  /// examples:
  ///   - name: Example tags
  ///     value: "\"cve,cve2019,grafana,auth-bypass,dos\""
  #[serde(with = "string_vec_serde", default)]
  #[cfg_attr(
    feature = "mcp",
    schemars(
      with = "Vec<String>",
      title = "tags of the template",
      description = "Any tags for the template"
    )
  )]
  pub tags: Vec<String>,
  /// description: |
  ///   Description of the template.
  ///
  ///   You can go in-depth here on what the template actually does.
  ///
  /// examples:
  ///   - value: "\"Bower is a package manager which stores package information in the bower.json file\""
  ///   - value: "\"Subversion ALM for the enterprise before 8.8.2 allows reflected XSS at multiple locations\""
  #[serde(skip_serializing_if = "Option::is_none")]
  #[cfg_attr(feature = "mcp", schemars(
    title = "description of the template",
    description = "In-depth explanation on what the template does",
    example = &"Bower is a package manager which stores package information in the bower.json file"
  ))]
  pub description: Option<String>,
  /// description: |
  ///   Impact of the template.
  ///
  ///   You can go in-depth here on impact of the template.
  ///
  /// examples:
  ///   - value: "\"Successful exploitation of this vulnerability could allow an attacker to execute arbitrary SQL queries, potentially leading to unauthorized access, data leakage, or data manipulation.\""
  ///   - value: "\"Successful exploitation of this vulnerability could allow an attacker to execute arbitrary script code in the context of the victim's browser, potentially leading to session hijacking, defacement, or theft of sensitive information.\""
  #[serde(skip_serializing_if = "Option::is_none")]
  #[cfg_attr(feature = "mcp", schemars(
    title = "impact of the template",
    description = "In-depth explanation on the impact of the issue found by the template",
    example = &"Successful exploitation of this vulnerability could allow an attacker to execute arbitrary SQL queries, potentially leading to unauthorized access, data leakage, or data manipulation."
  ))]
  pub impact: Option<String>,
  /// description: |
  ///   References for the template.
  ///
  ///   This should contain links relevant to the template.
  ///
  /// examples:
  /// - value: >
  ///   []string{"https://github.com/strapi/strapi", "https://github.com/getgrav/grav"}
  ///
  #[serde(
    deserialize_with = "string_vec_serde::deserialize",
    skip_serializing_if = "Vec::is_empty",
    default
  )]
  #[cfg_attr(
    feature = "mcp",
    schemars(
      title = "references for the template",
      description = "Links relevant to the template"
    )
  )]
  pub reference: Vec<String>,
  /// description: |
  ///   Severity of the template.
  #[cfg_attr(
    feature = "mcp",
    schemars(
      title = "severity of the template",
      description = "Seriousness of the implications of the template"
    )
  )]
  pub severity: Severity,
  /// description: |
  ///   Metadata of the template.
  ///
  /// examples:
  /// - value: >
  ///   map[string]string{"customField1":"customValue1"}
  #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
  #[cfg_attr(
    feature = "mcp",
    schemars(
      title = "additional metadata for the template",
      description = "Additional metadata fields for the template"
    )
  )]
  pub metadata: BTreeMap<String, Value>,
  /// description: |
  ///   Extracted version information from metadata.
  #[serde(skip_serializing_if = "Option::is_none")]
  #[cfg_attr(
    feature = "mcp",
    schemars(
      title = "version information",
      description = "Structured version information extracted from metadata"
    )
  )]
  pub version: Option<Version>,
  /// description: |
  ///   Classification contains classification information about the template.
  #[serde(skip_serializing_if = "Option::is_none")]
  #[cfg_attr(
    feature = "mcp",
    schemars(
      title = "classification info for the template",
      description = "Classification information for the template"
    )
  )]
  pub classification: Option<Classification>,
  /// description: |
  ///   Remediation steps for the template.
  ///
  ///   You can go in-depth here on how to mitigate the problem found by this template.
  ///
  /// examples:
  ///   - value: "\"Change the default administrative username and password of Apache ActiveMQ by editing the file jetty-realm.properties\""
  #[serde(skip_serializing_if = "Option::is_none")]
  #[cfg_attr(feature = "mcp", schemars(
    title = "remediation steps for the template",
    description = "In-depth explanation on how to fix the issues found by the template",
    example = &"Change the default administrative username and password of Apache ActiveMQ by editing the file jetty-realm.properties"
  ))]
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
#[cfg_attr(feature = "mcp", derive(schemars::JsonSchema))]
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
#[serde(deny_unknown_fields)]
pub struct Classification {
  ///description: |
  ///   CVE ID for the template
  ///examples:
  ///   - value: "\"CVE-2020-14420\""
  #[cfg_attr(feature = "mcp", schemars(with = "Vec<String>"))]
  #[serde(with = "string_vec_serde", default, skip_serializing_if = "is_default")]
  pub cve_id: Vec<String>,
  ///description: |
  ///   CWE ID for the template.
  ///examples:
  ///   - value: "\"CWE-22\""
  #[cfg_attr(feature = "mcp", schemars(with = "Vec<String>"))]
  #[serde(with = "string_vec_serde", default, skip_serializing_if = "is_default")]
  pub cwe_id: Vec<String>,
  ///description: |
  ///   CVSS Metrics for the template.
  ///examples:
  ///   - value: "\"3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H\""
  #[serde(default, skip_serializing_if = "is_default")]
  pub cvss_metrics: Option<String>,
  ///description: |
  ///   CVSS Score for the template.
  ///examples:
  ///   - value: "\"9.8\""
  #[serde(default, skip_serializing_if = "is_default")]
  pub cvss_score: Option<f32>,
  ///description: |
  ///   EPSS Score for the template.
  ///examples:
  ///   - value: "\"0.42509\""
  #[serde(default, skip_serializing_if = "is_default")]
  pub epss_score: Option<f32>,
  ///description: |
  ///   EPSS Percentile for the template.
  ///examples:
  ///   - value: "\"0.42509\""
  #[serde(default, skip_serializing_if = "is_default")]
  pub epss_percentile: Option<f32>,
  ///description: |
  ///   CPE for the template.
  ///examples:
  ///   - value: "\"cpe:/a:vendor:product:version\""
  #[serde(default, skip_serializing_if = "is_default")]
  pub cpe: Option<String>,
}
