use crate::serde_format::is_default;
use serde::{Deserialize, Serialize};
use slinger::http::header::HeaderValue;
#[cfg_attr(feature = "mcp", derive(schemars::JsonSchema))]
#[derive(Debug, Default, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "kebab-case")]
pub struct HttpOption {
  #[serde(default, skip_serializing_if = "is_default")]
  #[cfg_attr(
    feature = "mcp",
    schemars(
      title = "perform HTTP 1.1 pipelining",
      description = "Pipeline defines if the attack should be performed with HTTP 1.1 Pipelining"
    )
  )]
  pub host_redirects: bool,
  #[serde(default, skip_serializing_if = "is_default")]
  #[cfg_attr(
    feature = "mcp",
    schemars(
      title = "follow http redirects",
      description = "Specifies whether redirects should be followed by the HTTP Client"
    )
  )]
  pub redirects: bool,
  // description: |
  //   RaceCount is the number of times to send a request in Race Condition Attack.
  // examples:
  //   - name: Send a request 5 times
  //     value: "5"
  #[serde(default, skip_serializing_if = "is_default")]
  #[cfg_attr(
    feature = "mcp",
    schemars(
      title = "number of times to repeat request in race condition",
      description = "Number of times to send a request in Race Condition Attack",
      example = 5
    )
  )]
  pub race_count: Option<u8>,
  // description: |
  //   MaxRedirects is the maximum number of redirects that should be followed.
  // examples:
  //   - name: Follow up to 5 redirects
  //     value: "5"
  #[serde(default, skip_serializing_if = "is_default")]
  #[cfg_attr(
    feature = "mcp",
    schemars(
      title = "maximum number of redirects to follow",
      description = "Maximum number of redirects that should be followed",
      example = 5
    )
  )]
  pub max_redirects: Option<usize>,
  // description: |
  //   Threads specifies number of threads to use sending requests. This enables Connection Pooling.
  //
  //   Connection: Close attribute must not be used in request while using threads flag, otherwise
  //   pooling will fail and engine will continue to close connections after requests.
  // examples:
  //   - name: Send requests using 10 concurrent threads
  //     value: 10
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
  // description: |
  //   MaxSize is the maximum size of http response body to read in bytes.
  // examples:
  //   - name: Read max 2048 bytes of the response
  //     value: 2048
  #[serde(default, skip_serializing_if = "is_default")]
  #[cfg_attr(
    feature = "mcp",
    schemars(
      title = "maximum http response body size",
      description = "Maximum size of http response body to read in bytes",
      example = 2048
    )
  )]
  pub max_size: Option<u16>,
  // description: |
  //   CookieReuse is an optional setting that enables cookie reuse for
  //   all requests defined in raw section.
  // Deprecated: This is default now. Use disable-cookie to disable cookie reuse. cookie-reuse will be removed in future releases.
  #[serde(default, skip_serializing_if = "is_default")]
  #[cfg_attr(
    feature = "mcp",
    schemars(
      title = "optional cookie reuse enable",
      description = "Optional setting that enables cookie reuse",
    )
  )]
  pub cookie_reuse: bool,
  /// Enables force reading of the entire raw unsafe request body
  #[serde(default, skip_serializing_if = "is_default")]
  #[cfg_attr(
    feature = "mcp",
    schemars(
      title = "force read all body",
      description = "Enables force reading of entire unsafe http request body"
    )
  )]
  pub read_all: bool,
  /// DisableCookie is an optional setting that disables cookie reuse
  #[serde(default, skip_serializing_if = "is_default")]
  #[cfg_attr(
    feature = "mcp",
    schemars(
      title = "optional disable cookie reuse",
      description = "Optional setting that disables cookie reuse"
    )
  )]
  pub disable_cookie: bool,
}

impl HttpOption {
  pub fn builder_client(&self) -> slinger::ClientBuilder {
    let redirect = if self.redirects {
      if self.host_redirects {
        slinger::redirect::Policy::Custom(crate::common::http::js_redirect)
      } else {
        slinger::redirect::Policy::Limit(self.max_redirects.unwrap_or(10))
      }
    } else {
      slinger::redirect::Policy::None
    };
    slinger::ClientBuilder::new()
      .danger_accept_invalid_certs(true)
      .danger_accept_invalid_hostnames(true)
      .cookie_store(self.cookie_reuse)
      .redirect(redirect)
      .min_tls_version(Some(slinger::tls::Version::TLS_1_0))
      .user_agent(HeaderValue::from_static(
        "Mozilla/5.0 (X11; Linux x86_64; rv:123.0) Gecko/20100101 Firefox/123.0",
      ))
  }
}
