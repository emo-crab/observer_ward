use crate::serde_format::is_default;
use serde::{Deserialize, Serialize};
use slinger::http::header::HeaderValue;

#[derive(Debug, Default, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "kebab-case")]
pub struct HttpOption {
  #[serde(default, skip_serializing_if = "is_default")]
  pub host_redirects: bool,
  #[serde(default, skip_serializing_if = "is_default")]
  pub redirects: bool,
  // description: |
  //   RaceCount is the number of times to send a request in Race Condition Attack.
  // examples:
  //   - name: Send a request 5 times
  //     value: "5"
  #[serde(default, skip_serializing_if = "is_default")]
  pub race_count: Option<u8>,
  // description: |
  //   MaxRedirects is the maximum number of redirects that should be followed.
  // examples:
  //   - name: Follow up to 5 redirects
  //     value: "5"
  #[serde(default, skip_serializing_if = "is_default")]
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
  pub threads: Option<u8>,
  // description: |
  //   MaxSize is the maximum size of http response body to read in bytes.
  // examples:
  //   - name: Read max 2048 bytes of the response
  //     value: 2048
  #[serde(default, skip_serializing_if = "is_default")]
  pub max_size: Option<u16>,
  #[serde(default, skip_serializing_if = "is_default")]
  pub cookie_reuse: bool,
  #[serde(default, skip_serializing_if = "is_default")]
  pub read_all: bool,
}

impl HttpOption {
  pub fn builder_client(&self) -> slinger::ClientBuilder {
    let redirect = if self.redirects {
      if self.host_redirects {
        slinger::redirect::Policy::Custom(slinger::redirect::only_same_host)
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
      .min_tls_version(Some(slinger::native_tls::Protocol::Tlsv10))
      .user_agent(HeaderValue::from_static(
        "Mozilla/5.0 (X11; Linux x86_64; rv:123.0) Gecko/20100101 Firefox/123.0",
      ))
  }
}
