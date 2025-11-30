use console::Emoji;
use engine::execute::ClusterType;
use engine::results::MatchEvent;
use futures::channel::mpsc::UnboundedSender;
use log::{debug, info};
use std::sync::Arc;

use crate::cli::ObserverWardConfig;

use async_trait::async_trait;
use engine::slinger_mitm::MitmResponse;


pub async fn mitm_proxy_server(
  address: &crate::cli::UnixSocketAddr,
  config: ObserverWardConfig,
  cluster_type: ClusterType,
  tx: UnboundedSender<crate::ExecuteResult>,
) -> Result<(), Box<dyn std::error::Error>> {
  use engine::slinger_mitm::{MitmConfig, MitmProxy};

  info!(
    "{}Starting MITM proxy server on {}",
    Emoji("🔌", ""),
    address
  );

  // Get socket address
  let addr = match address {
    crate::cli::UnixSocketAddr::SocketAddr(socket) => format!("{}:{}", socket.ip(), socket.port()),
    #[cfg(unix)]
    crate::cli::UnixSocketAddr::Unix(_) => {
      return Err("Unix socket not supported for MITM proxy".into());
    }
  };

  let fingerprint_interceptor = Arc::new(FingerprintInterceptor {
    cluster_type: cluster_type.clone(),
    tx: tx.clone(),
    _config: config.clone(),
  });

  // Create MITM proxy with default config
  let mut mitm_config = MitmConfig::default();
  if let Some(proxy) = config.proxy {
    mitm_config.upstream_proxy = Some(proxy);
  }
  let proxy = MitmProxy::new(mitm_config).await?;

  info!(
    "{}MITM proxy service started: http://{}",
    Emoji("🌐", ""),
    addr
  );
  info!(
    "{}Configure your browser or tool to use this proxy",
    Emoji("📔", "")
  );
  info!(
    "{}CA certificate path: {}",
    Emoji("🔑", ""),
    proxy.ca_cert_path().display()
  );

  // Add the fingerprint interceptor
  {
    let handler = proxy.interceptor_handler();
    let mut handler_guard = handler.write().await;
    handler_guard.add_response_interceptor(fingerprint_interceptor);
  }

  // Start the proxy server
  proxy.start(&addr).await?;

  Ok(())
}


struct FingerprintInterceptor {
  cluster_type: ClusterType,
  tx: UnboundedSender<crate::ExecuteResult>,
  _config: ObserverWardConfig,
}


#[async_trait]
impl engine::slinger_mitm::ResponseInterceptor for FingerprintInterceptor {
  async fn intercept_response(&self, response: MitmResponse) -> engine::slinger_mitm::Result<Option<MitmResponse>>{
    use crate::MatchedResult;
    use std::collections::BTreeMap;

    // Clone data needed for async processing
    let response_clone = response.clone();
    let cluster_type = self.cluster_type.clone();
    let tx = self.tx.clone();

    // Get request from response extensions
    if let Some(request) = response.response.extensions().get::<engine::slinger::Request>() {
      let target = request.uri().clone();
      debug!("{}Intercepted response for: {}", Emoji("📥", ""), target);

      // Spawn async task for fingerprinting - don't block proxy speed
      tokio::spawn(async move {
        // Match against fingerprints
        let mut result = MatchEvent::new(&response_clone.response);
        // Find matching clusters based on scheme
        if target.scheme_str() == Some("https") || target.scheme_str() == Some("http") {
          // Match against web_default clusters
          for cluster in cluster_type.web_default.iter() {
            cluster
              .operators
              .iter()
              .for_each(|operator| operator.matcher(&mut result, true));
          }

          // Match favicon-specific clusters (ensure favicon matchers run)
          for cluster in cluster_type.web_favicon.iter() {
            cluster
              .operators
              .iter()
              .for_each(|operator| operator.matcher(&mut result, false));
          }

          // Match against web_other clusters
          for cluster in cluster_type.web_other.iter() {
            cluster
              .operators
              .iter()
              .for_each(|operator| operator.matcher(&mut result, true));
          }
        }

        // Only send results if matches found
        if !result.matcher_result().is_empty() {
          debug!("{}Match found for: {}", Emoji("✅", ""), target);
          let mut matched_map = BTreeMap::new();
          let mut matched_result = MatchedResult::default();
          matched_result.update_matched(&result);
          matched_map.insert(target.to_string(), matched_result);
          // Send result without HttpRecord (no active requests)
          let execute_result = crate::ExecuteResult {
            matched: matched_map,
            record: None,
          };
          let _ = tx.unbounded_send(execute_result);
        }
      });
    }

    // Immediately return the response - don't block proxy
    Ok(Some(response))
  }
}

#[cfg(not(feature = "mitm"))]
pub async fn mitm_proxy_server(
  _address: &crate::cli::UnixSocketAddr,
  _config: ObserverWardConfig,
  _cluster_type: ClusterType,
  _tx: UnboundedSender<crate::ExecuteResult>,
) -> Result<(), Box<dyn std::error::Error>> {
  use log::error;
  error!("{}MITM feature not enabled", Emoji("💢", ""));
  Err("MITM feature not enabled".into())
}
