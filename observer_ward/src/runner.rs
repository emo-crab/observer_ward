//! Common runner module for CLI and API servers
//!
//! Provides a unified interface for processing fingerprint identification results
//! with optional asynq queue support.

use crate::cli::ObserverWardConfig;
use crate::output::Output;
use crate::{FingerprintResult, ObserverWard};
use async_trait::async_trait;
use engine::execute::ClusterType;
use futures::StreamExt;
use futures::channel::mpsc::unbounded;

#[cfg(feature = "asynq_task")]
use crate::worker::AsynqClient;
#[cfg(feature = "asynq_task")]
use console::Emoji;
#[cfg(feature = "asynq_task")]
use log::error;

/// Trait for handling fingerprint identification results
#[async_trait]
pub trait ResultHandler: Send + Sync {
  /// Process a single execution result
  async fn handle_result(&self, result: &FingerprintResult);
}

/// Common runner for fingerprint identification
/// Contains shared state and functionality for both CLI and API modes
pub struct ObserverWardRunner {
  pub config: ObserverWardConfig,
  pub cluster_type: ClusterType,
  #[cfg(feature = "asynq_task")]
  pub asynq_client: Option<AsynqClient>,
}

impl ObserverWardRunner {
  /// Create a new runner with asynq support
  #[cfg(feature = "asynq_task")]
  pub fn new(
    config: ObserverWardConfig,
    cluster_type: ClusterType,
    asynq_client: Option<AsynqClient>,
  ) -> Self {
    Self {
      config,
      cluster_type,
      asynq_client,
    }
  }

  /// Create a new runner without asynq support
  #[cfg(not(feature = "asynq_task"))]
  pub fn new(config: ObserverWardConfig, cluster_type: ClusterType) -> Self {
    Self {
      config,
      cluster_type,
    }
  }

  /// Send results to asynq queue if client is available
  #[cfg(feature = "asynq_task")]
  pub async fn send_to_asynq(&self, result: &FingerprintResult) {
    if let Some(client) = &self.asynq_client
      && let Err(e) = client.send_all_results(&result.matched).await
    {
      error!("{}Failed to send results to asynq: {}", Emoji("💢", ""), e);
    }
  }

  /// No-op for non-asynq builds
  #[cfg(not(feature = "asynq_task"))]
  pub async fn send_to_asynq(&self, _matched: &Vec<MatchedEntry>) {
    // No-op when asynq_task feature is not enabled
  }

  /// Run fingerprint identification for CLI mode
  /// Processes results sequentially with output and optional asynq sending
  pub async fn run_cli(&self) {
    let (tx, mut rx) = unbounded();

    let config = self.config.clone();
    let cluster_type = self.cluster_type.clone();
    tokio::task::spawn(async move {
      ObserverWard::new(&config, cluster_type).execute(tx).await;
    });

    let mut output = Output::new(&self.config);
    while let Some(execute_result) = rx.next().await {
      // Save and print results
      output.save_and_print(&execute_result);
      // Send to webhook if configured
      output.webhook_results(&execute_result).await;
      // Send to asynq if configured
      self.send_to_asynq(&execute_result).await;
    }
  }

  /// Run fingerprint identification and collect results
  /// Used by API for returning results in response
  pub async fn run_and_collect(&self) -> Vec<FingerprintResult> {
    let (tx, mut rx) = unbounded();

    let config = self.config.clone();
    let cluster_type = self.cluster_type.clone();
    tokio::task::spawn(async move {
      ObserverWard::new(&config, cluster_type).execute(tx).await;
    });

    let mut results = Vec::new();
    while let Some(execute_result) = rx.next().await {
      // Send to asynq if configured
      self.send_to_asynq(&execute_result).await;
      results.push(execute_result);
    }
    results
  }

  /// Run fingerprint identification with webhook callback
  /// Used by API for async webhook-based results
  pub async fn run_with_webhook(&self) {
    let (tx, mut rx) = unbounded();

    let config = self.config.clone();
    let cluster_type = self.cluster_type.clone();
    tokio::task::spawn(async move {
      ObserverWard::new(&config, cluster_type).execute(tx).await;
    });

    let output = Output::new(&self.config);
    while let Some(execute_result) = rx.next().await {
      // Send to webhook
      output.webhook_results(&execute_result).await;
      // Send to asynq if configured
      self.send_to_asynq(&execute_result).await;
    }
  }
}

impl Clone for ObserverWardRunner {
  fn clone(&self) -> Self {
    Self {
      config: self.config.clone(),
      cluster_type: self.cluster_type.clone(),
      #[cfg(feature = "asynq_task")]
      asynq_client: self.asynq_client.clone(),
    }
  }
}
