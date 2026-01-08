//! Asynq task queue worker module
//!
//! Provides distributed task processing via Redis-backed message queue.
//! Supports receiving tasks from observer_ward:task queue and sending results to observer_ward:result queue.

use crate::cli::{AsynqMode, ObserverWardConfig};
use crate::{MatchedResult, ObserverWard};
use async_trait::async_trait;
use asynq::client::Client;
use asynq::error::Result as AsynqResult;
use asynq::redis::RedisConnectionType;
use asynq::server::{Handler, Server, ServerConfig};
use asynq::task::Task;
use console::Emoji;
use engine::execute::ClusterType;
use engine::results::MatchEvent;
use engine::slinger::http::Uri;
use engine::slinger::{Request, Response};
use log::{debug, error, info};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashSet};
use std::str::FromStr;
use std::sync::Arc;

/// Task queue name for receiving fingerprint identification tasks
pub const TASK_QUEUE: &str = "observer_ward:task";
/// Result queue name for sending identification results
pub const RESULT_QUEUE: &str = "observer_ward:result";

/// Input type for fingerprint identification task
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
#[allow(clippy::large_enum_variant)]
pub enum TaskInput {
  /// URI target(s) - will actively send request(s) for fingerprint identification
  /// Accepts a set of target strings so a single task can contain multiple targets.
  Uri {
    /// Target URIs to scan
    target: HashSet<String>,
  },
  /// Request and Response data - will directly match rules without sending requests (like MITM mode)
  /// Uses engine::slinger::{Request, Response} which already implement serde serialization
  HttpData {
    /// HTTP request data
    request: Request,
    /// HTTP response data
    response: Response,
  },
}

/// Fingerprint identification task payload
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FingerprintTask {
  /// Task ID for tracking
  #[serde(default = "default_task_id")]
  pub task_id: String,
  /// Task input (URI or HTTP data)
  pub input: TaskInput,
  /// Optional config overrides
  #[serde(default)]
  pub config: Option<ObserverWardConfig>,
}

fn default_task_id() -> String {
  uuid::Uuid::new_v4().to_string()
}

/// Fingerprint identification result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FingerprintResult {
  /// Task ID that produced this result
  pub task_id: String,
  /// Target that was scanned
  pub target: String,
  /// Matched fingerprint results
  pub matched: BTreeMap<String, MatchedResult>,
  /// Whether the scan was successful
  pub success: bool,
  /// Error message if scan failed
  #[serde(skip_serializing_if = "Option::is_none")]
  pub error: Option<String>,
}

/// Asynq client wrapper for sending results to the result queue
#[derive(Clone)]
pub struct AsynqClient {
  client: Arc<Client>,
}

impl AsynqClient {
  /// Create a new asynq client
  pub async fn new(redis_uri: &str) -> Result<Self, Box<dyn std::error::Error>> {
    let redis_config = RedisConnectionType::single(redis_uri)?;
    let client = Client::new(redis_config).await?;
    Ok(Self {
      client: Arc::new(client),
    })
  }

  /// Send fingerprint result to the result queue
  pub async fn send_result(&self, result: &FingerprintResult) -> AsynqResult<()> {
    let task = Task::new_with_json("fingerprint:result", result)?
      .with_queue(RESULT_QUEUE);
    self.client.enqueue(task).await?;
    debug!(
      "{}Sent result for task {} to queue",
      Emoji("📤", ""),
      result.task_id
    );
    Ok(())
  }

  /// Send all results from a scan to the result queue
  pub async fn send_all_results(
    &self,
    matched: &BTreeMap<String, MatchedResult>,
  ) -> Result<(), Box<dyn std::error::Error>> {
    if matched.is_empty() {
      return Ok(());
    }

    for (target, target_matched) in matched {
      let task_id = uuid::Uuid::new_v4().to_string();
      let mut result_matched = BTreeMap::new();
      result_matched.insert(target.clone(), target_matched.clone());

      let result = FingerprintResult {
        task_id,
        target: target.clone(),
        matched: result_matched,
        success: true,
        error: None,
      };

      let task = Task::new_with_json("fingerprint:result", &result)?
        .with_queue(RESULT_QUEUE);
      self.client.enqueue(task).await?;

      debug!(
        "{}Sent result for {} to queue",
        Emoji("📤", ""),
        target
      );
    }

    Ok(())
  }
}

/// Asynq task handler for fingerprint identification
pub struct FingerprintHandler {
  config: ObserverWardConfig,
  cluster_type: Arc<ClusterType>,
  client: Option<AsynqClient>,
  mode: AsynqMode,
}

impl FingerprintHandler {
  /// Create a new fingerprint handler
  pub fn new(
    config: ObserverWardConfig,
    cluster_type: ClusterType,
    client: Option<AsynqClient>,
    mode: AsynqMode,
  ) -> Self {
    Self {
      config,
      cluster_type: Arc::new(cluster_type),
      client,
      mode,
    }
  }

  /// Process URI target task
  async fn process_uri_target(&self, task: &FingerprintTask, target: &str) -> FingerprintResult {
    let task_config = task.config.as_ref().unwrap_or(&self.config);

    // Parse URI
    let uri = match Uri::from_str(target) {
      Ok(u) => u,
      Err(e) => {
        return FingerprintResult {
          task_id: task.task_id.clone(),
          target: target.to_string(),
          matched: BTreeMap::new(),
          success: false,
          error: Some(format!(
            "Invalid URI '{}': {}. Expected format: http(s)://host:port/path or host:port",
            target, e
          )),
        };
      }
    };

    // Run fingerprint identification
    let observer_ward = ObserverWard::new(task_config, (*self.cluster_type).clone());
    let result = observer_ward.run(uri).await;

    FingerprintResult {
      task_id: task.task_id.clone(),
      target: target.to_string(),
      matched: result.matched,
      success: true,
      error: None,
    }
  }

  /// Process HTTP data task (passive matching like MITM)
  /// Uses engine::slinger::{Request, Response} directly
  async fn process_http_data(
    &self,
    task: &FingerprintTask,
    request: &Request,
    response: &Response,
  ) -> FingerprintResult {
    // Clone response and insert request into extensions for matching
    let mut response = response.clone();
    response.extensions_mut().insert(request.clone());

    // Get target URI from request
    let target = request.uri().to_string();

    // Match against fingerprints (similar to MITM mode)
    let mut result = MatchEvent::new(&response);

    // Match against web_default clusters
    for cluster in self.cluster_type.web_default.iter() {
      cluster
        .operators
        .iter()
        .for_each(|operator| operator.matcher(&mut result, true));
    }
    // Match against web_other clusters
    for cluster in self.cluster_type.web_other.iter() {
      cluster
        .operators
        .iter()
        .for_each(|operator| operator.matcher(&mut result, true));
    }

    // Build result
    let mut matched_map = BTreeMap::new();
    if !result.matcher_result().is_empty() {
      let mut matched_result = MatchedResult::default();
      matched_result.update_matched(&result);
      matched_map.insert(target.clone(), matched_result);
    }

    FingerprintResult {
      task_id: task.task_id.clone(),
      target,
      matched: matched_map,
      success: true,
      error: None,
    }
  }
}

#[async_trait]
impl Handler for FingerprintHandler {
  async fn process_task(&self, task: Task) -> AsynqResult<()> {
    // Parse task payload
    let fingerprint_task: FingerprintTask = task.get_payload_with_json()?;
    debug!(
      "{}Processing task: {}",
      Emoji("📥", ""),
      fingerprint_task.task_id
    );

    // Process based on input type
    let result = match &fingerprint_task.input {
      TaskInput::Uri { target } => {
        // When multiple targets are provided, process them all and aggregate matched results.
        let mut aggregated = BTreeMap::new();
        for t in target.iter() {
          let r = self.process_uri_target(&fingerprint_task, t.as_str()).await;
          for (k, v) in r.matched {
            aggregated.insert(k, v);
          }
        }

        FingerprintResult {
          task_id: fingerprint_task.task_id.clone(),
          target: target.iter().cloned().collect::<Vec<_>>().join(","),
          matched: aggregated,
          success: true,
          error: None,
        }
      }
      TaskInput::HttpData { request, response } => {
        self.process_http_data(&fingerprint_task, request, response).await
      }
    };

    // Send result to result queue only in Both mode (where we both receive and send)
    // In ReceiveOnly mode, we only process tasks without sending results
    if matches!(self.mode, AsynqMode::Both)
      && let Some(client) = &self.client
        && let Err(e) = client.send_result(&result).await {
          error!("{}Failed to send result: {}", Emoji("💢", ""), e);
        }

    // Log result
    if result.success {
      info!(
        "{}Task {} completed, found {} fingerprints",
        Emoji("✅", ""),
        result.task_id,
        result.matched.values().map(|m| m.fingerprint().len()).sum::<usize>()
      );
    } else {
      error!(
        "{}Task {} failed: {}",
        Emoji("💢", ""),
        result.task_id,
        result.error.as_deref().unwrap_or("unknown error")
      );
    }

    Ok(())
  }
}

/// Start the asynq worker
pub async fn start_asynq_worker(
  redis_uri: &str,
  config: ObserverWardConfig,
  cluster_type: ClusterType,
  asynq_mode: AsynqMode,
) -> Result<(), Box<dyn std::error::Error>> {
  info!(
    "{}Starting asynq worker with mode: {}",
    Emoji("🚀", ""),
    asynq_mode
  );
  info!("{}Task queue: {}", Emoji("📋", ""), TASK_QUEUE);
  info!("{}Result queue: {}", Emoji("📤", ""), RESULT_QUEUE);

  let redis_config = RedisConnectionType::single(redis_uri)?;

  // Create asynq client based on mode
  let asynq_client = if matches!(asynq_mode, AsynqMode::Both) {
    Some(AsynqClient::new(redis_uri).await?)
  } else {
    None
  };

  // Create server config
  let server_config = ServerConfig::default()
    .concurrency(config.thread)
    .add_queue(TASK_QUEUE, 10)?;

  // Create handler
  let handler = FingerprintHandler::new(
    config,
    cluster_type,
    asynq_client,
    asynq_mode,
  );

  // Create and start server
  let mut server = Server::new(redis_config, server_config).await?;

  info!("{}Asynq worker started, waiting for tasks...", Emoji("🔄", ""));

  server.run(handler).await?;

  Ok(())
}
