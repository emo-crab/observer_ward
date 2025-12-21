use console::Emoji;
use engine::execute::ClusterType;
use engine::template::cluster::cluster_templates;
use futures::StreamExt;
use futures::channel::mpsc::unbounded;
use log::{error, info, warn};
use observer_ward::ExecuteResult;
use observer_ward::api::api_server;
#[cfg(not(target_os = "windows"))]
use observer_ward::api::background;
use observer_ward::cli::ObserverWardConfig;
use observer_ward::helper::Helper;
use observer_ward::output::Output;
use observer_ward::runner::ObserverWardRunner;
use tracing_subscriber::prelude::*;

#[cfg(feature = "asynq_task")]
use observer_ward::cli::AsynqMode;

#[tokio::main]
async fn main() {
  let config = ObserverWardConfig::default();
  if config.no_color {
    console::set_colors_enabled(false);
  }
  let log_filter = if config.debug {
    "observer_ward=debug,actix_web=debug"
  } else if config.silent {
    "observer_ward=off,actix_web=off"
  } else {
    "observer_ward=info,actix_web=info"
  };
  // 构建日志格式
  let fmt_layer = tracing_subscriber::fmt::layer()
    .with_target(false)
    .without_time()
    .with_ansi(!config.no_color);
  // 设置全局日志订阅器
  tracing_subscriber::registry()
    .with(tracing_subscriber::EnvFilter::new(log_filter))
    .with(fmt_layer)
    .init();

  // Check for asynq SendOnly mode first to create client for API server
  #[cfg(feature = "asynq_task")]
  let asynq_client = if let Some(redis_uri) = &config.asynq_redis {
    let asynq_mode = config.asynq_mode.clone().unwrap_or_default();
    if matches!(asynq_mode, AsynqMode::Send) {
      match observer_ward::worker::AsynqClient::new(redis_uri).await {
        Ok(client) => {
          info!(
            "{}Asynq SendOnly mode enabled, results will be sent to queue",
            Emoji("📤", "")
          );
          Some(client)
        }
        Err(e) => {
          error!(
            "{}Failed to initialize asynq client: {}",
            Emoji("💢", ""),
            e
          );
          std::process::exit(1);
        }
      }
    } else {
      None
    }
  } else {
    None
  };

  if let Some(address) = &config.api_server {
    #[cfg(not(target_os = "windows"))]
    if config.daemon {
      background();
    }
    #[cfg(feature = "asynq_task")]
    {
      api_server(address, config.clone(), asynq_client)
        .await
        .map_err(|err| error!("start api server err:{err}"))
        .unwrap_or_default();
    }
    #[cfg(not(feature = "asynq_task"))]
    {
      api_server(address, config.clone())
        .await
        .map_err(|err| error!("start api server err:{err}"))
        .unwrap_or_default();
    }
    std::process::exit(0);
  }
  let helper = Helper::new(&config);
  helper.run().await;
  let mut templates = config.templates();
  if templates.is_empty() {
    warn!(
      "{}unable to find fingerprint, automatically update fingerprint",
      Emoji("⚠️", "")
    );
    helper.update_fingerprint().await;
    templates = config.templates();
  }
  info!("{}probes loaded: {}", Emoji("📇", ""), templates.len());
  let cl = cluster_templates(&templates);
  info!("{}optimized probes: {}", Emoji("🚀", ""), cl.count());

  // Check for asynq mode
  #[cfg(feature = "asynq_task")]
  if let Some(redis_uri) = &config.asynq_redis {
    let asynq_mode = config.asynq_mode.clone().unwrap_or_default();

    match &asynq_mode {
      AsynqMode::Send => {
        // Continue with normal CLI processing, asynq_client already created
      }
      AsynqMode::Receive | AsynqMode::Both => {
        // Start asynq worker
        #[cfg(not(target_os = "windows"))]
        if config.daemon {
          background();
        }
        if let Err(e) =
          observer_ward::worker::start_asynq_worker(redis_uri, config.clone(), cl, asynq_mode).await
        {
          error!("{}Failed to start asynq worker: {}", Emoji("💢", ""), e);
          std::process::exit(1);
        }
        std::process::exit(0);
      }
    }
  }

  #[cfg(feature = "mitm")]
  if let Some(address) = &config.mitm {
    #[cfg(not(target_os = "windows"))]
    if config.daemon {
      background();
    }
    let (tx, mut rx) = unbounded::<ExecuteResult>();
    let output_config = config.clone();
    tokio::task::spawn(async move {
      let mut output = Output::new(&output_config);
      while let Some(execute_result) = rx.next().await {
        output.save_and_print(&execute_result.matched);
        output.webhook_results(vec![execute_result.matched]).await;
      }
    });
    observer_ward::mitm::mitm_proxy_server(address, config.clone(), cl, tx)
      .await
      .map_err(|err| error!("start mitm proxy server err:{err}"))
      .unwrap_or_default();
    std::process::exit(0);
  }

  if config.mcp {
    mcp(config, cl).await
  } else {
    // Create runner with unified interface
    #[cfg(feature = "asynq_task")]
    let runner = ObserverWardRunner::new(config, cl, asynq_client);
    #[cfg(not(feature = "asynq_task"))]
    let runner = ObserverWardRunner::new(config, cl);

    runner.run_cli().await;
  }
}

#[cfg(not(feature = "mcp"))]
async fn mcp(_config: ObserverWardConfig, _cl: ClusterType) {
  warn!("MCP feature not enabled")
}

#[cfg(feature = "mcp")]
async fn mcp(config: ObserverWardConfig, cl: ClusterType) {
  use observer_ward::mcp::ObserverWardHandler;
  use rmcp::ServiceExt;
  use rmcp::transport::stdio;
  // Create ObserverWard handler
  let handler = ObserverWardHandler::new(config, cl);
  info!("Starting ObserverWard MCP Server...");
  // Start server
  let service = handler.serve(stdio()).await.inspect_err(|e| {
    error!("{}Server startup failed: {:?}", Emoji("💢", ""), e);
  });
  match service {
    Ok(service) => {
      if let Err(err) = service.waiting().await {
        error!("{}Server waiting failed: {:?}", Emoji("💢", ""), err);
      };
    }
    Err(err) => {
      error!("{}Server startup failed: {:?}", Emoji("💢", ""), err);
    }
  }
}
