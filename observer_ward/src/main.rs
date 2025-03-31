use console::{style, Emoji};
use engine::template::cluster::cluster_templates;
use futures::channel::mpsc::unbounded;
use futures::StreamExt;
use log::{error, info, warn};
use observer_ward::api::api_server;
#[cfg(not(target_os = "windows"))]
use observer_ward::api::background;
use observer_ward::cli::ObserverWardConfig;
use observer_ward::helper::Helper;
use observer_ward::output::Output;
use observer_ward::ObserverWard;

#[tokio::main]
async fn main() {
  let config = ObserverWardConfig::default();
  if config.debug {
    std::env::set_var("RUST_LOG", "observer_ward=debug,actix_web=debug");
  } else if config.silent {
    std::env::set_var("RUST_LOG", "observer_ward=off,actix_web=off");
  } else {
    std::env::set_var("RUST_LOG", "observer_ward=info,actix_web=info");
  }
  if config.no_color {
    console::set_colors_enabled(false);
    std::env::set_var("RUST_LOG_STYLE", "never");
  }
  // 自定义日志输出
  env_logger::builder()
    .format_target(false)
    // .format_level(false)
    .format_timestamp(None)
    .init();
  if let Some(address) = &config.api_server {
    #[cfg(not(target_os = "windows"))]
    if config.daemon {
      background();
    }
    api_server(address, config.clone()).await
      .map_err(|err| error!("start api server err:{}", err))
      .unwrap_or_default();
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
  info!(
    "{}probes loaded: {}",
    Emoji("📇", ""),
    style(templates.len()).blue()
  );
  let cl = cluster_templates(&templates);
  info!(
    "{}optimized probes: {}",
    Emoji("🚀", ""),
    style(cl.count()).blue()
  );
  let (tx, mut rx) = unbounded();
  let output_config = config.clone();
  tokio::task::spawn(async move {
    ObserverWard::new(&config, cl).execute(tx).await;
  });
  let mut output = Output::new(&output_config);
  while let Some(result) = rx.next().await {
    output.save_and_print(result.clone());
    output.webhook_results(vec![result]).await;
  }
}
