use crate::cli::{ObserverWardConfig, UnixSocketAddr};
use crate::helper::Helper;
use crate::output::Output;
use crate::{cluster_templates, MatchedResult, ObserverWard};
use actix_web::{get, middleware, post, rt, web, App, HttpResponse, HttpServer, Responder};
use actix_web_httpauth::extractors::bearer::BearerAuth;
use console::{style, Emoji};
#[cfg(not(target_os = "windows"))]
use daemonize::Daemonize;
use engine::execute::ClusterType;
use futures::channel::mpsc::unbounded;
use futures::StreamExt;
use log::{error, info};
use std::collections::BTreeMap;
use std::ops::Deref;
use std::sync::RwLock;

#[derive(Clone, Debug)]
struct TokenAuth {
  token: Option<String>,
}

fn validator(token_auth: web::Data<TokenAuth>, credentials: BearerAuth) -> bool {
  if let Some(token) = &token_auth.token {
    token == credentials.token()
  } else {
    true
  }
}

#[post("/v1/observer_ward")]
async fn what_web_api(
  token: web::Data<TokenAuth>,
  auth: BearerAuth,
  config: web::Json<ObserverWardConfig>,
  cli_config: web::Data<ObserverWardConfig>,
  cl: web::Data<RwLock<ClusterType>>,
) -> impl Responder {
  if !validator(token, auth) {
    return HttpResponse::Unauthorized().finish();
  }
  let mut config = config.clone();
  config.plugin = cli_config.plugin.clone();
  config.config_dir = cli_config.config_dir.clone();
  config.mode = cli_config.mode.clone();
  config.proxy = cli_config.proxy.clone();
  config.nuclei_args = cli_config.nuclei_args.clone();
  let webhook = config.webhook.is_some();
  let cl = {
    if let Ok(cl_guard) = cl.read() {
      cl_guard.deref().clone()
    } else {
      ClusterType::default()
    }
  };
  let output = Output::new(&config);
  let (tx, mut rx) = unbounded();
  tokio::task::spawn(async move {
    ObserverWard::new(&config, cl).execute(tx).await;
  });
  if webhook {
    // 异步识别任务，通过webhook返回结果
    rt::spawn(async move {
      while let Some(r) = rx.next().await {
        output.webhook_results(vec![r]).await;
      }
    });
    HttpResponse::Ok().finish()
  } else {
    let mut results: Vec<BTreeMap<String, MatchedResult>> = Vec::new();
    while let Some(result) = rx.next().await {
      results.push(result)
    }
    HttpResponse::Ok().json(results)
  }
}

#[post("/v1/config")]
async fn set_config_api(
  token: web::Data<TokenAuth>,
  auth: BearerAuth,
  config: web::Json<ObserverWardConfig>,
  cl: web::Data<RwLock<ClusterType>>,
) -> impl Responder {
  if !validator(token, auth) {
    return HttpResponse::Unauthorized().finish();
  }
  let helper = Helper::new(&config);
  if config.update_fingerprint {
    helper.update_fingerprint().await;
  }
  if config.update_plugin {
    helper.update_plugins().await;
  }
  if let Ok(mut cl) = cl.write() {
    let templates = config.templates();
    info!(
      "{}probes loaded: {}",
      Emoji("📇", ""),
      style(templates.len().to_string()).blue()
    );
    let new_cl = cluster_templates(&templates);
    info!(
      "{}optimized probes: {}",
      Emoji("🚀", ""),
      style(new_cl.count()).blue()
    );
    *cl = new_cl;
  }
  HttpResponse::Ok().json(config)
}

#[get("/v1/config")]
async fn get_config_api(
  token: web::Data<TokenAuth>,
  auth: BearerAuth,
  config: web::Data<ObserverWardConfig>,
) -> impl Responder {
  if !validator(token, auth) {
    return HttpResponse::Unauthorized().finish();
  }
  HttpResponse::Ok().json(config.clone())
}

pub async fn api_server(
  listening_address: &UnixSocketAddr,
  config: ObserverWardConfig,
) -> std::io::Result<()> {
  let templates = config.templates();
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
  let cluster_templates = web::Data::new(RwLock::new(cl));
  let web_config = web::Data::new(config.clone());
  let token_auth = web::Data::new(TokenAuth {
    token: config.token.clone(),
  });
  let token = config.token.clone();
  let http_server = HttpServer::new(move || {
    App::new()
      .wrap(middleware::Logger::default())
      .app_data(token_auth.clone())
      .app_data(web_config.clone())
      .app_data(web::JsonConfig::default().limit(40960))
      .app_data(cluster_templates.clone())
      .service(what_web_api)
      .service(get_config_api)
      .service(set_config_api)
  });
  let (http_server, url) = match &listening_address {
    #[cfg(unix)]
    UnixSocketAddr::Unix(u) => (
      http_server.bind_uds(u)?,
      "http://localhost/v1/observer_ward".to_string(),
    ),
    UnixSocketAddr::SocketAddr(sa) => (
      http_server.bind(sa)?,
      format!("http://{}/v1/observer_ward", listening_address),
    ),
  };
  print_help(&url, token, listening_address);
  http_server.workers(config.thread).run().await
}

fn print_help(url: &str, t: Option<String>, listening_address: &UnixSocketAddr) {
  let api_doc = match listening_address {
    #[cfg(unix)]
    UnixSocketAddr::Unix(p) => {
      info!(
        "{}API service has been started: {}",
        Emoji("🌐", ""),
        p.to_string_lossy()
      );
      format!(
        r#"curl --request POST \
--unix-socket {} \
--url {} \
--header 'Authorization: Bearer {}' \
--json '{{"target":["https://httpbin.org/"]}}'"#,
        listening_address,
        url,
        t.unwrap_or_default()
      )
    }
    UnixSocketAddr::SocketAddr(_) => {
      info!("{}API service has been started: {}", Emoji("🌐", ""), url);
      format!(
        r#"curl --request POST \
--url {} \
--header 'Authorization: Bearer {}' \
--json '{{"target":["https://httpbin.org/"]}}'"#,
        url,
        t.unwrap_or_default()
      )
    }
  };
  let result = r#"[result...]"#;
  info!("{}:{}", Emoji("📔", ""), style(api_doc).green());
  info!("{}:{}", Emoji("🗳", ""), style(result).green());
}

#[cfg(not(target_os = "windows"))]
pub fn background() {
  let stdout = std::fs::File::create("/tmp/observer_ward.out").unwrap();
  let stderr = std::fs::File::create("/tmp/observer_ward.err").unwrap();

  let daemonize = Daemonize::new()
    .pid_file("/tmp/observer_ward.pid") // Every method except `new` and `start`
    .chown_pid_file(false) // is optional, see `Daemonize` documentation
    .working_directory("/tmp") // for default behaviour.
    .user("nobody")
    .group("daemon") // Group name
    .umask(0o777) // Set umask, `0o027` by default.
    .stdout(stdout) // Redirect stdout to `/tmp/observer_ward.out`.
    .stderr(stderr) // Redirect stderr to `/tmp/observer_ward.err`.
    .privileged_action(|| "Executed before drop privileges");
  match daemonize.start() {
    Ok(_) => info!("{}Success, daemonized", Emoji("ℹ️", "")),
    Err(e) => error!("{}Error, {}", Emoji("💢", ""), e),
  }
}

#[cfg(target_os = "windows")]
pub fn background() {
  error!(
    "{}Windows does not support background services",
    Emoji("💢", "")
  );
}
