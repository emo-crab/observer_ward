use std::net::SocketAddr;
use std::sync::mpsc::channel;
use std::sync::RwLock;
use std::thread;
use actix_web::{get, middleware, post, web, App, HttpResponse, HttpServer, Responder, rt};
use actix_web_httpauth::extractors::bearer::BearerAuth;
use console::{Emoji, style};
#[cfg(not(target_os = "windows"))]
use daemonize::Daemonize;
use log::{info};
use engine::execute::ClusterType;
use engine::slinger::openssl::ssl::{SslAcceptor, SslAcceptorBuilder, SslFiletype, SslMethod};
use crate::cli::ObserverWardConfig;
use crate::{cluster_templates, ClusterExecuteRunner, scan};
use crate::helper::Helper;
use crate::output::Output;

#[derive(Clone, Debug)]
struct TokenAuth {
  token: String,
}

fn validator(token_auth: web::Data<TokenAuth>, credentials: BearerAuth) -> bool {
  return token_auth.token.is_empty() || token_auth.token == credentials.token();
}

#[post("/v1/observer_ward")]
async fn what_web_api(
  token: web::Data<TokenAuth>,
  auth: BearerAuth,
  config: web::Json<ObserverWardConfig>,
  cl: web::Data<RwLock<Vec<ClusterType>>>,
) -> impl Responder {
  if !validator(token, auth) {
    return HttpResponse::Unauthorized().finish();
  }
  let webhook = config.webhook.is_some();
  if let Ok(cl) = cl.read() {
    let output = Output::new(&config);
    let (tx, rx) = channel();
    let cl = cl.clone();
    thread::spawn(move || {
      scan(&config, cl, tx);
    });
    if webhook {
      rx.iter().for_each(|r| {
        output.webhook_results(vec![r]);
      });
      HttpResponse::Ok().finish()
    } else {
      let results: Vec<ClusterExecuteRunner> = rx.iter().collect();
      HttpResponse::Ok().json(results)
    }
  } else {
    HttpResponse::InternalServerError().finish()
  }
}

#[post("/v1/config")]
async fn set_config_api(
  token: web::Data<TokenAuth>,
  auth: BearerAuth,
  config: web::Json<ObserverWardConfig>,
  cl: web::Data<RwLock<Vec<ClusterType>>>,
) -> impl Responder {
  if !validator(token, auth) {
    return HttpResponse::Unauthorized().finish();
  }
  let helper = Helper::new(&config);
  if config.update_fingerprint {
    helper.update_plugins();
  }
  if config.update_plugin {
    helper.update_plugins();
  }
  if let Ok(mut cl) = cl.write() {
    let templates = config.templates();
    info!("{}probes loaded: {}", Emoji("📇",""),style(templates.len().to_string()).blue());
    let new_cl = cluster_templates(&templates);
    info!("{}optimized probes: {}", Emoji("🚀",""),style(new_cl.len()).blue());
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

pub fn api_server(listening_address: SocketAddr, config: ObserverWardConfig) -> std::io::Result<()> {
  let templates = config.templates();
  info!("{}probes loaded: {}",Emoji("📇",""), style(templates.len()).blue());
  let cl = cluster_templates(&templates);
  info!("{}optimized probes: {}",Emoji("🚀",""), style(cl.len()).blue());
  let cluster_templates = web::Data::new(RwLock::new(cl));
  let web_config = web::Data::new(config.clone());
  let token_auth = web::Data::new(TokenAuth {
    token: config.token.clone(),
  });
  let mut s = format!("http://{}/v1/observer_ward", listening_address);
  let token = config.token.clone();
  let ssl = get_ssl_config(&config);
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
  let http_server = if let Ok(ssl_config) = ssl {
    s = s.replace("http://", "https://");
    http_server.bind_openssl(listening_address, ssl_config)?
  } else {
    http_server.bind(listening_address)?
  };
  print_help(&s, &token);
  rt::System::new().block_on(http_server.workers(32).run())
}

fn print_help(s: &str, t: &str) {
  info!("{}API service has been started:{}",Emoji("🌐",""), s);
  let api_doc = format!(
    r#"curl --request POST \
  --url {} \
  --header 'Authorization: Bearer {}' \
  --header 'Content-Type: application/json' \
  --data '{{"target":["https://httpbin.org/"],"or":true,"oc":true}}'"#,
    s, t
  );
  let result = r#"[result...]"#;
  info!("{}:",Emoji("📤",""));
  info!("{}:{}",Emoji("📔",""), style(api_doc).green());
  info!("{}:",Emoji("📥",""));
  info!("{}:{}",Emoji("🗳",""), style(result).green());
}

fn get_ssl_config(config: &ObserverWardConfig) -> Result<SslAcceptorBuilder, engine::slinger::openssl::error::ErrorStack> {
  let mut builder = SslAcceptor::mozilla_intermediate(SslMethod::tls())?;
  let key_path = config.config_dir.join("key.pem");
  let cert_path = config.config_dir.join("cert.pem");
  builder.set_private_key_file(key_path, SslFiletype::PEM)?;
  builder.set_certificate_chain_file(cert_path)?;
  Ok(builder)
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
    Ok(_) => println!("Success, daemonized"),
    Err(e) => eprintln!("Error, {}", e),
  }
}

#[cfg(target_os = "windows")]
pub fn background() {
  println!("Windows does not support background services");
}
