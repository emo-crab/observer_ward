#[cfg(not(target_os = "windows"))]
extern crate daemonize;

use crate::{print_color, Helper, ObserverWard, ObserverWardConfig};
#[cfg(not(target_os = "windows"))]
use daemonize::Daemonize;
use lazy_static::lazy_static;
use std::collections::{HashMap, HashSet};
#[cfg(not(target_os = "windows"))]
use std::fs::File;
use std::net::SocketAddr;
use std::str::FromStr;
use std::sync::Arc;
use std::thread;
use tokio::sync::RwLock;
use warp::Filter;
lazy_static! {
    static ref OBSERVER_WARD_INS: Arc<RwLock<ObserverWard>> = {
        let config = ObserverWardConfig::new();
        let mut helper = Helper::new(&config);
        let web_fingerprint = helper.read_web_fingerprint(&config.verify);
        let mut nmap_fingerprint = vec![];
        if config.service {
            nmap_fingerprint = helper.read_nmap_fingerprint();
        }
        let observer_ward_ins =
            ObserverWard::new(config.clone(), web_fingerprint, nmap_fingerprint);
        return Arc::new(RwLock::new(observer_ward_ins));
    };
}
async fn what_web_api(token: String, config: ObserverWardConfig) -> Result<impl warp::Reply, warp::Rejection> {
    let token_key = format!("Bearer {}", OBSERVER_WARD_INS.read().await.config.token);
    if !token_key.is_empty() {
        if token != token_key {
            let mut m: HashMap<String, String> = HashMap::new();
            m.insert(String::from("err"), String::from("UNAUTHORIZED"));
            return Ok(warp::reply::json(&m));
        }
    }
    let vec_results = OBSERVER_WARD_INS.read().await.scan(config.targets).await;
    return Ok(warp::reply::json(&vec_results));
}

async fn set_config_api(token: String, mut config: ObserverWardConfig) -> Result<impl warp::Reply, warp::Rejection> {
    let token_key = format!("Bearer {}", OBSERVER_WARD_INS.read().await.config.token);
    if !token_key.is_empty() {
        if token != token_key {
            let mut m: HashMap<String, String> = HashMap::new();
            m.insert(String::from("err"), String::from("UNAUTHORIZED"));
            return Ok(warp::reply::json(&m));
        }
    }
    let mut helper = Helper::new(&config);
    let msg = helper.run().await;
    helper.msg = HashMap::new();
    config.targets = HashSet::new();
    OBSERVER_WARD_INS.write().await.reload(&config);
    if msg.is_empty() {
        let msg = OBSERVER_WARD_INS.read().await.config.clone();
        return Ok(warp::reply::json(&msg));
    }
    return Ok(warp::reply::json(&msg));
}

async fn get_config_api(token: String) -> Result<impl warp::Reply, warp::Rejection> {
    let token_key = format!("Bearer {}", OBSERVER_WARD_INS.read().await.config.token);
    if !token_key.is_empty() {
        if token != token_key {
            let mut m: HashMap<String, String> = HashMap::new();
            m.insert(String::from("err"), String::from("UNAUTHORIZED"));
            return Ok(warp::reply::json(&m));
        }
    }
    let config = OBSERVER_WARD_INS.read().await.config.clone();
    return Ok(warp::reply::json(&config));
}

fn observer_ward_config() -> impl Filter<Extract=(ObserverWardConfig, ), Error=warp::Rejection> + Clone {
    warp::body::content_length_limit(1024 * 16).and(warp::body::json())
}

#[tokio::main]
async fn api_server(listening_address: SocketAddr) {
    let observer_ward_api_router = warp::post()
        .and(warp::path("v1"))
        .and(warp::path("observer_ward"))
        .and(warp::path::end())
        .and(warp::header::<String>("Authorization"))
        .and(observer_ward_config())
        .and_then(what_web_api);
    let set_config_api_router = warp::post()
        .and(warp::path("v1"))
        .and(warp::path("config"))
        .and(warp::path::end())
        .and(warp::header::<String>("Authorization"))
        .and(observer_ward_config())
        .and_then(set_config_api);
    let get_config_api_router = warp::get()
        .and(warp::path("v1"))
        .and(warp::path("config"))
        .and(warp::path::end())
        .and(warp::header::<String>("Authorization"))
        .and_then(get_config_api);
    warp::serve(
        observer_ward_api_router
            .or(get_config_api_router)
            .or(set_config_api_router),
    )
        .run(listening_address)
        .await;
}

pub fn run_server(listening_address: &String, is_daemon: bool) {
    let s = format!("http://{}/v1/observer_ward", listening_address);
    println!("API service has been started:{}", s.clone());
    let api_doc = format!(
        r#"curl --request POST \
  --url {} \
  --header 'Content-Type: application/json' \
  --data '{{"targets":["https://httpbin.org/"]}}'"#,
        s
    );
    let result = r#"[{"url":"http://httpbin.org/","name":["swagger"],"priority":5,"length":9593,"title":"httpbin.org","status_code":200,"is_web":true,"plugins":[]}]"#;
    print!("Request:\n");
    print_color(api_doc, term::color::BRIGHT_GREEN, true);
    println!("Response:");
    print_color(result.to_string(), term::color::GREEN, true);
    if is_daemon {
        background();
    }
    if let Ok(address) = std::net::SocketAddr::from_str(&listening_address) {
        thread::spawn(move || {
            api_server(address);
        })
            .join()
            .expect("API service startup failed")
    } else {
        println!("Invalid listening address");
    }
}

#[cfg(not(target_os = "windows"))]
fn background() {
    let stdout = File::create("/tmp/observer_ward.out").unwrap();
    let stderr = File::create("/tmp/observer_ward.err").unwrap();

    let daemonize = Daemonize::new()
        .pid_file("/tmp/observer_ward.pid") // Every method except `new` and `start`
        .chown_pid_file(false) // is optional, see `Daemonize` documentation
        .working_directory("/tmp") // for default behaviour.
        .user("nobody")
        .group("daemon") // Group name
        .umask(0o777) // Set umask, `0o027` by default.
        .stdout(stdout) // Redirect stdout to `/tmp/observer_ward.out`.
        .stderr(stderr) // Redirect stderr to `/tmp/observer_ward.err`.
        .exit_action(|| println!("Executed before master process exits"))
        .privileged_action(|| "Executed before drop privileges");
    match daemonize.start() {
        Ok(_) => println!("Success, daemonized"),
        Err(e) => eprintln!("Error, {}", e),
    }
}

#[cfg(target_os = "windows")]
fn background() {
    print_color(
        "Windows does not support background services".to_string(),
        term::color::GREEN,
        true,
    );
}
