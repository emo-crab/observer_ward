#[cfg(not(target_os = "windows"))]
extern crate daemonize;

#[cfg(not(target_os = "windows"))]
use std::fs::File;
use std::net::SocketAddr;
use std::str::FromStr;
use std::thread;
use warp::Filter;
#[cfg(not(target_os = "windows"))]
use daemonize::Daemonize;
use crate::{Helper, ObserverWard, ObserverWardConfig, print_color};

async fn what_web_api(mut observer_ward_ins: ObserverWard, config: ObserverWardConfig) -> Result<impl warp::Reply, warp::Rejection> {
    observer_ward_ins.config = config.clone();
    let vec_results = observer_ward_ins.scan(config.targets).await;
    Ok(warp::reply::json(&vec_results))
}

async fn config_api(mut observer_ward_ins: ObserverWard, config: ObserverWardConfig) -> Result<impl warp::Reply, warp::Rejection> {
    let helper = Helper::new(&config);
    helper.run().await;
    observer_ward_ins.config = config.clone();
    Ok(warp::reply::json(&config))
}

fn observer_ward_config() -> impl Filter<Extract=(ObserverWardConfig, ), Error=warp::Rejection> + Clone {
    warp::body::content_length_limit(1024 * 16).and(warp::body::json())
}

#[tokio::main]
async fn api_server(listening_address: SocketAddr) {
    let config = ObserverWardConfig::new();
    let helper = Helper::new(&config);
    let web_fingerprint = helper.read_web_fingerprint(&config.verify);
    let mut nmap_fingerprint = vec![];
    if config.service {
        nmap_fingerprint = helper.read_nmap_fingerprint();
    }
    helper.run().await;
    let observer_ward_ins = ObserverWard::new(config.clone(), web_fingerprint, nmap_fingerprint);
    let observer_ward_filter = warp::any().map(move || observer_ward_ins.clone());
    let observer_ward_api = warp::post()
        .and(warp::path("v1"))
        .and(warp::path("observer_ward"))
        .and(warp::path::end())
        .and(observer_ward_filter.clone())
        .and(observer_ward_config())
        .and_then(what_web_api);
    let get_config_api = warp::post()
        .and(warp::path("v1"))
        .and(warp::path("config"))
        .and(warp::path::end())
        .and(observer_ward_filter.clone())
        .and(observer_ward_config())
        .and_then(config_api);
    warp::serve(observer_ward_api.or(get_config_api))
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
        }).join().expect("API service startup failed")
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
