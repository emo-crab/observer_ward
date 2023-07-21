use std::collections::HashSet;
use std::io::{self, Read};

use observer_ward::api::run_server;
use observer_ward::cli::ObserverWardConfig;
use observer_ward::error::Error;
use observer_ward::{
    print_opening, print_results_and_save, read_file_to_target, strings_to_urls, Helper,
    ObserverWard,
};

#[tokio::main]
async fn main() {
    match start().await {
        Ok(_) => {}
        Err(e) => println!("{}", e),
    }
}

async fn start() -> Result<(), Error> {
    let config = ObserverWardConfig::new();
    if !(config.stdin || config.silent) {
        print_opening();
    }
    if let Some(server) = &config.api_server {
        run_server(server);
    }
    let mut targets = HashSet::new();
    if config.stdin {
        let mut buffer = String::new();
        io::stdin().read_to_string(&mut buffer)?;
        targets.extend(strings_to_urls(buffer));
    }
    if let Some(target) = &config.target {
        targets.insert(String::from(target));
    }
    if let Some(file_path) = &config.file {
        targets.extend(read_file_to_target(file_path));
    }
    let mut helper = Helper::new(&config);
    let web_fingerprint = helper.read_web_fingerprint(&config);
    let mut nmap_fingerprint = vec![];
    if config.service {
        nmap_fingerprint = helper.read_nmap_fingerprint();
    }
    helper.run();
    let observer_ward_ins = ObserverWard::new(config.clone(), web_fingerprint, nmap_fingerprint);
    let vec_results = observer_ward_ins.scan(targets).await;
    print_results_and_save(vec_results, &config);
    Ok(())
}
