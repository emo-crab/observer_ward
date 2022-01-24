use crossbeam::channel::unbounded;
use futures::stream::FuturesUnordered;
use futures::StreamExt;
use std::collections::HashSet;
use std::io::{self, Read};

use observer_ward::cli::WardArgs;
use observer_ward::{
    print_nuclei, print_opening, print_results_and_save, print_what_web, read_file_to_target,
    read_nmap_fingerprint, webhook_results, Helper,
};
use observer_ward_what_server::WhatServer;
use observer_ward_what_web::fingerprint::read_form_file;
use observer_ward_what_web::{strings_to_urls, RequestOption, WhatWeb, WhatWebResult};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let config = WardArgs::new();
    if !config.stdin {
        print_opening();
    }
    let mut targets = HashSet::new();
    if config.stdin {
        let mut buffer = String::new();
        io::stdin().read_to_string(&mut buffer)?;
        targets.extend(strings_to_urls(buffer));
    } else if !config.target.is_empty() {
        targets.insert(String::from(&config.target));
    } else if !config.file.is_empty() {
        targets.extend(read_file_to_target(&config.file));
    }
    let request_option = RequestOption::new(&config.timeout, &config.proxy);
    let helper = Helper::new(&config);
    helper.run().await;
    let web_fingerprint = read_form_file(&config.verify);
    let mut nmap_fingerprint = vec![];
    if config.service {
        nmap_fingerprint = read_nmap_fingerprint();
    }
    let what_server_ins = WhatServer::new(300, nmap_fingerprint);
    let what_web_ins = WhatWeb::new(request_option.clone(), web_fingerprint);
    let (what_web_sender, what_web_receiver) = unbounded();
    let (what_server_sender, what_server_receiver) = unbounded();
    let (verify_sender, verify_receiver) = unbounded();
    let (results_sender, results_receiver) = unbounded();
    let mut vec_results: Vec<WhatWebResult> = vec![];
    let config_thread = config.thread.clone();
    let what_web_handle = tokio::task::spawn(async move {
        let mut worker = FuturesUnordered::new();
        let mut targets_iter = targets.iter();
        for _ in 0..config_thread {
            match targets_iter.next() {
                Some(target) => worker.push(what_web_ins.scan(target.to_string())),
                None => {
                    break;
                }
            }
        }
        while let Some(result) = worker.next().await {
            if let Some(target) = targets_iter.next() {
                worker.push(what_web_ins.scan(target.to_string()));
            }
            what_web_sender.send(result).unwrap_or_default();
        }
        return true;
    });
    let what_server_handle = tokio::task::spawn(async move {
        let mut worker = FuturesUnordered::new();
        for _ in 0..3 {
            match what_web_receiver.recv() {
                Ok(wwr) => worker.push(what_server_ins.scan(wwr)),
                Err(_) => {
                    break;
                }
            }
        }
        while let Some(wwr) = worker.next().await {
            if let Ok(v_wwr) = what_web_receiver.recv() {
                worker.push(what_server_ins.scan(v_wwr));
            }
            print_what_web(&wwr);
            what_server_sender.send(wwr).unwrap_or_default();
        }
        return true;
    });
    let plugins_path = config.plugins.clone();
    let verify_handle = tokio::task::spawn(async move {
        if !plugins_path.is_empty() {
            let mut worker = FuturesUnordered::new();
            for _ in 0..3 {
                match what_server_receiver.recv() {
                    Ok(wwr) => worker.push(helper.get_plugins_by_nuclei(wwr)),
                    Err(_) => {
                        break;
                    }
                }
            }
            while let Some(wwr) = worker.next().await {
                if let Ok(v_wwr) = what_server_receiver.recv() {
                    worker.push(helper.get_plugins_by_nuclei(v_wwr));
                }
                print_nuclei(&wwr);
                verify_sender.send(wwr).unwrap_or_default();
            }
        } else {
            while let Ok(wwr) = what_server_receiver.recv() {
                verify_sender.send(wwr).unwrap_or_default();
            }
        }
        return true;
    });
    let webhook = config.webhook;
    let results_handle = tokio::task::spawn(async move {
        let mut worker = FuturesUnordered::new();
        if !webhook.is_empty() {
            for _ in 0..3 {
                match verify_receiver.recv() {
                    Ok(wwr) => {
                        worker.push(webhook_results(wwr, &webhook));
                    }
                    Err(_) => {
                        break;
                    }
                }
            }
            while let Some(wwr) = worker.next().await {
                if let Ok(v_wwr) = verify_receiver.recv() {
                    worker.push(webhook_results(v_wwr, &webhook));
                }
                results_sender.send(wwr).unwrap_or_default();
            }
        }
        return true;
    });
    let (_r1, _r2, _r3, _r4) = tokio::join!(
        what_web_handle,
        what_server_handle,
        verify_handle,
        results_handle
    );
    let is_enable_plugin = !config.plugins.is_empty();
    while let Ok(wwr) = results_receiver.recv() {
        vec_results.push(wwr);
    }
    if vec_results.len() < 2000 {
        vec_results.sort_by(|a, b| b.priority.cmp(&a.priority));
    }
    print_results_and_save(&config.json, &config.csv, vec_results, is_enable_plugin);
    Ok(())
}
