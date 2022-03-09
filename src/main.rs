use futures::channel::mpsc::unbounded;
use futures::stream::FuturesUnordered;
use futures::StreamExt;
use std::collections::HashSet;
use std::io::{self, Read};

use observer_ward::cli::WardArgs;
use observer_ward::{
    print_nuclei, print_opening, print_results_and_save, print_what_web, read_file_to_target,
    webhook_results, Helper,
};
use observer_ward_what_server::WhatServer;
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
    let web_fingerprint = helper.read_web_fingerprint(&config.verify);
    let mut nmap_fingerprint = vec![];
    if config.service {
        nmap_fingerprint = helper.read_nmap_fingerprint();
    }
    let what_server_ins = WhatServer::new(300, nmap_fingerprint);
    let what_web_ins = WhatWeb::new(request_option.clone(), web_fingerprint);
    let (what_web_sender, mut what_web_receiver) = unbounded();
    let (mut what_server_sender, mut what_server_receiver) = unbounded();
    let (mut verify_sender, mut verify_receiver) = unbounded();
    let (mut results_sender, mut results_receiver) = unbounded();
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
            what_web_sender.unbounded_send(result).unwrap_or_default();
        }
        return true;
    });
    let what_server_handle = tokio::task::spawn(async move {
        let mut worker = FuturesUnordered::new();
        for _ in 0..3 {
            match what_web_receiver.next().await {
                Some(w) => worker.push(what_server_ins.scan(w)),
                None => {
                    break;
                }
            }
        }
        while let Some(wwr) = worker.next().await {
            if let Some(v_wwr) = what_web_receiver.next().await {
                worker.push(what_server_ins.scan(v_wwr));
            }
            print_what_web(&wwr);
            what_server_sender.start_send(wwr).unwrap_or_default();
        }
        return true;
    });
    let plugins_path = config.plugins.clone();
    let verify_handle = tokio::task::spawn(async move {
        if !plugins_path.is_empty() {
            let mut worker = FuturesUnordered::new();
            for _ in 0..3 {
                match what_server_receiver.next().await {
                    Some(w) => {
                        worker.push(helper.get_plugins_by_nuclei(w));
                    }
                    None => {
                        break;
                    }
                }
            }
            while let Some(wwr) = worker.next().await {
                if let Some(v_wwr) = what_server_receiver.next().await {
                    worker.push(helper.get_plugins_by_nuclei(v_wwr));
                }
                print_nuclei(&wwr);
                verify_sender.start_send(wwr).unwrap_or_default();
            }
        } else {
            while let Some(wwr) = what_server_receiver.next().await {
                verify_sender.start_send(wwr).unwrap_or_default();
            }
        }
        return true;
    });
    let webhook = config.webhook;
    let results_handle = tokio::task::spawn(async move {
        let mut worker = FuturesUnordered::new();
        if !webhook.is_empty() {
            for _ in 0..3 {
                match verify_receiver.next().await {
                    Some(w) => {
                        worker.push(webhook_results(w, &webhook));
                    }
                    None => {
                        break;
                    }
                }
            }
            while let Some(wwr) = worker.next().await {
                if let Some(w) = verify_receiver.next().await {
                    worker.push(webhook_results(w, &webhook));
                }
                results_sender.start_send(wwr).unwrap_or_default();
            }
        } else {
            while let Some(wwr) = verify_receiver.next().await {
                results_sender.start_send(wwr).unwrap_or_default();
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
    while let Some(wwr) = results_receiver.next().await {
        vec_results.push(wwr);
    }
    if vec_results.len() < 2000 {
        vec_results.sort_by(|a, b| b.priority.cmp(&a.priority));
    }
    print_results_and_save(&config.json, &config.csv, vec_results, is_enable_plugin);
    Ok(())
}
