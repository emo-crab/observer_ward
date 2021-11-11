extern crate prettytable;
extern crate reqwest;
extern crate term;
extern crate url;
use std::fs::File;
use std::io::{self, Read};
use std::process;

use cli::WardArgs;
use futures::stream::FuturesUnordered;
use futures::StreamExt;
use observer_ward::{
    download_file_from_github, get_plugins_by_nuclei, print_color, read_file_to_target,
    read_results_file, scan, strings_to_urls, update_self, WhatWebResult,
};
use prettytable::{color, Attr, Cell, Row, Table};

use crate::api::run_server;

mod api;
mod cli;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let config = WardArgs::new();
    let mut targets = vec![];
    if !config.server_host_port.is_empty() {
        run_server(config.server_host_port, config.daemon);
    }
    if config.stdin {
        let mut buffer = String::new();
        io::stdin().read_to_string(&mut buffer)?;
        targets.extend(strings_to_urls(buffer));
    } else if !config.target.is_empty() {
        targets.push(String::from(&config.target));
    } else if !config.file.is_empty() {
        targets.extend(read_file_to_target(&config.file));
    }
    if config.update_fingerprint {
        download_file_from_github(
            "https://0x727.github.io/FingerprintHub/web_fingerprint_v3.json",
            "web_fingerprint_v3.json",
        )
        .await;
        process::exit(0);
    }
    if config.update_self {
        update_self().await;
        process::exit(0);
    }
    if config.update_plugins {
        download_file_from_github(
            "https://github.com/0x727/FingerprintHub/releases/download/default/plugins.zip",
            "plugins.zip",
        )
        .await;
        process::exit(0);
    }
    if !targets.is_empty() {
        let mut worker = FuturesUnordered::new();
        let mut targets_iter = targets.iter();
        let mut results = vec![];
        for _ in 0..100 {
            match targets_iter.next() {
                Some(target) => worker.push(scan(target.to_string())),
                None => {
                    break;
                }
            }
        }
        while let Some(result) = worker.next().await {
            results.push(result);
            if let Some(target) = targets_iter.next() {
                worker.push(scan(target.to_string()));
            }
        }
        if results.len() < 2000 {
            results.sort_by(|a, b| b.priority.cmp(&a.priority));
        }
        print_results_and_save(config.json.clone(), config.csv.clone(), results, false);
    }
    if !config.plugins.is_empty() && (!config.csv.is_empty() || !config.json.is_empty()) {
        let wwr_results: Vec<WhatWebResult> = read_results_file();
        let mut worker = FuturesUnordered::new();
        let mut wwr_results_iter = wwr_results.iter();
        let mut plugins_results = vec![];
        for _ in 0..5 {
            match wwr_results_iter.next() {
                Some(wwr) => worker.push(get_plugins_by_nuclei(wwr)),
                None => {
                    break;
                }
            }
        }
        while let Some(result) = worker.next().await {
            plugins_results.push(result);
            if let Some(wwr) = wwr_results_iter.next() {
                worker.push(get_plugins_by_nuclei(wwr));
            }
        }
        print_results_and_save(
            config.json.clone(),
            config.csv.clone(),
            plugins_results,
            true,
        );
    }
    Ok(())
}

fn print_results_and_save(
    json: String,
    csv: String,
    results: Vec<WhatWebResult>,
    has_plugins: bool,
) {
    if !json.is_empty() {
        let out = File::create(&json).expect("Failed to create file");
        serde_json::to_writer(out, &results).expect("Failed to save file")
    }
    let mut table = Table::new();
    let mut headers = vec![
        Cell::new("Url"),
        Cell::new("Name"),
        Cell::new("Length"),
        Cell::new("Title"),
        Cell::new("Priority"),
    ];
    if has_plugins {
        headers.push(Cell::new("Plugins"))
    }
    table.set_titles(Row::new(headers.clone()));
    for res in &results {
        let wwn: Vec<String> = res.what_web_name.iter().map(String::from).collect();
        let mut rows = vec![
            Cell::new(&res.url.as_str()),
            Cell::new(&wwn.join("\n")).with_style(Attr::ForegroundColor(color::GREEN)),
            Cell::new(&res.length.to_string()),
            Cell::new(&textwrap::fill(res.title.as_str(), 40)),
            Cell::new(&res.priority.to_string()),
        ];
        if has_plugins {
            let wp: Vec<String> = res.plugins.iter().map(String::from).collect();
            rows.push(Cell::new(&wp.join("\n")).with_style(Attr::ForegroundColor(color::RED)))
        }
        table.add_row(Row::new(rows));
    }
    if !csv.is_empty() {
        let out = File::create(&csv).expect("Failed to create file");
        table.to_csv(out).expect("Failed to save file");
    }
    let mut table = Table::new();
    table.set_titles(Row::new(headers.clone()));
    for res in &results {
        if res.priority > 0 {
            let wwn: Vec<String> = res.what_web_name.iter().map(String::from).collect();
            let mut rows = vec![
                Cell::new(&res.url.as_str()),
                Cell::new(&wwn.join("\n")).with_style(Attr::ForegroundColor(color::GREEN)),
                Cell::new(&res.length.to_string()),
                Cell::new(&textwrap::fill(res.title.as_str(), 40)),
                Cell::new(&res.priority.to_string()),
            ];
            if has_plugins {
                let wp: Vec<String> = res.plugins.iter().map(String::from).collect();
                rows.push(Cell::new(&wp.join("\n")).with_style(Attr::ForegroundColor(color::RED)))
            }
            table.add_row(Row::new(rows));
        }
    }
    if table.len() > 0 {
        print_color(
            "Important technology:\n".to_string(),
            term::color::YELLOW,
            true,
        );
        table.printstd();
    }
}
