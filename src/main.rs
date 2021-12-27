use std::collections::HashSet;
use std::fs::File;
use std::io::{self, Read};
use std::process;

use futures::stream::FuturesUnordered;
use futures::StreamExt;
use prettytable::{color, Attr, Cell, Row, Table};

use observer_ward::{print_color, print_nuclei, print_opening, print_what_web};
use observer_ward_target_input::ip_port::ip_cidr_to_host_port;
use observer_ward_what_web::cli::WardArgs;
use observer_ward_what_web::fingerprint::read_form_file;
use observer_ward_what_web::{read_file_to_target, strings_to_urls, WhatWeb, WhatWebResult};

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
    } else if !config.ip.is_empty() {
        targets.extend(ip_cidr_to_host_port(&config.ip).await);
    }
    let mut what_web_ins = WhatWeb::new(config.clone(), vec![]);
    if config.update_fingerprint {
        what_web_ins
            .download_file_from_github(
                "https://0x727.github.io/FingerprintHub/web_fingerprint_v3.json",
                "web_fingerprint_v3.json",
            )
            .await;
        process::exit(0);
    }
    if config.update_self {
        what_web_ins.update_self().await;
        process::exit(0);
    }
    if config.update_plugins {
        what_web_ins
            .download_file_from_github(
                "https://github.com/0x727/FingerprintHub/releases/download/default/plugins.zip",
                "plugins.zip",
            )
            .await;
        process::exit(0);
    }
    let web_fingerprint = read_form_file(&config.verify);
    what_web_ins = WhatWeb::new(config.clone(), web_fingerprint);
    if !targets.is_empty() {
        let mut worker = FuturesUnordered::new();
        let mut targets_iter = targets.iter();
        let mut results = vec![];
        for _ in 0..config.thread {
            match targets_iter.next() {
                Some(target) => worker.push(what_web_ins.scan(target.to_string())),
                None => {
                    break;
                }
            }
        }
        while let Some(result) = worker.next().await {
            if result.status_code != 0 {
                print_what_web(result.clone());
                results.push(result);
            }
            if let Some(target) = targets_iter.next() {
                worker.push(what_web_ins.scan(target.to_string()));
            }
        }
        if results.len() < 2000 {
            results.sort_by(|a, b| b.priority.cmp(&a.priority));
        }
        print_results_and_save(&config.json, &config.csv, results, false);
    }
    if !config.plugins.is_empty() && (!config.csv.is_empty() || !config.json.is_empty()) {
        let wwr_results: Vec<WhatWebResult> = what_web_ins.read_results_file();
        let mut worker = FuturesUnordered::new();
        let mut wwr_results_iter = wwr_results.iter();
        let mut plugins_results = vec![];
        for _ in 0..5 {
            match wwr_results_iter.next() {
                Some(wwr) => worker.push(what_web_ins.get_plugins_by_nuclei(wwr)),
                None => {
                    break;
                }
            }
        }
        while let Some(result) = worker.next().await {
            print_nuclei(result.clone());
            plugins_results.push(result);
            if let Some(wwr) = wwr_results_iter.next() {
                worker.push(what_web_ins.get_plugins_by_nuclei(wwr));
            }
        }
        print_results_and_save(&config.json, &config.csv, plugins_results, true);
    }
    Ok(())
}

fn print_results_and_save(
    json: &String,
    csv: &String,
    results: Vec<WhatWebResult>,
    has_plugins: bool,
) {
    if !json.is_empty() {
        let out = File::create(&json).expect("Failed to create file");
        serde_json::to_writer(out, &results).expect("Failed to save file")
    }
    let mut table = Table::new();
    let mut headers = vec![
        Cell::new("url"),
        Cell::new("name"),
        Cell::new("length"),
        Cell::new("status_code"),
        Cell::new("title"),
        Cell::new("priority"),
    ];
    if has_plugins {
        headers.push(Cell::new("plugins"))
    }
    table.set_titles(Row::new(headers.clone()));
    for res in &results {
        let wwn: Vec<String> = res.name.iter().map(String::from).collect();
        let status_code = reqwest::StatusCode::from_u16(res.status_code).unwrap_or_default();
        let mut status_code_color = Attr::ForegroundColor(color::RED);
        if status_code.is_success() {
            status_code_color = Attr::ForegroundColor(color::GREEN);
        }
        let mut rows = vec![
            Cell::new(&res.url.as_str()),
            Cell::new(&wwn.join("\n")).with_style(Attr::ForegroundColor(color::GREEN)),
            Cell::new(&res.length.to_string()),
            Cell::new(&res.status_code.to_string()).with_style(status_code_color),
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
        let wwn: Vec<String> = res.name.iter().map(String::from).collect();
        let status_code = reqwest::StatusCode::from_u16(res.status_code).unwrap_or_default();
        let mut status_code_color = Attr::ForegroundColor(color::RED);
        if status_code.is_success() {
            status_code_color = Attr::ForegroundColor(color::GREEN);
        }
        let mut rows = vec![
            Cell::new(&res.url.as_str()),
            Cell::new(&wwn.join("\n")).with_style(Attr::ForegroundColor(color::GREEN)),
            Cell::new(&res.length.to_string()),
            Cell::new(&res.status_code.to_string()).with_style(status_code_color),
            Cell::new(&textwrap::fill(res.title.as_str(), 40)),
            Cell::new(&res.priority.to_string()),
        ];
        if has_plugins {
            let wp: Vec<String> = res.plugins.iter().map(String::from).collect();
            rows.push(Cell::new(&wp.join("\n")).with_style(Attr::ForegroundColor(color::RED)))
        }
        table.add_row(Row::new(rows));
    }
    if table.len() > 0 {
        print_color(
            String::from("Important technology:\n"),
            term::color::YELLOW,
            true,
        );
        table.printstd();
    }
}
