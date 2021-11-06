extern crate prettytable;
extern crate reqwest;
extern crate url;

mod api;
mod cli;
mod nuclei;

use api::api_server;
use cli::WardArgs;
use colored::Colorize;
use futures::stream::FuturesUnordered;
use futures::StreamExt;
use observer_ward::{download_file_from_github, read_file_to_target, scan, strings_to_urls};
use prettytable::{color, Attr, Cell, Row, Table};
use std::fs::File;
use std::io::{self, Read};
use std::process;
use std::thread;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let config = WardArgs::new();
    let mut targets = vec![];
    if !config.server_host_port.is_empty() {
        let server_host_port: String = config.server_host_port;
        thread::spawn(|| {
            api_server(server_host_port).unwrap();
        })
        .join()
        .expect("Thread panicked")
    }
    if config.stdin {
        let mut buffer = String::new();
        io::stdin().read_to_string(&mut buffer)?;
        targets.extend(strings_to_urls(buffer));
    } else if !config.target.is_empty() {
        targets.push(String::from(config.target));
    } else if !config.file.is_empty() {
        targets.extend(read_file_to_target(config.file));
    }
    if config.update_fingerprint {
        download_file_from_github(
            "https://0x727.github.io/FingerprintHub/web_fingerprint_v3.json",
            "web_fingerprint_v3.json",
        )
        .await;
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
        if !config.json.is_empty() {
            serde_json::to_writer(&File::create(config.json)?, &results)?
        }
        let mut table = Table::new();
        table.set_titles(Row::new(vec![
            Cell::new("Url"),
            Cell::new("Name"),
            Cell::new("Length"),
            Cell::new("Title"),
            Cell::new("Priority"),
            Cell::new("Plugins"),
        ]));
        for res in &results {
            let wwn: Vec<String> = res.what_web_name.iter().map(String::from).collect();
            let wp: Vec<String> = res.plugins.iter().map(String::from).collect();
            table.add_row(Row::new(vec![
                Cell::new(&res.url.as_str()),
                Cell::new(&wwn.join("\n")).with_style(Attr::ForegroundColor(color::GREEN)),
                Cell::new(&res.length.to_string()),
                Cell::new(&textwrap::fill(res.title.as_str(), 40)),
                Cell::new(&res.priority.to_string()),
                Cell::new(&wp.join("\n")).with_style(Attr::ForegroundColor(color::GREEN)),
            ]));
        }
        if !config.csv.is_empty() {
            let out = File::create(config.csv)?;
            table.to_csv(out)?;
        }
        let mut table = Table::new();
        table.set_titles(Row::new(vec![
            Cell::new("Url"),
            Cell::new("Name"),
            Cell::new("Length"),
            Cell::new("Title"),
            Cell::new("Priority"),
            Cell::new("Plugins"),
        ]));
        for res in &results {
            if res.priority > 0 {
                let wwn: Vec<String> = res.what_web_name.iter().map(String::from).collect();
                let wp: Vec<String> = res.plugins.iter().map(String::from).collect();
                table.add_row(Row::new(vec![
                    Cell::new(&res.url.as_str()),
                    Cell::new(&wwn.join("\n")).with_style(Attr::ForegroundColor(color::GREEN)),
                    Cell::new(&res.length.to_string()),
                    Cell::new(&textwrap::fill(res.title.as_str(), 40)),
                    Cell::new(&res.priority.to_string()),
                    Cell::new(&wp.join("\n")).with_style(Attr::ForegroundColor(color::GREEN)),
                ]));
            }
        }
        if table.len() > 0 {
            println!("{}", "Important technology:".red());
            table.printstd();
        }
    }
    Ok(())
}
