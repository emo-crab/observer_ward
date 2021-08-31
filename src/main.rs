extern crate base64;
extern crate reqwest;
extern crate url;
extern crate prettytable;

mod cli;
mod api;
mod benchmark;

use observer_ward::{scan, strings_to_urls, read_file_to_target, update_web_fingerprint};
use api::{api_server};
use cli::{WardArgs};
use std::process;
use std::io::{self, Read};
use std::thread;
use colored::Colorize;
use prettytable::{Table, Cell, Row, Attr, color};
use std::fs::File;
use futures::stream::FuturesUnordered;
use futures::StreamExt;
use benchmark::{Benchmark, NamedTimer};

#[macro_use]
extern crate log;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    env_logger::init();
    let config = WardArgs::new();
    let mut targets = vec![];
    if !config.server_host_port.is_empty() {
        let server_host_port: String = config.server_host_port;
        thread::spawn(|| {
            api_server(server_host_port).unwrap();
        }).join().expect("Thread panicked")
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
    if config.update {
        update_web_fingerprint().await;
        process::exit(0);
    }
    let mut benchmarks = Benchmark::init();
    let mut observer_ward_bench = NamedTimer::start("ObserverWard");
    if !targets.is_empty() {
        let mut worker = FuturesUnordered::new();
        let mut targets_iter = targets.iter();
        let mut results = vec![];
        for _ in 0..100 {
            match targets_iter.next() {
                Some(target) => {
                    worker.push(scan(target.to_string()))
                }
                None => { break; }
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
        table.set_titles(Row::new(vec![Cell::new("Url"), Cell::new("Name"), Cell::new("Length"), Cell::new("Title"), Cell::new("Priority")]));
        for res in &results {
            let wwn: Vec<String> = res.what_web_name.iter().map(String::from).collect();
            table.add_row(
                Row::new(vec![
                    Cell::new(&res.url.as_str()),
                    Cell::new(&wwn.join("\n")).with_style(Attr::ForegroundColor(color::GREEN)),
                    Cell::new(&res.length.to_string()),
                    Cell::new(&textwrap::fill(res.title.as_str(), 40)),
                    Cell::new(&res.priority.to_string()),
                ]));
        }
        if !config.csv.is_empty() {
            let out = File::create(config.csv)?;
            table.to_csv(out)?;
        }
        let mut table = Table::new();
        table.set_titles(Row::new(vec![Cell::new("Url"), Cell::new("Name"), Cell::new("Length"), Cell::new("Title"), Cell::new("Priority")]));
        for res in &results {
            if res.priority > 0 {
                let wwn: Vec<String> = res.what_web_name.iter().map(String::from).collect();
                table.add_row(
                    Row::new(vec![
                        Cell::new(&res.url.as_str()),
                        Cell::new(&wwn.join("\n")).with_style(Attr::ForegroundColor(color::GREEN)),
                        Cell::new(&res.length.to_string()),
                        Cell::new(&textwrap::fill(res.title.as_str(), 40)),
                        Cell::new(&res.priority.to_string()),
                    ]));
            }
        }
        if table.len() > 0 {
            println!("{}", "Important technology:".red());
            table.printstd();
        }
    }
    observer_ward_bench.end();
    benchmarks.push(observer_ward_bench);
    debug!("Benchmarks raw {:?}", benchmarks);
    info!("{}", benchmarks.summary());
    Ok(())
}