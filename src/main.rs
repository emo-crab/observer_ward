extern crate base64;
extern crate reqwest;
extern crate url;
extern crate prettytable;

pub mod cli;
pub mod api;

use futures::future::join_all;
use observer_ward::{scan, strings_to_urls, read_file_to_target, update_web_fingerprint};
use api::{api_server};
use cli::{WardArgs};
use std::process;
use std::io::{self, Read};
use std::thread;
use colored::Colorize;
use prettytable::{Table, Cell, Row, Attr, color};
use std::fs::File;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
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
    if !targets.is_empty() {
        let futures = targets.into_iter().map(scan).collect::<Vec<_>>();
        let results = join_all(futures).await;
        // results.sort_by(|a, b| b.priority.cmp(&a.priority));
        // 导出json
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
        // 导出CSV文件
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
            println!("{}", "\n高关注组件:\n".red());
            table.printstd();
        }
    }
    Ok(())
}