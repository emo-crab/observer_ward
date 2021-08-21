extern crate clap;

use serde::{Deserialize, Serialize};
use clap::{Arg, App};
use std::{process, env};
use colored::Colorize;

#[derive(Debug, Serialize, Deserialize)]
pub struct WardArgs {
    pub target: String,
    pub stdin: bool,
    pub file: String,
    pub update: bool,
    pub server_host_port: String,
    pub csv: String,
    pub json: String,
}

impl WardArgs {
    pub fn new() -> Self {
        let mut app = App::new("ObserverWard")
            .version("0.0.1")
            // .about("about: Community based web fingerprint analysis tool.")
            .author("author: Kali-Team")
            .arg(Arg::with_name("target")
                     .short("t")
                     .long("target")
                     .value_name("TARGET")
                     .help("The target URL(s) (required, unless --stdin used)"),
            )
            .arg(Arg::with_name("server")
                     .short("s")
                     .long("server")
                     .value_name("SERVER")
                     .help("Start a web API service (127.0.0.1:8080)"),
            )
            .arg(Arg::with_name("stdin")
                .long("stdin")
                .takes_value(false)
                .help("Read url(s) from STDIN")
                .conflicts_with("url")
            )
            .arg(Arg::with_name("file")
                .short("f")
                .long("file")
                .value_name("FILE")
                .help("Path to the file")
            )
            .arg(Arg::with_name("csv")
                .short("c")
                .long("csv")
                .value_name("CSV")
                .help("Export to the csv file")
            )
            .arg(Arg::with_name("json")
                .short("j")
                .long("json")
                .value_name("JSON")
                .help("Export to the json file")
            )
            .arg(Arg::with_name("update")
                .short("u")
                .long("update")
                .takes_value(false)
                .help("Update web fingerprint")
            );
        if env::args().len() == 1 {
            print_opening();
            app.print_long_help().unwrap();
            process::exit(0);
        }
        let args = app.get_matches();
        let mut stdin: bool = false;
        let mut update: bool = false;
        let mut target_url: String = String::new();
        let mut file_path: String = String::new();
        let mut csv_file_path: String = String::new();
        let mut json_file_path: String = String::new();
        let mut server_host_port: String = String::new();
        if args.is_present("stdin") {
            stdin = true;
        }
        if args.is_present("update") {
            update = true;
        }
        if let Some(target) = args.value_of("target") {
            target_url = target.to_string();
        };
        if let Some(server) = args.value_of("server") {
            server_host_port = server.to_string();
        };
        if let Some(file) = args.value_of("file") {
            file_path = file.to_string();
        };
        if let Some(file) = args.value_of("csv") {
            csv_file_path = file.to_string();
        };
        if let Some(file) = args.value_of("json") {
            json_file_path = file.to_string();
        };
        WardArgs { target: target_url, stdin, file: file_path, update, server_host_port, csv: csv_file_path, json: json_file_path }
    }
}

fn print_opening() {
    let s = r#" __     __     ______     ______     _____
/\ \  _ \ \   /\  __ \   /\  == \   /\  __-.
\ \ \/ ".\ \  \ \  __ \  \ \  __<   \ \ \/\ \
 \ \__/".~\_\  \ \_\ \_\  \ \_\ \_\  \ \____-
  \/_/   \/_/   \/_/\/_/   \/_/ /_/   \/____/
Community based web fingerprint analysis tool."#;
    println!("{}", s.green());
    let info = r#"______________________________________________
: https://github.com/0x727/FingerprintHub    :
: https://github.com/0x727/ObserverWard_0x727:
 ---------------------------------------------"#;
    println!("{}", info.yellow());
}