#[macro_use]
extern crate lazy_static;

use std::collections::HashSet;
use std::env;
use std::fmt;
use std::fs::File;
use std::io::{self, BufRead, Read};
use std::io::Cursor;
use std::iter::FromIterator;
use std::marker::PhantomData;
use std::path::{Path, PathBuf};
use std::str;
use std::sync::RwLock;

use csv::{DeserializeRecordsIntoIter, Reader};
use serde::{de, Deserialize, Deserializer, Serialize};
use tokio::process::Command;

use cli::WardArgs;
use fingerprint::{WebFingerPrintLib, WebFingerPrintRequest};
use request::{get_title, index_fetch};
use ward::check;

mod cli;
pub mod fingerprint;
mod request;
mod ward;

lazy_static! {
    static ref CONFIG: WardArgs = {
        let config = WardArgs::new();
        config
    };
}
// 加载指纹库到常量，防止在文件系统反复加载
lazy_static! {
    static ref WEB_FINGERPRINT_LIB_DATA: RwLock<WebFingerPrintLib> = RwLock::new({
        let mut web_fingerprint_lib = WebFingerPrintLib::new();
        web_fingerprint_lib.init();
        web_fingerprint_lib
    });
}

#[derive(Debug, Serialize, Deserialize)]
pub struct WhatWebResult {
    pub url: String,
    pub what_web_name: HashSet<String>,
    pub priority: u32,
    pub length: usize,
    pub title: String,
    pub plugins: HashSet<String>,
}

impl WhatWebResult {
    pub fn new(url: String) -> Self {
        Self {
            url,
            what_web_name: HashSet::new(),
            priority: 0,
            length: 0,
            title: String::new(),
            plugins: HashSet::new(),
        }
    }
}

pub async fn scan(url: String) -> WhatWebResult {
    let mut what_web_name: HashSet<String> = HashSet::new();
    let mut what_web_result: WhatWebResult = WhatWebResult::new(url.clone());
    let default_request = WebFingerPrintRequest {
        path: "/".to_string(),
        request_method: "get".to_string(),
        request_headers: Default::default(),
        request_data: "".to_string(),
    };
    if let Ok(raw_data_list) = index_fetch(&url, &default_request, true, false).await {
        //首页请求允许跳转
        for raw_data in raw_data_list {
            let web_name_set = check(
                &raw_data,
                &WEB_FINGERPRINT_LIB_DATA.read().unwrap().to_owned(),
                false,
            )
                .await;
            for (k, v) in web_name_set {
                what_web_name.insert(k);
                what_web_result.priority = v;
            }
            what_web_result.url = String::from(raw_data.url.clone());
            if what_web_result.title.is_empty() {
                what_web_result.title = get_title(&raw_data);
                what_web_result.priority = what_web_result.priority + 1;
            }
            what_web_result.length = raw_data.text.len();
        }
    };
    for special_wfp in WEB_FINGERPRINT_LIB_DATA
        .read()
        .unwrap()
        .to_owned()
        .special
        .iter()
    {
        if let Ok(raw_data_list) = index_fetch(&url, &special_wfp.request, false, true).await {
            for raw_data in raw_data_list {
                let web_name_set = check(
                    &raw_data,
                    &WEB_FINGERPRINT_LIB_DATA.read().unwrap().to_owned(),
                    true,
                )
                    .await;
                for (k, v) in web_name_set {
                    what_web_name.insert(k);
                    what_web_result.priority = v;
                }
            }
        }
    }
    if what_web_name.len() > 5 {
        let count = what_web_name.len();
        what_web_name.clear();
        what_web_name.insert(format!("Honeypot 蜜罐{}", count));
    }
    what_web_result.what_web_name = what_web_name.clone();
    let color_web_name: Vec<String> = what_web_name.iter().map(String::from).collect();
    if !what_web_name.is_empty() {
        print!("[ {} |", what_web_result.url);
        print_color(format!("{:?}", color_web_name), false);
        println!(" | {} | {} ]", what_web_result.length,
                 what_web_result.title);
    } else {
        println!(
            "[ {} | {:?} | {} | {} ]",
            what_web_result.url, color_web_name, what_web_result.length, what_web_result.title,
        );
    }
    what_web_result
}

// 去重
pub fn strings_to_urls(domains: String) -> HashSet<String> {
    let target_list: Vec<String> = domains
        .split_terminator('\n')
        .map(|s| s.to_string())
        .collect();
    HashSet::from_iter(target_list)
}

pub fn read_file_to_target(file_path: &String) -> HashSet<String> {
    if let Ok(lines) = read_lines(file_path) {
        let target_list: Vec<String> = lines.filter_map(Result::ok).collect();
        return HashSet::from_iter(target_list);
    }
    return HashSet::from_iter([]);
}

fn read_lines<P>(filename: P) -> io::Result<io::Lines<io::BufReader<File>>>
    where
        P: AsRef<Path>,
{
    let file = File::open(filename)?;
    Ok(io::BufReader::new(file).lines())
}

pub async fn download_file_from_github(update_url: &str, filename: &str) {
    match reqwest::get(update_url).await {
        Ok(response) => {
            let self_path: PathBuf = env::current_exe().unwrap_or(PathBuf::new());
            let path = Path::new(&self_path).parent().unwrap_or(Path::new(""));
            let mut file = std::fs::File::create(path.join(filename)).unwrap();
            let mut content = Cursor::new(response.bytes().await.unwrap());
            std::io::copy(&mut content, &mut file).unwrap();
            println!(
                "Complete {} update: {} file size => {:?}",
                filename,
                filename,
                file.metadata().unwrap().len()
            );
        }
        Err(_) => {
            println!(
                "Update failed, please download {} to local directory manually.",
                update_url
            );
        }
    };
}

pub async fn update_self() {
    let mut base_url = String::from("https://github.com/0x727/ObserverWard_0x727/releases/download/default/");
    if cfg!(target_os = "windows") {
        base_url.push_str("observer_ward.exe");
        download_file_from_github(
            &base_url,
            "update_observer_ward.exe",
        ).await;
    } else if cfg!(target_os = "linux") {
        base_url.push_str("observer_ward_amd64");
        download_file_from_github(
            &base_url,
            "update_observer_ward_amd64",
        ).await;
    } else if cfg!(target_os = "macos") {
        base_url.push_str("observer_ward_darwin");
        download_file_from_github(
            &base_url,
            "update_observer_ward_darwin",
        ).await;
    };
    println!("Please rename the file starting with update");
}

#[derive(Debug, Serialize, Deserialize, Eq, PartialEq)]
pub struct RowWhatWebResult {
    #[serde(rename = "Url")]
    pub url: String,
    #[serde(rename = "Name")]
    #[serde(deserialize_with = "string_to_hashset")]
    pub what_web_name: HashSet<String>,
    #[serde(rename = "Priority")]
    pub priority: u32,
    #[serde(rename = "Length")]
    pub length: usize,
    #[serde(rename = "Title")]
    pub title: String,
    #[serde(rename = "Plugins")]
    #[serde(default)]
    pub plugins: HashSet<String>,
}

pub fn read_results_file() -> Vec<WhatWebResult> {
    let mut results: Vec<WhatWebResult> = Vec::new();
    let read_file_data = |path: &String| {
        let mut file = match File::open(path) {
            Err(err) => {
                println!("{}", err.to_string());
                std::process::exit(0);
            }
            Ok(file) => file,
        };
        let mut data = String::new();
        file.read_to_string(&mut data).unwrap();
        data
    };
    if !CONFIG.json.is_empty() {
        let data = read_file_data(&CONFIG.json);
        let wwr: Vec<WhatWebResult> = serde_json::from_str(&data).expect("BAD JSON");
        results.extend(wwr);
    }
    if !CONFIG.csv.is_empty() {
        let rdr = Reader::from_path(&CONFIG.csv).expect("BAD CSV");
        let iter: DeserializeRecordsIntoIter<File, RowWhatWebResult> = rdr.into_deserialize();
        let wwr: Vec<WhatWebResult> = iter
            .filter_map(Result::ok)
            .map(|w| WhatWebResult {
                url: w.url,
                what_web_name: w.what_web_name,
                priority: w.priority,
                length: w.length,
                title: w.title,
                plugins: w.plugins,
            })
            .collect();
        results.extend(wwr);
    }
    results
}

#[derive(Debug, Serialize, Deserialize, Clone)]
struct Template {
    #[serde(rename = "template-id")]
    pub template_id: String,
}

pub async fn get_plugins_by_nuclei(w: &WhatWebResult) -> WhatWebResult {
    let mut wwr = WhatWebResult {
        url: w.url.clone(),
        what_web_name: w.what_web_name.clone(),
        priority: w.priority.clone(),
        length: w.length.clone(),
        title: w.title.clone(),
        plugins: w.plugins.clone(),
    };
    let mut plugins_set: HashSet<String> = HashSet::new();
    let mut exist_plugins: Vec<String> = Vec::new();
    for name in wwr.what_web_name.iter() {
        let plugins_name_path = Path::new(&CONFIG.plugins).join(name);
        if plugins_name_path.exists() {
            if let Some(p_path) = plugins_name_path.to_str() {
                exist_plugins.push(p_path.to_string())
            }
        }
    }
    if exist_plugins.is_empty() {
        return wwr;
    }
    let mut command_line = Command::new("nuclei");
    command_line.args([
        "-u",
        &wwr.url,
        "-no-color",
        "-timeout",
        &(CONFIG.timeout + 5).to_string(),
    ]);
    command_line.args([
        "-H",
        "Mozilla/5.0 (X11; Linux x86_64; rv:94.0) Gecko/20100101 Firefox/94.0",
    ]);
    for p in exist_plugins.iter() {
        command_line.args(["-t", p]);
    }
    command_line.args(["-silent", "-json"]);
    let output = command_line.output().await.unwrap();
    if let Ok(template_output) = String::from_utf8(output.stdout) {
        let templates_output: Vec<String> = template_output
            .split_terminator('\n')
            .map(|s| s.to_string())
            .collect();
        for line in templates_output.iter() {
            let template: Template = serde_json::from_str(&line).unwrap();
            plugins_set.insert(template.template_id);
        }
    }
    wwr.plugins = plugins_set;
    if !wwr.plugins.is_empty() {
        wwr.priority = wwr.priority + 1;
    }
    return wwr;
}

fn string_to_hashset<'de, D>(deserializer: D) -> Result<HashSet<String>, D::Error>
    where
        D: Deserializer<'de>,
{
    struct StringOrVec(PhantomData<HashSet<String>>);
    impl<'de> de::Visitor<'de> for StringOrVec {
        type Value = HashSet<String>;
        fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
            formatter.write_str("string or list of strings")
        }
        fn visit_str<E>(self, value: &str) -> Result<Self::Value, E>
            where
                E: de::Error,
        {
            let name: Vec<String> = value
                .split_terminator('\n')
                .map(|s| s.to_string())
                .collect();
            Ok(HashSet::from_iter(name))
        }

        fn visit_seq<S>(self, visitor: S) -> Result<Self::Value, S::Error>
            where
                S: de::SeqAccess<'de>,
        {
            Deserialize::deserialize(de::value::SeqAccessDeserializer::new(visitor))
        }
    }
    deserializer.deserialize_any(StringOrVec(PhantomData))
}

pub fn print_color(mut string: String, nl: bool) {
    if nl {
        string.push('\n')
    }
    let mut t = term::stdout().unwrap();
    t.fg(term::color::GREEN).unwrap();
    write!(t, "{}", string).unwrap();
    t.reset().unwrap();
}