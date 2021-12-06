#[macro_use]
extern crate lazy_static;

use std::collections::{HashMap, HashSet};
use std::fmt;
use std::fs::File;
use std::io::Cursor;
use std::io::{self, BufRead, Read};
use std::iter::FromIterator;
use std::marker::PhantomData;
use std::path::{Path, PathBuf};
use std::str;
use std::sync::{Arc, RwLock};
use std::{env, process};

use csv::{DeserializeRecordsIntoIter, Reader};
use reqwest::Proxy;
use serde::{de, Deserialize, Deserializer, Serialize};
#[cfg(not(feature = "observer_ward_nuclei_rs"))]
use tokio::process::Command;
use url::Url;
#[cfg(feature = "observer_ward_nuclei_rs")]
use walkdir::WalkDir;

use cli::WardArgs;
use fingerprint::{WebFingerPrintLib, WebFingerPrintRequest};
#[cfg(feature = "observer_ward_nuclei_rs")]
use observer_ward_nuclei_rs::NucleiTemplate;
use request::{get_title, index_fetch};
use ward::check;

use crate::fingerprint::WebFingerPrint;

pub mod cli;
pub mod fingerprint;
mod request;
mod ward;

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct WhatWebResult {
    pub url: String,
    #[serde(deserialize_with = "string_to_hashset")]
    pub name: HashSet<String>,
    pub priority: u32,
    pub length: usize,
    pub title: String,
    pub status_code: u16,
    #[serde(default)]
    pub is_web: bool,
    #[serde(default)]
    pub plugins: HashSet<String>,
    #[serde(skip)]
    pub template_result: Vec<TemplateResult>,
}

impl WhatWebResult {
    pub fn new(url: String) -> Self {
        Self {
            url,
            name: HashSet::new(),
            priority: 0,
            length: 0,
            status_code: 0,
            title: String::new(),
            plugins: HashSet::new(),
            template_result: vec![],
            is_web: true,
        }
    }
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

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct TemplateResult {
    #[serde(rename = "template-id")]
    pub template_id: String,
    #[serde(rename = "matched-at")]
    pub matched_at: String,
    #[serde(default)]
    pub meta: HashMap<String, String>,
}
#[cfg(feature = "observer_ward_nuclei_rs")]
fn run_nuclei_rs_to(p: &String, target: String) -> HashSet<String> {
    let mut plugins_set: HashSet<String> = HashSet::new();
    for entry in WalkDir::new(p)
        .follow_links(true)
        .into_iter()
        .filter_map(|e| e.ok())
    {
        let f_name = entry.file_name().to_string_lossy();

        if f_name.ends_with(".yaml") && f_name != "tags.yaml" {
            let mut file = match File::open(entry.path()) {
                Err(_) => {
                    return plugins_set;
                }
                Ok(file) => file,
            };
            let mut data = String::new();
            file.read_to_string(&mut data).unwrap();
            let template: NucleiTemplate = serde_yaml::from_str(&data).unwrap();
            if !template.requests.is_empty() {
                for mut request in template.requests.into_iter() {
                    if request.execute_request(target.clone()) {
                        plugins_set.insert(template.id.clone());
                    };
                }
            }
        }
    }
    return plugins_set;
}

fn string_to_hashset<'de, D>(deserializer: D) -> Result<HashSet<String>, D::Error>
where
    D: Deserializer<'de>,
{
    struct StringToHashSet(PhantomData<HashSet<String>>);
    impl<'de> de::Visitor<'de> for StringToHashSet {
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
    deserializer.deserialize_any(StringToHashSet(PhantomData))
}

pub struct WhatWeb {
    fingerprint: Arc<RwLock<WebFingerPrintLib>>,
    config: WardArgs,
}

impl WhatWeb {
    pub fn new(config: WardArgs, web_fingerprint: Vec<WebFingerPrint>) -> Self {
        let fingerprint: Arc<RwLock<WebFingerPrintLib>> = Arc::new(RwLock::new({
            let web_fingerprint_lib = WebFingerPrintLib::new(web_fingerprint);
            web_fingerprint_lib
        }));
        Self {
            fingerprint,
            config,
        }
    }
    pub async fn update_self(&self) {
        let mut base_url =
            String::from("https://github.com/0x727/ObserverWard_0x727/releases/download/default/");
        let mut download_name = "observer_ward_amd64";
        if cfg!(target_os = "windows") {
            download_name = "observer_ward.exe";
        } else if cfg!(target_os = "linux") {
            download_name = "observer_ward_amd64";
        } else if cfg!(target_os = "macos") {
            download_name = "observer_ward_darwin";
        };
        base_url.push_str(download_name);
        let save_filename = "update_".to_owned() + download_name;
        self.download_file_from_github(&base_url, &save_filename)
            .await;
        println!(
            "Please rename the file {} => {}",
            save_filename, download_name
        );
    }
    pub fn read_results_file(&self) -> Vec<WhatWebResult> {
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
        if !self.config.json.is_empty() {
            let data = read_file_data(&self.config.json);
            let wwr: Vec<WhatWebResult> = serde_json::from_str(&data).expect("BAD JSON");
            results.extend(wwr);
        }
        if !self.config.csv.is_empty() {
            let rdr = Reader::from_path(&self.config.csv).expect("BAD CSV");
            let iter: DeserializeRecordsIntoIter<File, WhatWebResult> = rdr.into_deserialize();
            let wwr: Vec<WhatWebResult> = iter.filter_map(Result::ok).collect();
            results.extend(wwr);
        }
        results
    }

    #[cfg(feature = "observer_ward_nuclei_rs")]
    pub async fn get_plugins_by_nuclei(&self, w: &WhatWebResult) -> WhatWebResult {
        let mut wwr = w.clone();
        let mut plugins_set: HashSet<String> = HashSet::new();
        let mut exist_plugins: Vec<String> = Vec::new();
        for name in wwr.name.iter() {
            let plugins_name_path = Path::new(&self.config.plugins).join(name);
            if plugins_name_path.exists() {
                if let Some(p_path) = plugins_name_path.to_str() {
                    exist_plugins.push(p_path.to_string())
                }
            }
        }
        if exist_plugins.is_empty() {
            return wwr;
        }
        for p in exist_plugins.iter() {
            let plugins = run_nuclei_rs_to(p, wwr.url.clone());
            plugins_set.extend(plugins);
        }
        wwr.plugins = plugins_set;
        if !wwr.plugins.is_empty() {
            wwr.priority = wwr.priority + 1;
        }
        return wwr;
    }
    #[cfg(not(feature = "observer_ward_nuclei_rs"))]
    pub async fn get_plugins_by_nuclei(&self, w: &WhatWebResult) -> WhatWebResult {
        let mut wwr = w.clone();
        let mut plugins_set: HashSet<String> = HashSet::new();
        let mut exist_plugins: Vec<String> = Vec::new();
        for name in wwr.name.iter() {
            let plugins_name_path = Path::new(&self.config.plugins).join(name);
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
            &(self.config.timeout + 5).to_string(),
        ]);
        command_line.args([
            "-H",
            "User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:94.0) Gecko/20100101 Firefox/94.0",
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
                let template: TemplateResult = serde_json::from_str(&line).unwrap();
                wwr.template_result.push(template.clone());
                plugins_set.insert(template.template_id);
            }
        }
        wwr.plugins = plugins_set;
        if !wwr.plugins.is_empty() {
            wwr.priority = wwr.priority + 1;
        }
        return wwr;
    }
    pub async fn download_file_from_github(&self, update_url: &str, filename: &str) {
        let proxy_url = self.config.proxy.clone();
        if !proxy_url.is_empty() {
            if let Err(_err) = Url::parse(&proxy_url) {
                println!("Invalid Proxy Uri");
                process::exit(0);
            }
        }
        let proxy_obj = Proxy::custom(move |_url| {
            if let Ok(proxy_uri) = Url::parse(&proxy_url) {
                Some(proxy_uri.clone())
            } else {
                None
            }
        });
        let client = reqwest::Client::builder().proxy(proxy_obj);
        match client.build().unwrap().get(update_url).send().await {
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
    pub async fn scan(&self, url: String) -> WhatWebResult {
        let mut name: HashSet<String> = HashSet::new();
        let mut what_web_result: WhatWebResult = WhatWebResult::new(url.clone());
        let default_request = WebFingerPrintRequest {
            path: String::from("/"),
            request_method: String::from("get"),
            request_headers: Default::default(),
            request_data: String::new(),
        };
        if let Ok(raw_data_list) = index_fetch(
            &url,
            &default_request,
            true,
            false,
            self.config.timeout,
            &self.config.proxy,
        )
        .await
        {
            if raw_data_list.is_empty() {
                what_web_result.is_web = false;
            }
            //首页请求允许跳转
            for raw_data in raw_data_list {
                let web_name_set = check(
                    &raw_data,
                    &self.fingerprint.read().unwrap().to_owned(),
                    false,
                )
                .await;
                for (k, v) in web_name_set {
                    name.insert(k);
                    what_web_result.priority = v;
                }
                if url.starts_with("http://") || url.starts_with("https://") {
                    what_web_result.url = url.clone();
                } else {
                    what_web_result.url = String::from(raw_data.url.clone());
                }
                if what_web_result.title.is_empty() {
                    what_web_result.title = get_title(&raw_data);
                    what_web_result.priority = what_web_result.priority + 1;
                }
                what_web_result.length = raw_data.text.len();
                what_web_result.status_code = raw_data.status_code.as_u16();
                if raw_data.status_code.is_success() {
                    what_web_result.priority = what_web_result.priority + 1;
                }
            }
        };
        // 在首页请求时不是Web也没必要跑特殊请求了
        if !what_web_result.is_web {
            return what_web_result;
        }
        for special_wfp in self.fingerprint.read().unwrap().to_owned().special.iter() {
            if let Ok(raw_data_list) = index_fetch(
                &url,
                &special_wfp.request,
                false,
                true,
                self.config.timeout,
                &self.config.proxy,
            )
            .await
            {
                for raw_data in raw_data_list {
                    let web_name_set = check(
                        &raw_data,
                        &self.fingerprint.read().unwrap().to_owned(),
                        true,
                    )
                    .await;
                    for (k, v) in web_name_set {
                        name.insert(k);
                        what_web_result.priority = v;
                    }
                }
            }
        }
        if name.len() > 10 {
            let count = name.len();
            name.clear();
            name.insert(format!("Honeypot 蜜罐{}", count));
        }
        what_web_result.name = name.clone();
        what_web_result
    }
}
