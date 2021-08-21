use futures::future::join_all;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::collections::HashSet;
use std::sync::Arc;
use std::fs::File;
use std::io::Read;
use std::env;

#[derive(Debug, Serialize, Deserialize)]
pub struct WebFingerPrint {
    name: String,
    status_code: u16,
    headers: HashMap<String, String>,
    keyword: Vec<String>,
    favicon_hash: Vec<String>,
    priority: u32,
}

#[derive(Debug)]
pub struct RawData {
    pub url: String,
    pub path: String,
    pub headers: reqwest::header::HeaderMap,
    pub status_code: reqwest::StatusCode,
    pub text: String,
    pub favicon_hash: HashMap<String, HashMap<String, String>>,

}
// 加载指纹库到常量，防止在文件系统反复加载
lazy_static! {
    static ref WEB_FINGERPRINT_JSON_DATA: HashMap<String, Vec<WebFingerPrint>> = {
        let mut file = match File::open("web_fingerprint.json") {
            Err(_) => {
                println!("The fingerprint library cannot be found in the current directory!");
                std::process::exit(0);
            }
            Ok(file) => file,
        };
        let mut data = String::new();
        file.read_to_string(&mut data).unwrap();
        let web_fingerprint: HashMap<String, Vec<WebFingerPrint>> =
            serde_json::from_str(&data).expect("JSON was not well-formatted");
        web_fingerprint
    };
}
pub async fn check(raw_data: &Arc<RawData>) -> HashMap<String, u32> {
    let mut futures = vec![];
    let mut web_name_set: HashMap<String, u32> = HashMap::new();
    let path_list: Vec<String> = vec![String::from("/"), String::from("/favicon.ico")];
    for path in path_list {
        match WEB_FINGERPRINT_JSON_DATA.get(path.as_str()) {
            Some(fingerprints) => {
                for fingerprint in fingerprints {
                    futures.push(what_web(raw_data.clone(), fingerprint));
                }
            }
            None => {}
        }
    }
    let results = join_all(futures).await;
    for res in results {
        let (is_match, match_web_fingerprint) = res;
        if is_match {
            web_name_set.insert(match_web_fingerprint.name.clone(), match_web_fingerprint.priority.clone());
        }
    }
    return web_name_set;
}

pub async fn what_web(raw_data: Arc<RawData>, fingerprint: &WebFingerPrint) -> (bool, &WebFingerPrint) {
    let mut hash_set = HashSet::new();
    let mut default_result = (false, fingerprint);
    for favicon_hash in raw_data.favicon_hash.iter() {
        let (_path, md5_mmh3) = favicon_hash;
        for (_key, value) in md5_mmh3.iter() {
            hash_set.insert(value);
        }
    }
    if !fingerprint.favicon_hash.is_empty() {
        let mut fph_set = HashSet::new();
        for fph in fingerprint.favicon_hash.iter() {
            fph_set.insert(fph);
        }
        if hash_set.intersection(&fph_set).count() == 0 {
            return default_result;
        }
    }
    if fingerprint.status_code != 0 && raw_data.status_code.as_u16() != fingerprint.status_code {
        return default_result;
    }
    for (k, v) in &fingerprint.headers {
        if raw_data.headers.contains_key(k) {
            let is_match = format!("{:?}", raw_data.headers).to_lowercase().find(&v.to_lowercase());
            if is_match == None && v != "*" {
                return default_result;
            }
        } else {
            return default_result;
        }
    }
    for keyword in &fingerprint.keyword {
        if raw_data.text.find(&keyword.to_lowercase()) == None {
            return default_result;
        }
    }
    default_result.0 = true;
    let is_output = env::var("OUTPUT_MATCH").is_ok();
    if is_output {
        println!("Matching fingerprint{:?}", fingerprint);
    }
    return default_result;
}
