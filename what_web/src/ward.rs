use crate::fingerprint::{V3WebFingerPrint, WebFingerPrintLib};
use futures::future::join_all;
use std::collections::{HashMap, HashSet};
use std::env;
use std::sync::Arc;
use url::Url;

#[derive(Debug)]
pub struct RawData {
    pub url: Url,
    pub path: String,
    pub headers: reqwest::header::HeaderMap,
    pub status_code: reqwest::StatusCode,
    pub text: String,
    pub favicon: HashMap<String, String>,
    pub next_url: Option<Url>,
}

pub async fn check(
    raw_data: &Arc<RawData>,
    fingerprint_lib: &WebFingerPrintLib,
    is_special: bool,
) -> HashMap<String, u32> {
    let mut futures_e = vec![];
    let mut web_name_set: HashMap<String, u32> = HashMap::new();
    if is_special {
        for fingerprint in fingerprint_lib.special.iter() {
            futures_e.push(what_web(raw_data.clone(), fingerprint, false));
        }
    } else {
        for fingerprint in fingerprint_lib.index.iter() {
            futures_e.push(what_web(raw_data.clone(), fingerprint, false));
        }
    }
    if !raw_data.favicon.is_empty() {
        for fingerprint in fingerprint_lib.favicon.iter() {
            futures_e.push(what_web(raw_data.clone(), fingerprint, true));
        }
    }
    let results = join_all(futures_e).await;
    for res in results {
        let (is_match, match_web_fingerprint) = res;
        if is_match {
            web_name_set.insert(
                match_web_fingerprint.name.clone(),
                match_web_fingerprint.priority,
            );
        }
    }
    web_name_set
}

pub async fn what_web(
    raw_data: Arc<RawData>,
    fingerprint: &V3WebFingerPrint,
    is_favicon: bool,
) -> (bool, &V3WebFingerPrint) {
    let mut default_result = (false, fingerprint);
    if is_favicon {
        let mut hash_set = HashSet::new();
        for (_key, value) in raw_data.favicon.iter() {
            hash_set.insert(value);
        }
        let mut fph_set = HashSet::new();
        for fph in fingerprint.match_rules.favicon_hash.iter() {
            fph_set.insert(fph);
        }
        if hash_set.intersection(&fph_set).count() == 0 {
            return default_result;
        }
    } else {
        if fingerprint.match_rules.status_code != 0
            && raw_data.status_code.as_u16() != fingerprint.match_rules.status_code
        {
            return default_result;
        }
        for (k, v) in &fingerprint.match_rules.headers {
            let matcher_part = format!("{:?}", raw_data.headers);
            if k == "set-cookie" && !matcher_part.contains(v) {
                return default_result;
            }
            if raw_data.headers.contains_key(k) {
                let is_match = matcher_part.to_lowercase().find(&v.to_lowercase());
                if is_match == None && v != "*" {
                    return default_result;
                }
            } else {
                return default_result;
            }
        }
        for keyword in &fingerprint.match_rules.keyword {
            if raw_data.text.find(&keyword.to_lowercase()) == None {
                return default_result;
            }
        }
    }
    default_result.0 = true;
    let is_output = env::var("OUTPUT_MATCH").is_ok();
    if is_output {
        println!("Matching fingerprint{:?}", fingerprint);
    }
    default_result
}
