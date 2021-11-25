use std::collections::HashMap;
use std::iter::FromIterator;

use regex::Regex;
use serde::{Deserialize, Serialize};

use crate::requests::{ResponseRaw, string_to_is_and};

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Matcher {
    //   - "status"
    //   - "size"
    //   - "word"
    //   - "regex"
    //   - "binary"
    //   - "dsl"
    #[serde(rename = "type")]
    match_type: String,
    //or and
    #[serde(default)]
    #[serde(deserialize_with = "string_to_is_and")]
    #[serde(rename = "condition")]
    condition_is_and: bool,
    //   - value: "\"body\""
    //   - value: "\"raw\""
    #[serde(default)]
    part: String,
    // !
    #[serde(default)]
    negative: bool,
    #[serde(default)]
    name: String,
    #[serde(default)]
    status: Vec<u16>,
    #[serde(default)]
    size: Vec<usize>,
    #[serde(default)]
    words: Vec<String>,
    #[serde(default)]
    regex: Vec<String>,
    #[serde(default)]
    binary: Vec<String>,
    #[serde(default)]
    dsl: Vec<String>,
    #[serde(default)]
    encoding: String,
    #[serde(skip)]
    response_raw: ResponseRaw,
}

#[derive(Debug)]
enum ExtractorType {
    RegexExtractor,
    KValExtractor,
    XPathExtractor,
    JSONExtractor,
}

#[derive(Debug)]
enum MatcherTypes {
    WordsMatcher,
    RegexMatcher,
    BinaryMatcher,
    StatusMatcher,
    SizeMatcher,
    DSLMatcher,
}

impl Matcher {
    fn match_status_code(&self) -> bool {
        for status_code in self.status.iter() {
            if status_code != &self.response_raw.status_code {
                continue;
            }
            return true;
        }
        return false;
    }
    fn match_size(&self) -> bool {
        for size in self.size.iter() {
            if size != &self.response_raw.raw.len() {
                continue;
            }
            return true;
        }
        return false;
    }
    fn match_words(&self) -> bool {
        let match_part = self.get_part_data();
        for (index, word) in self.words.iter().enumerate() {
            if !match_part.contains(&word.to_lowercase()) {
                if self.condition_is_and {
                    return false;
                }
                continue;
            }
            if !self.condition_is_and {
                return true;
            }
            if self.words.len() - 1 == index {
                return true;
            }
        }
        return false;
    }
    fn match_regex(&self) -> bool {
        let match_part = self.get_part_data();
        for (index, reg) in self.regex.iter().enumerate() {
            match Regex::new(reg) {
                Ok(reg) => {
                    if !reg.is_match(&match_part) {
                        if !self.condition_is_and {
                            return false;
                        }
                        continue;
                    }
                    if !self.condition_is_and {
                        return true;
                    }
                    if self.regex.len() - 1 == index {
                        return true;
                    }
                }
                Err(_) => {}
            }
        }
        return false;
    }
    fn match_binary(&self) -> bool {
        for (index, raw) in self.binary.iter().enumerate() {
            let hex_raw: Vec<String> = self
                .response_raw
                .raw
                .clone()
                .iter()
                .map(|b| format!("{:02X}", b))
                .collect();
            if !hex_raw.join("").contains(raw) {
                if self.condition_is_and {
                    return false;
                }
                continue;
            }
            if !self.condition_is_and {
                return true;
            }
            if self.binary.len() - 1 == index {
                return true;
            }
        }
        return false;
    }
}

impl Matcher {
    fn get_matcher_type(&self) -> MatcherTypes {
        let mut matcher_type: HashMap<String, MatcherTypes> = HashMap::from_iter([
            ("status".to_string(), MatcherTypes::StatusMatcher),
            ("size".to_string(), MatcherTypes::SizeMatcher),
            ("word".to_string(), MatcherTypes::WordsMatcher),
            ("regex".to_string(), MatcherTypes::RegexMatcher),
            ("binary".to_string(), MatcherTypes::BinaryMatcher),
            ("dsl".to_string(), MatcherTypes::DSLMatcher),
        ]);
        let mt = matcher_type
            .remove(&self.match_type)
            .unwrap_or(MatcherTypes::WordsMatcher);
        return mt;
    }
    fn get_part_data(&self) -> String {
        let mut result_string = String::new();
        if self.part == "body" || self.part.is_empty() {
            result_string.push_str(&self.response_raw.html.clone())
        } else if self.part == "header" {
            result_string.push_str(&format!("{:?}", self.response_raw.headers));
        }
        return result_string;
    }
    pub fn match_item(&mut self, raw_resp: ResponseRaw) -> bool {
        self.response_raw = raw_resp;
        let match_flag: bool;
        match self.get_matcher_type() {
            MatcherTypes::StatusMatcher => {
                match_flag = self.match_status_code();
            }
            MatcherTypes::SizeMatcher => {
                match_flag = self.match_size();
            }
            MatcherTypes::WordsMatcher => {
                match_flag = self.match_words();
            }
            MatcherTypes::RegexMatcher => {
                match_flag = self.match_regex();
            }
            MatcherTypes::BinaryMatcher => {
                match_flag = self.match_binary();
            }
            MatcherTypes::DSLMatcher => {
                //TODO
                match_flag = false;
            }
        };
        if self.negative {
            return !match_flag;
        }
        return match_flag;
    }
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Extractor {
    #[serde(default)]
    pub(crate) name: String,
    #[serde(rename = "type")]
    ext_type: String,
    #[serde(default)]
    regex: Vec<String>,
    #[serde(default)]
    group: usize,
    #[serde(rename = "kval")]
    #[serde(default)]
    key_value: Vec<String>,
    #[serde(default)]
    json: Vec<String>,
    #[serde(default)]
    xpath: Vec<String>,
    #[serde(default)]
    attribute: String,
    #[serde(default)]
    part: String,
    #[serde(default)]
    internal: bool,
    #[serde(skip)]
    response_raw: ResponseRaw,
}

impl Extractor {
    fn get_extractor_type(&self) -> ExtractorType {
        let mut extractor_type: HashMap<String, ExtractorType> = HashMap::from_iter([
            ("regex".to_string(), ExtractorType::RegexExtractor),
            ("kval".to_string(), ExtractorType::KValExtractor),
            ("xpath".to_string(), ExtractorType::XPathExtractor),
            ("json".to_string(), ExtractorType::JSONExtractor),
        ]);
        let et = extractor_type
            .remove(&self.ext_type)
            .unwrap_or(ExtractorType::RegexExtractor);
        return et;
    }
    fn get_part_data(&self) -> String {
        let mut result_string = String::new();
        if self.part == "body" || self.part.is_empty() {
            result_string.push_str(&self.response_raw.html.clone())
        } else if self.part == "header" {
            result_string.push_str(&format!("{:?}", self.response_raw.headers));
        }
        return result_string;
    }
    pub fn extract(&mut self, last_request_raw: &ResponseRaw) -> HashMap<String, String> {
        self.response_raw = last_request_raw.clone();
        match self.get_extractor_type() {
            ExtractorType::KValExtractor => {
                return self.key_value_extractor();
            }
            ExtractorType::JSONExtractor => {}
            ExtractorType::RegexExtractor => {
                return self.regex_extractor();
            }
            ExtractorType::XPathExtractor => {}
        };
        let resulted = HashMap::new();
        return resulted;
    }
}

impl Extractor {
    fn regex_extractor(&self) -> HashMap<String, String> {
        let extract_part = self.get_part_data();
        let mut result: HashMap<String, String> = HashMap::new();
        let re_list: Vec<Regex> = self
            .regex
            .iter()
            .map(|reg| Regex::new(reg))
            .filter_map(Result::ok)
            .collect();
        for re in re_list {
            if let Some(item) = re.captures(&extract_part) {
                if let Some(value) = item.get(self.group) {
                    result.insert(self.name.clone(), value.as_str().to_string());
                }
            }
        }
        return result;
    }
    fn key_value_extractor(&self) -> HashMap<String, String> {
        let mut result: HashMap<String, String> = HashMap::new();
        if self.part == "header" {
            let extract_part = self.response_raw.headers.clone();
            for kv in self.key_value.clone().into_iter() {
                if let Some(value) = extract_part.get(kv) {
                    result.insert(
                        self.name.clone(),
                        value.to_str().unwrap_or_default().to_string(),
                    );
                }
            }
        }

        return result;
    }
}
