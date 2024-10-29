use super::uri::join;
use fancy_regex::Regex;
use std::str::FromStr;
use std::sync::OnceLock;

/// 获取标题
pub fn extract_title(text: &str) -> Option<String> {
  let dom = tl::parse(text, tl::ParserOptions::default()).ok()?;
  let parser = dom.parser();
  if let Some(selector) = dom.query_selector("title") {
    for title in selector {
      if let Some(title) = title.get(parser) {
        let t = title.inner_text(parser).trim().to_string();
        if !t.is_empty() {
          return Some(t);
        }
      }
    }
  }
  let meta = vec!["meta[property$=title]", "meta[name=title]"];
  for m in meta {
    if let Some(selector) = dom.query_selector(m) {
      for title in selector {
        if let Some(title) = title.get(parser) {
          let content = title
            .as_tag()
            .and_then(|tag| {
              tag
                .attributes()
                .get("content")
                .and_then(|x| x.and_then(|x| x.try_as_utf8_str()))
            })
            .map(|x| x.trim().to_string());
          if content.is_some() {
            return content;
          }
        }
      }
    }
  }
  None
}
static RE: OnceLock<Vec<Regex>> = OnceLock::new();
pub fn extract_redirect(text: &str, cur_uri: &slinger::http::Uri) -> Option<slinger::http::Uri> {
  let re = RE.get_or_init(|| {
    let js_reg = [
      r#"(?im)location(?:\.(:?open|replace|href))\s=\s['"]\s*?(?P<name>.*?)['"]"#,
      r#"(?im)location\.(?:open|replace|href|assign)\((?P<name>.*?)\)"#,
    ];
    let re_list: Vec<Regex> = js_reg
      .iter()
      .map(|reg| Regex::new(reg).expect("RE_COMPILE_BY_JUMP"))
      .collect();
    re_list
  });
  let mut next_url_list = Vec::new();
  let dom = tl::parse(text, tl::ParserOptions::default()).ok()?;
  let parser = dom.parser();
  if let Some(selector) = dom.query_selector("meta[http-equiv=refresh]") {
    for meta in selector {
      if let Some(meta) = meta.get(parser) {
        let content = meta
          .as_tag()
          .and_then(|tag| {
            tag
              .attributes()
              .get("content")
              .and_then(|x| x.and_then(|x| x.try_as_utf8_str()))
          })
          .map(|x| x.trim().to_string())
          .unwrap_or_default();
        if let Some((_, u)) = content.split_once('=') {
          let n = u.replace(['\'', '\"'], "");
          next_url_list.push(n);
        }
      }
    }
  }
  if next_url_list.is_empty() && text.len() <= 1024 {
    for reg in re.iter() {
      if let Ok(Some(x)) = reg.captures(text) {
        let mut u = x.name("name").map_or("", |m| m.as_str()).to_string();
        u = u.replace(['\'', '\"'], "");
        next_url_list.push(u);
      }
    }
  }
  if let Some(next_url) = next_url_list.into_iter().next() {
    return if next_url.starts_with("http://") || next_url.starts_with("https://") {
      match slinger::http::Uri::from_str(&next_url) {
        Ok(next_path) => Some(next_path),
        Err(_) => None,
      }
    } else {
      join(cur_uri, &next_url)
    };
  };
  None
}
