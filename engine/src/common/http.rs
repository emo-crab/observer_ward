use crate::error::Error;
use crate::matchers::FaviconMap;
use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use md5::{Digest, Md5};
use mime::Mime;
use slinger::http::header;
use slinger::http::header::HeaderMap;
use slinger::http::uri::Uri;
use slinger::{Body, ClientBuilder, Response};
use std::collections::{BTreeMap, HashSet};
use std::path::PathBuf;
use std::str::FromStr;

#[derive(Debug, Clone)]
pub struct HttpRecord {
  response: Response,
  skip: HashSet<String>,
  favicon: BTreeMap<String, FaviconMap>,
  client_builder: ClientBuilder,
}

impl HttpRecord {
  pub fn new(client_builder: ClientBuilder) -> Self {
    Self {
      response: Default::default(),
      skip: Default::default(),
      favicon: Default::default(),
      client_builder,
    }
  }
  fn fetch_favicon_hash(&mut self, url: &String) -> Option<FaviconMap> {
    self.skip.insert(url.to_string());
    let client = self.client_builder.clone().build().unwrap_or_default();
    if let Ok(resp) = client.get(url).send().map_err(Error::Http) {
      if resp.status_code().as_u16() != 200
        || (if let Some(b) = resp.body() {
          !is_image(resp.headers(), b)
        } else {
          true
        })
      {
        return None;
      }
      return if let Some(b) = resp.body() {
        let hash = favicon_hash(b);
        Some(hash)
      } else {
        None
      };
    }
    None
  }
  pub fn find_favicon_tag(&mut self, response: &mut Response) {
    // || self.response.status_code() > response.status_code()
    if self.response.uri() == "/" {
      self.response = response.clone();
    }
    // 补充默认路径
    let icon_sets = get_favicon_link(response);
    for link in icon_sets {
      if self.skip.contains(&link) {
        continue;
      }
      // 当图标404时，没有命中缓存，默认返回空字符串，需要判断一下
      if let Some(hash) = self.fetch_favicon_hash(&link) {
        self.favicon.insert(link, hash);
      }
    }
    response.extensions_mut().insert(self.favicon.clone());
  }
  // 把指纹结果插入到响应扩展中
  pub fn fav_response(&self) -> Option<Response> {
    if self.response.uri() != "/" {
      let mut resp = self.response.clone();
      resp.extensions_mut().insert(self.favicon.clone());
      Some(resp)
    } else {
      None
    }
  }
  pub fn favicon_hash(&self) -> &BTreeMap<String, FaviconMap> {
    &self.favicon
  }
  pub fn has_favicon(&self) -> bool {
    !self.favicon.is_empty()
  }
}

fn favicon_hash(content: &Body) -> FaviconMap {
  let mut hasher = Md5::new();
  hasher.update(content.to_vec());
  let result = hasher.finalize();
  let favicon_md5: String = format!("{:x}", &result);
  let bs64 = STANDARD.encode(content.to_vec());
  let mut buf = String::new();
  // # Insert newlines (\n) every 76 characters, and also at the end
  for (index, char) in bs64.chars().enumerate() {
    buf.push(char);
    if (index + 1) % 76 == 0 {
      buf.push('\n');
    }
  }
  buf.push('\n');
  let favicon_mmh3 = murmur3_32(buf.as_bytes(), 0).to_string();
  FaviconMap::new(favicon_md5, favicon_mmh3)
}

// 判断是否为图片，如果是图片直接算hash就可以了
fn is_image(headers: &HeaderMap, body: &Body) -> bool {
  let ct = headers
    .get(header::CONTENT_TYPE)
    .and_then(|value| value.to_str().ok())
    .and_then(|value| Mime::from_str(value).ok())
    .map(|value| value.type_() == mime::IMAGE)
    .unwrap_or_default();
  let encode_error = String::from_utf8(body.to_vec()).is_err();
  if encode_error {
    let text = String::from_utf8_lossy(body).to_lowercase();
    let is_html = vec!["html", "head", "script", "div", "title", "xml"]
      .into_iter()
      .any(|c| text.contains(c));
    ct || !is_html
  } else {
    ct
  }
}

fn get_favicon_link(response: &Response) -> HashSet<String> {
  let base_url = response.uri();
  let text = response.text().unwrap_or_default();
  let mut icon_links = HashSet::new();
  let dom = if let Ok(dom) = tl::parse(&text, tl::ParserOptions::default()) {
    dom
  } else {
    return HashSet::new();
  };
  let parser = dom.parser();
  if let Some(selector) = dom.query_selector("link[rel$=icon]") {
    for links in selector {
      if let Some(icon) = links.get(parser) {
        let href = icon.as_tag().and_then(|tag| {
          tag
            .attributes()
            .get("href")
            .and_then(|x| x.and_then(|x| x.try_as_utf8_str()))
        });
        if let Some(path) = href {
          if path.starts_with("http://") || path.starts_with("https://") {
            icon_links.insert(path.to_string());
          } else {
            let favicon_url = join(base_url, path).unwrap_or(base_url.clone());
            icon_links.insert(favicon_url.to_string());
          }
        }
      };
    }
    if let Some(favicon_url) = join(base_url, "/favicon.ico") {
      icon_links.insert(favicon_url.to_string());
    }
  }
  icon_links
}

fn join(cur_uri: &Uri, val: &str) -> Option<Uri> {
  let path = PathBuf::from(cur_uri.path()).join(val);
  Uri::builder()
    .scheme(cur_uri.scheme_str().unwrap_or_default())
    .authority(cur_uri.authority()?.as_str())
    .path_and_query(path.to_string_lossy().as_ref())
    .build()
    .ok()
}

pub fn murmur3_32(buf: &[u8], seed: u32) -> i32 {
  const fn pre_mix(buf: [u8; 4]) -> u32 {
    u32::from_le_bytes(buf)
      .wrapping_mul(0xcc9e2d51)
      .rotate_left(15)
      .wrapping_mul(0x1b873593)
  }

  let mut hash = seed;

  let mut i = 0;
  while i < buf.len() / 4 {
    let buf = [buf[i * 4], buf[i * 4 + 1], buf[i * 4 + 2], buf[i * 4 + 3]];
    hash ^= pre_mix(buf);
    hash = hash.rotate_left(13);
    hash = hash.wrapping_mul(5).wrapping_add(0xe6546b64);

    i += 1;
  }

  match buf.len() % 4 {
    0 => {}
    1 => {
      hash ^= pre_mix([buf[i * 4], 0, 0, 0]);
    }
    2 => {
      hash ^= pre_mix([buf[i * 4], buf[i * 4 + 1], 0, 0]);
    }
    3 => {
      hash ^= pre_mix([buf[i * 4], buf[i * 4 + 1], buf[i * 4 + 2], 0]);
    }
    _ => { /* unreachable!() */ }
  }

  hash ^= buf.len() as u32;
  hash = hash ^ (hash.wrapping_shr(16));
  hash = hash.wrapping_mul(0x85ebca6b);
  hash = hash ^ (hash.wrapping_shr(13));
  hash = hash.wrapping_mul(0xc2b2ae35);
  hash = hash ^ (hash.wrapping_shr(16));

  if hash & 0x80000000 == 0 {
    hash as i32
  } else {
    -(((hash ^ 0xFFFFFFFF) + 1) as i32)
  }
}
