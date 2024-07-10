use crate::cli::{Mode, ObserverWardConfig};
use crate::error::new_io_error;
use crate::nuclei::{gen_nuclei_tags, NucleiRunner};
use console::{style, Emoji};
use engine::common::html::extract_title;
use engine::common::http::HttpRecord;
use engine::execute::{ClusterExecute, ClusterType};
use engine::matchers::FaviconMap;
use engine::request::RequestGenerator;
use engine::results::{NucleiResult, ResultEvent};
use engine::slinger::http::header::HeaderValue;
use engine::slinger::http::uri::Uri;
use engine::slinger::http::StatusCode;
use engine::slinger::openssl::x509::X509;
use engine::slinger::redirect::{only_same_host, Policy};
use engine::slinger::{http_serde, Request, Response};
use engine::template::Template;
use error::Result;
use log::{debug, info};
use rustc_lexer::unescape;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::fs::File;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::sync::mpsc::Sender;
use std::time::Duration;
use threadpool::ThreadPool;

pub mod api;
pub mod cli;
mod cluster;
pub mod error;
pub mod helper;
pub mod input;
mod nuclei;
pub mod output;

pub use cluster::cluster_templates;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct X509Certificate {
  text: String,
  pem: Vec<u8>,
  public_key: Option<Vec<u8>>,
  subject_name: HashMap<String, String>,
  issuer_name: HashMap<String, String>,
  subject_alt_names: Option<Vec<GeneralName>>,
  issuer_alt_names: Option<Vec<GeneralName>>,
  subject_name_hash: u32,
  signature: Vec<u8>,
  signature_algorithm: String,
  ocsp_responders: Vec<String>,
  serial_number: Option<String>,
  not_after: String,
  not_before: String,
  version: i32,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "kebab-case")]
pub struct GeneralName {
  email: Option<String>,
  dns_name: Option<String>,
  uri: Option<String>,
  ipaddress: Option<Vec<u8>>,
}

impl X509Certificate {
  fn new(value: &X509) -> X509Certificate {
    X509Certificate {
      public_key: value
        .public_key()
        .ok()
        .map(|x| x.public_key_to_pem().unwrap_or_default()),
      text: String::from_utf8_lossy(&value.to_text().unwrap_or_default()).to_string(),
      pem: value.to_pem().unwrap_or_default(),
      not_after: value.not_after().to_string(),
      not_before: value.not_before().to_string(),
      version: value.version(),
      subject_name_hash: value.subject_name_hash(),
      serial_number: value.serial_number().to_bn().ok().map(|x| x.to_string()),
      ocsp_responders: value
        .ocsp_responders()
        .map_or(Vec::new(), |x| x.iter().map(|o| o.to_string()).collect()),
      signature_algorithm: value.signature_algorithm().object().to_string(),
      signature: value.signature().as_slice().to_vec(),
      subject_alt_names: value.subject_alt_names().map(|x| {
        x.into_iter()
          .map(|g| GeneralName {
            dns_name: g.dnsname().map(|d| d.to_string()),
            email: g.email().map(|e| e.to_string()),
            uri: g.uri().map(|u| u.to_string()),
            ipaddress: g.ipaddress().map(|i| i.to_vec()),
          })
          .collect()
      }),
      issuer_alt_names: value.issuer_alt_names().map(|x| {
        x.into_iter()
          .map(|g| GeneralName {
            dns_name: g.dnsname().map(|d| d.to_string()),
            email: g.email().map(|e| e.to_string()),
            uri: g.uri().map(|u| u.to_string()),
            ipaddress: g.ipaddress().map(|i| i.to_vec()),
          })
          .collect()
      }),
      subject_name: value
        .subject_name()
        .entries()
        .map(|e| {
          (
            kebab_case(&e.object().to_string()),
            String::from_utf8_lossy(e.data().as_slice()).to_string(),
          )
        })
        .collect(),
      issuer_name: value
        .issuer_name()
        .entries()
        .map(|e| {
          (
            kebab_case(&e.object().to_string()),
            String::from_utf8_lossy(e.data().as_slice()).to_string(),
          )
        })
        .collect(),
    }
  }
}

fn kebab_case(name: &str) -> String {
  let mut new_name = String::new();
  let chars = name.chars().collect::<Vec<_>>();
  let l = chars.len();
  for (index, c) in chars.into_iter().enumerate() {
    if c.is_uppercase() && (index != 0 || index != l - 1) {
      new_name.push('_');
      c.to_lowercase().for_each(|nc| new_name.push(nc));
    } else {
      new_name.push(c);
    }
  }
  new_name
}

// 子路径下面的匹配结果
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "kebab-case")]
pub struct MatchedResult {
  // 标题集合
  title: HashSet<String>,
  #[serde(with = "http_serde::option::status_code")]
  // 最新状态码
  #[serde(skip_serializing_if = "Option::is_none")]
  status: Option<StatusCode>,
  // favicon哈希
  favicon: HashMap<String, FaviconMap>,
  #[serde(skip_serializing_if = "Option::is_none")]
  certificate: Option<X509Certificate>,
  // 指纹信息
  fingerprints: Vec<ResultEvent>,
  // 漏洞信息
  nuclei_result: HashMap<String, Vec<NucleiResult>>,
}

impl MatchedResult {
  pub fn title(&self) -> &HashSet<String> {
    &self.title
  }
  pub fn status(&self) -> &Option<StatusCode> {
    &self.status
  }
  pub fn fingerprint(&self) -> &Vec<ResultEvent> {
    &self.fingerprints
  }
  pub fn nuclei_result(&self) -> &HashMap<String, Vec<NucleiResult>> {
    &self.nuclei_result
  }

  fn update_matched(&mut self, result: &ResultEvent) {
    let response = result.response().unwrap_or_default();
    let title = response.text().ok().and_then(|text| extract_title(&text));
    let status_code = response.status_code();
    if self.status.is_none() {
      self.status = Some(status_code);
    }
    if let Some(t) = title {
      self.title.insert(t.clone());
      self.status = Some(status_code);
    }
    if self.certificate.is_none() {
      self.certificate = response.certificate().map(X509Certificate::new);
    }
    if let Some(fav) = response.extensions().get::<HashMap<String, FaviconMap>>() {
      self.favicon.extend(fav.clone());
    }
    if !result.matcher_result().is_empty() {
      let mut result = result.clone();
      // 当标题为空时在提取器中template名称相同的键值为标题
      if self.title.is_empty() {
        result.matcher_result_mut().iter_mut().for_each(|x| {
          if let Some(template) = x.extractor.remove(&x.template) {
            self.title.extend(template);
          }
        });
      }
      self.fingerprints.push(result);
    }
  }
  fn merge_nuclei_args(&self, template_dir: &Path) -> HashMap<String, NucleiRunner> {
    let mut nuclei_map: HashMap<String, NucleiRunner> = HashMap::new();
    for result_event in self.fingerprints.iter() {
      let all_matched_result = result_event.matcher_result();
      for matcher_result in all_matched_result {
        if let Some(vpf) = matcher_result.info.get_vpf() {
          if let Some(nr) = nuclei_map.get_mut(&matcher_result.template) {
            nr.targets.insert(result_event.matched_at().to_string());
          } else {
            let mut args = NucleiRunner::new(vpf.name());
            args.targets.insert(result_event.matched_at().to_string());
            let plugin_path = template_dir.join(&vpf.vendor).join(&vpf.product);
            if vpf.verified && plugin_path.is_dir() {
              args.plugins.insert(plugin_path);
            } else {
              args
                .condition
                .push(gen_nuclei_tags(&vpf.product, &matcher_result.info.tags));
            }
            nuclei_map.insert(matcher_result.template.clone(), args);
          }
        }
      }
    }
    nuclei_map
  }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClusterExecuteRunner {
  // 单个目标
  #[serde(with = "http_serde::uri")]
  target: Uri,
  // 子路径匹配结果
  matched_result: HashMap<String, MatchedResult>,
}

impl ClusterExecuteRunner {
  pub fn target(&self) -> &Uri {
    &self.target
  }
  pub fn result(&self) -> &HashMap<String, MatchedResult> {
    &self.matched_result
  }
  pub fn new(uri: Uri) -> Self {
    Self {
      target: uri,
      matched_result: HashMap::new(),
    }
  }
  fn update_result(&mut self, result: ResultEvent, key: Option<String>) {
    let key = if let Some(key) = key {
      key
    } else {
      let u = result.matched_at().clone();
      let ub = Uri::builder()
        .scheme(u.scheme_str().unwrap_or_default())
        .authority(
          u.authority()
            .map_or(u.host().unwrap_or_default(), |a| a.as_str()),
        )
        .path_and_query("/");
      ub.build().map_or(u, |x| x).to_string()
    };
    if let Some(mr) = self.matched_result.get_mut(&key) {
      mr.update_matched(&result);
    } else {
      let mut m = MatchedResult::default();
      m.update_matched(&result);
      self.matched_result.insert(key, m);
    }
  }
  pub fn run(&mut self, iterator: Vec<ClusterType>, config: ObserverWardConfig) {
    let mut http_record = HttpRecord::new(self.target.clone(), config.http_client_builder());
    let mut favicon_cluster = Vec::new();
    let mode = config.mode.clone().unwrap_or_default();
    for (index, cluster_type) in iterator.iter().enumerate() {
      match cluster_type {
        ClusterType::Safe(clusters) => {
          if matches!(mode, Mode::DANGER) {
            continue;
          }
          if let Err(_err) = self.execute(&config, clusters, &mut http_record) {
            // 首页访问失败
            if index == 0 {
              break;
            }
          }
        }
        ClusterType::Danger(clusters) => {
          if matches!(mode, Mode::SAFE) {
            continue;
          }
          if let Err(_err) = self.execute(&config, clusters, &mut http_record) {
            // 第一次访问失败
            if index == 0 {
              break;
            }
          }
        }
        ClusterType::Favicon(clusters) => {
          favicon_cluster.push(clusters);
        }
      }
    }
    if let Some(resp) = http_record.fav_response() {
      let mut result = ResultEvent::new(&resp);
      for clusters in favicon_cluster {
        // 匹配favicon的，要等index的全部跑完
        if http_record.has_favicon() {
          debug!(
            "{}: {:#?}",
            Emoji("⭐️", "favicon"),
            http_record.favicon_hash()
          );
          clusters.operators.iter().for_each(|operator| {
            operator.matcher(&mut result);
          });
        }
      }
      // 如果有图标或者结果什么都没有，保存一个首页请求
      if !result.matcher_result().is_empty()
        || self.matched_result.is_empty()
        || !self.matched_result.contains_key(&self.target.to_string())
        || self
          .matched_result
          .get(&self.target.to_string())
          .map_or(false, |x| x.title.is_empty())
      {
        self.update_result(result, None);
      }
    }
    self.use_nuclei(&config);
    self.matched_result.values_mut().for_each(|mr| {
      if config.oc {
        mr.certificate = None;
      }
      mr.fingerprints.iter_mut().for_each(|x| {
        if config.or {
          x.omit_raw()
        }
      })
    });
  }
  fn use_nuclei(&mut self, config: &ObserverWardConfig) {
    let template_dir = if let Some(path) = &config.plugin {
      path.clone()
    } else {
      return;
    };
    // 相同插件和url只跑一次
    let mut skip_target: HashMap<String, Vec<String>> = HashMap::new();
    for (base_url, matched_result) in self.matched_result.iter_mut() {
      let mut key_args = matched_result.merge_nuclei_args(&template_dir);
      for (key, args) in key_args.iter_mut() {
        if args.plugins.is_empty() && args.condition.is_empty() {
          continue;
        }
        if let Some(targets) = skip_target.get_mut(&args.name) {
          if !targets.contains(base_url) {
            args.targets.insert(base_url.clone());
          }
        } else {
          skip_target.insert(args.name.clone(), vec![base_url.clone()]);
        }
        let nuclei_results = args.run(config);
        if let Some(nrs) = matched_result.nuclei_result.get_mut(key) {
          nrs.extend(nuclei_results.clone());
        } else {
          matched_result
            .nuclei_result
            .insert(key.clone(), nuclei_results);
        }
      }
    }
  }

  fn http(
    &mut self,
    config: &ObserverWardConfig,
    cluster: &ClusterExecute,
    http_record: &mut HttpRecord,
  ) -> Result<()> {
    // 可能会有多个http，一般只有一个，多个会有flow控制
    for http in cluster.requests.http.iter() {
      let mut client_builder = http.http_option.builder_client();
      client_builder = client_builder.timeout(Duration::from_secs(config.timeout));
      client_builder = client_builder.redirect(Policy::Custom(only_same_host));
      if let Ok(ua) = HeaderValue::from_str(&config.ua) {
        client_builder = client_builder.user_agent(ua);
      }
      if let Some(proxy) = &config.proxy {
        client_builder = client_builder.proxy(proxy.clone());
      }
      let client = client_builder.build().unwrap_or_default();
      let operators = cluster.operators.clone();
      let generator = RequestGenerator::new(http, self.target.clone());
      // 请求全部路径
      for request in generator {
        debug!("{}{:#?}", Emoji("📤", ""), request);
        let mut response = client.execute(request.clone())?;
        debug!("{}{:#?}", Emoji("📥", ""), response);
        // 提取icon
        http_record.find_favicon_tag(&mut response);
        let mut flag = false;
        let mut result = ResultEvent::new(&response);
        operators
          .iter()
          .for_each(|operator| operator.matcher(&mut result));
        if !result.matcher_result().is_empty() {
          flag = true;
          self.update_result(result, Some(request.uri().to_string()));
        }
        if http.stop_at_first_match && flag {
          break;
        }
      }
    }
    Ok(())
  }
  fn tcp(&mut self, config: &ObserverWardConfig, cluster: &ClusterExecute) -> Result<()> {
    // 服务指纹识别，实验功能 #TODO
    for tcp in cluster.requests.tcp.iter() {
      let conn_builder = config.tcp_client_builder();
      let mut socket = conn_builder.build()?.connect_with_uri(&self.target)?;
      socket.set_nonblocking(true).unwrap_or_default();
      let operators = cluster.operators.clone();
      for input in tcp.inputs.iter() {
        let data = input_to_byte(&input.data.clone().unwrap_or_default());
        let request = Request::raw(self.target.clone(), data.clone(), true);
        debug!("{}{:#?}", Emoji("📤", ""), request);
        socket.write_all(&data).unwrap_or_default();
        socket.flush().unwrap_or_default();
        let mut full = Vec::new();
        let mut buffer = vec![0; 12]; // 定义一个缓冲区
        let mut total_bytes_read = 0;
        loop {
          match socket.read(&mut buffer) {
            Ok(0) => break, // 如果读取到的数据长度为0，表示对端关闭连接
            Ok(n) => {
              full.extend_from_slice(&buffer[..n]);
              total_bytes_read += n;
            }
            Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
              // 如果没有数据可读，但超时尚未到达，可以在这里等待或重试
              if total_bytes_read > 0 {
                break;
              }
            }
            Err(_e) => {
              // 处理其他错误
              break;
            }
          }
          // 检查是否读取到了全部数据，如果是，则退出循环
          if total_bytes_read >= input.read.unwrap_or(2048) {
            break;
          }
        }
        let mut response: Response = Response::builder().body(full).unwrap_or_default().into();
        response.extensions_mut().insert(request.clone());
        debug!("{}{:#?}", Emoji("📥", ""), response);
        let mut result = ResultEvent::new(&response);
        operators
          .iter()
          .for_each(|operator| operator.matcher(&mut result));
        if !result.matcher_result().is_empty() {
          self.update_result(result, Some(request.uri().to_string()));
        }
      }
    }
    Ok(())
  }
  fn execute(
    &mut self,
    config: &ObserverWardConfig,
    cluster: &ClusterExecute,
    http_record: &mut HttpRecord,
  ) -> Result<()> {
    match self.target.scheme_str() {
      // 只跑web指纹
      Some("http") | Some("https") => {
        self.http(config, cluster, http_record)?;
      }
      // 只跑服务指纹
      None | Some("tcp") | Some("tls") => {
        self.tcp(config, cluster)?;
      }
      // 跳过
      _ => {}
    }
    Ok(())
  }
}

// yaml字符串转字节
fn input_to_byte(payload: &str) -> Vec<u8> {
  let mut buf = Vec::new();
  if !payload.is_empty() {
    unescape::unescape_byte_str(payload, &mut |_x, y| {
      if let Ok(c) = y {
        buf.push(c)
      }
    });
  }
  buf
}

pub fn parse_yaml(yaml_path: &PathBuf) -> Result<Template> {
  let name = yaml_path
    .file_name()
    .unwrap_or_default()
    .to_string_lossy()
    .to_string();
  let name = name.trim_end_matches(&format!(
    ".{}",
    yaml_path.extension().unwrap_or_default().to_string_lossy()
  ));
  let f = File::open(yaml_path)?;
  serde_yaml::from_reader::<File, Template>(f)
    .map_err(|x| new_io_error(&x.to_string()))
    .map(|mut t| {
      if name != t.id {
        t.id = format!("{}:{}", t.id, name);
      }
      t
    })
}

pub fn scan(config: &ObserverWardConfig, cl: Vec<ClusterType>, tx: Sender<ClusterExecuteRunner>) {
  let input = config.input();
  info!(
    "{}target loaded: {}",
    Emoji("🎯", ""),
    style(input.len()).blue()
  );
  let pool = ThreadPool::new(config.thread);
  for target in input.into_iter() {
    let config = config.clone();
    let cl = cl.clone();
    let tx = tx.clone();
    pool.execute(move || {
      debug!("{}: {}", Emoji("🚦", "start"), target);
      let mut runner = ClusterExecuteRunner::new(target);
      runner.run(cl.clone(), config.clone());
      debug!("{}: {}", Emoji("🔚", "end"), runner.target());
      tx.send(runner).unwrap_or_default();
    });
  }
  pool.join();
}
