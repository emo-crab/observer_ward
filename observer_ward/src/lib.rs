use crate::cli::{Mode, ObserverWardConfig};
use crate::error::new_io_error;
use crate::nuclei::{NucleiRunner, gen_nuclei_tags};
use console::{Emoji, style};
use engine::common::cert::X509Certificate;
use engine::common::html::extract_title;
use engine::common::http::HttpRecord;
use engine::execute::{ClusterExecute, ClusterType};
use engine::operators::matchers::FaviconMap;
use engine::request::RequestGenerator;
use engine::results::{FingerprintResult, NucleiResult};
use engine::slinger::http::StatusCode;
use engine::slinger::http::header::HeaderValue;
use engine::slinger::http::uri::{PathAndQuery, Uri};
use engine::slinger::redirect::Policy;
use engine::slinger::{Request, Response, http_serde};
use engine::template::Template;
use error::Result;
use futures::StreamExt;
use futures::channel::mpsc::UnboundedSender;
use futures::stream::FuturesUnordered;
use log::{debug, info};
use serde::{Deserialize, Serialize};
use std::collections::btree_map::Entry;
use std::collections::hash_map::DefaultHasher;
use std::collections::{BTreeMap, HashSet};
use std::fs::File;
use std::hash::Hasher;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};

pub mod api;
pub mod cli;
pub mod error;
pub mod helper;
pub mod input;
#[cfg(feature = "mcp")]
pub mod mcp;
mod nuclei;
pub mod output;

use engine::template::cluster::cluster_templates;

// 子路径下面的匹配结果
#[cfg_attr(feature = "mcp", derive(schemars::JsonSchema))]
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "kebab-case")]
pub struct MatchedResult {
  /// Collection of detected page titles (unique across different requests to same path)
  #[cfg_attr(
    feature = "mcp",
    schemars(
      title = "page titles",
      description = "Unique collection of detected page titles from different requests to same path",
      example = r#"["Homepage", "Login Page"]"#
    )
  )]
  title: HashSet<String>,
  /// Typical response body length in bytes
  #[cfg_attr(
    feature = "mcp",
    schemars(
      title = "response length",
      description = "Typical response body length in bytes",
      example = 1024
    )
  )]
  length: usize,
  // 最新状态码
  #[serde(with = "http_serde::option::status_code")]
  #[serde(skip_serializing_if = "Option::is_none")]
  #[cfg_attr(
    feature = "mcp",
    schemars(
      title = "status code",
      description = "The HTTP status code indicating the response status",
      example = 200,
      with = "Option<std::num::NonZeroU16>"
    )
  )]
  status: Option<StatusCode>,
  // favicon哈希
  /// Favicon hash mappings (keyed by favicon URL or path)
  #[cfg_attr(
    feature = "mcp",
    schemars(
      title = "favicon hashes",
      description = "Map of favicon hashes keyed by favicon URL/path",
      example = r#"{
            "/favicon.ico": {
                "md5": "d41d8cd98f00b204e9800998ecf8427e",
                "mmh3": -1205551036
            }
        }"#
    )
  )]
  favicon: BTreeMap<String, FaviconMap>,
  #[serde(skip_serializing_if = "Option::is_none")]
  #[cfg_attr(
    feature = "mcp",
    schemars(
      title = "SSL certificate",
      description = "SSL/TLS certificate information (present for HTTPS connections)",
    )
  )]
  certificate: Option<X509Certificate>,
  // 简化指纹列表
  /// Simplified fingerprint names/identifiers
  #[cfg_attr(
    feature = "mcp",
    schemars(
      title = "fingerprint names",
      description = "Simplified set of technology fingerprint names",
      example = r#"["nginx", "react", "bootstrap"]"#
    )
  )]
  name: HashSet<String>,
  // 指纹信息
  /// Detailed fingerprint matching results
  #[cfg_attr(
    feature = "mcp",
    schemars(
      title = "fingerprint details",
      description = "Detailed technology fingerprint matching results",
      example = r#"[{
            "name": "nginx",
            "version": "1.18.0",
            "confidence": 95
        }]"#
    )
  )]
  fingerprints: Vec<FingerprintResult>,
  // 漏洞信息
  /// Vulnerability detection results from Nuclei scans
  #[cfg_attr(
    feature = "mcp",
    schemars(
      title = "vulnerability findings",
      description = "Vulnerability detection results grouped by Nuclei template ID",
      example = r#"{
            "CVE-2021-44228": [{
                "template": "log4j-rce",
                "severity": "critical"
            }]
        }"#
    )
  )]
  nuclei: BTreeMap<String, Vec<Arc<NucleiResult>>>,
}

impl MatchedResult {
  pub fn title(&self) -> &HashSet<String> {
    &self.title
  }
  pub fn status(&self) -> &Option<StatusCode> {
    &self.status
  }
  pub fn fingerprint(&self) -> &Vec<FingerprintResult> {
    &self.fingerprints
  }
  pub fn nuclei_result(&self) -> &BTreeMap<String, Vec<Arc<NucleiResult>>> {
    &self.nuclei
  }

  fn update_matched(&mut self, result: &FingerprintResult) {
    let response = result.response().unwrap_or_default();
    let text = response.text().unwrap_or_default();
    let title = extract_title(&text);
    let status_code = response.status_code();
    if self.status.is_none() {
      self.status = Some(status_code);
    }
    if self.length < text.len() {
      self.length = text.len()
    }
    if let Some(t) = title {
      self.title.insert(t);
      self.status = Some(status_code);
    }
    // if self.certificate.is_none() {
    //   self.certificate = None;
    // }
    if let Some(fav) = response.extensions().get::<BTreeMap<String, FaviconMap>>() {
      self.favicon.extend(fav.clone());
    }
    if !result.matcher_result().is_empty() {
      debug!("{}{:#?}", Emoji("✅", ""), result.matcher_result());
      let mut result = result.clone();
      // 当标题为空时在提取器中template名称相同的键值为标题
      if self.title.is_empty() {
        result.matcher_result_mut().iter_mut().for_each(|x| {
          if let Some(template) = x.extractor.remove(&x.template) {
            self.title.extend(template);
          }
        });
      }
      self.name.extend(result.name());
      self.fingerprints.push(result);
    }
  }
  fn merge_nuclei_args(&self, template_dir: &Path) -> BTreeMap<String, NucleiRunner> {
    let mut nuclei_map: BTreeMap<String, NucleiRunner> = BTreeMap::new();
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
                .extend(gen_nuclei_tags(&vpf.product, &matcher_result.info.tags));
            }
            nuclei_map.insert(matcher_result.template.clone(), args);
          }
        }
      }
    }
    nuclei_map
  }
}

#[cfg_attr(feature = "mcp", derive(schemars::JsonSchema))]
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
#[serde(deny_unknown_fields)]
pub struct ClusterExecuteRunner {
  // 单个目标
  #[serde(with = "http_serde::uri")]
  #[cfg_attr(feature = "mcp", schemars(with = "String"))]
  target: Uri,
  // 子路径匹配结果
  matched_result: BTreeMap<String, MatchedResult>,
  http_record: Option<Arc<HttpRecord>>,
  cache: BTreeMap<u64, Response>,
}

impl ClusterExecuteRunner {
  pub fn result(&self) -> &BTreeMap<String, MatchedResult> {
    &self.matched_result
  }
  pub fn new(uri: &Uri) -> Self {
    Self {
      target: uri.clone(),
      matched_result: BTreeMap::new(),
      http_record: None,
      cache: Default::default(),
    }
  }
  fn update_result(&mut self, result: FingerprintResult, key: Option<String>) {
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
  fn use_nuclei(&mut self, config: &ObserverWardConfig) {
    let template_dir = if let Some(path) = &config.plugin {
      path.clone()
    } else {
      return;
    };
    // 相同插件和url只跑一次
    let mut skip_target: BTreeMap<String, Vec<String>> = BTreeMap::new();
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
        if let Some(nrs) = matched_result.nuclei.get_mut(key) {
          nrs.extend(nuclei_results.clone());
        } else {
          matched_result.nuclei.insert(key.clone(), nuclei_results);
        }
      }
    }
  }
}

// 处理http的探针
impl ClusterExecuteRunner {
  async fn http(
    &mut self,
    config: &ObserverWardConfig,
    cluster: &ClusterExecute,
    http_record: &mut HttpRecord,
  ) -> Result<()> {
    // 可能会有多个http，一般只有一个，多个会有flow控制
    for http in cluster.requests.http.iter() {
      let mut client_builder = http.http_option.builder_client();
      client_builder = client_builder.timeout(Some(Duration::from_secs(config.timeout)));
      client_builder = client_builder.redirect(Policy::Custom(engine::common::http::js_redirect));
      if let Ok(ua) = HeaderValue::from_str(&config.ua) {
        client_builder = client_builder.user_agent(ua);
      }
      if let Some(proxy) = &config.proxy {
        client_builder = client_builder.proxy(proxy.clone());
      }
      let client = client_builder.build().unwrap_or_default();
      let generator = RequestGenerator::new(http, self.target.clone());
      // 请求全部路径
      for request in generator {
        debug!("{}{:#?}", Emoji("📤", ""), request);
        let response = match self.cache.entry(self.get_request_hash(&request)) {
          Entry::Vacant(v) => v.insert(client.execute(request.clone()).await?),
          Entry::Occupied(o) => o.into_mut(),
        };
        debug!("{}{:#?}", Emoji("📥", ""), response);
        // 提取icon
        http_record.find_favicon_tag(response).await;
        let mut flag = false;
        let mut result = FingerprintResult::new(response);
        cluster
          .operators
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
  fn get_request_hash(&self, request: &Request) -> u64 {
    let mut hasher = DefaultHasher::new();
    hasher.write(request.method().to_string().as_bytes());
    hasher.write(request.uri().to_string().as_bytes());
    hasher.write(format!("{:?}", request.headers()).as_bytes());
    hasher.write(request.body().unwrap_or(&engine::slinger::Body::default()));
    hasher.finish()
  }
}

// 处理tcp的探针
impl ClusterExecuteRunner {
  // 单个tcp
  async fn tcp(&mut self, config: &ObserverWardConfig, cluster: &ClusterExecute) -> Result<bool> {
    // 服务指纹识别，实验功能
    let mut flag = false;
    for tcp in cluster.requests.tcp.iter() {
      let conn_builder = config.tcp_client_builder();
      let timeout = Duration::from_secs(config.timeout / 2);
      let mut socket = conn_builder
        .read_timeout(Some(timeout))
        .write_timeout(Some(timeout))
        .build()?
        .connect_with_uri(&self.target)
        .await?;
      for input in tcp.inputs.iter() {
        let data = input.data();
        let request = Request::raw(self.target.clone(), data.clone(), true);
        debug!("{}{:#?}", Emoji("📤", ""), request);
        socket.write_all(&data).await.unwrap_or_default();
        socket.flush().await.unwrap_or_default();
        let mut full = Vec::new();
        let mut buffer = vec![0; 12]; // 定义一个缓冲区
        let mut total_bytes_read = 0;
        // http超时对于tcp来说还是太长了
        while let Ok(n) = socket.read(&mut buffer).await {
          if n == 0 {
            break;
          }
          full.extend_from_slice(&buffer[..n]);
          total_bytes_read += n;
          // 检查是否读取到了全部数据，如果是，则退出循环
          if total_bytes_read >= input.read.unwrap_or(2048) {
            break;
          }
        }
        let mut response: Response = Response::builder().body(full).unwrap_or_default().into();
        response.extensions_mut().insert(request.clone());
        debug!("{}{:#?}", Emoji("📥", ""), response);
        // TCP的如果没有响应都不用匹配规则了
        if response.body().is_none() {
          continue;
        }
        let mut result = FingerprintResult::new(&response);
        cluster
          .operators
          .iter()
          .for_each(|operator| operator.matcher(&mut result));
        if !result.matcher_result().is_empty() {
          flag = true;
          self.update_result(result, Some(request.uri().to_string()));
        }
      }
    }
    Ok(flag)
  }
}

fn set_uri_scheme(scheme: &str, target: &Uri) -> Result<Uri> {
  Uri::builder()
    .scheme(scheme)
    .authority(
      target
        .authority()
        .map_or(target.host().unwrap_or_default(), |a| a.as_str()),
    )
    .path_and_query(
      target
        .path_and_query()
        .unwrap_or(&PathAndQuery::from_static("/"))
        .as_str(),
    )
    .build()
    .map_err(|e| new_io_error(&e.to_string()))
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

pub struct ObserverWard {
  config: ObserverWardConfig,
  cluster_type: ClusterType,
}
pub struct ExecuteResult {
  pub matched: BTreeMap<String, MatchedResult>,
  pub record: Option<Arc<HttpRecord>>,
}
impl ObserverWard {
  pub fn new(config: &ObserverWardConfig, cluster_type: ClusterType) -> Arc<Self> {
    Arc::new(Self {
      config: config.clone(),
      cluster_type,
    })
  }
  pub async fn execute(self: Arc<Self>, tx: UnboundedSender<ExecuteResult>) {
    let input = self.config.input();
    info!(
      "{}target loaded: {}",
      Emoji("🎯", ""),
      style(input.len()).blue()
    );
    let mut worker = FuturesUnordered::new();
    let mut targets = input.into_iter();
    for _ in 0..self.config.thread {
      if let Some(u) = targets.next() {
        worker.push(self.run(u));
      } else {
        break;
      }
    }
    while let Some(result) = worker.next().await {
      if let Some(u) = targets.next() {
        worker.push(self.run(u));
      }
      tx.unbounded_send(result).unwrap_or_default();
    }
  }
  async fn http(&self, runner: &mut ClusterExecuteRunner) {
    // TODO： 可以考虑加个多线程
    let mut http_record = HttpRecord::new(self.config.http_client_builder());
    for (index, clusters) in self.cluster_type.web_default.iter().enumerate() {
      if let Err(err) = runner.http(&self.config, clusters, &mut http_record).await {
        debug!("{}:{}", Emoji("💢", ""), err);
        // 首页访问失败
        if index == 0 {
          return;
        }
      }
    }
    for (index, clusters) in self.cluster_type.web_other.iter().enumerate() {
      if let Err(err) = runner.http(&self.config, clusters, &mut http_record).await {
        debug!("{}:{}", Emoji("💢", ""), err);
        // 第一次访问失败
        if index == 0 {
          break;
        }
      }
    }
    if let Some(resp) = http_record.fav_response() {
      let mut result = FingerprintResult::new(&resp);
      for clusters in self.cluster_type.web_favicon.iter() {
        // 匹配favicon的，要等index的全部跑完
        if http_record.has_favicon() {
          debug!(
            "{}: {:#?}",
            Emoji("⭐️", "favicon"),
            http_record.favicon_hash()
          );
          let now = Instant::now();
          clusters.operators.iter().for_each(|operator| {
            operator.matcher(&mut result);
          });
          debug!(
            "{}: {} secs",
            Emoji("⏳️", "time"),
            now.elapsed().as_secs_f32()
          );
        }
      }
      // 如果有图标或者结果什么都没有，保存一个首页请求
      if !result.matcher_result().is_empty()
        || runner.matched_result.is_empty()
        || !runner
          .matched_result
          .contains_key(&runner.target.to_string())
        || runner
          .matched_result
          .get(&runner.target.to_string())
          .is_some_and(|x| x.title.is_empty())
      {
        runner.update_result(result, None);
      }
    }
    runner.http_record = Some(Arc::new(http_record));
  }
  // 根据端口优先选择探针
  async fn tcp(&self, runner: &mut ClusterExecuteRunner) {
    let (mut include, mut exclude) = (Vec::new(), Vec::new());
    let port = if let Some(port) = runner.target.port_u16() {
      port
    } else {
      return;
    };
    for (name, port_range) in self.cluster_type.port_range.iter() {
      let clusters = if let Some(clusters) = self.cluster_type.tcp_other.get(name) {
        clusters
      } else {
        continue;
      };
      if let Some(pr) = port_range {
        if pr.contains(port) {
          include.push(clusters);
        } else {
          exclude.push(clusters);
        }
      } else {
        exclude.push(clusters);
      }
    }
    include.sort_by(|x, y| x.rarity.cmp(&y.rarity));
    exclude.sort_by(|x, y| x.rarity.cmp(&y.rarity));
    // 先跑有匹配到端口的，如果有匹配到就不跑其他的冷门指纹
    // TODO： 可以考虑加个多线程
    for clusters in include {
      if let Ok(flag) = runner.tcp(&self.config, clusters).await {
        if flag {
          break;
        }
      }
    }
    for clusters in exclude {
      runner.tcp(&self.config, clusters).await.unwrap_or_default();
    }
  }
  pub async fn run(&self, target: Uri) -> ExecuteResult {
    debug!("{}: {}", Emoji("🚦", "start"), target);
    let mut runner = ClusterExecuteRunner::new(&target);
    match target.scheme_str() {
      None => {
        // 如果没有协议尝试https和http
        match self.config.clone().mode.unwrap_or_default() {
          Mode::ALL => {
            self.handle_tcp_mode(&mut runner, &target).await;
            self.handle_http_mode(&mut runner, &target).await;
          }
          Mode::TCP => self.handle_tcp_mode(&mut runner, &target).await,
          Mode::HTTP => self.handle_http_mode(&mut runner, &target).await,
        }
      }
      // 只跑web指纹
      Some("http") | Some("https") => {
        self.http(&mut runner).await;
      }
      // 只跑服务指纹
      Some("tcp") | Some("tls") => {
        if let Some(tcp) = &self.cluster_type.tcp_default {
          if let Err(_err) = runner.tcp(&self.config, tcp).await {
            return ExecuteResult {
              matched: runner.matched_result,
              record: runner.http_record,
            };
          }
        }
        self.tcp(&mut runner).await;
      }
      // 跳过
      _ => {}
    }
    runner.use_nuclei(&self.config);
    runner.matched_result.values_mut().for_each(|mr| {
      if !self.config.ic {
        mr.certificate = None;
      }
      mr.fingerprints.iter_mut().for_each(|x| {
        if !self.config.ir {
          x.omit_raw()
        }
      })
    });
    debug!("{}: {}", Emoji("🔚", "end"), target);
    ExecuteResult {
      matched: runner.matched_result,
      record: runner.http_record,
    }
  }
  async fn handle_http_mode(&self, runner: &mut ClusterExecuteRunner, target: &Uri) {
    let schemes = vec!["https", "http"];
    for scheme in schemes {
      if let Ok(http_target) = set_uri_scheme(scheme, target) {
        runner.target = http_target;
        self.http(runner).await;
        if !runner.matched_result.is_empty() {
          break;
        }
      }
    }
  }

  async fn handle_tcp_mode(&self, runner: &mut ClusterExecuteRunner, target: &Uri) {
    if let Ok(tcp_target) = set_uri_scheme("tcp", target) {
      runner.target = tcp_target;
      if let Some(tcp) = &self.cluster_type.tcp_default {
        if let Err(_err) = runner.tcp(&self.config, tcp).await {
          return;
        }
      }
      self.tcp(runner).await;
    }
  }
}
