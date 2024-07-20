use crate::execute::{ClusterExecute, ClusterType, ClusteredOperator};
use crate::request::Requests;
use crate::template::Template;
use log::debug;
use std::collections::HashSet;

// 根据优化生成请求和匹配组合
pub fn cluster_templates(templates_list: &[Template]) -> ClusterType {
  let mut compile_templates_list = Vec::new();
  let mut favicon_cops = Vec::new();
  let mut executes = ClusterType::default();
  for mut template in templates_list.iter().cloned() {
    // 编译正则和一些预处理
    match template.compile() {
      Ok(_) => {
        // 剔除图标指纹，如果还有其他规则就加进已经编译列表
        let favicon = template.find_favicon();
        if !template
          .requests
          .operators()
          .iter()
          .map(|op| op.matchers.is_empty() && op.extractors.is_empty())
          .all(|op| op)
        {
          compile_templates_list.push(template);
        }
        if let Some(fav) = favicon {
          favicon_cops.push(ClusteredOperator::new(fav));
        }
      }
      Err(err) => {
        debug!("{}{}", template.id, err);
      }
    }
  }
  for clusters in cluster(&compile_templates_list) {
    if clusters.is_empty() {
      continue;
    }
    let requests = clusters[0].requests.clone();
    let info = clusters[0].info.clone();
    let cops = clusters.into_iter().map(ClusteredOperator::new).collect();
    let cluster_execute = ClusterExecute {
      requests: requests.clone(),
      rarity: info.get_rarity().unwrap_or_default(),
      operators: cops,
    };
    if let Some(_web) = requests.is_web() {
      // 如果请求是首页请求就加进去首页分类，否则加入危险分类
      if requests.is_web_default() {
        executes.web_default.push(cluster_execute);
      } else {
        executes.web_other.push(cluster_execute);
      }
    } else if let Some(tcp) = requests.is_tcp() {
      if requests.is_tcp_default() {
        executes.tcp_default = Some(cluster_execute)
      } else {
        executes
          .tcp_other
          .insert(tcp.name.clone().unwrap_or_default(), cluster_execute);
        executes
          .port_range
          .insert(tcp.name.clone().unwrap_or_default(), tcp.port.clone());
      }
    }
  }
  // 确保favicon在最后，不用排序
  if !favicon_cops.is_empty() {
    executes.web_favicon.push(ClusterExecute {
      requests: Default::default(),
      rarity: 0,
      operators: favicon_cops,
    });
  }
  // 如果只有图标hash，没有请求就补充一个Web首页请求
  if executes.web_default.is_empty() && !executes.web_favicon.is_empty() {
    executes.web_default.push(ClusterExecute {
      requests: Requests::default_web_index(),
      rarity: 0,
      operators: vec![],
    })
  }
  executes
}

// 分类优化请求
fn cluster(list: &[Template]) -> Vec<Vec<Template>> {
  let mut all_cluster = Vec::new();
  let mut skip = HashSet::new();
  for t in list.to_owned().iter() {
    // 排除重复的id
    if !skip.contains(&t.id) {
      skip.insert(&t.id);
    } else {
      continue;
    }
    if t.requests.http.len() == 1 || t.requests.tcp.len() == 1 {
      let mut cluster = Vec::new();
      for ot in list.iter() {
        if skip.contains(&ot.id) {
          continue;
        }
        if t.requests.can_cluster(&ot.requests) {
          skip.insert(&ot.id);
          cluster.push(ot.clone());
        };
      }
      if !cluster.is_empty() {
        cluster.push(t.clone());
        all_cluster.push(cluster);
      } else {
        all_cluster.push(vec![t.clone()]);
      }
    } else {
      all_cluster.push(vec![t.clone()]);
    }
  }
  all_cluster
}
