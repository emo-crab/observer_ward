use console::Emoji;
use engine::execute::{ClusterExecute, ClusterType, ClusteredOperator};
use engine::request::Requests;
use engine::template::Template;
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
        debug!("{}{}", Emoji("💢", ""), err);
      }
    }
  }
  for clusters in cluster(&compile_templates_list) {
    if clusters.is_empty() {
      continue;
    }
    let mut cops = Vec::new();
    let requests = clusters[0].requests.clone();
    for t in clusters {
      cops.push(ClusteredOperator::new(t));
    }
    // 如果请求是首页请求就加进去首页分类，否则加入危险分类
    if requests.is_safe() {
      executes.web_index.push(ClusterExecute {
        requests,
        operators: cops,
      });
    } else {
      executes.web_danger.push(ClusterExecute {
        requests,
        operators: cops,
      });
    }
  }
  // 确保favicon在最后，不用排序
  if !favicon_cops.is_empty() {
    executes.web_favicon.push(ClusterExecute {
      requests: Default::default(),
      operators: favicon_cops,
    });
  }
  // 如果只有图标hash，没有请求就补充一个Web首页请求
  if executes.web_index.is_empty() && !executes.web_favicon.is_empty() {
    executes.web_index.push(ClusterExecute {
      requests: Requests::default_web_index(),
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
