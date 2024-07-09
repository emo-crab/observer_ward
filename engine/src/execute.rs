use crate::info::Info;
use crate::operators::{OperatorResult, Operators};
use crate::request::Requests;
use crate::results::ResultEvent;
use crate::template::Template;

#[derive(Debug, Clone)]
pub struct ClusteredOperator {
  template: String,
  info: Info,
  operators: Vec<Operators>,
}

impl ClusteredOperator {
  pub fn new(t: Template) -> Self {
    let template = t
      .id
      .split_once(':')
      .map_or(t.id.to_string(), |(name, _hash)| name.to_string());
    Self {
      template,
      info: t.info,
      operators: t.requests.operators(),
    }
  }
  pub fn matcher(&self, results: &mut ResultEvent) {
    let response = results.response().unwrap_or_default();
    for operator in self.operators.iter() {
      let mut result = OperatorResult::default();
      if let Err(_err) = operator.matcher(&response, &mut result) {
        continue;
      };
      operator.extractor(self.info.get_version(), &response, &mut result);
      if result.is_matched() || result.is_extract() {
        results.push(&self.template, &self.info, result);
      }
    }
  }
}

#[derive(Debug, Clone)]
pub enum ClusterType {
  Safe(ClusterExecute),
  Danger(ClusterExecute),
  Favicon(ClusterExecute),
}

#[derive(Debug, Clone)]
pub struct ClusterExecute {
  pub requests: Requests,
  pub operators: Vec<ClusteredOperator>,
}
