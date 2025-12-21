use crate::info::Info;
use crate::operators::{OperatorResult, Operators};
use crate::request::{PortRange, Requests};
use crate::results::MatchEvent;
use crate::template::Template;
use slinger::Request;
use std::collections::BTreeMap;
use std::sync::Arc;

#[derive(Debug, Clone)]
pub struct ClusteredOperator {
  template: Arc<str>,
  info: Arc<Info>,
  operators: Vec<Arc<Operators>>,
}

impl ClusteredOperator {
  pub fn new(t: Arc<Template>) -> Arc<Self> {
    let (name, _hash) = t.id.split_once(':').unwrap_or((&t.id, ":"));
    let template = Arc::<str>::from(name.to_string().into_boxed_str());
    Arc::new(Self {
      template,
      info: t.info.clone(),
      operators: t.requests.operators(),
    })
  }
  pub fn matcher(&self, results: &mut MatchEvent, operator_request: bool) {
    let response = results.response().unwrap_or_default();
    for operator in self.operators.iter() {
      // Response-only matching
      let mut response_operator_result = OperatorResult::default();
      if let Err(_err) = operator.matcher(&response, &mut response_operator_result) {
        // continue to attempt request-aware matching below
      } else {
        operator.extractor(
          self.info.get_version(),
          &response,
          &mut response_operator_result,
        );
        if response_operator_result.is_matched() || response_operator_result.is_extract() {
          results.push(&self.template, &self.info, response_operator_result);
        }
      }
      if !operator_request {
        return;
      }
      if let Some(req_ref) = response.extensions().get::<Request>() {
        let req = req_ref.clone();
        let mut request_operator_result = OperatorResult::default();
        if let Err(_err) =
          operator.matcher_generic(&req, Some(&response), &mut request_operator_result)
        {
          // continue to next operator
        } else {
          operator.extractor_generic(self.info.get_version(), &req, &mut request_operator_result);
          if request_operator_result.is_matched() || request_operator_result.is_extract() {
            results.push(&self.template, &self.info, request_operator_result);
          }
        }
      }
    }
  }
}

#[derive(Debug, Clone, Default)]
pub struct ClusterType {
  pub web_default: Vec<Arc<ClusterExecute>>,
  pub web_favicon: Vec<Arc<ClusterExecute>>,
  pub web_other: Vec<Arc<ClusterExecute>>,
  pub tcp_default: Option<Arc<ClusterExecute>>,
  pub tcp_other: BTreeMap<String, Arc<ClusterExecute>>,
  pub port_range: BTreeMap<String, Option<PortRange>>,
}

impl ClusterType {
  pub fn count(&self) -> usize {
    let mut count =
      self.web_default.len() + self.web_other.len() + self.web_favicon.len() + self.tcp_other.len();
    if self.tcp_default.is_some() {
      count += 1;
    }
    count
  }
}

#[derive(Debug, Clone)]
pub struct ClusterExecute {
  pub requests: Arc<Requests>,
  pub rarity: u8,
  pub operators: Vec<Arc<ClusteredOperator>>,
}
