use engine::execute::ClusterType;
use engine::results::MatchEvent;
use engine::template::Template;
use engine::template::cluster::cluster_templates;
use pyo3::prelude::*;
use pyo3::types::{PyDict, PyList};
use slinger::Response;
use slinger::http::StatusCode;
use std::collections::HashSet;

#[pyclass]
struct ObserverWard {
  cluster_type: ClusterType,
}

#[pymethods]
impl ObserverWard {
  #[new]
  #[pyo3(signature = (json_content=None))]
  fn new(json_content: Option<&str>) -> PyResult<Self> {
    let cluster_type = match json_content {
      Some(content) => create_operators_from_json(content)?,
      None => {
        // 尝试从默认位置读取指纹库
        let content = std::fs::read_to_string("./web_fingerprint_v4.json").map_err(|_| {
          PyErr::new::<pyo3::exceptions::PyFileNotFoundError, _>(
            "找不到指纹库文件。请提供有效的JSON内容或确保web_fingerprint_v4.json可用。",
          )
        })?;
        create_operators_from_json(&content)?
      }
    };

    Ok(Self { cluster_type })
  }

  fn execute(
    &self,
    py: Python,
    html_content: String,
    headers: Vec<(String, String)>,
  ) -> PyResult<Py<PyAny>> {
    let mut builder = Response::builder();

    for (name, value) in &headers {
      builder = builder.header(name, value);
    }

    let response = builder
      .status(StatusCode::OK)
      .body(html_content.into_bytes())
      .map_err(|e| {
        PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(format!("构建 response 失败: {}", e))
      })?
      .into();

    let mut result = MatchEvent::new(&response);

    for cluster_execute in self.cluster_type.web_default.iter() {
      cluster_execute.operators.iter().for_each(|operator| {
        operator.matcher(&mut result, false);
      });
    }
    for cluster_execute in self.cluster_type.web_other.iter() {
      cluster_execute.operators.iter().for_each(|operator| {
        operator.matcher(&mut result, false);
      });
    }
    // 将匹配结果转换为Python对象，并进行去重
    let matcher_results = result.matcher_result();

    // 构建一个 Python 列表，同时用 HashSet 做去重（按 mr.info.name）
    let results_list = PyList::empty(py);
    let mut seen: HashSet<String> = HashSet::new();

    for mr in matcher_results {
      if seen.contains(&mr.info.name) {
        continue;
      }

      let dict = PyDict::new(py);
      dict.set_item("name", &mr.info.name)?;
      dict.set_item("template", &mr.template)?;
      dict.set_item("tags", &mr.info.tags)?;
      dict.set_item("matcher_names", &mr.matcher_name)?;

      let extractor_dict = PyDict::new(py);
      for (key, values) in &mr.extractor {
        extractor_dict.set_item(key, values)?;
      }
      dict.set_item("extractor", extractor_dict)?;

      results_list.append(dict)?;
      seen.insert(mr.info.name.clone());
    }

    Ok(results_list.into())
  }
}

/// 通过 JSON 字符串创建并返回 operators
///
/// 假设 JSON 字符串表示模板数组，每个模板可用于构造 ClusteredOperator 实例。
pub fn create_operators_from_json(json: &str) -> PyResult<ClusterType> {
  // 使用 serde_json 解析 JSON 字符串为模板数组
  let templates: Vec<Template> = serde_json::from_str(json).map_err(|e| {
    PyErr::new::<pyo3::exceptions::PyValueError, _>(format!(
      "解析 JSON 失败，请检查输入格式: {}",
      e
    ))
  })?;
  let ct = cluster_templates(&templates[..]);
  Ok(ct)
}

/// Python模块定义
#[pymodule]
#[pyo3(name = "observer_ward")]
fn observer_ward(_py: Python, m: &Bound<PyModule>) -> PyResult<()> {
  m.add_class::<ObserverWard>()?;
  Ok(())
}
