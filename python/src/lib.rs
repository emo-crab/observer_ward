use pyo3::prelude::*;
use pyo3::types::{PyDict, PyList};
use std::fs;
use std::collections::HashMap;
use engine::execute::ClusteredOperator;
use engine::results::FingerprintResult;
use engine::template::Template;
use slinger::http::StatusCode;
use slinger::Response;

#[pyclass]
struct ObserverWard {
    operators: Vec<ClusteredOperator>,
}

#[pymethods]
impl ObserverWard {
    #[new]
    #[pyo3(signature = (json_content=None))]
    fn new(json_content: Option<&str>) -> PyResult<Self> {
        let operators = match json_content {
            Some(content) => create_operators_from_json(content),
            None => {
                // 尝试从默认位置读取指纹库
                match fs::read_to_string("./web_fingerprint_v4.json") {
                    Ok(content) => create_operators_from_json(&content),
                    Err(_) => {
                        return Err(PyErr::new::<pyo3::exceptions::PyFileNotFoundError, _>(
                            "找不到指纹库文件。请提供有效的JSON内容或确保web_fingerprint_v4.json可用。"
                        ));
                    }
                }
            }
        };
        
        Ok(Self { operators })
    }
    
    fn execute(&self, py: Python, html_content: String, headers: Vec<(String, String)>) -> PyResult<PyObject> {
        let mut builder = Response::builder();
        
        for (name, value) in &headers {
            builder = builder.header(name, value);
        }
        
        let response = builder
            .status(StatusCode::OK)
            .body(html_content.into_bytes())
            .unwrap_or_default()
            .into();
        
        let mut result = FingerprintResult::new(&response);
        
        for operator in self.operators.clone() {
            operator.matcher(&mut result);
        }

        // 将匹配结果转换为Python对象，并进行去重
        let matcher_results = result.matcher_result();
        
        let mut deduplicated_results: HashMap<String, PyObject> = HashMap::new();
        for mr in matcher_results {
            if deduplicated_results.contains_key(&mr.info.name) {
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
            
            deduplicated_results.insert(mr.info.name.clone(), dict.into());
        }
        
        let results_list = PyList::new(py, deduplicated_results.values())?;
        
        Ok(results_list.into())
    }
}

/// 通过 JSON 字符串创建并返回 operators
///
/// 假设 JSON 字符串表示模板数组，每个模板可用于构造 ClusteredOperator 实例。
pub fn create_operators_from_json(json: &str) -> Vec<ClusteredOperator> {
    // 使用 serde_json 解析 JSON 字符串为模板数组
    let templates: Vec<Template> = serde_json::from_str(json)
        .expect("解析 JSON 失败，请检查输入格式");

    // 遍历每个模板，创建 ClusteredOperator 对象并收集到 operators 数组中
    let operators: Vec<ClusteredOperator> = templates.into_iter()
        .map(ClusteredOperator::new)
        .collect();

    println!("已接收到 {} 个指纹模板", operators.len());

    operators
}

/// Python模块定义
#[pymodule]
#[pyo3(name = "observer_ward_py")]
fn observer_ward_py(_py: Python, m: &Bound<PyModule>) -> PyResult<()> {
    m.add_class::<ObserverWard>()?;
    Ok(())
}
