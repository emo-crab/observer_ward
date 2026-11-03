use crate::operators::Operators;
use serde::{Deserialize, Serialize};
use slinger::http::uri::Uri;

#[cfg_attr(feature = "mcp", derive(schemars::JsonSchema))]
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "kebab-case")]
pub struct CodeRequest {
  // Operators for the current request go here.
  #[serde(flatten)]
  pub operators: Operators,
  // ID is the optional id of the request
  pub id: Option<String>,
  pub engine: Vec<String>,
  #[serde(default)]
  pub args: Vec<String>,
  pub pattern: Option<String>,
  pub source: String,
}

impl CodeRequest {
  /// Returns true if this request uses the starlark engine.
  pub fn is_starlark(&self) -> bool {
    self
      .engine
      .iter()
      .any(|e| e.eq_ignore_ascii_case("starlark"))
  }

  /// Execute the Starlark source code and return the captured `print` output.
  ///
  /// Template variables derived from `target` are injected as module-level variables
  /// at the top of the script, matching nuclei's code protocol variable conventions.
  ///
  /// No standard library modules (os, sys, io, etc.) are available to the script.
  /// Returns `None` when the engine is not starlark or the code feature is disabled.
  pub fn execute(&self, target: &Uri) -> Option<String> {
    if !self.is_starlark() {
      return None;
    }
    let preamble = build_preamble(target);
    let full_source = format!("{preamble}\n{}", self.source);
    run_starlark(&full_source)
  }
}

/// Build a Starlark preamble that injects template variables derived from `target`
/// so that user code can reference `Hostname`, `Host`, `Port`, `Scheme`, `BaseURL`.
fn build_preamble(target: &Uri) -> String {
  let scheme = target.scheme_str().unwrap_or("http");
  let host = target.host().unwrap_or("");
  let port = target
    .port_u16()
    .map(|p| p.to_string())
    .unwrap_or_else(|| default_port(scheme).to_string());
  let hostname = if target.port_u16().is_some() {
    format!("{host}:{port}")
  } else {
    host.to_string()
  };
  let base_url = format!("{scheme}://{hostname}");
  format!(
    "Scheme = {scheme:?}\nHost = {host:?}\nPort = {port:?}\nHostname = {hostname:?}\nBaseURL = {base_url:?}\n"
  )
}

fn default_port(scheme: &str) -> u16 {
  match scheme {
    "https" => 443,
    "http" => 80,
    _ => 0,
  }
}

/// Accumulator for `print` output, shared with the evaluator via `eval.extra`.
#[derive(Debug, Default, starlark::any::ProvidesStaticType)]
struct Capture(std::cell::RefCell<String>);

impl Capture {
  fn add_line(&self, line: String) {
    self.0.borrow_mut().push_str(&line);
    self.0.borrow_mut().push('\n');
  }
}

/// Starlark builtins: a `print` that routes output into the capture buffer.
#[starlark::starlark_module]
fn code_globals(builder: &mut starlark::environment::GlobalsBuilder) {
  /// Print some values, separated by a single space, followed by a newline.
  fn print(
    #[starlark(args)] args: starlark::values::tuple::UnpackTuple<starlark::values::Value>,
    eval: &mut starlark::eval::Evaluator,
  ) -> anyhow::Result<starlark::values::none::NoneType> {
    let line = args
      .items
      .iter()
      .map(|v| v.to_str())
      .collect::<Vec<_>>()
      .join(" ");
    if let Some(c) = eval
      .extra
      .as_ref()
      .and_then(|extra| extra.downcast_ref::<Capture>()) { c.add_line(line) }
    Ok(starlark::values::none::NoneType)
  }
}

/// Execute Starlark `source` in an interpreter with no loadable modules.
///
/// `print` output is captured and returned instead of being written to the
/// process stdout. Parse or evaluation errors are logged and yield `None`.
fn run_starlark(source: &str) -> Option<String> {
  use starlark::environment::Module;
  use starlark::eval::Evaluator;
  use starlark::syntax::{AstModule, Dialect};

  let capture = Capture::default();
  Module::with_temp_heap(|module| {
    let mut eval = Evaluator::new(&module);
    eval.extra = Some(&capture);
    let globals = starlark::environment::GlobalsBuilder::standard()
      .with(code_globals)
      .build();
    let ast = match AstModule::parse("script.star", source.to_owned(), &Dialect::Standard) {
      Ok(ast) => ast,
      Err(err) => {
        log::warn!("starlark parse error: {err}");
        return None;
      }
    };
    match eval.eval_module(ast, &globals) {
      Ok(_) => Some(std::mem::take(&mut *capture.0.borrow_mut())),
      Err(err) => {
        log::warn!("starlark execution error: {err}");
        None
      }
    }
  })
}

#[cfg(test)]
mod tests {
  use super::*;

  fn code_req(engine: &str, source: &str) -> CodeRequest {
    CodeRequest {
      operators: Operators::default(),
      id: None,
      engine: vec![engine.to_owned()],
      args: vec![],
      pattern: None,
      source: source.to_owned(),
    }
  }

  #[test]
  fn test_starlark_captures_print() {
    let req = code_req("starlark", "print(2 + 2)\nprint(\"hello\", Hostname)\n");
    let target = Uri::from_static("http://example.com:8080/path");
    let output = req.execute(&target).expect("starlark should run");
    assert_eq!(output, "4\nhello example.com:8080\n");
  }

  #[test]
  fn test_non_starlark_engine_is_skipped() {
    let req = code_req("python", "print(1)");
    let target = Uri::from_static("http://example.com");
    assert!(req.execute(&target).is_none());
  }

  #[test]
  fn test_starlark_error_returns_none() {
    let req = code_req("starlark", "def broken(:");
    let target = Uri::from_static("http://example.com");
    assert!(req.execute(&target).is_none());
  }
}
