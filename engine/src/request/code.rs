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
  /// Returns true if this request uses the python engine.
  pub fn is_python(&self) -> bool {
    self.engine.iter().any(|e| e.eq_ignore_ascii_case("python"))
  }

  /// Execute the Python source code in a RustPython sandbox and return the captured stdout.
  ///
  /// Template variables derived from `target` are injected as module-level variables
  /// at the top of the script, matching nuclei's code protocol variable conventions.
  ///
  /// No standard library modules (os, sys, io, etc.) are available to the script.
  /// Returns `None` when the engine is not python or the code feature is disabled.
  #[cfg(feature = "code")]
  pub fn execute(&self, target: &Uri) -> Option<String> {
    if !self.is_python() {
      return None;
    }
    let preamble = build_preamble(target);
    let full_source = format!("{preamble}\n{}", self.source);
    run_python(&full_source)
  }
}

/// Build a Python preamble that injects template variables derived from `target`
/// so that user code can reference `Hostname`, `Host`, `Port`, `Scheme`, `BaseURL`.
#[cfg(feature = "code")]
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

#[cfg(feature = "code")]
fn default_port(scheme: &str) -> u16 {
  match scheme {
    "https" => 443,
    "http" => 80,
    _ => 0,
  }
}

/// Execute Python `source` in a RustPython interpreter with no stdlib modules loaded.
///
/// The built-in `print` function is overridden so that all output is captured and
/// returned as a `String` instead of being written to the process stdout.
#[cfg(feature = "code")]
fn run_python(source: &str) -> Option<String> {
  use rustpython_vm as vm;
  use vm::function::FuncArgs;

  thread_local! {
    static CAPTURED: std::cell::RefCell<String> = const { std::cell::RefCell::new(String::new()) };
  }

  // Reset the capture buffer for this invocation.
  CAPTURED.with(|c| c.borrow_mut().clear());

  let interpreter = vm::Interpreter::without_stdlib(Default::default());
  let _ = interpreter.enter(|vm| -> vm::PyResult<()> {
    let scope = vm.new_scope_with_builtins();

    // Replace the built-in `print` with a Rust function that appends to CAPTURED.
    let print_fn = vm.new_function(
      "print",
      |args: FuncArgs, vm: &vm::VirtualMachine| -> vm::PyResult<()> {
        let sep = match args.kwargs.get("sep") {
          None => " ".to_owned(),
          Some(v) if vm.is_none(v) => " ".to_owned(),
          Some(v) => v.str(vm).map(|r| r.to_string_lossy().into_owned())?,
        };
        let end = match args.kwargs.get("end") {
          None => "\n".to_owned(),
          Some(v) if vm.is_none(v) => "\n".to_owned(),
          Some(v) => v.str(vm).map(|r| r.to_string_lossy().into_owned())?,
        };
        let parts: vm::PyResult<Vec<String>> = args
          .args
          .iter()
          .map(|a| a.str(vm).map(|r| r.to_string_lossy().into_owned()))
          .collect();
        let line = format!("{}{}", parts?.join(&sep), end);
        CAPTURED.with(|c| c.borrow_mut().push_str(&line));
        Ok(())
      },
    );

    scope.globals.set_item("print", print_fn.into(), vm)?;

    let code = vm
      .compile(source, vm::compiler::Mode::Exec, "script.py".to_owned())
      .map_err(|e| vm.new_syntax_error(&e, Some(source)))?;
    vm.run_code_obj(code, scope).map(|_| ())
  });

  Some(CAPTURED.with(|c| std::mem::take(&mut *c.borrow_mut())))
}
