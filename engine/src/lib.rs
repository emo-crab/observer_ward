pub mod common;
pub mod error;
pub mod execute;
pub mod extractors;
pub mod info;
pub mod matchers;
pub mod operators;
pub mod request;
pub mod results;
pub mod serde_format;
pub mod template;

pub use slinger;
use std::path::{Path, PathBuf};

fn is_hidden(entry: &std::fs::DirEntry) -> bool {
  entry
    .file_name()
    .to_str()
    .map(|s| !s.starts_with('.'))
    .unwrap_or(false)
}

pub fn find_yaml_file(path: &PathBuf, nest: bool) -> Vec<PathBuf> {
  let mut yaml_file_list: Vec<PathBuf> = Vec::new();
  if let Ok(read_dir) = Path::new(&path).read_dir() {
    for element in read_dir.filter_map(|res| res.ok()).filter(is_hidden) {
      if element.path().is_dir() && nest {
        yaml_file_list.extend(find_yaml_file(&element.path(), nest));
      }
      if element.path().is_file() && element.path().extension() == Some("yaml".as_ref()) {
        yaml_file_list.push(element.path());
      }
    }
  }
  yaml_file_list
}
