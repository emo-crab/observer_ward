#[cfg(target_os = "windows")]
use winres;

// only build for windows
#[cfg(target_os = "windows")]
fn main() {
  use std::io::Write;
  let target = std::env::var("TARGET").unwrap_or_else(|_| "unknown-target".to_string());
  println!("cargo:rustc-env=OBSERVER_WARD_TARGET={}", target);
  // only build the resource for release builds
  // as calling rc.exe might be slow
  if std::env::var("PROFILE").unwrap() == "release" {
    let mut res = winres::WindowsResource::new();
    res.set_icon("res//logo.ico");
    match res.compile() {
      Err(e) => {
        write!(std::io::stderr(), "{}", e).unwrap();
        std::process::exit(1);
      }
      Ok(_) => {}
    }
  }
}

// nothing to do for other operating systems
#[cfg(not(target_os = "windows"))]
fn main() {
  let target = std::env::var("TARGET").unwrap_or_else(|_| "unknown-target".to_string());
  println!("cargo:rustc-env=OBSERVER_WARD_TARGET={target}");
}
