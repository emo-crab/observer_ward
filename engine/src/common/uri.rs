use slinger::http::uri::Uri;
use std::path::PathBuf;
pub(crate) fn join(cur_uri: &Uri, val: &str) -> Option<Uri> {
  let path = PathBuf::from(cur_uri.path()).join(val);
  Uri::builder()
    .scheme(cur_uri.scheme_str().unwrap_or_default())
    .authority(cur_uri.authority()?.as_str())
    .path_and_query(path.to_string_lossy().as_ref())
    .build()
    .ok()
}
