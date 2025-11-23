use crate::error::Result;
use slinger::{Body, Request, Response};

/// Trait for types that can be matched and extracted from
pub trait OperatorTarget {
  /// Get headers as a formatted string
  fn get_headers(&self) -> String;
  
  /// Get body if available
  fn get_body(&self) -> Option<Body>;
  
  /// Get a specific header value by name
  fn get_header(&self, name: &str) -> Option<String>;
  
  /// Get the full content (headers + body) for matching
  fn get_full_content(&self) -> String {
    let body = self.get_body();
    let body_string = if let Some(body) = body {
      match String::from_utf8(body.as_ref().to_vec()) {
        Ok(s) => s,
        Err(_) => format!("{}", body.escape_ascii()),
      }
    } else {
      String::new()
    };
    let header_string = self.get_headers();
    format!("{header_string}\r\n\r\n{body_string}")
  }
  
  /// Get body as string
  fn get_body_string(&self) -> String {
    if let Some(body) = self.get_body() {
      match String::from_utf8(body.as_ref().to_vec()) {
        Ok(s) => s,
        Err(_) => format!("{}", body.escape_ascii()),
      }
    } else {
      String::new()
    }
  }
}

/// Implementation for slinger::Response
impl OperatorTarget for Response {
  fn get_headers(&self) -> String {
    let mut header_string = String::new();
    for (k, v) in self.headers() {
      header_string.push_str(&format!("{}: {}\r\n", k, v.to_str().unwrap_or_default()));
    }
    header_string
  }
  
  fn get_body(&self) -> Option<Body> {
    self.body().clone()
  }
  
  fn get_header(&self, name: &str) -> Option<String> {
    self.headers()
      .get(name)
      .and_then(|v| v.to_str().ok())
      .map(|s| s.to_string())
  }
}

/// Implementation for slinger::Request
impl OperatorTarget for Request {
  fn get_headers(&self) -> String {
    let mut header_string = String::new();
    for (k, v) in self.headers.iter() {
      header_string.push_str(&format!("{}: {}\r\n", k, v.to_str().unwrap_or_default()));
    }
    header_string
  }
  
  fn get_body(&self) -> Option<Body> {
    self.body.clone()
  }
  
  fn get_header(&self, name: &str) -> Option<String> {
    self.headers
      .get(name)
      .and_then(|v| v.to_str().ok())
      .map(|s| s.to_string())
  }
}

/// Part represents which part of the target to extract/match from
#[derive(Debug, Clone)]
pub enum TargetPart {
  Body,
  Header,
  Full,
  Name(String),
}

impl TargetPart {
  /// Get the content from the target based on the part type
  pub fn get_content<T: OperatorTarget>(&self, target: &T) -> Result<(String, Option<Body>)> {
    use crate::error::Error;
    
    let body = target.get_body();
    let result = match self {
      TargetPart::Body => target.get_body_string(),
      TargetPart::Header => target.get_headers(),
      TargetPart::Full => target.get_full_content(),
      TargetPart::Name(name) => {
        target.get_header(name).ok_or_else(|| {
          Error::IO(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("header '{}' not found", name),
          ))
        })?
      }
    };
    Ok((result, body))
  }
}
