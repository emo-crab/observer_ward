use cel::extractors::{Arguments, This};
use cel::objects::Value;
use cel::{Context, ExecutionError, FunctionContext, Program};
use log::error;
use std::collections::HashMap;
use std::sync::Arc;

type CelResult<T> = Result<T, ExecutionError>;

/// Variables extracted from HTTP response for DSL evaluation
#[derive(Debug, Clone, Default)]
pub struct DslVariables {
  pub body: String,
  pub all_headers: String,
  pub status_code: u16,
  pub content_length: i64,
  pub content_type: String,
  /// Extra variables from extractors or template variables
  pub extra: HashMap<String, String>,
}

/// Evaluate a nuclei DSL expression against the given variables.
/// Returns true if the expression evaluates to a truthy value.
pub fn evaluate_dsl(expression: &str, vars: &DslVariables) -> Result<bool, String> {
  let preprocessed = preprocess_expression(expression);
  let program = Program::compile(&preprocessed).map_err(|e| format!("DSL parse error: {e}"))?;
  let ctx = build_context(vars);
  match program.execute(&ctx) {
    Ok(Value::Bool(b)) => Ok(b),
    Ok(Value::Int(i)) => Ok(i != 0),
    Ok(Value::UInt(u)) => Ok(u != 0),
    Ok(Value::Float(f)) => Ok(f != 0.0),
    Ok(Value::String(s)) => Ok(!s.is_empty()),
    Ok(Value::Null) => Ok(false),
    Ok(v) => Err(format!("DSL expression returned non-boolean value: {v:?}")),
    Err(e) => Err(format!("DSL evaluation error: {e}")),
  }
}

/// Preprocess nuclei DSL expression to be compatible with CEL syntax.
/// Handles nuclei-specific syntax that differs from CEL.
fn preprocess_expression(expr: &str) -> String {
  let mut result = expr.to_string();
  // Nuclei uses 'true' and 'false' as boolean literals (same in CEL, no change needed)
  // Nuclei uses '&&' and '||' (same in CEL, no change needed)
  // Nuclei uses '==' and '!=' (same in CEL, no change needed)

  // Handle nuclei's `!=` comparison that might appear between string and int
  // No transformation needed since CEL handles this

  // Handle potential bare `content_length` references that might need int conversion
  // CEL handles this natively

  // Replace nuclei's `\r\n` literal escape sequences in string comparisons if any
  result = result.replace("\\r\\n", "\r\n");

  result
}

/// Build a CEL context with nuclei-compatible functions and variables.
fn build_context(vars: &DslVariables) -> Context<'static> {
  let mut ctx = Context::default();

  // Add response variables
  ctx.add_variable_from_value("body", vars.body.clone());
  ctx.add_variable_from_value("all_headers", vars.all_headers.clone());
  ctx.add_variable_from_value("header", vars.all_headers.clone());
  ctx.add_variable_from_value("raw", format!("{}\r\n\r\n{}", vars.all_headers, vars.body));
  ctx.add_variable_from_value(
    "response",
    format!("{}\r\n\r\n{}", vars.all_headers, vars.body),
  );
  ctx.add_variable_from_value("status_code", vars.status_code as i64);
  ctx.add_variable_from_value("content_length", vars.content_length);
  ctx.add_variable_from_value("content_type", vars.content_type.clone());

  // Add extra variables from extractors/template
  for (k, v) in &vars.extra {
    ctx.add_variable_from_value(k.as_str(), v.clone());
  }

  // Register nuclei-compatible DSL functions
  register_nuclei_functions(&mut ctx);

  ctx
}

/// Register all nuclei-compatible DSL functions into the CEL context.
fn register_nuclei_functions(ctx: &mut Context) {
  // String functions
  ctx.add_function("tolower", dsl_tolower);
  ctx.add_function("to_lower", dsl_tolower);
  ctx.add_function("toupper", dsl_toupper);
  ctx.add_function("to_upper", dsl_toupper);
  ctx.add_function("trim", dsl_trim);
  ctx.add_function("trim_left", dsl_trim_left);
  ctx.add_function("trim_right", dsl_trim_right);
  ctx.add_function("trim_space", dsl_trim_space);
  ctx.add_function("trim_prefix", dsl_trim_prefix);
  ctx.add_function("trim_suffix", dsl_trim_suffix);
  ctx.add_function("reverse", dsl_reverse);
  ctx.add_function("replace", dsl_replace);
  ctx.add_function("replace_regex", dsl_replace_regex);
  ctx.add_function("repeat", dsl_repeat);
  ctx.add_function("split", dsl_split);
  ctx.add_function("join", dsl_join);
  ctx.add_function("concat", dsl_concat);
  ctx.add_function("sort", dsl_sort);
  ctx.add_function("uniq", dsl_uniq);
  ctx.add_function("len", dsl_len);

  // Matching functions
  ctx.add_function("contains_all", dsl_contains_all);
  ctx.add_function("contains_any", dsl_contains_any);
  ctx.add_function("starts_with", dsl_starts_with);
  ctx.add_function("ends_with", dsl_ends_with);
  ctx.add_function("regex", dsl_regex);
  ctx.add_function("re", dsl_regex);

  // Hash functions
  ctx.add_function("md5", dsl_md5);
  ctx.add_function("sha1", dsl_sha1);
  ctx.add_function("sha256", dsl_sha256);
  ctx.add_function("sha512", dsl_sha512);
  ctx.add_function("mmh3", dsl_mmh3);

  // Encoding functions
  ctx.add_function("base64", dsl_base64_encode);
  ctx.add_function("base64_py", dsl_base64_py);
  ctx.add_function("base64_decode", dsl_base64_decode);
  ctx.add_function("url_encode", dsl_url_encode);
  ctx.add_function("url_decode", dsl_url_decode);
  ctx.add_function("hex_encode", dsl_hex_encode);
  ctx.add_function("hex_decode", dsl_hex_decode);
  ctx.add_function("html_escape", dsl_html_escape);
  ctx.add_function("html_unescape", dsl_html_unescape);

  // Conversion functions
  ctx.add_function("to_number", dsl_to_number);
  ctx.add_function("to_string", dsl_to_string);

  // Utility functions
  ctx.add_function("rand_int", dsl_rand_int);
  ctx.add_function("rand_text_alpha", dsl_rand_text_alpha);
  ctx.add_function("rand_text_alphanumeric", dsl_rand_text_alphanumeric);
  ctx.add_function("rand_base", dsl_rand_base);
  ctx.add_function("generate_java_gadget", dsl_generate_java_gadget);
  ctx.add_function("wait_for", dsl_wait_for);
  ctx.add_function("print_debug", dsl_print_debug);
  ctx.add_function("index", dsl_index);
}

// ---------------------------------------------------------------------------
// String functions
// ---------------------------------------------------------------------------

fn dsl_tolower(This(s): This<Arc<String>>) -> String {
  s.to_lowercase()
}

fn dsl_toupper(This(s): This<Arc<String>>) -> String {
  s.to_uppercase()
}

fn dsl_trim(This(s): This<Arc<String>>, cutset: Arc<String>) -> String {
  s.trim_matches(|c: char| cutset.contains(c)).to_string()
}

fn dsl_trim_left(This(s): This<Arc<String>>, cutset: Arc<String>) -> String {
  s.trim_start_matches(|c: char| cutset.contains(c))
    .to_string()
}

fn dsl_trim_right(This(s): This<Arc<String>>, cutset: Arc<String>) -> String {
  s.trim_end_matches(|c: char| cutset.contains(c)).to_string()
}

fn dsl_trim_space(This(s): This<Arc<String>>) -> String {
  s.trim().to_string()
}

fn dsl_trim_prefix(This(s): This<Arc<String>>, prefix: Arc<String>) -> String {
  s.strip_prefix(prefix.as_str()).unwrap_or(&s).to_string()
}

fn dsl_trim_suffix(This(s): This<Arc<String>>, suffix: Arc<String>) -> String {
  s.strip_suffix(suffix.as_str()).unwrap_or(&s).to_string()
}

fn dsl_reverse(This(s): This<Arc<String>>) -> String {
  s.chars().rev().collect()
}

fn dsl_replace(This(s): This<Arc<String>>, old: Arc<String>, new: Arc<String>) -> String {
  s.replace(old.as_str(), new.as_str())
}

fn dsl_replace_regex(
  ftx: &FunctionContext,
  This(s): This<Arc<String>>,
  pattern: Arc<String>,
  replacement: Arc<String>,
) -> CelResult<Value> {
  let re =
    regex::Regex::new(&pattern).map_err(|e| ftx.error(format!("invalid regex pattern: {e}")))?;
  Ok(Value::String(Arc::new(
    re.replace_all(&s, replacement.as_str()).to_string(),
  )))
}

fn dsl_repeat(This(s): This<Arc<String>>, count: i64) -> String {
  s.repeat(count.max(0) as usize)
}

fn dsl_split(
  ftx: &FunctionContext,
  This(s): This<Arc<String>>,
  sep: Arc<String>,
) -> CelResult<Value> {
  let _ = ftx;
  let parts: Vec<Value> = s
    .split(sep.as_str())
    .map(|p| Value::String(Arc::new(p.to_string())))
    .collect();
  Ok(Value::List(Arc::new(parts)))
}

fn dsl_join(Arguments(args): Arguments) -> CelResult<Value> {
  if args.is_empty() {
    return Ok(Value::String(Arc::new(String::new())));
  }
  let sep = value_to_string(&args[0]);
  let parts: Vec<String> = args[1..].iter().map(value_to_string).collect();
  Ok(Value::String(Arc::new(parts.join(&sep))))
}

fn dsl_concat(Arguments(args): Arguments) -> CelResult<Value> {
  let mut result = String::new();
  for arg in args.iter() {
    result.push_str(&value_to_string(arg));
  }
  Ok(Value::String(Arc::new(result)))
}

fn dsl_sort(This(s): This<Arc<String>>) -> String {
  let mut chars: Vec<char> = s.chars().collect();
  chars.sort();
  chars.into_iter().collect()
}

fn dsl_uniq(This(s): This<Arc<String>>) -> String {
  let mut seen = std::collections::HashSet::new();
  s.chars().filter(|c| seen.insert(*c)).collect()
}

fn dsl_len(This(v): This<Value>) -> CelResult<Value> {
  let length = match v {
    Value::String(s) => s.len() as i64,
    Value::List(l) => l.len() as i64,
    Value::Map(m) => m.map.len() as i64,
    Value::Bytes(b) => b.len() as i64,
    _ => return Ok(Value::Int(0)),
  };
  Ok(Value::Int(length))
}

// ---------------------------------------------------------------------------
// Matching functions
// ---------------------------------------------------------------------------

fn dsl_contains_all(Arguments(args): Arguments) -> CelResult<Value> {
  if args.len() < 2 {
    return Ok(Value::Bool(false));
  }
  let body = value_to_string(&args[0]);
  for arg in &args[1..] {
    if !body.contains(&value_to_string(arg)) {
      return Ok(Value::Bool(false));
    }
  }
  Ok(Value::Bool(true))
}

fn dsl_contains_any(Arguments(args): Arguments) -> CelResult<Value> {
  if args.len() < 2 {
    return Ok(Value::Bool(false));
  }
  let body = value_to_string(&args[0]);
  for arg in &args[1..] {
    if body.contains(&value_to_string(arg)) {
      return Ok(Value::Bool(true));
    }
  }
  Ok(Value::Bool(false))
}

fn dsl_starts_with(This(s): This<Arc<String>>, prefix: Arc<String>) -> bool {
  s.starts_with(prefix.as_str())
}

fn dsl_ends_with(This(s): This<Arc<String>>, suffix: Arc<String>) -> bool {
  s.ends_with(suffix.as_str())
}

fn dsl_regex(ftx: &FunctionContext, pattern: Arc<String>, input: Arc<String>) -> CelResult<Value> {
  let re =
    regex::Regex::new(&pattern).map_err(|e| ftx.error(format!("invalid regex pattern: {e}")))?;
  Ok(Value::Bool(re.is_match(&input)))
}

// ---------------------------------------------------------------------------
// Hash functions
// ---------------------------------------------------------------------------

fn dsl_md5(This(s): This<Arc<String>>) -> String {
  use md5::Digest;
  let hash = md5::Md5::digest(s.as_bytes());
  hex::encode(hash)
}

fn dsl_sha1(This(s): This<Arc<String>>) -> String {
  use sha1::Digest;
  let hash = sha1::Sha1::digest(s.as_bytes());
  format!("{:x}", hash)
}

fn dsl_sha256(This(s): This<Arc<String>>) -> String {
  use sha2::Digest;
  let hash = sha2::Sha256::digest(s.as_bytes());
  format!("{:x}", hash)
}

fn dsl_sha512(This(s): This<Arc<String>>) -> String {
  use sha2::Digest;
  let hash = sha2::Sha512::digest(s.as_bytes());
  format!("{:x}", hash)
}

fn dsl_mmh3(This(s): This<Arc<String>>) -> String {
  // Simple MurmurHash3 32-bit implementation matching nuclei's behavior
  let hash = murmur3_32(s.as_bytes(), 0);
  format!("{}", hash as i32)
}

/// MurmurHash3 32-bit hash implementation
fn murmur3_32(data: &[u8], seed: u32) -> u32 {
  let c1: u32 = 0xcc9e2d51;
  let c2: u32 = 0x1b873593;
  let mut h1 = seed;
  let len = data.len();
  let nblocks = len / 4;

  for i in 0..nblocks {
    let offset = i * 4;
    let mut k1 = u32::from_le_bytes([
      data[offset],
      data[offset + 1],
      data[offset + 2],
      data[offset + 3],
    ]);
    k1 = k1.wrapping_mul(c1);
    k1 = k1.rotate_left(15);
    k1 = k1.wrapping_mul(c2);
    h1 ^= k1;
    h1 = h1.rotate_left(13);
    h1 = h1.wrapping_mul(5).wrapping_add(0xe6546b64);
  }

  let tail = &data[nblocks * 4..];
  let mut k1: u32 = 0;
  match tail.len() {
    3 => {
      k1 ^= (tail[2] as u32) << 16;
      k1 ^= (tail[1] as u32) << 8;
      k1 ^= tail[0] as u32;
      k1 = k1.wrapping_mul(c1);
      k1 = k1.rotate_left(15);
      k1 = k1.wrapping_mul(c2);
      h1 ^= k1;
    }
    2 => {
      k1 ^= (tail[1] as u32) << 8;
      k1 ^= tail[0] as u32;
      k1 = k1.wrapping_mul(c1);
      k1 = k1.rotate_left(15);
      k1 = k1.wrapping_mul(c2);
      h1 ^= k1;
    }
    1 => {
      k1 ^= tail[0] as u32;
      k1 = k1.wrapping_mul(c1);
      k1 = k1.rotate_left(15);
      k1 = k1.wrapping_mul(c2);
      h1 ^= k1;
    }
    _ => {}
  }

  h1 ^= len as u32;
  // fmix32
  h1 ^= h1 >> 16;
  h1 = h1.wrapping_mul(0x85ebca6b);
  h1 ^= h1 >> 13;
  h1 = h1.wrapping_mul(0xc2b2ae35);
  h1 ^= h1 >> 16;
  h1
}

// ---------------------------------------------------------------------------
// Encoding functions
// ---------------------------------------------------------------------------

fn dsl_base64_encode(This(s): This<Arc<String>>) -> String {
  use base64::Engine;
  base64::engine::general_purpose::STANDARD.encode(s.as_bytes())
}

fn dsl_base64_py(This(s): This<Arc<String>>) -> String {
  use base64::Engine;
  let encoded = base64::engine::general_purpose::STANDARD.encode(s.as_bytes());
  // Python-style base64: lines of 76 characters terminated by newlines
  let mut result = String::new();
  for (i, c) in encoded.chars().enumerate() {
    if i > 0 && i % 76 == 0 {
      result.push('\n');
    }
    result.push(c);
  }
  result.push('\n');
  result
}

fn dsl_base64_decode(ftx: &FunctionContext, This(s): This<Arc<String>>) -> CelResult<Value> {
  use base64::Engine;
  let decoded = base64::engine::general_purpose::STANDARD
    .decode(s.as_bytes())
    .map_err(|e| ftx.error(format!("base64 decode error: {e}")))?;
  Ok(Value::String(Arc::new(
    String::from_utf8_lossy(&decoded).to_string(),
  )))
}

fn dsl_url_encode(This(s): This<Arc<String>>) -> String {
  let mut result = String::new();
  for c in s.chars() {
    let is_unreserved = c.is_ascii_alphanumeric()
      || c == '-'
      || c == '_'
      || c == '.'
      || c == '!'
      || c == '~'
      || c == '*'
      || c == '\''
      || c == '('
      || c == ')';
    if is_unreserved {
      result.push(c);
    } else {
      for b in c.to_string().as_bytes() {
        result.push_str(&format!("%{:02X}", b));
      }
    }
  }
  result
}

fn dsl_url_decode(This(s): This<Arc<String>>) -> String {
  let mut result = String::new();
  let bytes = s.as_bytes();
  let mut i = 0;
  while i < bytes.len() {
    if bytes[i] == b'%'
      && i + 2 < bytes.len()
      && let Ok(hex_val) = u8::from_str_radix(&String::from_utf8_lossy(&bytes[i + 1..i + 3]), 16)
    {
      result.push(hex_val as char);
      i += 3;
      continue;
    }
    result.push(bytes[i] as char);
    i += 1;
  }
  result
}

fn dsl_hex_encode(This(s): This<Arc<String>>) -> String {
  hex::encode(s.as_bytes())
}

fn dsl_hex_decode(ftx: &FunctionContext, This(s): This<Arc<String>>) -> CelResult<Value> {
  let decoded =
    hex::decode(s.as_bytes()).map_err(|e| ftx.error(format!("hex decode error: {e}")))?;
  Ok(Value::String(Arc::new(
    String::from_utf8_lossy(&decoded).to_string(),
  )))
}

fn dsl_html_escape(This(s): This<Arc<String>>) -> String {
  s.replace('&', "&amp;")
    .replace('<', "&lt;")
    .replace('>', "&gt;")
    .replace('"', "&quot;")
    .replace('\'', "&#39;")
}

fn dsl_html_unescape(This(s): This<Arc<String>>) -> String {
  s.replace("&amp;", "&")
    .replace("&lt;", "<")
    .replace("&gt;", ">")
    .replace("&quot;", "\"")
    .replace("&#39;", "'")
}

// ---------------------------------------------------------------------------
// Conversion functions
// ---------------------------------------------------------------------------

fn dsl_to_number(ftx: &FunctionContext, This(v): This<Value>) -> CelResult<Value> {
  match v {
    Value::Int(i) => Ok(Value::Float(i as f64)),
    Value::UInt(u) => Ok(Value::Float(u as f64)),
    Value::Float(f) => Ok(Value::Float(f)),
    Value::String(s) => {
      if let Ok(i) = s.parse::<i64>() {
        Ok(Value::Int(i))
      } else if let Ok(f) = s.parse::<f64>() {
        Ok(Value::Float(f))
      } else {
        Err(ftx.error(format!("cannot convert '{s}' to number")))
      }
    }
    _ => Err(ftx.error(format!("cannot convert {v:?} to number"))),
  }
}

fn dsl_to_string(_ftx: &FunctionContext, This(v): This<Value>) -> CelResult<Value> {
  Ok(Value::String(Arc::new(value_to_string(&v))))
}

// ---------------------------------------------------------------------------
// Utility functions
// ---------------------------------------------------------------------------

fn dsl_rand_int(_min: i64, _max: i64) -> i64 {
  // Simple pseudo-random for compatibility; not cryptographically secure
  use std::time::{SystemTime, UNIX_EPOCH};
  let seed = SystemTime::now()
    .duration_since(UNIX_EPOCH)
    .unwrap_or_default()
    .subsec_nanos() as i64;
  let range = (_max - _min).max(1);
  _min + (seed.abs() % range)
}

fn dsl_rand_text_alpha(n: i64) -> String {
  use std::time::{SystemTime, UNIX_EPOCH};
  let seed = SystemTime::now()
    .duration_since(UNIX_EPOCH)
    .unwrap_or_default()
    .subsec_nanos();
  let chars = b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";
  let len = n.max(0) as usize;
  (0..len)
    .map(|i| {
      let idx = ((seed as usize).wrapping_add(i.wrapping_mul(31))) % chars.len();
      chars[idx] as char
    })
    .collect()
}

fn dsl_rand_text_alphanumeric(n: i64) -> String {
  use std::time::{SystemTime, UNIX_EPOCH};
  let seed = SystemTime::now()
    .duration_since(UNIX_EPOCH)
    .unwrap_or_default()
    .subsec_nanos();
  let chars = b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
  let len = n.max(0) as usize;
  (0..len)
    .map(|i| {
      let idx = ((seed as usize).wrapping_add(i.wrapping_mul(37))) % chars.len();
      chars[idx] as char
    })
    .collect()
}

fn dsl_rand_base(n: i64) -> String {
  dsl_rand_text_alphanumeric(n)
}

fn dsl_generate_java_gadget(
  _gadget: Arc<String>,
  _cmd: Arc<String>,
  _encoding: Arc<String>,
) -> String {
  // Placeholder for Java gadget generation - returns empty string
  // Full implementation would require Java deserialization gadget generation
  String::new()
}

fn dsl_wait_for(_seconds: i64) -> bool {
  // In matching context, wait_for is a no-op
  true
}

fn dsl_print_debug(Arguments(args): Arguments) -> CelResult<Value> {
  for arg in args.iter() {
    error!("DSL debug: {:?}", arg);
  }
  Ok(Value::Bool(true))
}

fn dsl_index(This(v): This<Value>, idx: i64) -> CelResult<Value> {
  match v {
    Value::String(s) => {
      let i = idx as usize;
      if i < s.len() {
        Ok(Value::String(Arc::new(
          s.chars().nth(i).unwrap_or_default().to_string(),
        )))
      } else {
        Ok(Value::String(Arc::new(String::new())))
      }
    }
    Value::List(l) => {
      let i = idx as usize;
      if i < l.len() {
        Ok(l[i].clone())
      } else {
        Ok(Value::Null)
      }
    }
    _ => Ok(Value::Null),
  }
}

// ---------------------------------------------------------------------------
// Helper functions
// ---------------------------------------------------------------------------

fn value_to_string(v: &Value) -> String {
  match v {
    Value::String(s) => s.as_ref().clone(),
    Value::Int(i) => i.to_string(),
    Value::UInt(u) => u.to_string(),
    Value::Float(f) => f.to_string(),
    Value::Bool(b) => b.to_string(),
    Value::Bytes(b) => String::from_utf8_lossy(b).to_string(),
    Value::Null => String::new(),
    Value::List(l) => {
      let parts: Vec<String> = l.iter().map(value_to_string).collect();
      parts.join(", ")
    }
    Value::Map(_) => "[map]".to_string(),
    Value::Function(name, _) => format!("[function: {name}]"),
    _ => format!("{v:?}"),
  }
}

#[cfg(test)]
mod tests {
  use super::*;

  fn make_vars(body: &str, headers: &str, status_code: u16) -> DslVariables {
    DslVariables {
      body: body.to_string(),
      all_headers: headers.to_string(),
      status_code,
      content_length: body.len() as i64,
      content_type: "text/html".to_string(),
      extra: HashMap::new(),
    }
  }

  // -----------------------------------------------------------------------
  // Basic variable and comparison tests
  // -----------------------------------------------------------------------

  #[test]
  fn test_status_code_comparison() {
    let vars = make_vars("", "", 200);
    assert!(evaluate_dsl("status_code == 200", &vars).unwrap());
    assert!(!evaluate_dsl("status_code == 404", &vars).unwrap());
    assert!(evaluate_dsl("status_code != 404", &vars).unwrap());
    assert!(evaluate_dsl("status_code >= 200", &vars).unwrap());
    assert!(evaluate_dsl("status_code < 300", &vars).unwrap());
  }

  #[test]
  fn test_body_contains() {
    let vars = make_vars("<html><title>Test Page</title></html>", "", 200);
    assert!(evaluate_dsl("contains(body, 'Test Page')", &vars).unwrap());
    assert!(!evaluate_dsl("contains(body, 'Not Found')", &vars).unwrap());
  }

  #[test]
  fn test_combined_conditions() {
    let vars = make_vars(
      "<html>packages</html>",
      "content-type: application/octet-stream\r\n",
      200,
    );
    let expr = "contains(body, 'packages') && contains(tolower(all_headers), 'application/octet-stream') && status_code == 200";
    assert!(evaluate_dsl(expr, &vars).unwrap());
  }

  #[test]
  fn test_or_conditions() {
    let vars = make_vars("hello world", "", 200);
    assert!(
      evaluate_dsl(
        "contains(body, 'hello') || contains(body, 'missing')",
        &vars
      )
      .unwrap()
    );
    assert!(
      !evaluate_dsl(
        "contains(body, 'missing') || contains(body, 'also missing')",
        &vars
      )
      .unwrap()
    );
  }

  #[test]
  fn test_negation() {
    let vars = make_vars("hello", "", 200);
    assert!(evaluate_dsl("!contains(body, 'world')", &vars).unwrap());
    assert!(!evaluate_dsl("!contains(body, 'hello')", &vars).unwrap());
  }

  // -----------------------------------------------------------------------
  // String function tests
  // -----------------------------------------------------------------------

  #[test]
  fn test_tolower_toupper() {
    let vars = make_vars("Hello World", "", 200);
    assert!(evaluate_dsl("tolower(body) == 'hello world'", &vars).unwrap());
    assert!(evaluate_dsl("to_lower(body) == 'hello world'", &vars).unwrap());
    assert!(evaluate_dsl("toupper(body) == 'HELLO WORLD'", &vars).unwrap());
    assert!(evaluate_dsl("to_upper(body) == 'HELLO WORLD'", &vars).unwrap());
  }

  #[test]
  fn test_trim_functions() {
    let vars = make_vars("  hello  ", "", 200);
    assert!(evaluate_dsl("trim_space(body) == 'hello'", &vars).unwrap());

    let mut vars2 = make_vars("xxhelloxx", "", 200);
    vars2.extra.insert("s".to_string(), "xxhelloxx".to_string());
    assert!(evaluate_dsl("trim(s, 'x') == 'hello'", &vars2).unwrap());
    assert!(evaluate_dsl("trim_left(s, 'x') == 'helloxx'", &vars2).unwrap());
    assert!(evaluate_dsl("trim_right(s, 'x') == 'xxhello'", &vars2).unwrap());
  }

  #[test]
  fn test_trim_prefix_suffix() {
    let mut vars = make_vars("", "", 200);
    vars
      .extra
      .insert("s".to_string(), "hello_world".to_string());
    assert!(evaluate_dsl("trim_prefix(s, 'hello_') == 'world'", &vars).unwrap());
    assert!(evaluate_dsl("trim_suffix(s, '_world') == 'hello'", &vars).unwrap());
  }

  #[test]
  fn test_replace() {
    let mut vars = make_vars("", "", 200);
    vars
      .extra
      .insert("s".to_string(), "hello world".to_string());
    assert!(evaluate_dsl("replace(s, 'world', 'rust') == 'hello rust'", &vars).unwrap());
  }

  #[test]
  fn test_replace_regex() {
    let mut vars = make_vars("", "", 200);
    vars
      .extra
      .insert("s".to_string(), "hello 123 world".to_string());
    assert!(
      evaluate_dsl(
        "replace_regex(s, '[0-9]+', 'NUM') == 'hello NUM world'",
        &vars
      )
      .unwrap()
    );
  }

  #[test]
  fn test_reverse() {
    let mut vars = make_vars("", "", 200);
    vars.extra.insert("s".to_string(), "hello".to_string());
    assert!(evaluate_dsl("reverse(s) == 'olleh'", &vars).unwrap());
  }

  #[test]
  fn test_repeat() {
    let mut vars = make_vars("", "", 200);
    vars.extra.insert("s".to_string(), "ab".to_string());
    assert!(evaluate_dsl("repeat(s, 3) == 'ababab'", &vars).unwrap());
  }

  #[test]
  fn test_concat() {
    let mut vars = make_vars("", "", 200);
    vars.extra.insert("a".to_string(), "hello".to_string());
    vars.extra.insert("b".to_string(), " world".to_string());
    assert!(evaluate_dsl("concat(a, b) == 'hello world'", &vars).unwrap());
  }

  #[test]
  fn test_sort_and_uniq() {
    let mut vars = make_vars("", "", 200);
    vars.extra.insert("s".to_string(), "dcba".to_string());
    assert!(evaluate_dsl("sort(s) == 'abcd'", &vars).unwrap());

    vars.extra.insert("s".to_string(), "aabbcc".to_string());
    assert!(evaluate_dsl("uniq(s) == 'abc'", &vars).unwrap());
  }

  #[test]
  fn test_len() {
    let vars = make_vars("hello", "", 200);
    assert!(evaluate_dsl("len(body) == 5", &vars).unwrap());
    assert!(evaluate_dsl("len(body) > 0", &vars).unwrap());
  }

  // -----------------------------------------------------------------------
  // Matching function tests
  // -----------------------------------------------------------------------

  #[test]
  fn test_contains_all() {
    let vars = make_vars("hello beautiful world", "", 200);
    assert!(evaluate_dsl("contains_all(body, 'hello', 'world')", &vars).unwrap());
    assert!(!evaluate_dsl("contains_all(body, 'hello', 'missing')", &vars).unwrap());
  }

  #[test]
  fn test_contains_any() {
    let vars = make_vars("hello beautiful world", "", 200);
    assert!(evaluate_dsl("contains_any(body, 'missing', 'world')", &vars).unwrap());
    assert!(!evaluate_dsl("contains_any(body, 'missing', 'gone')", &vars).unwrap());
  }

  #[test]
  fn test_starts_with_ends_with() {
    let vars = make_vars("hello world", "", 200);
    assert!(evaluate_dsl("starts_with(body, 'hello')", &vars).unwrap());
    assert!(!evaluate_dsl("starts_with(body, 'world')", &vars).unwrap());
    assert!(evaluate_dsl("ends_with(body, 'world')", &vars).unwrap());
    assert!(!evaluate_dsl("ends_with(body, 'hello')", &vars).unwrap());
  }

  #[test]
  fn test_regex_match() {
    let vars = make_vars("version: 1.2.3", "", 200);
    assert!(evaluate_dsl("regex('[0-9]+\\\\.[0-9]+\\\\.[0-9]+', body)", &vars).unwrap());
    assert!(!evaluate_dsl("regex('^[a-z]+$', body)", &vars).unwrap());
  }

  // -----------------------------------------------------------------------
  // Hash function tests
  // -----------------------------------------------------------------------

  #[test]
  fn test_md5() {
    let mut vars = make_vars("", "", 200);
    vars.extra.insert("s".to_string(), "hello".to_string());
    assert!(evaluate_dsl("md5(s) == '5d41402abc4b2a76b9719d911017c592'", &vars).unwrap());
  }

  #[test]
  fn test_sha1() {
    let mut vars = make_vars("", "", 200);
    vars.extra.insert("s".to_string(), "hello".to_string());
    assert!(
      evaluate_dsl(
        "sha1(s) == 'aaf4c61ddcc5e8a2dabede0f3b482cd9aea9434d'",
        &vars
      )
      .unwrap()
    );
  }

  #[test]
  fn test_sha256() {
    let mut vars = make_vars("", "", 200);
    vars.extra.insert("s".to_string(), "hello".to_string());
    assert!(
      evaluate_dsl(
        "sha256(s) == '2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824'",
        &vars
      )
      .unwrap()
    );
  }

  #[test]
  fn test_sha512() {
    let mut vars = make_vars("", "", 200);
    vars.extra.insert("s".to_string(), "hello".to_string());
    // SHA512 of "hello"
    let result = evaluate_dsl(
      "sha512(s) == '9b71d224bd62f3785d96d46ad3ea3d73319bfbc2890caadae2dff72519673ca72323c3d99ba5c11d7c7acc6e14b8c5da0c4663475c2e5c3adef46f73bcdec043'",
      &vars,
    );
    assert!(result.unwrap());
  }

  // -----------------------------------------------------------------------
  // Encoding function tests
  // -----------------------------------------------------------------------

  #[test]
  fn test_base64_encode_decode() {
    let mut vars = make_vars("", "", 200);
    vars.extra.insert("s".to_string(), "hello".to_string());
    assert!(evaluate_dsl("base64(s) == 'aGVsbG8='", &vars).unwrap());
    assert!(evaluate_dsl("base64_decode('aGVsbG8=') == 'hello'", &vars).unwrap());
  }

  #[test]
  fn test_url_encode_decode() {
    let mut vars = make_vars("", "", 200);
    vars
      .extra
      .insert("s".to_string(), "hello world&foo=bar".to_string());
    assert!(evaluate_dsl("url_encode(s) == 'hello%20world%26foo%3Dbar'", &vars).unwrap());
    assert!(
      evaluate_dsl(
        "url_decode('hello%20world%26foo%3Dbar') == 'hello world&foo=bar'",
        &vars
      )
      .unwrap()
    );
  }

  #[test]
  fn test_hex_encode_decode() {
    let mut vars = make_vars("", "", 200);
    vars.extra.insert("s".to_string(), "hello".to_string());
    assert!(evaluate_dsl("hex_encode(s) == '68656c6c6f'", &vars).unwrap());
    assert!(evaluate_dsl("hex_decode('68656c6c6f') == 'hello'", &vars).unwrap());
  }

  #[test]
  fn test_html_escape_unescape() {
    let mut vars = make_vars("", "", 200);
    vars
      .extra
      .insert("s".to_string(), "<script>alert('xss')</script>".to_string());
    assert!(
      evaluate_dsl(
        "html_escape(s) == '&lt;script&gt;alert(&#39;xss&#39;)&lt;/script&gt;'",
        &vars
      )
      .unwrap()
    );
    assert!(
      evaluate_dsl(
        "html_unescape('&lt;b&gt;hello&lt;/b&gt;') == '<b>hello</b>'",
        &vars
      )
      .unwrap()
    );
  }

  // -----------------------------------------------------------------------
  // Conversion function tests
  // -----------------------------------------------------------------------

  #[test]
  fn test_to_number() {
    let mut vars = make_vars("", "", 200);
    vars.extra.insert("s".to_string(), "42".to_string());
    assert!(evaluate_dsl("to_number(s) == 42", &vars).unwrap());
  }

  // -----------------------------------------------------------------------
  // Nuclei template compatibility tests
  // -----------------------------------------------------------------------

  #[test]
  fn test_nuclei_template_wordpress() {
    // Common nuclei template expression for WordPress detection
    let vars = make_vars(
      "<html><meta name=\"generator\" content=\"WordPress 6.0\"></html>",
      "content-type: text/html\r\nserver: nginx\r\n",
      200,
    );
    assert!(evaluate_dsl("status_code == 200 && contains(body, 'WordPress')", &vars).unwrap());
  }

  #[test]
  fn test_nuclei_template_apache_status() {
    let vars = make_vars(
      "<html><title>Apache Status</title></html>",
      "server: Apache/2.4.41\r\ncontent-type: text/html\r\n",
      200,
    );
    let expr =
      "status_code == 200 && contains(body, 'Apache Status') && contains(all_headers, 'Apache')";
    assert!(evaluate_dsl(expr, &vars).unwrap());
  }

  #[test]
  fn test_nuclei_template_content_type_check() {
    let vars = make_vars(
      "{\"key\":\"value\"}",
      "content-type: application/json\r\n",
      200,
    );
    let expr = "status_code == 200 && contains(tolower(all_headers), 'application/json')";
    assert!(evaluate_dsl(expr, &vars).unwrap());
  }

  #[test]
  fn test_nuclei_template_redirect() {
    let vars = make_vars("", "location: https://example.com/login\r\n", 302);
    let expr = "status_code == 302 && contains(all_headers, '/login')";
    assert!(evaluate_dsl(expr, &vars).unwrap());
  }

  #[test]
  fn test_nuclei_template_header_detection() {
    let vars = make_vars(
      "Not Found",
      "x-powered-by: Express\r\nserver: nginx\r\n",
      404,
    );
    let expr = "contains(all_headers, 'Express') && status_code == 404";
    assert!(evaluate_dsl(expr, &vars).unwrap());
  }

  #[test]
  fn test_nuclei_template_complex_body() {
    let vars = make_vars(
      r#"<html><head><title>phpMyAdmin</title></head><body><div id="version">4.9.5</div></body></html>"#,
      "content-type: text/html\r\nset-cookie: phpMyAdmin=abc123\r\n",
      200,
    );
    let expr =
      "status_code == 200 && contains(body, 'phpMyAdmin') && contains(all_headers, 'phpMyAdmin')";
    assert!(evaluate_dsl(expr, &vars).unwrap());
  }

  #[test]
  fn test_nuclei_template_length_check() {
    let vars = make_vars("some content here", "", 200);
    let expr = "status_code == 200 && len(body) > 0";
    assert!(evaluate_dsl(expr, &vars).unwrap());
  }

  #[test]
  fn test_nuclei_template_regex_version() {
    let vars = make_vars("Server: Apache/2.4.41 (Ubuntu)", "", 200);
    let expr = "regex('Apache/[0-9.]+', body)";
    assert!(evaluate_dsl(expr, &vars).unwrap());
  }

  #[test]
  fn test_nuclei_template_md5_check() {
    // Testing a template that checks MD5 of body content
    let body = "test_content";
    let mut vars = make_vars(body, "", 200);
    vars.extra.insert("s".to_string(), body.to_string());
    let expected_md5 = {
      use md5::Digest;
      hex::encode(md5::Md5::digest(body.as_bytes()))
    };
    let expr = format!("md5(body) == '{expected_md5}'");
    assert!(evaluate_dsl(&expr, &vars).unwrap());
  }

  #[test]
  fn test_nuclei_template_nested_functions() {
    let vars = make_vars(
      "<HTML><TITLE>Test</TITLE></HTML>",
      "Content-Type: TEXT/HTML\r\n",
      200,
    );
    let expr = "contains(tolower(body), '<title>test</title>') && contains(tolower(all_headers), 'text/html')";
    assert!(evaluate_dsl(expr, &vars).unwrap());
  }

  #[test]
  fn test_content_length_variable() {
    let vars = make_vars("hello", "", 200);
    assert!(evaluate_dsl("content_length == 5", &vars).unwrap());
    assert!(evaluate_dsl("content_length > 0", &vars).unwrap());
  }

  #[test]
  fn test_content_type_variable() {
    let vars = make_vars("", "", 200);
    assert!(evaluate_dsl("content_type == 'text/html'", &vars).unwrap());
  }

  #[test]
  fn test_extra_variables() {
    let mut vars = make_vars("", "", 200);
    vars
      .extra
      .insert("interactsh_url".to_string(), "test.oast.pro".to_string());
    assert!(evaluate_dsl("interactsh_url == 'test.oast.pro'", &vars).unwrap());
  }
}
