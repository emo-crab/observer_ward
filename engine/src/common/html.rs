/// 获取标题
pub fn extract_title(text: &str) -> Option<String> {
  let dom = tl::parse(text, tl::ParserOptions::default()).ok()?;
  let parser = dom.parser();
  if let Some(selector) = dom.query_selector("title") {
    for title in selector {
      if let Some(title) = title.get(parser) {
        let t = title.inner_text(parser).trim().to_string();
        if !t.is_empty() {
          return Some(t);
        }
      }
    }
  }
  let meta = vec!["meta[property$=title]", "meta[name=title]"];
  for m in meta {
    if let Some(selector) = dom.query_selector(m) {
      for title in selector {
        if let Some(title) = title.get(parser) {
          let content = title
            .as_tag()
            .and_then(|tag| {
              tag
                .attributes()
                .get("content")
                .and_then(|x| x.and_then(|x| x.try_as_utf8_str()))
            })
            .map(|x| x.trim().to_string());
          if content.is_some() {
            return content;
          }
        }
      }
    }
  }
  None
}
