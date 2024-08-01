use crate::cli::{ObserverWardConfig, OutputFormat};
use crate::MatchedResult;
use console::{style, Emoji};
use engine::slinger::http::header;
use std::collections::{BTreeMap, HashSet};
use std::fs::File;
use std::io::{BufWriter, Write};

pub struct Output {
  config: ObserverWardConfig,
  format: OutputFormat,
  writer: BufWriter<Box<dyn Write + Sync + Send + 'static>>,
  output: bool,
}

fn set_to_string(set: &HashSet<String>) -> String {
  set
    .iter()
    .map(|x| x.trim().to_string().replace("\r\n", " ").replace('\t', ""))
    .collect::<HashSet<_>>()
    .iter()
    .cloned()
    .collect::<Vec<_>>()
    .join(",")
}

impl Output {
  pub fn new(config: &ObserverWardConfig) -> Self {
    let output_format = config.format.clone().unwrap_or_default();
    let mut output = false;
    // 选择了json,只打印到标准输出
    let mut writer: BufWriter<Box<dyn Write + Sync + Send + 'static>> = match &config.output {
      Some(path) => {
        output = true;
        // 保存文件禁用颜色输出
        let f = File::create(path).expect("create output file err");
        BufWriter::new(Box::new(f))
      }
      None => {
        let handle = std::io::stdout();
        BufWriter::new(Box::new(handle))
      }
    };
    if let OutputFormat::CSV = output_format {
      writeln!(writer, "url,name,title,status_code,nuclei").unwrap_or_default();
    }
    Self {
      config: config.clone(),
      format: output_format,
      writer,
      output,
    }
  }

  pub fn save_and_print(&mut self, result: BTreeMap<String, MatchedResult>) {
    match self.format {
      OutputFormat::STD => {
        // 保存到文件
        if self.output {
          console::set_colors_enabled(false);
          write_to_buf(&mut self.writer, &result);
        }
        if !self.config.silent {
          console::set_colors_enabled(true);
          write_to_buf(&mut BufWriter::new(Box::new(std::io::stdout())), &result);
        }
      }
      OutputFormat::JSON => {
        if !self.config.silent {
          write_to_buf(&mut BufWriter::new(Box::new(std::io::stdout())), &result);
        }
        writeln!(
          self.writer,
          "{}",
          serde_json::to_string(&result).unwrap_or_default()
        )
        .unwrap_or_default();
      }
      OutputFormat::CSV => {
        if !self.config.silent {
          write_to_buf(&mut BufWriter::new(Box::new(std::io::stdout())), &result);
        }
        for (uri, mr) in result {
          let app: Vec<String> = mr
            .fingerprint()
            .iter()
            .flat_map(|f| {
              f.matcher_result()
                .iter()
                .map(|x| x.info.name.clone())
                .collect::<Vec<String>>()
            })
            .collect();
          let nuclei: Vec<String> = mr
            .nuclei_result()
            .iter()
            .flat_map(|(_, nr)| {
              nr.iter()
                .map(|n| n.template_id.clone())
                .collect::<Vec<String>>()
            })
            .collect();
          writeln!(
            self.writer,
            "{},\"{}\",\"{}\",{},\"{}\"",
            uri,
            app.join(";").trim(),
            set_to_string(&mr.title),
            mr.status.map_or(0, |x| x.as_u16()),
            nuclei.join(";").trim()
          )
          .unwrap_or_default();
        }
      }
    }
    self.writer.flush().unwrap_or_default();
  }
  pub fn webhook_results(&self, result: Vec<BTreeMap<String, MatchedResult>>) {
    if let Some(webhook_url) = &self.config.webhook {
      let mut headers = header::HeaderMap::new();
      headers.insert(
        header::CONTENT_TYPE,
        header::HeaderValue::from_static("application/json"),
      );
      let ua = "Mozilla/5.0 (X11; Linux x86_64; rv:94.0) Gecko/20100101 Firefox/94.0";
      headers.insert(header::USER_AGENT, header::HeaderValue::from_static(ua));
      if let Some(wa) = &self.config.webhook_auth {
        let h = header::HeaderValue::from_str(wa);
        headers.insert(
          header::AUTHORIZATION,
          h.unwrap_or(header::HeaderValue::from_static("AUTHORIZATION")),
        );
      }
      let client = self
        .config
        .http_client_builder()
        .default_headers(headers)
        .build()
        .unwrap_or_default();
      let what_web_result_json = serde_json::to_string(&result).unwrap_or("[]".to_string());
      let _: Result<_, _> = client.post(webhook_url).body(what_web_result_json).send();
    }
  }
}

fn write_to_buf(writer: &mut BufWriter<dyn Write>, result: &BTreeMap<String, MatchedResult>) {
  for (uri, mr) in result {
    let nr = mr.nuclei_result();
    // 根据状态码显示颜色
    let osc = mr.status().as_ref().map(|sc| {
      if sc.is_success() {
        style(sc).green()
      } else if sc.is_server_error() {
        style(sc).red()
      } else {
        style(sc).cyan()
      }
    });
    // 打印指纹
    let mut all_app: HashSet<String> = HashSet::new();
    for fp in mr.fingerprint() {
      let apps: HashSet<String> = fp
        .matcher_result()
        .iter()
        .map(|x| x.info.name.clone())
        .collect();
      // 当前app是全集的子集,跳过打印
      if apps.is_superset(&all_app) && !all_app.is_empty() {
        continue;
      }
      write!(writer, "{}:[ {}", Emoji("🎯", "uri"), uri).unwrap_or_default();
      write!(writer, " [{}] ", style(set_to_string(&apps)).green()).unwrap_or_default();
      write!(writer, " <{}>", set_to_string(mr.title())).unwrap_or_default();
      if let Some(csc) = &osc {
        write!(writer, " ({}) ", csc).unwrap_or_default();
      }
      writeln!(writer, "]").unwrap_or_default();
      if !fp.matcher_result().iter().all(|x| x.extractor.is_empty()) {
        write!(writer, " |_{}: ", Emoji("📰", "extractor")).unwrap_or_default();
        fp.extractor().iter().for_each(|(n, v)| {
          write!(
            writer,
            "{}:[{}] ",
            style(n).red(),
            style(set_to_string(v).trim()).yellow()
          )
          .unwrap_or_default();
        });
        writeln!(writer).unwrap_or_default();
      }
      // 指纹对应的nuclei结果
      for app in apps.iter() {
        if let Some(n) = nr.get(app) {
          if n.is_empty() {
            continue;
          }
          for v in n {
            writeln!(
              writer,
              " |_{}: [{}] {}: {}",
              Emoji("🐞", "exploitable"),
              style(format!("{:?}", v.info.severity)).red(),
              style(&v.template_id).green(),
              style(&v.info.name).cyan()
            )
            .unwrap_or_default();
            writeln!(
              writer,
              "  |_{}: {}",
              Emoji("🔥", "matched_at"),
              v.matched_at
            )
            .unwrap_or_default();
            if !v.curl_command.is_empty() {
              writeln!(
                writer,
                "  |_{}: {}",
                Emoji("🐚", "shell"),
                style(&v.curl_command).yellow()
              )
              .unwrap_or_default();
            }
          }
        }
      }
      all_app.extend(apps);
    }
    if mr.fingerprint().is_empty() {
      write!(writer, "{}:[ {}", Emoji("🎯", "uri"), uri).unwrap_or_default();
      if !mr.title().is_empty() {
        write!(
          writer,
          " <{}> ",
          mr.title()
            .iter()
            .map(|x| x.to_string())
            .collect::<Vec<String>>()
            .join(",")
        )
        .unwrap_or_default();
      }
      if let Some(csc) = &osc {
        write!(writer, " ({}) ", csc).unwrap_or_default();
      }
      writeln!(writer, "]").unwrap_or_default();
    }
  }
}
