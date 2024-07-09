use crate::cli::ObserverWardConfig;
use console::Emoji;
use engine::results::NucleiResult;
use log::debug;
use std::collections::HashSet;
use std::path::PathBuf;
use std::process::Command;

#[derive(Debug, Clone)]
pub struct NucleiRunner {
  pub name: String,
  pub plugins: HashSet<PathBuf>,
  pub condition: Vec<String>,
  pub targets: HashSet<String>,
}

impl NucleiRunner {
  pub fn new(name: String) -> Self {
    Self {
      name,
      plugins: HashSet::new(),
      condition: Vec::new(),
      targets: HashSet::new(),
    }
  }
  fn output(&self, command: &mut Command) -> Vec<NucleiResult> {
    debug!("{}: {:?}", Emoji("🐚", "nuclei command"), command);
    let mut result = Vec::new();
    let output = command.output().expect("command_line_output");
    if let Ok(template_output) = String::from_utf8(output.stdout) {
      let templates_output: Vec<String> = template_output
        .split_terminator('\n')
        .map(String::from)
        .collect();
      for line in templates_output.iter() {
        if let Ok(template) = serde_json::from_str::<NucleiResult>(line) {
          result.push(template);
        };
      }
    }
    result
  }
  fn run_with_plugin(&self, config: &ObserverWardConfig) -> Vec<NucleiResult> {
    if self.plugins.is_empty() {
      return Default::default();
    }
    let mut command = self.command(config);
    for p in self.plugins.iter() {
      command.args(["-t", p.to_string_lossy().as_ref()]);
    }
    self.output(&mut command)
  }
  fn run_with_condition(&self, config: &ObserverWardConfig) -> Vec<NucleiResult> {
    if self.condition.is_empty() {
      return Default::default();
    }
    let mut command = self.command(config);
    if let Some(p) = &config.plugin {
      command.args(["-t", p.to_string_lossy().as_ref()]);
    }
    command.args(["-tc", &self.condition.join("||")]);
    self.output(&mut command)
  }
  fn command(&self, config: &ObserverWardConfig) -> Command {
    let mut command = Command::new("nuclei");
    command.args([
      "-no-color",
      "-timeout",
      &(config.timeout + 5).to_string(),
      "-silent",
      "-jsonl",
      "-ot",
      "-duc",
    ]);
    for target in self.targets.iter() {
      command.args(["-u", target]);
    }
    if let Some(args) = &config.nuclei_args {
      let args: Vec<&str> = args.split(' ').collect();
      for arg in args {
        command.arg(arg);
      }
    }
    if config.or {
      command.args(["-or"]);
    }
    if let Some(proxy) = &config.proxy {
      command.args(["-p", &proxy.uri().to_string()]);
    }
    command
  }
  pub fn run(&self, config: &ObserverWardConfig) -> Vec<NucleiResult> {
    let mut result = Vec::new();
    result.extend(self.run_with_plugin(config));
    result.extend(self.run_with_condition(config));
    result
  }
}

// 生成nuclei的标签过滤表达式
pub fn gen_nuclei_tags(product: &str, tags: &[String]) -> String {
  let mut or_condition = Vec::new();
  let finger_tags = ["detect", "tech"];
  let tags: Vec<String> = tags
    .iter()
    .filter(|x| !finger_tags.contains(&x.as_str()))
    .map(|x| x.to_string())
    .collect();
  if !tags.contains(&product.to_string()) {
    or_condition.push(format!("contains(tags,'{}')", product));
  }
  // 只留单个的tags，防止误报
  if tags.len() == 1 {
    or_condition.push(format!("contains(tags,'{}')", tags[0]));
  } else {
    let mut and_condition = Vec::new();
    for tag in tags {
      and_condition.push(format!("contains(tags,'{}')", tag));
    }
    or_condition.push(format!("({})", and_condition.join("&&")));
  }

  or_condition.join("||")
}
