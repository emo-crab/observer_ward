use crate::cli::ObserverWardConfig;
use crate::output::Output;
use crate::{MatchedResult, ObserverWard};
use engine::execute::ClusterType;
use engine::info::Info;
use engine::operators::{OperatorResult, Operators};
use engine::slinger::Response;
use engine::slinger::http::Uri;
use engine::slinger::http_serde;
use engine::template::Template;
use engine::template::cluster::cluster_templates;
use futures::StreamExt;
use futures::channel::mpsc::unbounded;
use rmcp::{
  ErrorData, RoleServer, ServerHandler,
  handler::server::{router::tool::ToolRouter, wrapper::Parameters},
  model::*,
  service::RequestContext,
  tool, tool_handler, tool_router,
};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::ops::Deref;
use std::sync::RwLock;
const DEFAULT_PROMPT: &str = include_str!("../../prompt.txt");

pub struct ObserverWardHandler {
  cluster_templates: RwLock<ClusterType>,
  config: ObserverWardConfig,
  tool_router: ToolRouter<ObserverWardHandler>,
}
impl ObserverWardHandler {
  fn get_cluster_templates(&self) -> ClusterType {
    {
      if let Ok(cl_guard) = self.cluster_templates.read() {
        cl_guard.deref().clone()
      } else {
        ClusterType::default()
      }
    }
  }
}
#[derive(Debug, Serialize, Deserialize, Clone, schemars::JsonSchema)]
#[serde(rename_all = "kebab-case")]
struct Target {
  /// the URL target and other parameters to be verified
  #[serde(with = "http_serde::uri")]
  #[cfg_attr(feature = "mcp", schemars(with = "String"))]
  target: Uri,
}
#[derive(Debug, Serialize, Deserialize, Clone, schemars::JsonSchema)]
#[serde(rename_all = "kebab-case")]
struct VerifyTemplate {
  /// the URL target and other parameters to be verified
  #[serde(with = "http_serde::uri")]
  #[cfg_attr(feature = "mcp", schemars(with = "String"))]
  target: Uri,
  /// template to be validated
  template: Template,
}
/// Verify Operators for Response
#[derive(Debug, Serialize, Deserialize, Clone, schemars::JsonSchema)]
#[serde(rename_all = "kebab-case")]
struct VerifyMatcher {
  /// Response is the response of the request
  response: Response,
  /// Operators for the current request go here,matchers in operators cannot be empty
  operators: Operators,
}
/// Verify Operators for Response
#[derive(Debug, Serialize, Deserialize, Clone, schemars::JsonSchema)]
#[serde(rename_all = "kebab-case")]
struct VerifyExtractor {
  /// template info,store version information in metadata
  info: Info,
  /// Response is the response of the request
  response: Response,
  /// Operators for the current request go here,extractors in operators cannot be empty
  operators: Operators,
}
// Use tool_router macro to generate the tool router
#[tool_router]
impl ObserverWardHandler {
  pub fn new(config: ObserverWardConfig, cl: ClusterType) -> Self {
    let cluster_templates = RwLock::new(cl);
    Self {
      cluster_templates,
      config,
      tool_router: Self::tool_router(),
    }
  }
  #[tool(description = "Scan the application fingerprint of the URL target")]
  async fn scan(
    &self,
    Parameters(Target { target }): Parameters<Target>,
  ) -> Result<CallToolResult, ErrorData> {
    let cl = self.get_cluster_templates();
    let mut config = self.config.clone();
    config.target = vec![target.to_string()];
    let webhook = config.webhook.is_some();
    let output = Output::new(&config);
    let (tx, mut rx) = unbounded();
    tokio::task::spawn(async move {
      ObserverWard::new(&config, cl).execute(tx).await;
    });
    let mut results: Vec<BTreeMap<String, MatchedResult>> = Vec::new();
    if webhook {
      // 异步识别任务，通过webhook返回结果
      tokio::task::spawn(async move {
        while let Some(execute_result) = rx.next().await {
          output.webhook_results(vec![execute_result.matched]).await;
        }
      });
    } else {
      while let Some(execute_result) = rx.next().await {
        results.push(execute_result.matched);
      }
    }
    let result = Content::json(&results)?;
    Ok(CallToolResult::success(vec![result]))
  }
  #[tool(description = "Provide target and template calls to verify if the template is valid")]
  async fn verify_template(
    &self,
    Parameters(VerifyTemplate { target, template }): Parameters<VerifyTemplate>,
  ) -> Result<CallToolResult, ErrorData> {
    let mut config = self.config.clone();
    config.target = vec![target.to_string()];
    let cl = cluster_templates(&[template]);
    let (tx, mut rx) = unbounded();
    tokio::task::spawn(async move {
      ObserverWard::new(&config, cl).execute(tx).await;
    });
    let mut results: Vec<BTreeMap<String, MatchedResult>> = Vec::new();
    while let Some(execute_result) = rx.next().await {
      results.push(execute_result.matched);
    }
    let result = Content::json(&results)?;
    Ok(CallToolResult::success(vec![result]))
  }
  #[tool(description = "Get templates count")]
  async fn templates_count(&self) -> Result<CallToolResult, ErrorData> {
    match self.cluster_templates.read() {
      Ok(ct) => Ok(CallToolResult::success(vec![Content::text(
        ct.count().to_string(),
      )])),
      Err(err) => Err(ErrorData::internal_error(err.to_string(), None)),
    }
  }
  #[tool(
    description = "Fetch response from uri,supporting http(s)://, tcp:// and tls:// protocols"
  )]
  async fn get_response(
    &self,
    Parameters(Target { target }): Parameters<Target>,
  ) -> Result<CallToolResult, ErrorData> {
    let mut config = self.config.clone();
    config.target = vec![target.to_string()];
    let (tx, mut rx) = unbounded();
    let cl = self.get_cluster_templates();
    tokio::task::spawn(async move {
      ObserverWard::new(&config, cl).execute(tx).await;
    });
    let mut records = None;
    while let Some(execute_result) = rx.next().await {
      records = execute_result.record;
    }
    let record = Content::json(&records)?;
    Ok(CallToolResult::success(vec![record]))
  }
  #[tool(description = "Verify response matcher (for fingerprint generation only)")]
  async fn verify_matcher(
    &self,
    Parameters(VerifyMatcher {
      response,
      mut operators,
    }): Parameters<VerifyMatcher>,
  ) -> Result<CallToolResult, ErrorData> {
    let mut result = OperatorResult::default();
    if let Err(err) = operators.compile() {
      return Err(ErrorData::internal_error(err.to_string(), None));
    };
    if let Err(err) = operators.matcher(&response, &mut result) {
      return Err(ErrorData::internal_error(err.to_string(), None));
    };
    return Ok(CallToolResult::success(vec![Content::json(result)?]));
  }
  #[tool(description = "Verify response extractor (for fingerprint generation only)")]
  async fn verify_extractor(
    &self,
    Parameters(VerifyExtractor {
      info,
      response,
      mut operators,
    }): Parameters<VerifyExtractor>,
  ) -> Result<CallToolResult, ErrorData> {
    let mut result = OperatorResult::default();
    if let Err(err) = operators.compile() {
      return Err(ErrorData::internal_error(err.to_string(), None));
    };
    operators.extractor(info.get_version(), &response, &mut result);
    return Ok(CallToolResult::success(vec![Content::json(result)?]));
  }
}

#[tool_handler]
impl ServerHandler for ObserverWardHandler {
  fn get_info(&self) -> ServerInfo {
    ServerInfo {
      protocol_version: ProtocolVersion::V_2024_11_05,
      capabilities: ServerCapabilities::builder()
        .enable_prompts()
        .enable_tools()
        .build(),
      server_info: Implementation {
        name: "observer_ward MCP Server".to_string(),
        version: env!("CARGO_PKG_VERSION").to_string(),
      },
      instructions: Some("observer_ward MCP server. A set of MCP services for web application fingerprint identification based on FingerprintHub rules".to_string()),
    }
  }
  async fn list_prompts(
    &self,
    _request: Option<PaginatedRequestParam>,
    _: RequestContext<RoleServer>,
  ) -> Result<ListPromptsResult, ErrorData> {
    Ok(ListPromptsResult {
      next_cursor: None,
      prompts: vec![Prompt::new(
        "fingerprint_prompt",
        Some("This prompt word is about how to generate fingerprint rules"),
        None,
      )],
    })
  }
  async fn get_prompt(
    &self,
    GetPromptRequestParam { name, .. }: GetPromptRequestParam,
    _: RequestContext<RoleServer>,
  ) -> Result<GetPromptResult, ErrorData> {
    match name.as_str() {
      "fingerprint_prompt" => {
        let prompt = self
          .config
          .prompt_path
          .clone()
          .map(|p| std::fs::read_to_string(p).unwrap_or(DEFAULT_PROMPT.to_string()))
          .unwrap_or(DEFAULT_PROMPT.to_string());
        Ok(GetPromptResult {
          description: None,
          messages: vec![PromptMessage {
            role: PromptMessageRole::User,
            content: PromptMessageContent::text(prompt),
          }],
        })
      }
      _ => Err(ErrorData::invalid_params("prompt not found", None)),
    }
  }
  async fn list_resource_templates(
    &self,
    _request: Option<PaginatedRequestParam>,
    _: RequestContext<RoleServer>,
  ) -> Result<ListResourceTemplatesResult, ErrorData> {
    Ok(ListResourceTemplatesResult {
      next_cursor: None,
      resource_templates: Vec::new(),
    })
  }

  async fn initialize(
    &self,
    _request: InitializeRequestParam,
    _context: RequestContext<RoleServer>,
  ) -> Result<InitializeResult, ErrorData> {
    Ok(self.get_info())
  }
}
