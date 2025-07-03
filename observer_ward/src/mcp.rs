use crate::cli::ObserverWardConfig;
use crate::{MatchedResult, ObserverWard};
use engine::execute::ClusterType;
use engine::info::Info;
use engine::operators::{OperatorResult, Operators};
use engine::slinger::Response;
use engine::template::Template;
use engine::template::cluster::cluster_templates;
use futures::StreamExt;
use futures::channel::mpsc::unbounded;
use rmcp::{
  Error as McpError, RoleServer, ServerHandler,
  handler::server::{router::tool::ToolRouter, tool::Parameters},
  model::*,
  service::RequestContext,
  tool, tool_handler, tool_router,
};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::future::Future;
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
struct VerifyTemplate {
  /// the URL target and other parameters to be verified
  config: ObserverWardConfig,
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
  async fn scan(&self, config: Parameters<ObserverWardConfig>) -> Result<CallToolResult, McpError> {
    let cl = self.get_cluster_templates();
    let (tx, mut rx) = unbounded();
    tokio::task::spawn(async move {
      ObserverWard::new(&config.0, cl).execute(tx).await;
    });
    let mut results: Vec<BTreeMap<String, MatchedResult>> = Vec::new();
    let mut records = None;
    while let Some((result, record)) = rx.next().await {
      results.push(result);
      records = record;
    }
    let result = Content::json(&results)?;
    let record = Content::json(&records)?;
    Ok(CallToolResult::success(vec![result, record]))
  }
  #[tool(description = "Provide target and template calls to verify if the template is valid")]
  async fn verify_template(
    &self,
    Parameters(VerifyTemplate { config, template }): Parameters<VerifyTemplate>,
  ) -> Result<CallToolResult, McpError> {
    let cl = cluster_templates(&vec![template]);
    let (tx, mut rx) = unbounded();
    tokio::task::spawn(async move {
      ObserverWard::new(&config, cl).execute(tx).await;
    });
    let mut results: Vec<BTreeMap<String, MatchedResult>> = Vec::new();
    let mut records = None;
    while let Some((result, record)) = rx.next().await {
      results.push(result);
      records = record;
    }
    let result = Content::json(&results)?;
    let record = Content::json(&records)?;
    Ok(CallToolResult::success(vec![result, record]))
  }
  #[tool(description = "Get templates count")]
  async fn templates_count(&self) -> Result<CallToolResult, McpError> {
    match self.cluster_templates.read() {
      Ok(ct) => Ok(CallToolResult::success(vec![Content::text(
        ct.count().to_string(),
      )])),
      Err(err) => Err(McpError::internal_error(err.to_string(), None)),
    }
  }
  #[tool(description = "Get response by target")]
  async fn get_response(
    &self,
    config: Parameters<ObserverWardConfig>,
  ) -> Result<CallToolResult, McpError> {
    let (tx, mut rx) = unbounded();
    let cl = self.get_cluster_templates();
    tokio::task::spawn(async move {
      ObserverWard::new(&config.0, cl).execute(tx).await;
    });
    let mut records = None;
    while let Some((_result, record)) = rx.next().await {
      records = record;
    }
    let record = Content::json(&records)?;
    Ok(CallToolResult::success(vec![record]))
  }
  #[tool(description = "Verify Matcher for Response")]
  async fn verify_matcher(
    &self,
    Parameters(VerifyMatcher {
      response,
      mut operators,
    }): Parameters<VerifyMatcher>,
  ) -> Result<CallToolResult, McpError> {
    let mut result = OperatorResult::default();
    if let Err(err) = operators.compile() {
      return Err(McpError::internal_error(err.to_string(), None));
    };
    if let Err(err) = operators.matcher(&response, &mut result) {
      return Err(McpError::internal_error(err.to_string(), None));
    };
    return Ok(CallToolResult::success(vec![Content::json(result)?]));
  }
  #[tool(description = "Verify Extractor for Response")]
  async fn verify_extractor(
    &self,
    Parameters(VerifyExtractor {
      info,
      response,
      mut operators,
    }): Parameters<VerifyExtractor>,
  ) -> Result<CallToolResult, McpError> {
    let mut result = OperatorResult::default();
    if let Err(err) = operators.compile() {
      return Err(McpError::internal_error(err.to_string(), None));
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
  ) -> Result<ListPromptsResult, McpError> {
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
  ) -> Result<GetPromptResult, McpError> {
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
      _ => Err(McpError::invalid_params("prompt not found", None)),
    }
  }
  async fn list_resource_templates(
    &self,
    _request: Option<PaginatedRequestParam>,
    _: RequestContext<RoleServer>,
  ) -> Result<ListResourceTemplatesResult, McpError> {
    Ok(ListResourceTemplatesResult {
      next_cursor: None,
      resource_templates: Vec::new(),
    })
  }

  async fn initialize(
    &self,
    _request: InitializeRequestParam,
    _context: RequestContext<RoleServer>,
  ) -> Result<InitializeResult, McpError> {
    Ok(self.get_info())
  }
}
