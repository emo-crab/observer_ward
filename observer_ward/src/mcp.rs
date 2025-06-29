use crate::cli::ObserverWardConfig;
use crate::{MatchedResult, ObserverWard};
use engine::execute::ClusterType;
use futures::StreamExt;
use futures::channel::mpsc::unbounded;
use rmcp::{
  Error as McpError, RoleServer, ServerHandler,
  handler::server::{router::tool::ToolRouter, tool::Parameters},
  model::*,
  service::RequestContext,
  tool, tool_handler, tool_router,
};
use std::collections::BTreeMap;
use std::future::Future;
use std::ops::Deref;
use std::sync::RwLock;
pub struct ObserverWardHandler {
  cluster_templates: RwLock<ClusterType>,
  config: ObserverWardConfig,
  tool_router: ToolRouter<ObserverWardHandler>,
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
    let cl = {
      if let Ok(cl_guard) = self.cluster_templates.read() {
        cl_guard.deref().clone()
      } else {
        ClusterType::default()
      }
    };
    let (tx, mut rx) = unbounded();
    tokio::task::spawn(async move {
      ObserverWard::new(&config.0, cl).execute(tx).await;
    });
    let mut results: Vec<BTreeMap<String, MatchedResult>> = Vec::new();
    while let Some(result) = rx.next().await {
      results.push(result)
    }
    let result = Content::json(&results)?;
    Ok(CallToolResult::success(vec![result]))
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
        "example_prompt",
        Some("This is an example prompt that takes one required argument, message"),
        None,
      )],
    })
  }
  async fn get_prompt(
    &self,
    GetPromptRequestParam { name, arguments }: GetPromptRequestParam,
    _: RequestContext<RoleServer>,
  ) -> Result<GetPromptResult, McpError> {
    match name.as_str() {
      "example_prompt" => {
        let message = arguments
          .and_then(|json| json.get("message")?.as_str().map(|s| s.to_string()))
          .ok_or_else(|| McpError::invalid_params("No message provided to example_prompt", None))?;
        let prompt = format!("This is an example prompt with your message here: '{message}'");
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
