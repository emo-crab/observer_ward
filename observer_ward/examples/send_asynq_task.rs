use asynq::client::Client;
use asynq::redis::RedisConnectionType;
use asynq::task::Task;
use engine::slinger::http::{Method, StatusCode, Version};
use engine::slinger::{Request, Response};
use std::collections::HashSet;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
  // Connect to local Redis (default)
  let redis_uri = "redis://127.0.0.1:6379";
  let redis_config = RedisConnectionType::single(redis_uri)?;
  let client = Client::new(redis_config).await?;
  let payload = observer_ward::worker::FingerprintTask {
    task_id: "target_example".to_string(),
    input: observer_ward::worker::TaskInput::Uri {
      target: HashSet::from_iter(vec!["http://example.com".to_string()]),
    },
    config: None,
  };

  // Create the task with a type name (worker does not filter by type) and send it to the worker queue.
  let task =
    Task::new_with_json("fingerprint:run", &payload)?.with_queue(observer_ward::worker::TASK_QUEUE);
  client.enqueue(task).await?;
  let http_data = observer_ward::worker::FingerprintTask {
    task_id: "http_data_example".to_string(),
    input: observer_ward::worker::TaskInput::HttpData {
      request: Request {
        method: Method::GET,
        uri: "http://example.com".parse().unwrap(),
        headers: Default::default(),
        body: None,
        version: Version::HTTP_11,
        raw_request: None,
      },
      response: Response {
        version: Version::HTTP_11,
        uri: "http://example.com".parse().unwrap(),
        status_code: StatusCode::OK,
        headers: Default::default(),
        extensions: Default::default(),
        body: Some("<html><head><title>Example Domain</title></head><body></body></html>".into()),
      },
    },
    config: None,
  };
  let task = Task::new_with_json("fingerprint:run", &http_data)?
    .with_queue(observer_ward::worker::TASK_QUEUE);
  client.enqueue(task).await?;
  Ok(())
}
