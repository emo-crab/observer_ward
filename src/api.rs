use actix_web::{web, App, HttpResponse, HttpServer};
use serde::{Deserialize, Serialize};
use observer_ward::{scan, WhatWebResult, update_web_fingerprint};
use futures::future::join_all;
use colored::Colorize;
use std::collections::{HashSet};
use std::iter::FromIterator;

#[derive(Debug, Serialize, Deserialize)]
struct ApiTargetList {
    targets: Vec<String>,
}

async fn index(item: web::Json<ApiTargetList>) -> HttpResponse {
    let mut results_list: Vec<WhatWebResult> = Vec::new();
    let api_target_list: HashSet<String> = HashSet::from_iter(item.targets.clone());
    let futures = api_target_list.into_iter().map(scan).collect::<Vec<_>>();
    let results = join_all(futures).await;
    for res in results {
        results_list.push(res);
    }
    HttpResponse::Ok().json(results_list)
}

async fn update() -> HttpResponse {
    update_web_fingerprint().await;
    let results: Vec<String> = Vec::new();
    HttpResponse::Ok().json(results)
}

#[actix_web::main]
pub async fn api_server(server_host_port: String) -> std::io::Result<()> {
    let s = format!("http://{}/what_web", server_host_port);
    println!("API service has been started:{}", s.clone());
    let api_doc = format!(r#"curl --request POST \
  --url {} \
  --header 'Content-Type: application/json' \
  --data '{{"targets":["https://httpbin.org/"]}}'"#, s);
    let result = r#"[{"url":"https://httpbin.org/","what_web_name":["swagger"],"priority":2,"length":9593,"title":"httpbin.org"}]"#;
    println!("Instructions:\n{}\nResult:\n{}", api_doc.green().bold(), result.red());
    HttpServer::new(|| {
        App::new()
            .data(web::JsonConfig::default().limit(4096))
            .service(web::resource("/what_web").route(web::post().to(index)))
            .service(web::resource("/update").route(web::get().to(update)))
    }).bind(server_host_port)?
        .run()
        .await
}
