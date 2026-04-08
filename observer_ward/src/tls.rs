use engine::slinger::http::Uri;
use engine::slinger::tls::{CustomTlsConnector, CustomTlsStream, PeerCertificate};
use engine::slinger::{Client, Request, RequestBuilder, Response, Socket, StreamWrapper};
use native_tls::{Protocol, TlsConnector};
use std::collections::HashMap;
use std::sync::{Arc, RwLock};
use tokio::net::TcpStream;

struct NativeTlsStream {
  inner: tokio_native_tls::TlsStream<TcpStream>,
}

impl NativeTlsStream {
  fn new(stream: tokio_native_tls::TlsStream<TcpStream>) -> Self {
    Self { inner: stream }
  }
}

engine::slinger::impl_tls_stream!(NativeTlsStream, inner);

impl CustomTlsStream for NativeTlsStream {
  fn peer_certificate(&self) -> Option<Vec<PeerCertificate>> {
    let cert = self.inner.get_ref().peer_certificate().ok()??.to_der().ok()?;
    Some(vec![PeerCertificate { inner: cert }])
  }

  fn alpn_protocol(&self) -> Option<Vec<u8>> {
    self.inner.get_ref().negotiated_alpn().ok()?
  }
}

struct NativeTlsConnector {
  connector: tokio_native_tls::TlsConnector,
}

impl NativeTlsConnector {
  fn new() -> std::result::Result<Self, Box<dyn std::error::Error>> {
    let mut builder = TlsConnector::builder();
    builder.danger_accept_invalid_certs(true);
    builder.danger_accept_invalid_hostnames(true);
    builder.request_alpns(&["http/1.1", "h2"]);
    builder.min_protocol_version(Some(Protocol::Tlsv10));
    let connector = builder.build()?;
    Ok(Self {
      connector: tokio_native_tls::TlsConnector::from(connector),
    })
  }
}

impl CustomTlsConnector for NativeTlsConnector {
  fn connect<'a>(
    &'a self,
    domain: &'a str,
    stream: Socket,
  ) -> std::pin::Pin<Box<dyn std::future::Future<Output = engine::slinger::Result<Socket>> + Send + 'a>>
  {
    let connector = self.connector.clone();
    let domain = domain.to_string();

    Box::pin(async move {
      let tcp_stream = match stream.inner {
        StreamWrapper::Tcp(tcp) => tcp,
        _ => {
          return Err(engine::slinger::Error::Other(
            "Expected plain TCP stream for TLS upgrade".to_string(),
          ));
        }
      };

      let tls_stream = connector.connect(&domain, tcp_stream).await.map_err(|e| {
        engine::slinger::Error::Other(format!("native-tls handshake failed: {}", e))
      })?;

      Ok(Socket::new(
        StreamWrapper::Custom(Box::new(NativeTlsStream::new(tls_stream))),
        stream.read_timeout,
        stream.write_timeout,
      ))
    })
  }
}

pub fn fallback_tls_connector() -> Arc<dyn CustomTlsConnector> {
  Arc::new(NativeTlsConnector::new().expect("failed to build native-tls connector"))
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TlsBackend {
  Rustls,
  NativeTls,
}

#[derive(Clone)]
pub struct FallbackHttpClient {
  rustls: Client,
  native_tls: Client,
  backend_cache: Arc<RwLock<HashMap<String, TlsBackend>>>,
}

impl FallbackHttpClient {
  pub fn new(rustls: Client, native_tls: Client) -> Self {
    Self::with_cache(rustls, native_tls, Arc::new(RwLock::new(HashMap::new())))
  }

  pub fn with_cache(
    rustls: Client,
    native_tls: Client,
    backend_cache: Arc<RwLock<HashMap<String, TlsBackend>>>,
  ) -> Self {
    Self {
      rustls,
      native_tls,
      backend_cache,
    }
  }

  pub fn client_for_backend(&self, backend: TlsBackend) -> Client {
    match backend {
      TlsBackend::Rustls => self.rustls.clone(),
      TlsBackend::NativeTls => self.native_tls.clone(),
    }
  }

  pub fn request_builder_client(&self) -> Client {
    self.rustls.clone()
  }

  pub fn preferred_backend_for_uri(&self, uri: &Uri) -> TlsBackend {
    let key = match backend_cache_key(uri) {
      Some(key) => key,
      None => return TlsBackend::Rustls,
    };

    self
      .backend_cache
      .read()
      .ok()
      .and_then(|cache| cache.get(&key).copied())
      .unwrap_or(TlsBackend::Rustls)
  }

  pub async fn execute(&self, request: Request) -> engine::slinger::Result<Response> {
    self.execute_with_backend(request).await.map(|(response, _)| response)
  }

  pub async fn execute_with_backend(
    &self,
    request: Request,
  ) -> engine::slinger::Result<(Response, TlsBackend)> {
    let preferred_backend = self.preferred_backend_for_uri(request.uri());

    if preferred_backend == TlsBackend::NativeTls {
      let response = self.native_tls.execute(request).await?;
      return Ok((response, TlsBackend::NativeTls));
    }

    match self.rustls.execute(request.clone()).await {
      Ok(response) => {
        self.remember_backend(request.uri(), TlsBackend::Rustls);
        Ok((response, TlsBackend::Rustls))
      }
      Err(err) if should_fallback(&request, &err) => match self.native_tls.execute(request).await {
        Ok(response) => {
          self.remember_backend(response.uri(), TlsBackend::NativeTls);
          Ok((response, TlsBackend::NativeTls))
        }
        Err(_) => Err(err),
      },
      Err(err) => Err(err),
    }
  }

  pub async fn send(
    &self,
    request_builder: RequestBuilder,
  ) -> engine::slinger::Result<(Response, TlsBackend)> {
    let request = request_builder.build()?;
    self.execute_with_backend(request).await
  }

  fn remember_backend(&self, uri: &Uri, backend: TlsBackend) {
    if let Some(key) = backend_cache_key(uri)
      && let Ok(mut cache) = self.backend_cache.write()
    {
      cache.insert(key, backend);
    }
  }
}

fn backend_cache_key(uri: &Uri) -> Option<String> {
  if uri.scheme_str() != Some("https") {
    return None;
  }
  uri.authority()
    .map(|authority| authority.as_str().to_string())
    .or_else(|| uri.host().map(str::to_string))
}

fn should_fallback(request: &Request, err: &engine::slinger::Error) -> bool {
  if request.uri().scheme_str() != Some("https") {
    return false;
  }

  match err {
    engine::slinger::Error::Tls(_) => true,
    engine::slinger::Error::Other(message) => {
      let message = message.to_ascii_lowercase();
      [
        "rustls handshake failed",
        "peer is incompatible",
        "received fatal alert",
        "handshake failure",
        "protocol version",
        "tls handshake eof",
        "alert handshake failure",
      ]
      .iter()
      .any(|pattern| message.contains(pattern))
    }
    _ => false,
  }
}
