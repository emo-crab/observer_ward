use crate::slinger::tls::{CustomTlsConnector, CustomTlsStream, PeerCertificate};
use crate::slinger::{Socket, StreamWrapper};
use std::sync::Arc;
use tokio::net::TcpStream;

struct NativeTlsStream {
  inner: tokio_native_tls::TlsStream<TcpStream>,
}

impl NativeTlsStream {
  fn new(stream: tokio_native_tls::TlsStream<TcpStream>) -> Self {
    Self { inner: stream }
  }
}

slinger::impl_tls_stream!(NativeTlsStream, inner);

impl CustomTlsStream for NativeTlsStream {
  fn peer_certificate(&self) -> Option<Vec<PeerCertificate>> {
    let cert = self.inner.get_ref().peer_certificate().ok()??.to_der().ok()?;
    Some(vec![PeerCertificate { inner: cert }])
  }

  fn alpn_protocol(&self) -> Option<Vec<u8>> {
    None
  }
}

struct NativeTlsConnector {
  connector: tokio_native_tls::TlsConnector,
}

impl NativeTlsConnector {
  fn new() -> std::result::Result<Self, Box<dyn std::error::Error>> {
    let mut builder = tokio_native_tls::native_tls::TlsConnector::builder();
    builder.danger_accept_invalid_certs(true);
    builder.danger_accept_invalid_hostnames(true);
    builder.min_protocol_version(Some(tokio_native_tls::native_tls::Protocol::Tlsv10));
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
  ) -> std::pin::Pin<Box<dyn std::future::Future<Output = crate::slinger::Result<Socket>> + Send + 'a>>
  {
    let connector = self.connector.clone();
    let domain = domain.to_string();

    Box::pin(async move {
      let tcp_stream = match stream.inner {
        StreamWrapper::Tcp(tcp) => tcp,
        _ => {
          return Err(crate::slinger::Error::Other(
            "Expected plain TCP stream for TLS upgrade".to_string(),
          ));
        }
      };

      let tls_stream = connector.connect(&domain, tcp_stream).await.map_err(|e| {
        crate::slinger::Error::Other(format!("native-tls handshake failed: {}", e))
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
