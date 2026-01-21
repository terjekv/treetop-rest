use actix_service::{Service, Transform};
use actix_web::{
    error::ErrorForbidden,
    Error,
    dev::ServiceRequest,
    dev::ServiceResponse,
    http::header::{HeaderName, HeaderValue},
    HttpMessage,
};
use futures_util::future::{self, LocalBoxFuture, Ready};
use std::net::{IpAddr, SocketAddr};
use std::task::{Context, Poll};
use std::time::Instant;
use tracing::{info, span, Instrument, Level, warn};
use uuid::Uuid;
use crate::{config::ClientAllowlist, metrics};

#[derive(Clone)]
pub struct RequestIds {
    pub request_id: String,
    pub correlation_id: String,
}

#[derive(Clone)]
pub struct ClientAllowlistMiddleware {
    allowlist: ClientAllowlist,
    trust_ip_headers: bool,
}

impl ClientAllowlistMiddleware {
    pub fn new(allowlist: ClientAllowlist) -> Self {
        Self { allowlist, trust_ip_headers: true }
    }

    pub fn new_with_trust(allowlist: ClientAllowlist, trust_ip_headers: bool) -> Self {
        Self { allowlist, trust_ip_headers }
    }
}

impl<S, B> Transform<S, ServiceRequest> for ClientAllowlistMiddleware
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = Error> + 'static,
    S::Future: 'static,
    B: 'static,
{
    type Response = ServiceResponse<B>;
    type Error = Error;
    type Transform = ClientAllowlistMiddlewareService<S>;
    type InitError = ();
    type Future = Ready<Result<Self::Transform, Self::InitError>>;

    fn new_transform(&self, service: S) -> Self::Future {
        future::ready(Ok(ClientAllowlistMiddlewareService {
            service,
            allowlist: self.allowlist.clone(),
            trust_ip_headers: self.trust_ip_headers,
        }))
    }
}

pub struct ClientAllowlistMiddlewareService<S> {
    service: S,
    allowlist: ClientAllowlist,
    trust_ip_headers: bool,
}

impl<S, B> Service<ServiceRequest> for ClientAllowlistMiddlewareService<S>
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = Error> + 'static,
    B: 'static,
{
    type Response = ServiceResponse<B>;
    type Error = Error;
    type Future = LocalBoxFuture<'static, Result<Self::Response, Self::Error>>;

    fn poll_ready(&self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.service.poll_ready(cx)
    }

    fn call(&self, req: ServiceRequest) -> Self::Future {
        let allowlist = self.allowlist.clone();
        let trust = self.trust_ip_headers;
        let client_ip = extract_client_ip(&req, trust);
        let fut = self.service.call(req);

        Box::pin(async move {
            match client_ip {
                Some(ip) if allowlist.allows(ip) => fut.await,
                Some(ip) => {
                    warn!(message = "Rejected request from disallowed IP", client_ip = %ip);
                    Err(ErrorForbidden("Client not allowed"))
                }
                None => {
                    warn!(message = "Rejected request with missing client IP");
                    Err(ErrorForbidden("Client not allowed"))
                }
            }
        })
    }
}

const CORRELATION_ID: HeaderName = HeaderName::from_static("x-correlation-id");
const REQUEST_ID: HeaderName = HeaderName::from_static("x-request-id");

fn extract_client_ip(req: &ServiceRequest, trust_headers: bool) -> Option<IpAddr> {
    let header_ip = if trust_headers {
        req.connection_info()
            .realip_remote_addr()
            .and_then(|raw| raw.split(',').next())
            .and_then(|raw| raw.trim().parse::<IpAddr>().ok().or_else(|| parse_socket(raw)))
    } else {
        None
    };

    header_ip.or_else(|| req.peer_addr().map(|addr| addr.ip()))
}

fn parse_socket(raw: &str) -> Option<IpAddr> {
    if let Ok(sa) = raw.parse::<SocketAddr>() {
        return Some(sa.ip());
    }

    raw.trim_start_matches('[')
        .split(']')
        .next()
        .and_then(|ip| ip.parse::<IpAddr>().ok())
}

// Middleware factory
#[derive(Clone)]
pub struct TracingMiddleware {
    trust_ip_headers: bool,
}

impl TracingMiddleware {
    pub fn new() -> Self {
        Self { trust_ip_headers: true }
    }

    pub fn new_with_trust(trust_ip_headers: bool) -> Self {
        Self { trust_ip_headers }
    }
}

impl<S, B> Transform<S, ServiceRequest> for TracingMiddleware
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = Error> + 'static,
    S::Future: 'static,
    B: 'static,
{
    type Response = ServiceResponse<B>;
    type Error = Error;
    type Transform = TracingMiddlewareService<S>;
    type InitError = ();
    type Future = Ready<Result<Self::Transform, Self::InitError>>;

    fn new_transform(&self, service: S) -> Self::Future {
        future::ready(Ok(TracingMiddlewareService {
            service,
            trust_ip_headers: self.trust_ip_headers,
        }))
    }
}

pub struct TracingMiddlewareService<S> {
    service: S,
    trust_ip_headers: bool,
}

impl<S, B> Service<ServiceRequest> for TracingMiddlewareService<S>
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = Error> + 'static,
    B: 'static,
{
    type Response = ServiceResponse<B>;
    type Error = Error;
    type Future = LocalBoxFuture<'static, Result<Self::Response, Self::Error>>;

    fn poll_ready(&self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.service.poll_ready(cx)
    }

    fn call(&self, req: ServiceRequest) -> Self::Future {
        let request_id = Uuid::new_v4().to_string();
        let correlation_id = req
            .headers()
            .get(&CORRELATION_ID)
            .and_then(|hv| hv.to_str().ok())
            .map(str::to_string)
            .unwrap_or_else(|| request_id.clone());

        // Make IDs available to downstream handlers/services
        req.extensions_mut().insert(RequestIds {
            request_id: request_id.clone(),
            correlation_id: correlation_id.clone(),
        });

        let span = span!(
            Level::INFO,
            "request",
            request_id     = %request_id,
            correlation_id = %correlation_id
        );

        let method = req.method().to_string();
        let path = req.path().to_string();
        let client_ip = extract_client_ip(&req, self.trust_ip_headers);
        let client_ip_s = client_ip.map(|ip| ip.to_string());

        let start_time = Instant::now();
        info!(request_id = %request_id, correlation_id = %correlation_id, message = "Request start", method = &method, path = &path, client_ip = client_ip_s.as_deref());

        let fut = self.service.call(req);

        Box::pin(
            async move {
                let mut res = fut.await?;
                
                let elapsed_time = start_time.elapsed();
                info!(message = "Request end", request_id = %request_id, correlation_id = %correlation_id, method = &method, path = &path, client_ip = client_ip_s.as_deref(), run_time = ?elapsed_time, status_code = ?res.status());
                // Record HTTP metrics
                let status_code = res.status().as_u16();
                metrics::http_metrics().observe(
                    &method,
                    &path,
                    status_code,
                    client_ip_s.as_deref(),
                    elapsed_time.as_secs_f64(),
                );

                res.headers_mut().insert(
                    REQUEST_ID,
                    HeaderValue::from_str(&request_id)
                        .unwrap_or_else(|_| HeaderValue::from_static("<failed>")),
                );

                res.headers_mut().insert(
                    CORRELATION_ID,
                    HeaderValue::from_str(&correlation_id)
                        .unwrap_or_else(|_| HeaderValue::from_static("<failed>")),
                );
                Ok(res)
            }
            .instrument(span),
        )
    }
}

