#![allow(unused_imports)]

use crate::scp_prov::api_call;
use crate::scp_service;
use async_trait::async_trait;
use futures::future::BoxFuture;
use futures::{future, pin_mut, select, FutureExt, Stream, StreamExt, TryFutureExt, TryStreamExt};
use hyper::body::to_bytes;
use hyper::server::conn::{AddrStream, Http};
use hyper::service::{make_service_fn, service_fn, Service};
use hyper::{Body, HeaderMap, Request, Server, StatusCode};
use hyper_openssl::HttpsConnector;
use log::info;
use models::{self, ProblemDetails};
use nscp_api::{
    server::MakeService, Api, SCPDetectAssistRequest, SCPDetectAssistResponse,
    SCPDetectInitRequest, SCPDetectInitResponse, SCPDetectResultRequest, SCPDetectResultResponse,
    SCPForwardResponse, SCPIDFinalSetRequest, SCPIDFinalSetResponse, SCPIDInitSetRequest,
    SCPIDInitSetResponse,
};
use openssl::ssl::{Ssl, SslOptions};
#[cfg(not(any(target_os = "macos", target_os = "windows", target_os = "ios")))]
use openssl::ssl::SslAcceptorBuilder;
#[cfg(not(any(target_os = "macos", target_os = "windows", target_os = "ios")))]
use openssl::ssl::{SslAcceptor, SslFiletype, SslMethod};
use std::collections::HashMap;
use std::convert::Infallible;
use std::error::Error;
use std::future::Future;
use std::marker::PhantomData;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};
use swagger::auth::MakeAllowAllAuthenticator;
use swagger::ApiError;
use swagger::EmptyContext;
use swagger::{BodyExt, Has, XSpanIdString};
use tokio::net::{TcpListener, TcpStream};
use tokio_openssl::SslStream;

async fn shutdown_signal() {
    // intercept SIGTERM
    let mut t1 = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()).unwrap();
    let s1 = t1.recv().fuse();
    // intercept SIGINT
    let mut t2 = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::interrupt()).unwrap();
    let s2 = t2.recv().fuse();
    pin_mut!(s1, s2);
    // return when any of two is received
    select! {
        (_) = s1 => {return;},
        (_) = s2 => {return;},
    };
}
// use futures_util::stream::{Stream, StreamExt};
struct IncomingStream {
    listener: TcpListener,
    tls_acceptor: Arc<SslAcceptor>,
    in_progress: Option<
        Pin<Box<dyn futures::Future<Output = Result<SslStream<TcpStream>, io::Error>> + Send>>,
    >,
}
use std::io;
impl Stream for IncomingStream {
    type Item = Result<SslStream<TcpStream>, io::Error>;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        if let Some(fut) = self.in_progress.as_mut() {
            return match fut.as_mut().poll(cx) {
                Poll::Ready(result) => {
                    self.in_progress = None;
                    Poll::Ready(Some(result))
                }
                Poll::Pending => Poll::Pending,
            };
        }

        match self.listener.poll_accept(cx) {
            Poll::Ready(Ok((tcp, _))) => {
                let tls_acceptor = self.tls_acceptor.clone();
                let fut = Box::pin(async move {
                    let ssl = Ssl::new(tls_acceptor.context()).map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;
                    let mut tls_stream = SslStream::new(ssl, tcp).map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;
                    Pin::new(&mut tls_stream).accept().await.map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;
                    Ok(tls_stream)
                });
                self.in_progress = Some(fut);
                cx.waker().wake_by_ref();
                Poll::Pending
            }
            Poll::Ready(Err(e)) => Poll::Ready(Some(Err(e))),
            Poll::Pending => Poll::Pending,
        }
    }
}

/// Builds an SSL implementation for Simple HTTPS from some hard-coded file names
pub async fn create(addr: &str, https: bool) {
    let addr = addr.parse().expect("Failed to parse bind address");

    // let make_service = make_service_fn(|_| async {
    //     let acceptor = ssl_acceptor.clone();
    //     Ok::<_, hyper::Error>(hyper::service::service_fn(move |req| {
    //         let stream = acceptor.accept(listener.accept().await?.0).await?;
    //         async { Ok(hello_service(req).await?) }
    //     }))
    // });

    let make_service = make_service_fn(move |conn: &AddrStream| {
        // We have to clone the context to share it with each invocation of
        // `make_service`. If your data doesn't implement `Clone` consider using
        // an `std::sync::Arc`.
        // let context = context.clone();

        // You can grab the address of the incoming connection like so.
        let addr = conn.remote_addr();

        // Create a `Service` for responding to the request.
        let service = service_fn(move |req| {
            let context = XSpanIdString::get_or_generate(&req);
            // let stream = acceptor.accept(listener.accept().await?.0).await?;
            call(addr, (req, context))
        });

        // Return the service to hyper.
        async move { Ok::<_, Infallible>(service) }
    });

    // let server = Server::new();
    // let service = MakeService::new(server);
    // let service = MakeAllowAllAuthenticator::new(service, "cosmo");
    // let mut service =
    //     nscp_api::server::context::MakeAddContext::<_, EmptyContext>::new(
    // 		service
    // 	);
    if https {
        #[cfg(any(target_os = "macos", target_os = "windows", target_os = "ios"))]
        {
            unimplemented!("SSL is not implemented for the examples on MacOS, Windows or iOS");
        }
        #[cfg(not(any(target_os = "macos", target_os = "windows", target_os = "ios")))]
        {
            let make_service = make_service_fn(move |conn: &SslStream<TcpStream>| {
                // We have to clone the context to share it with each invocation of
                // `make_service`. If your data doesn't implement `Clone` consider using
                // an `std::sync::Arc`.
                // let context = context.clone();

                // You can grab the address of the incoming connection like so.
                let addr = conn.get_ref().peer_addr().unwrap();

                // Create a `Service` for responding to the request.
                let service = service_fn(move |req| {
                    let context = XSpanIdString::get_or_generate(&req);
                    // let stream = acceptor.accept(listener.accept().await?.0).await?;
                    call(addr, (req, context))
                });

                // Return the service to hyper.
                async move { Ok::<_, Infallible>(service) }
            });
				let mut ssl = SslAcceptor::mozilla_intermediate_v5(SslMethod::tls())
					.expect("Failed to create SSL Acceptor");
				// Server authentication
				ssl.set_private_key_file("/cfg/key_file.pem", SslFiletype::PEM)
					.expect("Failed to set private key");
				ssl.set_certificate_chain_file("/cfg/cert_file.pem")
					.expect("Failed to set cerificate chain");
				ssl.check_private_key()
					.expect("Failed to check private key");
				// ssl.set_options(SslOptions::)
				let tls_acceptor = Arc::new(ssl.build());
				let mut tcp_listener = TcpListener::bind(&addr).await.unwrap();
				// let mut incoming = tcp_listener.incoming();
				let incoming_stream = IncomingStream {
					listener: tcp_listener,
					tls_acceptor: tls_acceptor.clone(),
					in_progress: None,
				};
				Server::builder(hyper::server::accept::from_stream(incoming_stream))
                .serve(make_service)
                .await;
        }
    } else {
        // Using HTTP
        hyper::server::Server::bind(&addr)
            .http2_only(true)
            .serve(make_service)
            .await;
    }
}

// #[async_trait]
// impl<C> Api<C> for Server<C> where C: Has<XSpanIdString> + Send + Sync
// {
//     /// Activate SMS Service for a given UE
//     async fn scp_forward(
//         &self,
// 		old_request: Request<Body>,
//         context: &C) -> Result<SCPForwardResponse, ApiError>
//     {
//         let context = context.clone();
//         info!("pdf-connect(\"-----\") - X-Span-ID: {:?}", context.get().0.clone());
//         Ok(match scp_service::SCPForward(old_request).await {
// 			Ok(a) => a,
// 			Err(e) => SCPForwardResponse::InvalidServiceRequest(ProblemDetails::with_detail(&format!("Error: {}", e)))
// 		})
//     }
// 	async fn scp_notify(
// 		&self,
// 		data: models::NotificationData,
// 		route_binding: Option<String>,
// 		context: &C) -> Result<(), ApiError>
// 	{
// 		let context = context.clone();
// 		let req = scp_service::SCPNotify(data, route_binding);
// 		let client = hyper::Client::builder().http2_only(true).build_http();
// 		let response = client.request(req).await;
// 		if let Err(r) = response {
// 			log::warn!("Error notifying event consumer {:?}", r);
// 		}
// 		Ok(())
// 	}
// }

use base64::{engine::general_purpose, Engine as _};
use hyper::header::{HeaderName, HeaderValue, CONTENT_TYPE};
use hyper::Response;
use log::warn;
use mime_multipart::{read_multipart_body, Node, Part};
#[allow(unused_imports)]
use nscp_api::header;
#[allow(unused_imports)]
use std::convert::{TryFrom, TryInto};
pub use swagger::auth::Authorization;
use swagger::auth::Scopes;
use url::form_urlencoded;

pub use crate::context;

// fn clone_request_headers(request: Request<Body>) -> (Request<Body>, Request<Body>) {
//     let headers = request.headers().clone();
//     let mut cloned_request = Request::builder()
//         .method(request.method().clone())
//         .uri(request.uri().clone())
//         .body(request.body().clone().to_owned())
//         .unwrap();
//     let mut cloned_request1 = Request::builder()
//         .method(request.method().clone())
//         .uri(request.uri().clone())
//         .body(Body::from(&request.body()))
//         .unwrap();
// 	(cloned_request, cloned_request1)
// }

mod paths {
    use lazy_static::lazy_static;

    lazy_static! {
        pub static ref GLOBAL_REGEX_SET: regex::RegexSet = regex::RegexSet::new(vec![
            // r"^/nscp-fwd/v1/(?P<restPath>.+)$",
            r"^/nscp-notify/v1/subscriptions$",
            r"^/nscp-detect/v1/init$",
            r"^/nscp-detect/v1/assist$",
            r"^/nscp-detect/v1/result/(?P<id>.+)$",
            r"^/nscp-id/v1/initial-set/(?P<id>.+)$",
            r"^/nscp-id/v1/final-set/(?P<id>.+)$",
        ])
        .expect("Unable to create global regex set");
    }
    // pub(crate) static Forward: usize = 0;
    // lazy_static! {
    //     pub static ref REGEX_FORWARD_PATH: regex::Regex =
    //         regex::Regex::new( r"^/nscp-fwd/v1/(?P<restPath>.+)$")
    //             .expect("Unable to create regex for Connection");
    // }
    pub(crate) static Notify: usize = 0;
    lazy_static! {
        pub static ref REQEX_NOTIFY_PATH: regex::Regex =
            regex::Regex::new(r"^/nscp-notify/v1/subscriptions$")
                .expect("Unable to create regex for Connection");
    }
    pub(crate) static Detect_Init: usize = 1;
    lazy_static! {
        pub static ref REGEX_DETECT_INIT: regex::Regex =
            regex::Regex::new(r"^/nscp-detect/v1/init$")
                .expect("Unable to create regex for Connection");
    }
    pub(crate) static Detect_Assist: usize = 2;
    lazy_static! {
        pub static ref REGEX_DETECT_ASSIST: regex::Regex =
            regex::Regex::new(r"^/nscp-detect/v1/assist$")
                .expect("Unable to create regex for Connection");
    }
    pub(crate) static Detect_Result: usize = 3;
    lazy_static! {
        pub static ref REGEX_DETECT_RESULT: regex::Regex =
            regex::Regex::new(r"^/nscp-detect/v1/result/(?P<id>.+)$")
                .expect("Unable to create regex for Connection");
    }
    pub(crate) static ID_Initial_Set: usize = 4;
    lazy_static! {
        pub static ref REGEX_ID_INIT_SET: regex::Regex =
            regex::Regex::new(r"^/nscp-id/v1/initial-set/(?P<id>.+)$")
                .expect("Unable to create regex for Connection");
    }
    pub(crate) static ID_Final_Set: usize = 5;
    lazy_static! {
        pub static ref REGEX_ID_FINAL_SET: regex::Regex =
            regex::Regex::new(r"^/nscp-id/v1/final-set/(?P<id>.+)$")
                .expect("Unable to create regex for Connection");
    }
}
type ServiceError = Box<dyn Error + Send + Sync + 'static>;
fn method_not_allowed() -> Result<Response<Body>, ServiceError> {
    // // log::info!("Correct func 3");
    Ok(Response::builder()
        .status(StatusCode::METHOD_NOT_ALLOWED)
        .body(Body::empty())
        .expect("Unable to create Method Not Allowed response"))
}
type SFuture = BoxFuture<'static, Result<Response<Body>, ServiceError>>;
// type C = dyn Has<XSpanIdString>;
async fn call(
    addr: SocketAddr,
    req: (Request<Body>, XSpanIdString),
) -> Result<Response<Body>, ServiceError> {
    let (request, context) = req;
    let (parts, body) = request.into_parts();
    let (method, uri, headers) = (
        parts.method.clone(),
        parts.uri.clone(),
        parts.headers.clone(),
    );
    let path = paths::GLOBAL_REGEX_SET.matches(uri.path());
    let mut cloned_request = Request::from_parts(parts, Body::empty());
    // log::info!("METHOD {:?} URI {:?}", method, uri);
    // log::info!("Entering function");
    match &method {
        &hyper::Method::POST if path.matched(paths::Detect_Init) => {
            let path: &str = &uri.path().to_string();
            let result = to_bytes(body).await;
            match result {
					Ok(body) => {
						let body: Vec<u8> = body.to_vec();
						// info!("{:?}", body);
						let mut unused_elements = Vec::new();
						let str_map: Option<SCPDetectInitRequest> = if !body.is_empty() {
							let deserializer: &mut serde_json::Deserializer<serde_json::de::SliceRead<'_>> = &mut serde_json::Deserializer::from_slice(&*body);
							match serde_ignored::deserialize(deserializer, |path| {
									warn!("Ignoring unknown field in body: {}", path);
									unused_elements.push(path.to_string());
							}) {
								Ok(param_subscription_data) => param_subscription_data,
								Err(e) => return Ok(Response::builder()
												.status(StatusCode::BAD_REQUEST)
												.body(Body::from(format!("Couldn't parse body parameter SubscriptionData - doesn't match schema: {}", e)))
												.expect("Unable to create Bad Request response for invalid body parameter SubscriptionData due to schema")),
							}
						} else {
							None
						};
						if str_map.is_none() {
							let mut response = Response::new(Body::empty());
								*response.status_mut() = StatusCode::from_u16(503).expect("Unable to turn 503 into a StatusCode");
							response.headers_mut().insert(
								CONTENT_TYPE,
								HeaderValue::from_str("application/problem+json")
									.expect("Unable to create Content-Type header for PROVIDE_LOCATION_INFO_SERVICE_UNAVAILABLE"));
							let body = serde_json::to_string(&body).expect("Failed To Deserialize");
							*response.body_mut() = Body::from(body);
								return Ok(response);
						}
						let ds = str_map.unwrap();
						// let ds = SCPDetectInitRequest { algo_name: "LOL".to_owned(), start_time: 0, end_time: 0 };
						let result = api_call::scp_detect_init(
							ds
							).await;
						let mut response = Response::new(Body::empty());
						response.headers_mut().insert(
							HeaderName::from_static("x-span-id"),
							HeaderValue::from_str((&context).0.clone().to_string().as_str())
								.expect("Unable to create X-Span-ID header value"));
						match result {
							Ok(rsp) => match rsp {
								SCPDetectInitResponse::SCPDetectInitComplete
								{
									id
								}
								=> {
									*response.status_mut() = StatusCode::from_u16(201).expect("Unable to turn 200 into a StatusCode");
									response.headers_mut().insert(
										CONTENT_TYPE,
										HeaderValue::from_str("application/problem+json")
											.expect("Unable to create Content-Type header for PROVIDE_LOCATION_INFO_SERVICE_UNAVAILABLE"));
									// let body = serde_json::to_string(&id).expect("impossible to fail to serialize");
									*response.body_mut() = Body::from(id);
								},
								SCPDetectInitResponse::TemporaryRedirect
									{
										body,
										location,
										param_3gpp_sbi_target_nf_id
									}
								=> {
									let location = match header::IntoHeaderValue(location).try_into() {
										Ok(val) => val,
										Err(e) => {
											return Ok(Response::builder()
													.status(StatusCode::INTERNAL_SERVER_ERROR)
													.body(Body::from(format!("An internal server error occurred handling location header - {}", e)))
													.expect("Unable to create Internal Server Error for invalid response header"))
										}
									};

									response.headers_mut().insert(
										HeaderName::from_static("location"),
										location
									);
									if let Some(param_3gpp_sbi_target_nf_id) = param_3gpp_sbi_target_nf_id {
									let param_3gpp_sbi_target_nf_id = match header::IntoHeaderValue(param_3gpp_sbi_target_nf_id).try_into() {
										Ok(val) => val,
										Err(e) => {
											return Ok(Response::builder()
													.status(StatusCode::INTERNAL_SERVER_ERROR)
													.body(Body::from(format!("An internal server error occurred handling param_3gpp_sbi_target_nf_id header - {}", e)))
													.expect("Unable to create Internal Server Error for invalid response header"))
										}
									};

									response.headers_mut().insert(
										HeaderName::from_static("3gpp-sbi-target-nf-id"),
										param_3gpp_sbi_target_nf_id
									);
									}
									*response.status_mut() = StatusCode::from_u16(307).expect("Unable to turn 307 into a StatusCode");
									response.headers_mut().insert(
										CONTENT_TYPE,
										HeaderValue::from_str("application/json")
											.expect("Unable to create Content-Type header for PROVIDE_LOCATION_INFO_TEMPORARY_REDIRECT"));
									let body = serde_json::to_string(&body).expect("impossible to fail to serialize");
									*response.body_mut() = Body::from(body);
								},
								SCPDetectInitResponse::PermanentRedirect
									{
										body,
										location,
										param_3gpp_sbi_target_nf_id
									}
								=> {
									let location = match header::IntoHeaderValue(location).try_into() {
										Ok(val) => val,
										Err(e) => {
											return Ok(Response::builder()
													.status(StatusCode::INTERNAL_SERVER_ERROR)
													.body(Body::from(format!("An internal server error occurred handling location header - {}", e)))
													.expect("Unable to create Internal Server Error for invalid response header"))
										}
									};

									response.headers_mut().insert(
										HeaderName::from_static("location"),
										location
									);
									if let Some(param_3gpp_sbi_target_nf_id) = param_3gpp_sbi_target_nf_id {
									let param_3gpp_sbi_target_nf_id = match header::IntoHeaderValue(param_3gpp_sbi_target_nf_id).try_into() {
										Ok(val) => val,
										Err(e) => {
											return Ok(Response::builder()
													.status(StatusCode::INTERNAL_SERVER_ERROR)
													.body(Body::from(format!("An internal server error occurred handling param_3gpp_sbi_target_nf_id header - {}", e)))
													.expect("Unable to create Internal Server Error for invalid response header"))
										}
									};

									response.headers_mut().insert(
										HeaderName::from_static("3gpp-sbi-target-nf-id"),
										param_3gpp_sbi_target_nf_id
									);
									}
									*response.status_mut() = StatusCode::from_u16(308).expect("Unable to turn 308 into a StatusCode");
									response.headers_mut().insert(
										CONTENT_TYPE,
										HeaderValue::from_str("application/json")
											.expect("Unable to create Content-Type header for PROVIDE_LOCATION_INFO_PERMANENT_REDIRECT"));
									let body = serde_json::to_string(&body).expect("impossible to fail to serialize");
									*response.body_mut() = Body::from(body);
								},
								SCPDetectInitResponse::ServiceUnavailable
									(body)
								=> {
									*response.status_mut() = StatusCode::from_u16(503).expect("Unable to turn 503 into a StatusCode");
									response.headers_mut().insert(
										CONTENT_TYPE,
										HeaderValue::from_str("application/problem+json")
											.expect("Unable to create Content-Type header for PROVIDE_LOCATION_INFO_SERVICE_UNAVAILABLE"));
									let body = serde_json::to_string(&body).expect("impossible to fail to serialize");
									*response.body_mut() = Body::from(body);
								},
								SCPDetectInitResponse::NotFound
									(body)
								=> {
									*response.status_mut() = StatusCode::from_u16(404).expect("Unable to turn 404 into a StatusCode");
									response.headers_mut().insert(
										CONTENT_TYPE,
										HeaderValue::from_str("application/problem+json")
											.expect("Unable to create Content-Type header for PROVIDE_LOCATION_INFO_NOT_FOUND"));
									let body = serde_json::to_string(&body).expect("impossible to fail to serialize");
									*response.body_mut() = Body::from(body);
								},
								SCPDetectInitResponse::Forbidden
									(body)
								=> {
									*response.status_mut() = StatusCode::from_u16(403).expect("Unable to turn 403 into a StatusCode");
									response.headers_mut().insert(
										CONTENT_TYPE,
										HeaderValue::from_str("application/problem+json")
											.expect("Unable to create Content-Type header for PROVIDE_LOCATION_INFO_FORBIDDEN"));
									let body = serde_json::to_string(&body).expect("impossible to fail to serialize");
									*response.body_mut() = Body::from(body);
								},
								SCPDetectInitResponse::InvalidServiceRequest
									(body)
								=> {
									*response.status_mut() = StatusCode::from_u16(503).expect("Unable to turn 503 into a StatusCode");
									response.headers_mut().insert(
										CONTENT_TYPE,
										HeaderValue::from_str("application/problem+json")
											.expect("Unable to create Content-Type header for PROVIDE_LOCATION_INFO_SERVICE_UNAVAILABLE"));
									let body = serde_json::to_string(&body).expect("impossible to fail to serialize");
									*response.body_mut() = Body::from(body);
								},
								SCPDetectInitResponse::UnableToCreate
									(body)
								=> {
									*response.status_mut() = StatusCode::from_u16(503).expect("Unable to turn 503 into a StatusCode");
									response.headers_mut().insert(
										CONTENT_TYPE,
										HeaderValue::from_str("application/problem+json")
											.expect("Unable to create Content-Type header for PROVIDE_LOCATION_INFO_SERVICE_UNAVAILABLE"));
									let body = serde_json::to_string(&body).expect("impossible to fail to serialize");
									*response.body_mut() = Body::from(body);
								},
								SCPDetectInitResponse::TooManyRequests
								(body)
								=> {
									*response.status_mut() = StatusCode::from_u16(429).expect("Unable to turn 503 into a StatusCode");
									response.headers_mut().insert(
										CONTENT_TYPE,
										HeaderValue::from_str("application/problem+json")
											.expect("Unable to create Content-Type header for PROVIDE_LOCATION_INFO_SERVICE_UNAVAILABLE"));
									let body = serde_json::to_string(&body).expect("impossible to fail to serialize");
									*response.body_mut() = Body::from(body);
								},
								SCPDetectInitResponse::InternalServerError
								(body)
								=> {
									*response.status_mut() = StatusCode::from_u16(500).expect("Unable to turn 503 into a StatusCode");
									response.headers_mut().insert(
										CONTENT_TYPE,
										HeaderValue::from_str("application/problem+json")
											.expect("Unable to create Content-Type header for PROVIDE_LOCATION_INFO_SERVICE_UNAVAILABLE"));
									let body = serde_json::to_string(&body).expect("impossible to fail to serialize");
									*response.body_mut() = Body::from(body);
								},
								SCPDetectInitResponse::BadRequest
								(body)
								=> {
									*response.status_mut() = StatusCode::from_u16(400).expect("Unable to turn 503 into a StatusCode");
									response.headers_mut().insert(
										CONTENT_TYPE,
										HeaderValue::from_str("application/problem+json")
											.expect("Unable to create Content-Type header for PROVIDE_LOCATION_INFO_SERVICE_UNAVAILABLE"));
									let body = serde_json::to_string(&body).expect("impossible to fail to serialize");
									*response.body_mut() = Body::from(body);
								},
								SCPDetectInitResponse::UnexpectedError
								=> {
									*response.status_mut() = StatusCode::from_u16(503).expect("Unable to turn 503 into a StatusCode");
									response.headers_mut().insert(
										CONTENT_TYPE,
										HeaderValue::from_str("application/problem+json")
											.expect("Unable to create Content-Type header for PROVIDE_LOCATION_INFO_SERVICE_UNAVAILABLE"));
									let body = serde_json::to_string(&body).expect("impossible to fail to serialize");
									*response.body_mut() = Body::from(body);
								},
							},
							Err(_) => {
								// Application code returned an error. This should not happen, as the implementation should
								// return a valid response.
								*response.status_mut() = StatusCode::INTERNAL_SERVER_ERROR;
								*response.body_mut() = Body::from("An internal error occurred");
							},
						}

						Ok(response)
					},
					Err(e) => Ok(Response::builder()
										.status(StatusCode::BAD_REQUEST)
										.body(Body::from(format!("Couldn't read body parameter RequestLocInfo: {}", e)))
										.expect("Unable to create Bad Request response due to unable to read body parameter RequestLocInfo")),
				}
        }
        &hyper::Method::PUT if path.matched(paths::Detect_Assist) => {
            let path: &str = &uri.path().to_string();

            let result = to_bytes(body).await;
            match result {
					Ok(body) => {
						let body: Vec<u8> = body.to_vec();
						let mut unused_elements = Vec::new();
						let str_map: Option<SCPDetectAssistRequest> = if !body.is_empty() {
							let deserializer: &mut serde_json::Deserializer<serde_json::de::SliceRead<'_>> = &mut serde_json::Deserializer::from_slice(&*body);
							match serde_ignored::deserialize(deserializer, |path| {
									warn!("Ignoring unknown field in body: {}", path);
									unused_elements.push(path.to_string());
							}) {
								Ok(param_subscription_data) => param_subscription_data,
								Err(e) => return Ok(Response::builder()
												.status(StatusCode::BAD_REQUEST)
												.body(Body::from(format!("Couldn't parse body parameter SubscriptionData - doesn't match schema: {}", e)))
												.expect("Unable to create Bad Request response for invalid body parameter SubscriptionData due to schema")),
							}
						} else {
							None
						};
						if str_map.is_none() {
							let mut response = Response::new(Body::empty());
								*response.status_mut() = StatusCode::from_u16(503).expect("Unable to turn 503 into a StatusCode");
							response.headers_mut().insert(
								CONTENT_TYPE,
								HeaderValue::from_str("application/problem+json")
									.expect("Unable to create Content-Type header for PROVIDE_LOCATION_INFO_SERVICE_UNAVAILABLE"));
							let body = serde_json::to_string(&body).expect("Failed To Deserialize");
							*response.body_mut() = Body::from(body);
								return Ok(response);
						}
						let data = str_map.unwrap();

						let result = api_call::scp_detect_assist(
							data
							).await;
						let mut response = Response::new(Body::empty());
						response.headers_mut().insert(
							HeaderName::from_static("x-span-id"),
							HeaderValue::from_str((&context).0.clone().to_string().as_str())
								.expect("Unable to create X-Span-ID header value"));
						match result {
							Ok(rsp) => match rsp {
								SCPDetectAssistResponse::SCPIDAssistComplete{ data}
								=> {
									*response.status_mut() = StatusCode::from_u16(201).expect("Unable to turn 200 into a StatusCode");
									// response.headers_mut().insert(
									// 	CONTENT_TYPE,
									// 	HeaderValue::from_str("application/problem+json")
									// 		.expect("Unable to create Content-Type header for PROVIDE_LOCATION_INFO_SERVICE_UNAVAILABLE"));
									// *response.body_mut() = Body::from(body);
									response.headers_mut().insert(
										CONTENT_TYPE,
										HeaderValue::from_str("application/json")
											.expect("Unable to create Content-Type header for PROVIDE_LOCATION_INFO_PERMANENT_REDIRECT"));
									let body = serde_json::to_string(&body).expect("impossible to fail to serialize");
									*response.body_mut() = Body::from(body);
								},
								SCPDetectAssistResponse::TemporaryRedirect
									{
										body,
										location,
										param_3gpp_sbi_target_nf_id
									}
								=> {
									let location = match header::IntoHeaderValue(location).try_into() {
										Ok(val) => val,
										Err(e) => {
											return Ok(Response::builder()
													.status(StatusCode::INTERNAL_SERVER_ERROR)
													.body(Body::from(format!("An internal server error occurred handling location header - {}", e)))
													.expect("Unable to create Internal Server Error for invalid response header"))
										}
									};

									response.headers_mut().insert(
										HeaderName::from_static("location"),
										location
									);
									if let Some(param_3gpp_sbi_target_nf_id) = param_3gpp_sbi_target_nf_id {
									let param_3gpp_sbi_target_nf_id = match header::IntoHeaderValue(param_3gpp_sbi_target_nf_id).try_into() {
										Ok(val) => val,
										Err(e) => {
											return Ok(Response::builder()
													.status(StatusCode::INTERNAL_SERVER_ERROR)
													.body(Body::from(format!("An internal server error occurred handling param_3gpp_sbi_target_nf_id header - {}", e)))
													.expect("Unable to create Internal Server Error for invalid response header"))
										}
									};

									response.headers_mut().insert(
										HeaderName::from_static("3gpp-sbi-target-nf-id"),
										param_3gpp_sbi_target_nf_id
									);
									}
									*response.status_mut() = StatusCode::from_u16(307).expect("Unable to turn 307 into a StatusCode");
									response.headers_mut().insert(
										CONTENT_TYPE,
										HeaderValue::from_str("application/json")
											.expect("Unable to create Content-Type header for PROVIDE_LOCATION_INFO_TEMPORARY_REDIRECT"));
									let body = serde_json::to_string(&body).expect("impossible to fail to serialize");
									*response.body_mut() = Body::from(body);
								},
								SCPDetectAssistResponse::PermanentRedirect
									{
										body,
										location,
										param_3gpp_sbi_target_nf_id
									}
								=> {
									let location = match header::IntoHeaderValue(location).try_into() {
										Ok(val) => val,
										Err(e) => {
											return Ok(Response::builder()
													.status(StatusCode::INTERNAL_SERVER_ERROR)
													.body(Body::from(format!("An internal server error occurred handling location header - {}", e)))
													.expect("Unable to create Internal Server Error for invalid response header"))
										}
									};

									response.headers_mut().insert(
										HeaderName::from_static("location"),
										location
									);
									if let Some(param_3gpp_sbi_target_nf_id) = param_3gpp_sbi_target_nf_id {
									let param_3gpp_sbi_target_nf_id = match header::IntoHeaderValue(param_3gpp_sbi_target_nf_id).try_into() {
										Ok(val) => val,
										Err(e) => {
											return Ok(Response::builder()
													.status(StatusCode::INTERNAL_SERVER_ERROR)
													.body(Body::from(format!("An internal server error occurred handling param_3gpp_sbi_target_nf_id header - {}", e)))
													.expect("Unable to create Internal Server Error for invalid response header"))
										}
									};

									response.headers_mut().insert(
										HeaderName::from_static("3gpp-sbi-target-nf-id"),
										param_3gpp_sbi_target_nf_id
									);
									}
									*response.status_mut() = StatusCode::from_u16(308).expect("Unable to turn 308 into a StatusCode");
									response.headers_mut().insert(
										CONTENT_TYPE,
										HeaderValue::from_str("application/json")
											.expect("Unable to create Content-Type header for PROVIDE_LOCATION_INFO_PERMANENT_REDIRECT"));
									let body = serde_json::to_string(&body).expect("impossible to fail to serialize");
									*response.body_mut() = Body::from(body);
								},
								SCPDetectAssistResponse::ServiceUnavailable
									(body)
								=> {
									*response.status_mut() = StatusCode::from_u16(503).expect("Unable to turn 503 into a StatusCode");
									response.headers_mut().insert(
										CONTENT_TYPE,
										HeaderValue::from_str("application/problem+json")
											.expect("Unable to create Content-Type header for PROVIDE_LOCATION_INFO_SERVICE_UNAVAILABLE"));
									let body = serde_json::to_string(&body).expect("impossible to fail to serialize");
									*response.body_mut() = Body::from(body);
								},
								SCPDetectAssistResponse::NotFound
									(body)
								=> {
									*response.status_mut() = StatusCode::from_u16(404).expect("Unable to turn 404 into a StatusCode");
									response.headers_mut().insert(
										CONTENT_TYPE,
										HeaderValue::from_str("application/problem+json")
											.expect("Unable to create Content-Type header for PROVIDE_LOCATION_INFO_NOT_FOUND"));
									let body = serde_json::to_string(&body).expect("impossible to fail to serialize");
									*response.body_mut() = Body::from(body);
								},
								SCPDetectAssistResponse::Forbidden
									(body)
								=> {
									*response.status_mut() = StatusCode::from_u16(403).expect("Unable to turn 403 into a StatusCode");
									response.headers_mut().insert(
										CONTENT_TYPE,
										HeaderValue::from_str("application/problem+json")
											.expect("Unable to create Content-Type header for PROVIDE_LOCATION_INFO_FORBIDDEN"));
									let body = serde_json::to_string(&body).expect("impossible to fail to serialize");
									*response.body_mut() = Body::from(body);
								},
								SCPDetectAssistResponse::InvalidServiceRequest
									(body)
								=> {
									*response.status_mut() = StatusCode::from_u16(503).expect("Unable to turn 503 into a StatusCode");
									response.headers_mut().insert(
										CONTENT_TYPE,
										HeaderValue::from_str("application/problem+json")
											.expect("Unable to create Content-Type header for PROVIDE_LOCATION_INFO_SERVICE_UNAVAILABLE"));
									let body = serde_json::to_string(&body).expect("impossible to fail to serialize");
									*response.body_mut() = Body::from(body);
								},
								SCPDetectAssistResponse::UnableToCreate
									(body)
								=> {
									*response.status_mut() = StatusCode::from_u16(503).expect("Unable to turn 503 into a StatusCode");
									response.headers_mut().insert(
										CONTENT_TYPE,
										HeaderValue::from_str("application/problem+json")
											.expect("Unable to create Content-Type header for PROVIDE_LOCATION_INFO_SERVICE_UNAVAILABLE"));
									let body = serde_json::to_string(&body).expect("impossible to fail to serialize");
									*response.body_mut() = Body::from(body);
								},
								SCPDetectAssistResponse::TooManyRequests
								(body)
								=> {
									*response.status_mut() = StatusCode::from_u16(429).expect("Unable to turn 503 into a StatusCode");
									response.headers_mut().insert(
										CONTENT_TYPE,
										HeaderValue::from_str("application/problem+json")
											.expect("Unable to create Content-Type header for PROVIDE_LOCATION_INFO_SERVICE_UNAVAILABLE"));
									let body = serde_json::to_string(&body).expect("impossible to fail to serialize");
									*response.body_mut() = Body::from(body);
								},
								SCPDetectAssistResponse::InternalServerError
								(body)
								=> {
									*response.status_mut() = StatusCode::from_u16(500).expect("Unable to turn 503 into a StatusCode");
									response.headers_mut().insert(
										CONTENT_TYPE,
										HeaderValue::from_str("application/problem+json")
											.expect("Unable to create Content-Type header for PROVIDE_LOCATION_INFO_SERVICE_UNAVAILABLE"));
									let body = serde_json::to_string(&body).expect("impossible to fail to serialize");
									*response.body_mut() = Body::from(body);
								},
								SCPDetectAssistResponse::BadRequest
								(body)
								=> {
									*response.status_mut() = StatusCode::from_u16(400).expect("Unable to turn 503 into a StatusCode");
									response.headers_mut().insert(
										CONTENT_TYPE,
										HeaderValue::from_str("application/problem+json")
											.expect("Unable to create Content-Type header for PROVIDE_LOCATION_INFO_SERVICE_UNAVAILABLE"));
									let body = serde_json::to_string(&body).expect("impossible to fail to serialize");
									*response.body_mut() = Body::from(body);
								},
								SCPDetectAssistResponse::UnexpectedError
								=> {
									*response.status_mut() = StatusCode::from_u16(503).expect("Unable to turn 503 into a StatusCode");
									response.headers_mut().insert(
										CONTENT_TYPE,
										HeaderValue::from_str("application/problem+json")
											.expect("Unable to create Content-Type header for PROVIDE_LOCATION_INFO_SERVICE_UNAVAILABLE"));
									let body = serde_json::to_string(&body).expect("impossible to fail to serialize");
									*response.body_mut() = Body::from(body);
								},
							},
							Err(_) => {
								// Application code returned an error. This should not happen, as the implementation should
								// return a valid response.
								*response.status_mut() = StatusCode::INTERNAL_SERVER_ERROR;
								*response.body_mut() = Body::from("An internal error occurred");
							},
						}

						Ok(response)
					},
					Err(e) => Ok(Response::builder()
										.status(StatusCode::BAD_REQUEST)
										.body(Body::from(format!("Couldn't read body parameter RequestLocInfo: {}", e)))
										.expect("Unable to create Bad Request response due to unable to read body parameter RequestLocInfo")),
				}
        }
        // &hyper::Method::GET if path.matched(paths::Detect_Result) => {
        //     let path: &str = &uri.path().to_string();
        //     let path_params =
		// 		paths::REGEX_DETECT_RESULT
		// 		.captures(&path)
		// 		.unwrap_or_else(||
		// 			panic!("Path {} matched RE NAMF_MT_V1_UE_CONTEXTS_UECONTEXTID in set but failed match against \"{}\"", path, paths::REGEX_DETECT_RESULT.as_str())
		// 		);

        //     let id = match percent_encoding::percent_decode(path_params["id"].as_bytes())
        //         .decode_utf8()
        //     {
        //         Ok(id) => {
        //             match id.parse::<String>() {
        //                 Ok(id) => id,
        //                 Err(e) => return Ok(Response::builder()
        //                     .status(StatusCode::BAD_REQUEST)
        //                     .body(Body::from(format!(
        //                         "Couldn't parse path parameter id: {}",
        //                         e
        //                     )))
        //                     .expect(
        //                         "Unable to create Bad Request response for invalid path parameter",
        //                     )),
        //             }
        //         }
        //         Err(_) => {
        //             return Ok(Response::builder()
        //                 .status(StatusCode::BAD_REQUEST)
        //                 .body(Body::from(format!(
        //                     "Couldn't percent-decode path parameter as UTF-8: {}",
        //                     &path_params["id"]
        //                 )))
        //                 .expect(
        //                     "Unable to create Bad Request response for invalid percent decode",
        //                 ))
        //         }
        //     };
        //     let result = to_bytes(body).await;

        //     let result = api_call::scp_detect_result(id).await;
        //     let mut response = Response::new(Body::empty());
        //     response.headers_mut().insert(
        //         HeaderName::from_static("x-span-id"),
        //         HeaderValue::from_str((&context).0.clone().to_string().as_str())
        //             .expect("Unable to create X-Span-ID header value"),
        //     );
        //     match result {
        //         Ok(rsp) => match rsp {
        //             SCPDetectResultResponse::SCPDetectResultComplete { attackers } => {
        //                 *response.status_mut() = StatusCode::from_u16(200)
        //                     .expect("Unable to turn 200 into a StatusCode");
        //                 response.headers_mut().insert(
		// 						CONTENT_TYPE,
		// 						HeaderValue::from_str("application/problem+json")
		// 							.expect("Unable to create Content-Type header for PROVIDE_LOCATION_INFO_SERVICE_UNAVAILABLE"));
        //                 let body = serde_json::to_string(&attackers)
        //                     .expect("impossible to fail to serialize");
        //                 *response.body_mut() = Body::from(body);
        //             }
        //             SCPDetectResultResponse::SCPDetectResultAccepted(details) => {
        //                 *response.status_mut() = StatusCode::from_u16(202)
        //                     .expect("Unable to turn 200 into a StatusCode");
        //                 response.headers_mut().insert(
		// 						CONTENT_TYPE,
		// 						HeaderValue::from_str("application/problem+json")
		// 							.expect("Unable to create Content-Type header for PROVIDE_LOCATION_INFO_SERVICE_UNAVAILABLE"));
        //                 let body = serde_json::to_string(&details)
        //                     .expect("impossible to fail to serialize");
        //                 *response.body_mut() = Body::from(body);
        //             }
        //             SCPDetectResultResponse::TemporaryRedirect {
        //                 body,
        //                 location,
        //                 param_3gpp_sbi_target_nf_id,
        //             } => {
        //                 let location = match header::IntoHeaderValue(location).try_into() {
		// 						Ok(val) => val,
		// 						Err(e) => {
		// 							return Ok(Response::builder()
		// 									.status(StatusCode::INTERNAL_SERVER_ERROR)
		// 									.body(Body::from(format!("An internal server error occurred handling location header - {}", e)))
		// 									.expect("Unable to create Internal Server Error for invalid response header"))
		// 						}
		// 					};

        //                 response
        //                     .headers_mut()
        //                     .insert(HeaderName::from_static("location"), location);
        //                 if let Some(param_3gpp_sbi_target_nf_id) = param_3gpp_sbi_target_nf_id {
        //                     let param_3gpp_sbi_target_nf_id = match header::IntoHeaderValue(param_3gpp_sbi_target_nf_id).try_into() {
		// 						Ok(val) => val,
		// 						Err(e) => {
		// 							return Ok(Response::builder()
		// 									.status(StatusCode::INTERNAL_SERVER_ERROR)
		// 									.body(Body::from(format!("An internal server error occurred handling param_3gpp_sbi_target_nf_id header - {}", e)))
		// 									.expect("Unable to create Internal Server Error for invalid response header"))
		// 						}
		// 					};

        //                     response.headers_mut().insert(
        //                         HeaderName::from_static("3gpp-sbi-target-nf-id"),
        //                         param_3gpp_sbi_target_nf_id,
        //                     );
        //                 }
        //                 *response.status_mut() = StatusCode::from_u16(307)
        //                     .expect("Unable to turn 307 into a StatusCode");
        //                 response.headers_mut().insert(
		// 						CONTENT_TYPE,
		// 						HeaderValue::from_str("application/json")
		// 							.expect("Unable to create Content-Type header for PROVIDE_LOCATION_INFO_TEMPORARY_REDIRECT"));
        //                 let body =
        //                     serde_json::to_string(&body).expect("impossible to fail to serialize");
        //                 *response.body_mut() = Body::from(body);
        //             }
        //             SCPDetectResultResponse::PermanentRedirect {
        //                 body,
        //                 location,
        //                 param_3gpp_sbi_target_nf_id,
        //             } => {
        //                 let location = match header::IntoHeaderValue(location).try_into() {
		// 						Ok(val) => val,
		// 						Err(e) => {
		// 							return Ok(Response::builder()
		// 									.status(StatusCode::INTERNAL_SERVER_ERROR)
		// 									.body(Body::from(format!("An internal server error occurred handling location header - {}", e)))
		// 									.expect("Unable to create Internal Server Error for invalid response header"))
		// 						}
		// 					};

        //                 response
        //                     .headers_mut()
        //                     .insert(HeaderName::from_static("location"), location);
        //                 if let Some(param_3gpp_sbi_target_nf_id) = param_3gpp_sbi_target_nf_id {
        //                     let param_3gpp_sbi_target_nf_id = match header::IntoHeaderValue(param_3gpp_sbi_target_nf_id).try_into() {
		// 						Ok(val) => val,
		// 						Err(e) => {
		// 							return Ok(Response::builder()
		// 									.status(StatusCode::INTERNAL_SERVER_ERROR)
		// 									.body(Body::from(format!("An internal server error occurred handling param_3gpp_sbi_target_nf_id header - {}", e)))
		// 									.expect("Unable to create Internal Server Error for invalid response header"))
		// 						}
		// 					};

        //                     response.headers_mut().insert(
        //                         HeaderName::from_static("3gpp-sbi-target-nf-id"),
        //                         param_3gpp_sbi_target_nf_id,
        //                     );
        //                 }
        //                 *response.status_mut() = StatusCode::from_u16(308)
        //                     .expect("Unable to turn 308 into a StatusCode");
        //                 response.headers_mut().insert(
		// 						CONTENT_TYPE,
		// 						HeaderValue::from_str("application/json")
		// 							.expect("Unable to create Content-Type header for PROVIDE_LOCATION_INFO_PERMANENT_REDIRECT"));
        //                 let body =
        //                     serde_json::to_string(&body).expect("impossible to fail to serialize");
        //                 *response.body_mut() = Body::from(body);
        //             }
        //             SCPDetectResultResponse::ServiceUnavailable(body) => {
        //                 *response.status_mut() = StatusCode::from_u16(503)
        //                     .expect("Unable to turn 503 into a StatusCode");
        //                 response.headers_mut().insert(
		// 						CONTENT_TYPE,
		// 						HeaderValue::from_str("application/problem+json")
		// 							.expect("Unable to create Content-Type header for PROVIDE_LOCATION_INFO_SERVICE_UNAVAILABLE"));
        //                 let body =
        //                     serde_json::to_string(&body).expect("impossible to fail to serialize");
        //                 *response.body_mut() = Body::from(body);
        //             }
        //             SCPDetectResultResponse::NotFound(body) => {
        //                 *response.status_mut() = StatusCode::from_u16(404)
        //                     .expect("Unable to turn 404 into a StatusCode");
        //                 response.headers_mut().insert(
		// 						CONTENT_TYPE,
		// 						HeaderValue::from_str("application/problem+json")
		// 							.expect("Unable to create Content-Type header for PROVIDE_LOCATION_INFO_NOT_FOUND"));
        //                 let body =
        //                     serde_json::to_string(&body).expect("impossible to fail to serialize");
        //                 *response.body_mut() = Body::from(body);
        //             }
        //             SCPDetectResultResponse::Forbidden(body) => {
        //                 *response.status_mut() = StatusCode::from_u16(403)
        //                     .expect("Unable to turn 403 into a StatusCode");
        //                 response.headers_mut().insert(
		// 						CONTENT_TYPE,
		// 						HeaderValue::from_str("application/problem+json")
		// 							.expect("Unable to create Content-Type header for PROVIDE_LOCATION_INFO_FORBIDDEN"));
        //                 let body =
        //                     serde_json::to_string(&body).expect("impossible to fail to serialize");
        //                 *response.body_mut() = Body::from(body);
        //             }
        //             SCPDetectResultResponse::InvalidServiceRequest(body) => {
        //                 *response.status_mut() = StatusCode::from_u16(503)
        //                     .expect("Unable to turn 503 into a StatusCode");
        //                 response.headers_mut().insert(
		// 						CONTENT_TYPE,
		// 						HeaderValue::from_str("application/problem+json")
		// 							.expect("Unable to create Content-Type header for PROVIDE_LOCATION_INFO_SERVICE_UNAVAILABLE"));
        //                 let body =
        //                     serde_json::to_string(&body).expect("impossible to fail to serialize");
        //                 *response.body_mut() = Body::from(body);
        //             }
        //             SCPDetectResultResponse::UnableToCreate(body) => {
        //                 *response.status_mut() = StatusCode::from_u16(503)
        //                     .expect("Unable to turn 503 into a StatusCode");
        //                 response.headers_mut().insert(
		// 						CONTENT_TYPE,
		// 						HeaderValue::from_str("application/problem+json")
		// 							.expect("Unable to create Content-Type header for PROVIDE_LOCATION_INFO_SERVICE_UNAVAILABLE"));
        //                 let body =
        //                     serde_json::to_string(&body).expect("impossible to fail to serialize");
        //                 *response.body_mut() = Body::from(body);
        //             }
        //             SCPDetectResultResponse::TooManyRequests(body) => {
        //                 *response.status_mut() = StatusCode::from_u16(429)
        //                     .expect("Unable to turn 503 into a StatusCode");
        //                 response.headers_mut().insert(
		// 						CONTENT_TYPE,
		// 						HeaderValue::from_str("application/problem+json")
		// 							.expect("Unable to create Content-Type header for PROVIDE_LOCATION_INFO_SERVICE_UNAVAILABLE"));
        //                 let body =
        //                     serde_json::to_string(&body).expect("impossible to fail to serialize");
        //                 *response.body_mut() = Body::from(body);
        //             }
        //             SCPDetectResultResponse::InternalServerError(body) => {
        //                 *response.status_mut() = StatusCode::from_u16(500)
        //                     .expect("Unable to turn 503 into a StatusCode");
        //                 response.headers_mut().insert(
		// 						CONTENT_TYPE,
		// 						HeaderValue::from_str("application/problem+json")
		// 							.expect("Unable to create Content-Type header for PROVIDE_LOCATION_INFO_SERVICE_UNAVAILABLE"));
        //                 let body =
        //                     serde_json::to_string(&body).expect("impossible to fail to serialize");
        //                 *response.body_mut() = Body::from(body);
        //             }
        //             SCPDetectResultResponse::BadRequest(body) => {
        //                 *response.status_mut() = StatusCode::from_u16(400)
        //                     .expect("Unable to turn 503 into a StatusCode");
        //                 response.headers_mut().insert(
		// 						CONTENT_TYPE,
		// 						HeaderValue::from_str("application/problem+json")
		// 							.expect("Unable to create Content-Type header for PROVIDE_LOCATION_INFO_SERVICE_UNAVAILABLE"));
        //                 let body =
        //                     serde_json::to_string(&body).expect("impossible to fail to serialize");
        //                 *response.body_mut() = Body::from(body);
        //             }
        //             SCPDetectResultResponse::UnexpectedError => {
        //                 *response.status_mut() = StatusCode::from_u16(503)
        //                     .expect("Unable to turn 503 into a StatusCode");
        //                 response.headers_mut().insert(
		// 						CONTENT_TYPE,
		// 						HeaderValue::from_str("application/problem+json")
		// 							.expect("Unable to create Content-Type header for PROVIDE_LOCATION_INFO_SERVICE_UNAVAILABLE"));
        //                 // let body = serde_json::to_string(&body).expect("impossible to fail to serialize");
        //                 // *response.body_mut() = Body::from(body);
        //             }
        //         },
        //         Err(_) => {
        //             // Application code returned an error. This should not happen, as the implementation should
        //             // return a valid response.
        //             *response.status_mut() = StatusCode::INTERNAL_SERVER_ERROR;
        //             *response.body_mut() = Body::from("An internal error occurred");
        //         }
        //     }

        //     Ok(response)
        // }
        // &hyper::Method::GET if path.matched(paths::ID_Initial_Set) => {
        //     let path: &str = &uri.path().to_string();
        //     let path_params =
		// 		paths::REGEX_ID_INIT_SET
		// 		.captures(&path)
		// 		.unwrap_or_else(||
		// 			panic!("Path {} matched RE NAMF_MT_V1_UE_CONTEXTS_UECONTEXTID in set but failed match against \"{}\"", path, paths::REGEX_DETECT_RESULT.as_str())
		// 		);

        //     let id = match percent_encoding::percent_decode(path_params["id"].as_bytes())
        //         .decode_utf8()
        //     {
        //         Ok(id) => {
        //             match id.parse::<String>() {
        //                 Ok(id) => id,
        //                 Err(e) => return Ok(Response::builder()
        //                     .status(StatusCode::BAD_REQUEST)
        //                     .body(Body::from(format!(
        //                         "Couldn't parse path parameter id: {}",
        //                         e
        //                     )))
        //                     .expect(
        //                         "Unable to create Bad Request response for invalid path parameter",
        //                     )),
        //             }
        //         }
        //         Err(_) => {
        //             return Ok(Response::builder()
        //                 .status(StatusCode::BAD_REQUEST)
        //                 .body(Body::from(format!(
        //                     "Couldn't percent-decode path parameter as UTF-8: {}",
        //                     &path_params["id"]
        //                 )))
        //                 .expect(
        //                     "Unable to create Bad Request response for invalid percent decode",
        //                 ))
        //         }
        //     };
        //     let result = api_call::scp_id_init_set(id).await;
        //     let mut response = Response::new(Body::empty());
        //     response.headers_mut().insert(
        //         HeaderName::from_static("x-span-id"),
        //         HeaderValue::from_str((&context).0.clone().to_string().as_str())
        //             .expect("Unable to create X-Span-ID header value"),
        //     );
        //     match result {
        //         Ok(rsp) => match rsp {
        //             SCPIDInitSetResponse::SCPIDInitSetComplete { uc } => {
        //                 *response.status_mut() = StatusCode::from_u16(200)
        //                     .expect("Unable to turn 200 into a StatusCode");
        //                 response.headers_mut().insert(
		// 						CONTENT_TYPE,
		// 						HeaderValue::from_str("application/json")
		// 							.expect("Unable to create Content-Type header for PROVIDE_LOCATION_INFO_EXPECTED_RESPONSE_TO_A_VALID_REQUEST"));
        //                 // let mut new_hashmap: HashMap<String, String> = HashMap::new();
        //                 // new_hashmap.insert("status".to_string(), status.to_string());
        //                 // 	.insert("body".to_string(), body);
        //                 // new_hashmap.insert("headers".to_string(), serde_json::to_string(&headers).unwrap());
        //                 let body =
        //                     serde_json::to_string(&uc).expect("impossible to fail to serialize");
        //                 *response.body_mut() = Body::from(body);
        //             }
        //             SCPIDInitSetResponse::TemporaryRedirect {
        //                 body,
        //                 location,
        //                 param_3gpp_sbi_target_nf_id,
        //             } => {
        //                 let location = match header::IntoHeaderValue(location).try_into() {
		// 						Ok(val) => val,
		// 						Err(e) => {
		// 							return Ok(Response::builder()
		// 									.status(StatusCode::INTERNAL_SERVER_ERROR)
		// 									.body(Body::from(format!("An internal server error occurred handling location header - {}", e)))
		// 									.expect("Unable to create Internal Server Error for invalid response header"))
		// 						}
		// 					};

        //                 response
        //                     .headers_mut()
        //                     .insert(HeaderName::from_static("location"), location);
        //                 if let Some(param_3gpp_sbi_target_nf_id) = param_3gpp_sbi_target_nf_id {
        //                     let param_3gpp_sbi_target_nf_id = match header::IntoHeaderValue(param_3gpp_sbi_target_nf_id).try_into() {
		// 						Ok(val) => val,
		// 						Err(e) => {
		// 							return Ok(Response::builder()
		// 									.status(StatusCode::INTERNAL_SERVER_ERROR)
		// 									.body(Body::from(format!("An internal server error occurred handling param_3gpp_sbi_target_nf_id header - {}", e)))
		// 									.expect("Unable to create Internal Server Error for invalid response header"))
		// 						}
		// 					};

        //                     response.headers_mut().insert(
        //                         HeaderName::from_static("3gpp-sbi-target-nf-id"),
        //                         param_3gpp_sbi_target_nf_id,
        //                     );
        //                 }
        //                 *response.status_mut() = StatusCode::from_u16(307)
        //                     .expect("Unable to turn 307 into a StatusCode");
        //                 response.headers_mut().insert(
		// 						CONTENT_TYPE,
		// 						HeaderValue::from_str("application/json")
		// 							.expect("Unable to create Content-Type header for PROVIDE_LOCATION_INFO_TEMPORARY_REDIRECT"));
        //                 let body =
        //                     serde_json::to_string(&body).expect("impossible to fail to serialize");
        //                 *response.body_mut() = Body::from(body);
        //             }
        //             SCPIDInitSetResponse::PermanentRedirect {
        //                 body,
        //                 location,
        //                 param_3gpp_sbi_target_nf_id,
        //             } => {
        //                 let location = match header::IntoHeaderValue(location).try_into() {
		// 						Ok(val) => val,
		// 						Err(e) => {
		// 							return Ok(Response::builder()
		// 									.status(StatusCode::INTERNAL_SERVER_ERROR)
		// 									.body(Body::from(format!("An internal server error occurred handling location header - {}", e)))
		// 									.expect("Unable to create Internal Server Error for invalid response header"))
		// 						}
		// 					};

        //                 response
        //                     .headers_mut()
        //                     .insert(HeaderName::from_static("location"), location);
        //                 if let Some(param_3gpp_sbi_target_nf_id) = param_3gpp_sbi_target_nf_id {
        //                     let param_3gpp_sbi_target_nf_id = match header::IntoHeaderValue(param_3gpp_sbi_target_nf_id).try_into() {
		// 						Ok(val) => val,
		// 						Err(e) => {
		// 							return Ok(Response::builder()
		// 									.status(StatusCode::INTERNAL_SERVER_ERROR)
		// 									.body(Body::from(format!("An internal server error occurred handling param_3gpp_sbi_target_nf_id header - {}", e)))
		// 									.expect("Unable to create Internal Server Error for invalid response header"))
		// 						}
		// 					};

        //                     response.headers_mut().insert(
        //                         HeaderName::from_static("3gpp-sbi-target-nf-id"),
        //                         param_3gpp_sbi_target_nf_id,
        //                     );
        //                 }
        //                 *response.status_mut() = StatusCode::from_u16(308)
        //                     .expect("Unable to turn 308 into a StatusCode");
        //                 response.headers_mut().insert(
		// 						CONTENT_TYPE,
		// 						HeaderValue::from_str("application/json")
		// 							.expect("Unable to create Content-Type header for PROVIDE_LOCATION_INFO_PERMANENT_REDIRECT"));
        //                 let body =
        //                     serde_json::to_string(&body).expect("impossible to fail to serialize");
        //                 *response.body_mut() = Body::from(body);
        //             }
        //             SCPIDInitSetResponse::ServiceUnavailable(body) => {
        //                 *response.status_mut() = StatusCode::from_u16(503)
        //                     .expect("Unable to turn 503 into a StatusCode");
        //                 response.headers_mut().insert(
		// 						CONTENT_TYPE,
		// 						HeaderValue::from_str("application/problem+json")
		// 							.expect("Unable to create Content-Type header for PROVIDE_LOCATION_INFO_SERVICE_UNAVAILABLE"));
        //                 let body =
        //                     serde_json::to_string(&body).expect("impossible to fail to serialize");
        //                 *response.body_mut() = Body::from(body);
        //             }
        //             SCPIDInitSetResponse::NotFound(body) => {
        //                 *response.status_mut() = StatusCode::from_u16(404)
        //                     .expect("Unable to turn 404 into a StatusCode");
        //                 response.headers_mut().insert(
		// 						CONTENT_TYPE,
		// 						HeaderValue::from_str("application/problem+json")
		// 							.expect("Unable to create Content-Type header for PROVIDE_LOCATION_INFO_NOT_FOUND"));
        //                 let body =
        //                     serde_json::to_string(&body).expect("impossible to fail to serialize");
        //                 *response.body_mut() = Body::from(body);
        //             }
        //             SCPIDInitSetResponse::Forbidden(body) => {
        //                 *response.status_mut() = StatusCode::from_u16(403)
        //                     .expect("Unable to turn 403 into a StatusCode");
        //                 response.headers_mut().insert(
		// 						CONTENT_TYPE,
		// 						HeaderValue::from_str("application/problem+json")
		// 							.expect("Unable to create Content-Type header for PROVIDE_LOCATION_INFO_FORBIDDEN"));
        //                 let body =
        //                     serde_json::to_string(&body).expect("impossible to fail to serialize");
        //                 *response.body_mut() = Body::from(body);
        //             }
        //             SCPIDInitSetResponse::InvalidServiceRequest(body) => {
        //                 *response.status_mut() = StatusCode::from_u16(503)
        //                     .expect("Unable to turn 503 into a StatusCode");
        //                 response.headers_mut().insert(
		// 						CONTENT_TYPE,
		// 						HeaderValue::from_str("application/problem+json")
		// 							.expect("Unable to create Content-Type header for PROVIDE_LOCATION_INFO_SERVICE_UNAVAILABLE"));
        //                 let body =
        //                     serde_json::to_string(&body).expect("impossible to fail to serialize");
        //                 *response.body_mut() = Body::from(body);
        //             }
        //             SCPIDInitSetResponse::UnableToCreate(body) => {
        //                 *response.status_mut() = StatusCode::from_u16(503)
        //                     .expect("Unable to turn 503 into a StatusCode");
        //                 response.headers_mut().insert(
		// 						CONTENT_TYPE,
		// 						HeaderValue::from_str("application/problem+json")
		// 							.expect("Unable to create Content-Type header for PROVIDE_LOCATION_INFO_SERVICE_UNAVAILABLE"));
        //                 let body =
        //                     serde_json::to_string(&body).expect("impossible to fail to serialize");
        //                 *response.body_mut() = Body::from(body);
        //             }
        //             SCPIDInitSetResponse::TooManyRequests(body) => {
        //                 *response.status_mut() = StatusCode::from_u16(429)
        //                     .expect("Unable to turn 503 into a StatusCode");
        //                 response.headers_mut().insert(
		// 						CONTENT_TYPE,
		// 						HeaderValue::from_str("application/problem+json")
		// 							.expect("Unable to create Content-Type header for PROVIDE_LOCATION_INFO_SERVICE_UNAVAILABLE"));
        //                 let body =
        //                     serde_json::to_string(&body).expect("impossible to fail to serialize");
        //                 *response.body_mut() = Body::from(body);
        //             }
        //             SCPIDInitSetResponse::InternalServerError(body) => {
        //                 *response.status_mut() = StatusCode::from_u16(500)
        //                     .expect("Unable to turn 503 into a StatusCode");
        //                 response.headers_mut().insert(
		// 						CONTENT_TYPE,
		// 						HeaderValue::from_str("application/problem+json")
		// 							.expect("Unable to create Content-Type header for PROVIDE_LOCATION_INFO_SERVICE_UNAVAILABLE"));
        //                 let body =
        //                     serde_json::to_string(&body).expect("impossible to fail to serialize");
        //                 *response.body_mut() = Body::from(body);
        //             }
        //             SCPIDInitSetResponse::BadRequest(body) => {
        //                 *response.status_mut() = StatusCode::from_u16(400)
        //                     .expect("Unable to turn 503 into a StatusCode");
        //                 response.headers_mut().insert(
		// 						CONTENT_TYPE,
		// 						HeaderValue::from_str("application/problem+json")
		// 							.expect("Unable to create Content-Type header for PROVIDE_LOCATION_INFO_SERVICE_UNAVAILABLE"));
        //                 let body =
        //                     serde_json::to_string(&body).expect("impossible to fail to serialize");
        //                 *response.body_mut() = Body::from(body);
        //             }
        //             SCPIDInitSetResponse::UnexpectedError => {
        //                 *response.status_mut() = StatusCode::from_u16(503)
        //                     .expect("Unable to turn 503 into a StatusCode");
        //                 response.headers_mut().insert(
		// 						CONTENT_TYPE,
		// 						HeaderValue::from_str("application/problem+json")
		// 							.expect("Unable to create Content-Type header for PROVIDE_LOCATION_INFO_SERVICE_UNAVAILABLE"));
        //                 // let body = serde_json::to_string(&body).expect("impossible to fail to serialize");
        //                 // *response.body_mut() = Body::from(body);
        //             }
        //         },
        //         Err(_) => {
        //             // Application code returned an error. This should not happen, as the implementation should
        //             // return a valid response.
        //             *response.status_mut() = StatusCode::INTERNAL_SERVER_ERROR;
        //             *response.body_mut() = Body::from("An internal error occurred");
        //         }
        //     }

        //     Ok(response)
        // }
        // &hyper::Method::PUT if path.matched(paths::ID_Final_Set) => {
        //     let path: &str = &uri.path().to_string();
        //     let path_params =
		// 		paths::REGEX_ID_FINAL_SET
		// 		.captures(&path)
		// 		.unwrap_or_else(||
		// 			panic!("Path {} matched RE NAMF_MT_V1_UE_CONTEXTS_UECONTEXTID in set but failed match against \"{}\"", path, paths::REGEX_DETECT_RESULT.as_str())
		// 		);

        //     let id = match percent_encoding::percent_decode(path_params["id"].as_bytes())
        //         .decode_utf8()
        //     {
        //         Ok(id) => {
        //             match id.parse::<String>() {
        //                 Ok(id) => id,
        //                 Err(e) => return Ok(Response::builder()
        //                     .status(StatusCode::BAD_REQUEST)
        //                     .body(Body::from(format!(
        //                         "Couldn't parse path parameter id: {}",
        //                         e
        //                     )))
        //                     .expect(
        //                         "Unable to create Bad Request response for invalid path parameter",
        //                     )),
        //             }
        //         }
        //         Err(_) => {
        //             return Ok(Response::builder()
        //                 .status(StatusCode::BAD_REQUEST)
        //                 .body(Body::from(format!(
        //                     "Couldn't percent-decode path parameter as UTF-8: {}",
        //                     &path_params["id"]
        //                 )))
        //                 .expect(
        //                     "Unable to create Bad Request response for invalid percent decode",
        //                 ))
        //         }
        //     };
        //     let result = to_bytes(body).await;
        //     match result {
		// 			Ok(body) => {
		// 				let body: Vec<u8> = body.to_vec();
		// 				let mut unused_elements = Vec::new();
		// 				let str_map: Option<SCPIDFinalSetRequest> = if !body.is_empty() {
		// 					let deserializer: &mut serde_json::Deserializer<serde_json::de::SliceRead<'_>> = &mut serde_json::Deserializer::from_slice(&*body);
		// 					match serde_ignored::deserialize(deserializer, |path| {
		// 							warn!("Ignoring unknown field in body: {}", path);
		// 							unused_elements.push(path.to_string());
		// 					}) {
		// 						Ok(param_subscription_data) => param_subscription_data,
		// 						Err(e) => return Ok(Response::builder()
		// 										.status(StatusCode::BAD_REQUEST)
		// 										.body(Body::from(format!("Couldn't parse body parameter SubscriptionData - doesn't match schema: {}", e)))
		// 										.expect("Unable to create Bad Request response for invalid body parameter SubscriptionData due to schema")),
		// 					}
		// 				} else {
		// 					None
		// 				};
		// 				if str_map.is_none() {
		// 					let mut response = Response::new(Body::empty());
		// 						*response.status_mut() = StatusCode::from_u16(503).expect("Unable to turn 503 into a StatusCode");
		// 					response.headers_mut().insert(
		// 						CONTENT_TYPE,
		// 						HeaderValue::from_str("application/problem+json")
		// 							.expect("Unable to create Content-Type header for PROVIDE_LOCATION_INFO_SERVICE_UNAVAILABLE"));
		// 					let body = serde_json::to_string(&body).expect("Failed To Deserialize");
		// 					*response.body_mut() = Body::from(body);
		// 						return Ok(response);
		// 				}
		// 				let data = str_map.unwrap();
		// 				let result = api_call::scp_id_final_set(
		// 					id,
		// 					data
		// 					).await;
		// 				let mut response = Response::new(Body::empty());
		// 				response.headers_mut().insert(
		// 					HeaderName::from_static("x-span-id"),
		// 					HeaderValue::from_str((&context).0.clone().to_string().as_str())
		// 						.expect("Unable to create X-Span-ID header value"));
		// 				match result {
		// 					Ok(rsp) => match rsp {
		// 						SCPIDFinalSetResponse::SCPIDFinalSetComplete(())
		// 						=> {
		// 							*response.status_mut() = StatusCode::from_u16(200).expect("Unable to turn 200 into a StatusCode");
		// 							// let body = serde_json::to_string(&new_hashmap).expect("impossible to fail to serialize");
		// 							// *response.body_mut() = Body::from(body);
		// 						},
		// 						SCPIDFinalSetResponse::TemporaryRedirect
		// 							{
		// 								body,
		// 								location,
		// 								param_3gpp_sbi_target_nf_id
		// 							}
		// 						=> {
		// 							let location = match header::IntoHeaderValue(location).try_into() {
		// 								Ok(val) => val,
		// 								Err(e) => {
		// 									return Ok(Response::builder()
		// 											.status(StatusCode::INTERNAL_SERVER_ERROR)
		// 											.body(Body::from(format!("An internal server error occurred handling location header - {}", e)))
		// 											.expect("Unable to create Internal Server Error for invalid response header"))
		// 								}
		// 							};

		// 							response.headers_mut().insert(
		// 								HeaderName::from_static("location"),
		// 								location
		// 							);
		// 							if let Some(param_3gpp_sbi_target_nf_id) = param_3gpp_sbi_target_nf_id {
		// 							let param_3gpp_sbi_target_nf_id = match header::IntoHeaderValue(param_3gpp_sbi_target_nf_id).try_into() {
		// 								Ok(val) => val,
		// 								Err(e) => {
		// 									return Ok(Response::builder()
		// 											.status(StatusCode::INTERNAL_SERVER_ERROR)
		// 											.body(Body::from(format!("An internal server error occurred handling param_3gpp_sbi_target_nf_id header - {}", e)))
		// 											.expect("Unable to create Internal Server Error for invalid response header"))
		// 								}
		// 							};

		// 							response.headers_mut().insert(
		// 								HeaderName::from_static("3gpp-sbi-target-nf-id"),
		// 								param_3gpp_sbi_target_nf_id
		// 							);
		// 							}
		// 							*response.status_mut() = StatusCode::from_u16(307).expect("Unable to turn 307 into a StatusCode");
		// 							response.headers_mut().insert(
		// 								CONTENT_TYPE,
		// 								HeaderValue::from_str("application/json")
		// 									.expect("Unable to create Content-Type header for PROVIDE_LOCATION_INFO_TEMPORARY_REDIRECT"));
		// 							let body = serde_json::to_string(&body).expect("impossible to fail to serialize");
		// 							*response.body_mut() = Body::from(body);
		// 						},
		// 						SCPIDFinalSetResponse::PermanentRedirect
		// 							{
		// 								body,
		// 								location,
		// 								param_3gpp_sbi_target_nf_id
		// 							}
		// 						=> {
		// 							let location = match header::IntoHeaderValue(location).try_into() {
		// 								Ok(val) => val,
		// 								Err(e) => {
		// 									return Ok(Response::builder()
		// 											.status(StatusCode::INTERNAL_SERVER_ERROR)
		// 											.body(Body::from(format!("An internal server error occurred handling location header - {}", e)))
		// 											.expect("Unable to create Internal Server Error for invalid response header"))
		// 								}
		// 							};

		// 							response.headers_mut().insert(
		// 								HeaderName::from_static("location"),
		// 								location
		// 							);
		// 							if let Some(param_3gpp_sbi_target_nf_id) = param_3gpp_sbi_target_nf_id {
		// 							let param_3gpp_sbi_target_nf_id = match header::IntoHeaderValue(param_3gpp_sbi_target_nf_id).try_into() {
		// 								Ok(val) => val,
		// 								Err(e) => {
		// 									return Ok(Response::builder()
		// 											.status(StatusCode::INTERNAL_SERVER_ERROR)
		// 											.body(Body::from(format!("An internal server error occurred handling param_3gpp_sbi_target_nf_id header - {}", e)))
		// 											.expect("Unable to create Internal Server Error for invalid response header"))
		// 								}
		// 							};

		// 							response.headers_mut().insert(
		// 								HeaderName::from_static("3gpp-sbi-target-nf-id"),
		// 								param_3gpp_sbi_target_nf_id
		// 							);
		// 							}
		// 							*response.status_mut() = StatusCode::from_u16(308).expect("Unable to turn 308 into a StatusCode");
		// 							response.headers_mut().insert(
		// 								CONTENT_TYPE,
		// 								HeaderValue::from_str("application/json")
		// 									.expect("Unable to create Content-Type header for PROVIDE_LOCATION_INFO_PERMANENT_REDIRECT"));
		// 							let body = serde_json::to_string(&body).expect("impossible to fail to serialize");
		// 							*response.body_mut() = Body::from(body);
		// 						},
		// 						SCPIDFinalSetResponse::ServiceUnavailable
		// 							(body)
		// 						=> {
		// 							*response.status_mut() = StatusCode::from_u16(503).expect("Unable to turn 503 into a StatusCode");
		// 							response.headers_mut().insert(
		// 								CONTENT_TYPE,
		// 								HeaderValue::from_str("application/problem+json")
		// 									.expect("Unable to create Content-Type header for PROVIDE_LOCATION_INFO_SERVICE_UNAVAILABLE"));
		// 							let body = serde_json::to_string(&body).expect("impossible to fail to serialize");
		// 							*response.body_mut() = Body::from(body);
		// 						},
		// 						SCPIDFinalSetResponse::NotFound
		// 							(body)
		// 						=> {
		// 							*response.status_mut() = StatusCode::from_u16(404).expect("Unable to turn 404 into a StatusCode");
		// 							response.headers_mut().insert(
		// 								CONTENT_TYPE,
		// 								HeaderValue::from_str("application/problem+json")
		// 									.expect("Unable to create Content-Type header for PROVIDE_LOCATION_INFO_NOT_FOUND"));
		// 							let body = serde_json::to_string(&body).expect("impossible to fail to serialize");
		// 							*response.body_mut() = Body::from(body);
		// 						},
		// 						SCPIDFinalSetResponse::Forbidden
		// 							(body)
		// 						=> {
		// 							*response.status_mut() = StatusCode::from_u16(403).expect("Unable to turn 403 into a StatusCode");
		// 							response.headers_mut().insert(
		// 								CONTENT_TYPE,
		// 								HeaderValue::from_str("application/problem+json")
		// 									.expect("Unable to create Content-Type header for PROVIDE_LOCATION_INFO_FORBIDDEN"));
		// 							let body = serde_json::to_string(&body).expect("impossible to fail to serialize");
		// 							*response.body_mut() = Body::from(body);
		// 						},
		// 						SCPIDFinalSetResponse::InvalidServiceRequest
		// 							(body)
		// 						=> {
		// 							*response.status_mut() = StatusCode::from_u16(503).expect("Unable to turn 503 into a StatusCode");
		// 							response.headers_mut().insert(
		// 								CONTENT_TYPE,
		// 								HeaderValue::from_str("application/problem+json")
		// 									.expect("Unable to create Content-Type header for PROVIDE_LOCATION_INFO_SERVICE_UNAVAILABLE"));
		// 							let body = serde_json::to_string(&body).expect("impossible to fail to serialize");
		// 							*response.body_mut() = Body::from(body);
		// 						},
		// 						SCPIDFinalSetResponse::UnableToCreate
		// 							(body)
		// 						=> {
		// 							*response.status_mut() = StatusCode::from_u16(503).expect("Unable to turn 503 into a StatusCode");
		// 							response.headers_mut().insert(
		// 								CONTENT_TYPE,
		// 								HeaderValue::from_str("application/problem+json")
		// 									.expect("Unable to create Content-Type header for PROVIDE_LOCATION_INFO_SERVICE_UNAVAILABLE"));
		// 							let body = serde_json::to_string(&body).expect("impossible to fail to serialize");
		// 							*response.body_mut() = Body::from(body);
		// 						},
		// 						SCPIDFinalSetResponse::TooManyRequests
		// 						(body)
		// 						=> {
		// 							*response.status_mut() = StatusCode::from_u16(429).expect("Unable to turn 503 into a StatusCode");
		// 							response.headers_mut().insert(
		// 								CONTENT_TYPE,
		// 								HeaderValue::from_str("application/problem+json")
		// 									.expect("Unable to create Content-Type header for PROVIDE_LOCATION_INFO_SERVICE_UNAVAILABLE"));
		// 							let body = serde_json::to_string(&body).expect("impossible to fail to serialize");
		// 							*response.body_mut() = Body::from(body);
		// 						},
		// 						SCPIDFinalSetResponse::InternalServerError
		// 						(body)
		// 						=> {
		// 							*response.status_mut() = StatusCode::from_u16(500).expect("Unable to turn 503 into a StatusCode");
		// 							response.headers_mut().insert(
		// 								CONTENT_TYPE,
		// 								HeaderValue::from_str("application/problem+json")
		// 									.expect("Unable to create Content-Type header for PROVIDE_LOCATION_INFO_SERVICE_UNAVAILABLE"));
		// 							let body = serde_json::to_string(&body).expect("impossible to fail to serialize");
		// 							*response.body_mut() = Body::from(body);
		// 						},
		// 						SCPIDFinalSetResponse::BadRequest
		// 						(body)
		// 						=> {
		// 							*response.status_mut() = StatusCode::from_u16(400).expect("Unable to turn 503 into a StatusCode");
		// 							response.headers_mut().insert(
		// 								CONTENT_TYPE,
		// 								HeaderValue::from_str("application/problem+json")
		// 									.expect("Unable to create Content-Type header for PROVIDE_LOCATION_INFO_SERVICE_UNAVAILABLE"));
		// 							let body = serde_json::to_string(&body).expect("impossible to fail to serialize");
		// 							*response.body_mut() = Body::from(body);
		// 						},
		// 						SCPIDFinalSetResponse::UnexpectedError
		// 						=> {
		// 							*response.status_mut() = StatusCode::from_u16(503).expect("Unable to turn 503 into a StatusCode");
		// 							response.headers_mut().insert(
		// 								CONTENT_TYPE,
		// 								HeaderValue::from_str("application/problem+json")
		// 									.expect("Unable to create Content-Type header for PROVIDE_LOCATION_INFO_SERVICE_UNAVAILABLE"));
		// 							let body = serde_json::to_string(&body).expect("impossible to fail to serialize");
		// 							*response.body_mut() = Body::from(body);
		// 						},
		// 					},
		// 					Err(_) => {
		// 						// Application code returned an error. This should not happen, as the implementation should
		// 						// return a valid response.
		// 						*response.status_mut() = StatusCode::INTERNAL_SERVER_ERROR;
		// 						*response.body_mut() = Body::from("An internal error occurred");
		// 					},
		// 				}

		// 				Ok(response)
		// 			},
		// 			Err(e) => Ok(Response::builder()
		// 								.status(StatusCode::BAD_REQUEST)
		// 								.body(Body::from(format!("Couldn't read body parameter RequestLocInfo: {}", e)))
		// 								.expect("Unable to create Bad Request response due to unable to read body parameter RequestLocInfo")),
		// 		}
        // }
        &hyper::Method::POST if path.matched(paths::Notify) => {
            let mut unused_elements: Vec<String> = vec![];
            let mut response = Response::new(Body::empty());
            response.headers_mut().insert(
                HeaderName::from_static("x-span-id"),
                HeaderValue::from_str((&context).0.clone().to_string().as_str())
                    .expect("Unable to create X-Span-ID header value"),
            );

            if !unused_elements.is_empty() {
                response.headers_mut().insert(
                    HeaderName::from_static("warning"),
                    HeaderValue::from_str(
                        format!("Ignoring unknown fields in body: {:?}", unused_elements).as_str(),
                    )
                    .expect("Unable to create Warning header value"),
                );
            }

            let result = to_bytes(body);
            match result.await {
					Ok(body) => {
						let body: Vec<u8> = body.to_vec();
						let param_notify_data: Option<models::NotificationData> = if !body.is_empty() {
							let deserializer = &mut serde_json::Deserializer::from_slice(&*body);
							match serde_ignored::deserialize(deserializer, |path| {
									warn!("Ignoring unknown field in body: {}", path);
									unused_elements.push(path.to_string());
							}) {
								Ok(param_hsmf_update_data) => param_hsmf_update_data,
								Err(e) => return Ok(Response::builder()
												.status(StatusCode::BAD_REQUEST)
												.body(Body::from(format!("Couldn't parse body parameter NotificationData - doesn't match schema: {}", e)))
												.expect("Unable to create Bad Request response for invalid body parameter NotificationData due to schema")),
							}
						} else {
							None
						};
						let param_notify_data = match param_notify_data {
							Some(param_notify_data) => param_notify_data,
							None => return Ok(Response::builder()
												.status(StatusCode::BAD_REQUEST)
												.body(Body::from("Missing required body parameter NotificationData"))
												.expect("Unable to create Bad Request response for missing body parameter NotificationData")),
						};
						let route_binding = if headers.contains_key("3gpp-sbi-routing-binding") {
							let heads = headers.get("3gpp-sbi-routing-binding").unwrap();
							let s1: Vec<&str> = heads.to_str().unwrap().split(';').collect();
							let mut x: Option<String> = None;
							for s in s1.iter() {
								let two: Vec<&str> = s.split("=").collect();
								if two[0] == "nfinst" {
									x = Some(two[1].to_string());
								}
							}
							x
						} else { None };
						// let result = api_impl.scp_notify(
						// 	param_notify_data,
						// 	route_binding,
						// 	&context
						// ).await;
						let req = scp_service::SCPNotify(param_notify_data, route_binding);
						let https = hyper_tls::HttpsConnector::new();
						let client = hyper::Client::builder().http2_only(true).build(https);
						let reresponse = client.request(req).await;
						let result: Result<(), ApiError> = Ok(());
						match result {
							Ok(_) => {
								*response.status_mut() = StatusCode::from_u16(200).expect("Unable to turn 200 into a StatusCode");
								*response.body_mut() = Body::empty();
								// TODO: response from notification
							}
							Err(_) => {
								// Application code returned an error. This should not happen, as the implementation should
								// return a valid response.
								*response.status_mut() = StatusCode::INTERNAL_SERVER_ERROR;
								*response.body_mut() = Body::from("An internal error occurred");
							},
						}
						Ok(response)
					}
					Err(e) => Ok(Response::builder()
									.status(StatusCode::BAD_REQUEST)
									.body(Body::from(format!("Couldn't read body parameter NotificationData: {}", e)))
									.expect("Unable to create Bad Request response due to unable to read body parameter NotificationData")),
				}
        }

        // Connect - POST /npdf-com/v1/{uuid}/connect
        _ => {
            // Path parameters
            // log::info!("Correct func 1");
            // log::info!("STEP1");
            let path: &str = &uri.path().to_string();
            // Body parameters (note that non-required body parameters will ignore garbage
            // values, rather than causing a 400 response). Produce warning header and logs for
            // any unused fields.
            // let path_params =
            // paths::REGEX_FORWARD_PATH
            // .captures(&path)
            // .unwrap_or_else(||
            //     panic!("Path {} matched RE NPDF_CONNECT_UUID in set but failed match against \"{}\"", path, paths::REGEX_FORWARD_PATH.as_str())
            // );
            // // log::info!("STEP3");
            // let param_path = match percent_encoding::percent_decode(path_params["restPath"].as_bytes()).decode_utf8() {
            //     Ok(param_path) => match param_path.parse::<String>() {
            //         Ok(param_path) => param_path,
            //         Err(e) => return Ok(Response::builder()
            //                         .status(StatusCode::BAD_REQUEST)
            //                         .body(Body::from(format!("Couldn't parse path parameter uuid: {}", e)))
            //                         .expect("Unable to create Bad Request response for invalid path parameter")),
            //     },
            //     Err(_) => return Ok(Response::builder()
            //                         .status(StatusCode::BAD_REQUEST)
            //                         .body(Body::from(format!("Couldn't percent-decode path parameter as UTF-8: {}", &path_params["uuid"])))
            //                         .expect("Unable to create Bad Request response for invalid percent decode"))
            // };
            // let jwt_token = headers.get("authorization").map(|h| h.to_str().unwrap().strip_prefix("Bearer ")).flatten().map(|f| f.to_string());
            // log::info!("STEP4");
            // Body parameters (note that non-required body parameters will ignore garbage
            // values, rather than causing a 400 response). Produce warning header and logs for
            // any unused fields.
            // let bytes = hyper::body::to_bytes(body).await.unwrap();

            let result = to_bytes(body).await;
            match result {
							Ok(body) => {
								let body: Vec<u8> = body.to_vec();
								// let mut unused_elements = Vec::new();
								// let oci: &str = if headers.contains_key("3gpp-Sbi-Oci") {
								// 	headers.get("3gpp-Sbi-Oci").unwrap().to_str().unwrap()
								// } else {
								// 	"None"
								// };
                                // log::info!("STEP5");
								//Convert headers to hashmap hwerer
								// let requ = Request.from(body);
								// let mut headerset: HashMap<String, String> = HashMap::new();
								// for (x,y) in headers {
								// 	if x.is_some() {
								// 		let xx = x.unwrap();
								// 		headerset.insert(xx.to_string(), y.to_str().unwrap().to_string());
								// 	}
								// }
								// let str_body = serde_json::to_string(&body)?;
								// let mut unused_elements = Vec::new();
								// let str_map: Option<HashMap<String, String>> = if !body.is_empty() {
                                //     let deserializer: &mut serde_json::Deserializer<serde_json::de::SliceRead<'_>> = &mut serde_json::Deserializer::from_slice(&*body);
                                //     match serde_ignored::deserialize(deserializer, |path| {
                                //             warn!("Ignoring unknown field in body: {}", path);
                                //             unused_elements.push(path.to_string());
                                //     }) {
                                //         Ok(param_subscription_data) => param_subscription_data,
                                //         Err(e) => return Ok(Response::builder()
                                //                         .status(StatusCode::BAD_REQUEST)
                                //                         .body(Body::from(format!("Couldn't parse body parameter SubscriptionData - doesn't match schema: {}", e)))
                                //                         .expect("Unable to create Bad Request response for invalid body parameter SubscriptionData due to schema")),
                                //     }
                                // } else {
                                //     None
                                // };
								// if str_map.is_none() {
								// 	let mut response = Response::new(Body::empty());
								// 		*response.status_mut() = StatusCode::from_u16(503).expect("Unable to turn 503 into a StatusCode");
								// 	response.headers_mut().insert(
								// 		CONTENT_TYPE,
								// 		HeaderValue::from_str("application/problem+json")
								// 			.expect("Unable to create Content-Type header for PROVIDE_LOCATION_INFO_SERVICE_UNAVAILABLE"));
								// 	let body = serde_json::to_string(&body).expect("Failed To Deserialize");
								// 	*response.body_mut() = Body::from(body);
								// 		return Ok(response);
								// }
								// let str_map = str_map.unwrap();
								// // log::info!("BODY -> {:?}", str_map);
								// // let str_map =  serde_json::from_str::<HashMap<String, String>>(&str_body).unwrap();
								// let method = str_map.get("method").unwrap().to_owned();
								// let uri = str_map.get("uri").unwrap().to_owned();
								// let mut request = match Request::builder()
								// 	.method(hyper::Method::from_bytes(&method.as_bytes().to_vec())?)
								// 	.uri(uri)
								// 	.body(Body::empty()) {
								// 		Ok(req) => req,
								// 		Err(e) => return Err(format!("Unable to create request: {}", e).into())
								// };
								// let old_headers = str_map.get("headers").unwrap().to_owned();
								// let old_headers: HashMap<String, String> = serde_json::from_str::<HashMap<String,String>>(&old_headers).unwrap();
								// let mut h: HeaderMap = request.headers().clone();
								// // h.extend(crate::hash_to_map(old_headers));
								// // *request.headers_mut() = headers;
								// request.headers_mut().extend(nscp_api::hash_to_map(old_headers));
								// // log::info!("{:?}", request.headers_mut());
								// *request.body_mut() = Body::from(general_purpose::STANDARD.decode(str_map.get("body").unwrap()).unwrap());
								let cloned_body = Body::from(body.clone());
								*cloned_request.body_mut() = cloned_body;
								let result = scp_service::SCPForward(cloned_request, addr).await;
								// log::info!("Here");
								let mut response = Response::new(Body::empty());
								// log::info!("Here");
								response.headers_mut().insert(
											HeaderName::from_static("x-span-id"),
											HeaderValue::from_str((&context).0.clone().to_string().as_str())
												.expect("Unable to create X-Span-ID header value"));

										// if !unused_elements.is_empty() {
										// 	response.headers_mut().insert(
										// 		HeaderName::from_static("warning"),
										// 		HeaderValue::from_str(format!("Ignoring unknown fields in body: {:?}", unused_elements).as_str())
										// 			.expect("Unable to create Warning header value"));
										// }
										match result {
											Ok(rsp) => match rsp {
												SCPForwardResponse::ForwardSCPComplete
												{
													status,
													body,
													headers
												}
												=> {
													// log::info!("THE MESSAGE BODY \n{:?}", body);
													*response.status_mut() = StatusCode::from_u16(status).expect("Unable to turn 200 into a StatusCode");
													for (x,y) in headers {
														response.headers_mut().insert(
															HeaderName::from_bytes(x.as_bytes()).unwrap(),
															HeaderValue::from_str(&y).
															expect("Unable to create Content-Type header for PROVIDE_LOCATION_INFO_EXPECTED_RESPONSE_TO_A_VALID_REQUEST"));
													}
													// response.headers_mut().insert(
													// 	CONTENT_TYPE,
													// 	HeaderValue::from_str("application/json")
													// 		.expect("Unable to create Content-Type header for PROVIDE_LOCATION_INFO_EXPECTED_RESPONSE_TO_A_VALID_REQUEST"));
													// let mut new_hashmap: HashMap<String, String> = HashMap::new();
													// new_hashmap.insert("status".to_string(), status.to_string());
													// new_hashmap.insert("body".to_string(), body);
													// new_hashmap.insert("headers".to_string(), serde_json::to_string(&headers).unwrap());
													// let body = serde_json::to_string(&new_hashmap).expect("impossible to fail to serialize");
													*response.body_mut() = Body::from(body);
												},
												SCPForwardResponse::TemporaryRedirect
													{
														body,
														location,
														param_3gpp_sbi_target_nf_id
													}
												=> {
													let location = match header::IntoHeaderValue(location).try_into() {
														Ok(val) => val,
														Err(e) => {
															return Ok(Response::builder()
																	.status(StatusCode::INTERNAL_SERVER_ERROR)
																	.body(Body::from(format!("An internal server error occurred handling location header - {}", e)))
																	.expect("Unable to create Internal Server Error for invalid response header"))
														}
													};

													response.headers_mut().insert(
														HeaderName::from_static("location"),
														location
													);
													if let Some(param_3gpp_sbi_target_nf_id) = param_3gpp_sbi_target_nf_id {
													let param_3gpp_sbi_target_nf_id = match header::IntoHeaderValue(param_3gpp_sbi_target_nf_id).try_into() {
														Ok(val) => val,
														Err(e) => {
															return Ok(Response::builder()
																	.status(StatusCode::INTERNAL_SERVER_ERROR)
																	.body(Body::from(format!("An internal server error occurred handling param_3gpp_sbi_target_nf_id header - {}", e)))
																	.expect("Unable to create Internal Server Error for invalid response header"))
														}
													};

													response.headers_mut().insert(
														HeaderName::from_static("3gpp-sbi-target-nf-id"),
														param_3gpp_sbi_target_nf_id
													);
													}
													*response.status_mut() = StatusCode::from_u16(307).expect("Unable to turn 307 into a StatusCode");
													response.headers_mut().insert(
														CONTENT_TYPE,
														HeaderValue::from_str("application/json")
															.expect("Unable to create Content-Type header for PROVIDE_LOCATION_INFO_TEMPORARY_REDIRECT"));
													let body = serde_json::to_string(&body).expect("impossible to fail to serialize");
													*response.body_mut() = Body::from(body);
												},
												SCPForwardResponse::PermanentRedirect
													{
														body,
														location,
														param_3gpp_sbi_target_nf_id
													}
												=> {
													let location = match header::IntoHeaderValue(location).try_into() {
														Ok(val) => val,
														Err(e) => {
															return Ok(Response::builder()
																	.status(StatusCode::INTERNAL_SERVER_ERROR)
																	.body(Body::from(format!("An internal server error occurred handling location header - {}", e)))
																	.expect("Unable to create Internal Server Error for invalid response header"))
														}
													};

													response.headers_mut().insert(
														HeaderName::from_static("location"),
														location
													);
													if let Some(param_3gpp_sbi_target_nf_id) = param_3gpp_sbi_target_nf_id {
													let param_3gpp_sbi_target_nf_id = match header::IntoHeaderValue(param_3gpp_sbi_target_nf_id).try_into() {
														Ok(val) => val,
														Err(e) => {
															return Ok(Response::builder()
																	.status(StatusCode::INTERNAL_SERVER_ERROR)
																	.body(Body::from(format!("An internal server error occurred handling param_3gpp_sbi_target_nf_id header - {}", e)))
																	.expect("Unable to create Internal Server Error for invalid response header"))
														}
													};

													response.headers_mut().insert(
														HeaderName::from_static("3gpp-sbi-target-nf-id"),
														param_3gpp_sbi_target_nf_id
													);
													}
													*response.status_mut() = StatusCode::from_u16(308).expect("Unable to turn 308 into a StatusCode");
													response.headers_mut().insert(
														CONTENT_TYPE,
														HeaderValue::from_str("application/json")
															.expect("Unable to create Content-Type header for PROVIDE_LOCATION_INFO_PERMANENT_REDIRECT"));
													let body = serde_json::to_string(&body).expect("impossible to fail to serialize");
													*response.body_mut() = Body::from(body);
												},
												SCPForwardResponse::ServiceUnavailable
													(body)
												=> {
													*response.status_mut() = StatusCode::from_u16(503).expect("Unable to turn 503 into a StatusCode");
													response.headers_mut().insert(
														CONTENT_TYPE,
														HeaderValue::from_str("application/problem+json")
															.expect("Unable to create Content-Type header for PROVIDE_LOCATION_INFO_SERVICE_UNAVAILABLE"));
													let body = serde_json::to_string(&body).expect("impossible to fail to serialize");
													*response.body_mut() = Body::from(body);
												},
                                                SCPForwardResponse::NotFound
													(body)
												=> {
													*response.status_mut() = StatusCode::from_u16(404).expect("Unable to turn 404 into a StatusCode");
													response.headers_mut().insert(
														CONTENT_TYPE,
														HeaderValue::from_str("application/problem+json")
															.expect("Unable to create Content-Type header for PROVIDE_LOCATION_INFO_NOT_FOUND"));
													let body = serde_json::to_string(&body).expect("impossible to fail to serialize");
													*response.body_mut() = Body::from(body);
												},
                                                SCPForwardResponse::Forbidden
													(body)
												=> {
													*response.status_mut() = StatusCode::from_u16(403).expect("Unable to turn 403 into a StatusCode");
													response.headers_mut().insert(
														CONTENT_TYPE,
														HeaderValue::from_str("application/problem+json")
															.expect("Unable to create Content-Type header for PROVIDE_LOCATION_INFO_FORBIDDEN"));
													let body = serde_json::to_string(&body).expect("impossible to fail to serialize");
													*response.body_mut() = Body::from(body);
												},
                                                SCPForwardResponse::InvalidServiceRequest
													(body)
												=> {
													*response.status_mut() = StatusCode::from_u16(503).expect("Unable to turn 503 into a StatusCode");
													response.headers_mut().insert(
														CONTENT_TYPE,
														HeaderValue::from_str("application/problem+json")
															.expect("Unable to create Content-Type header for PROVIDE_LOCATION_INFO_SERVICE_UNAVAILABLE"));
													let body = serde_json::to_string(&body).expect("impossible to fail to serialize");
													*response.body_mut() = Body::from(body);
												},
                                                SCPForwardResponse::UnableToCreate
													(body)
												=> {
													*response.status_mut() = StatusCode::from_u16(503).expect("Unable to turn 503 into a StatusCode");
													response.headers_mut().insert(
														CONTENT_TYPE,
														HeaderValue::from_str("application/problem+json")
															.expect("Unable to create Content-Type header for PROVIDE_LOCATION_INFO_SERVICE_UNAVAILABLE"));
													let body = serde_json::to_string(&body).expect("impossible to fail to serialize");
													*response.body_mut() = Body::from(body);
												},
                                                SCPForwardResponse::UnexpectedError
													(body)
												=> {
													*response.status_mut() = StatusCode::from_u16(503).expect("Unable to turn 503 into a StatusCode");
													response.headers_mut().insert(
														CONTENT_TYPE,
														HeaderValue::from_str("application/problem+json")
															.expect("Unable to create Content-Type header for PROVIDE_LOCATION_INFO_SERVICE_UNAVAILABLE"));
													let body = serde_json::to_string(&body).expect("impossible to fail to serialize");
													*response.body_mut() = Body::from(body);
												},
											},
											Err(_) => {
												// Application code returned an error. This should not happen, as the implementation should
												// return a valid response.
												*response.status_mut() = StatusCode::INTERNAL_SERVER_ERROR;
												*response.body_mut() = Body::from("An internal error occurred");
											},
										}

										Ok(response)
							},
							Err(e) => Ok(Response::builder()
												.status(StatusCode::BAD_REQUEST)
												.body(Body::from(format!("Couldn't read body parameter RequestLocInfo: {}", e)))
												.expect("Unable to create Bad Request response due to unable to read body parameter RequestLocInfo")),
						}
        } // &hyper::Method::POST if path.matched(paths::Notify) => {
          // 	{
          // 		let mut unused_elements: Vec<String> = vec![];
          // 		let mut response = Response::new(Body::empty());
          // 		response.headers_mut().insert(
          // 			HeaderName::from_static("x-span-id"),
          // 			HeaderValue::from_str((&context).0.clone().to_string().as_str())
          // 				.expect("Unable to create X-Span-ID header value"));
          // 		if !unused_elements.is_empty() {
          // 			response.headers_mut().insert(
          // 				HeaderName::from_static("warning"),
          // 				HeaderValue::from_str(format!("Ignoring unknown fields in body: {:?}", unused_elements).as_str())
          // 					.expect("Unable to create Warning header value"));
          // 		}
          // 		let result = body.to_raw();
          // 		match result.await {
          // 			Ok(body) => {
          // 				let param_notify_data: Option<models::NotificationData> = if !body.is_empty() {
          // 					let deserializer = &mut serde_json::Deserializer::from_slice(&*body);
          // 					match serde_ignored::deserialize(deserializer, |path| {
          // 							warn!("Ignoring unknown field in body: {}", path);
          // 							unused_elements.push(path.to_string());
          // 					}) {
          // 						Ok(param_hsmf_update_data) => param_hsmf_update_data,
          // 						Err(e) => return Ok(Response::builder()
          // 										.status(StatusCode::BAD_REQUEST)
          // 										.body(Body::from(format!("Couldn't parse body parameter NotificationData - doesn't match schema: {}", e)))
          // 										.expect("Unable to create Bad Request response for invalid body parameter NotificationData due to schema")),
          // 					}
          // 				} else {
          // 					None
          // 				};
          // 				let param_notify_data = match param_notify_data {
          // 					Some(param_notify_data) => param_notify_data,
          // 					None => return Ok(Response::builder()
          // 										.status(StatusCode::BAD_REQUEST)
          // 										.body(Body::from("Missing required body parameter NotificationData"))
          // 										.expect("Unable to create Bad Request response for missing body parameter NotificationData")),
          // 				};
          // 				let route_binding = if headers.contains_key("3gpp-sbi-routing-binding") {
          // 					let heads = headers.get("3gpp-sbi-routing-binding").unwrap();
          // 					let s1: Vec<&str> = heads.to_str().unwrap().split(';').collect();
          // 					let mut x: Option<String> = None;
          // 					for s in s1.iter() {
          // 						let two: Vec<&str> = s.split("=").collect();
          // 						if two[0] == "nfinst" {
          // 							x = Some(two[1].to_string());
          // 						}
          // 					}
          // 					x
          // 				} else { None };
          // 				// let result = api_impl.scp_notify(
          // 				// 	param_notify_data,
          // 				// 	route_binding,
          // 				// 	&context
          // 				// ).await;
          // 				let req = scp_service::SCPNotify(param_notify_data, route_binding);
          // 				let client = hyper::Client::builder().http2_only(true).build_http();
          // 				let reresponse = client.request(req).await;
          // 				let result: Result<(), ApiError> = Ok(());
          // 				match result {
          // 					Ok(_) => {
          // 						*response.status_mut() = StatusCode::from_u16(200).expect("Unable to turn 200 into a StatusCode");
          // 						*response.body_mut() = Body::empty();
          // 						// TODO: response from notification
          // 					}
          // 					Err(_) => {
          // 						// Application code returned an error. This should not happen, as the implementation should
          // 						// return a valid response.
          // 						*response.status_mut() = StatusCode::INTERNAL_SERVER_ERROR;
          // 						*response.body_mut() = Body::from("An internal error occurred");
          // 					},
          // 				}
          // 				Ok(response)
          // 			}
          // 			Err(e) => Ok(Response::builder()
          // 							.status(StatusCode::BAD_REQUEST)
          // 							.body(Body::from(format!("Couldn't read body parameter NotificationData: {}", e)))
          // 							.expect("Unable to create Bad Request response due to unable to read body parameter NotificationData")),
          // 		}
          // 	}
          // },
          // // _ if path.matched(paths::ID_CONNECT) => method_not_allowed(),
          // _ => {  Ok(Response::builder().status(StatusCode::NOT_FOUND)
          //         .body(Body::empty())
          //         .expect("Unable to create Not Found response"))}
    }
} // Box::pin(run(req))
  //}

/// Request parser for `Api`.
// pub struct ApiRequestParser;
// impl<T> RequestParser<T> for ApiRequestParser {
//     fn parse_operation_id(request: &Request<T>) -> Result<&'static str, ()> {
//         let path = paths::GLOBAL_REGEX_SET.matches(request.uri().path());
//         match request.method() {
//             // SMServiceActivation - POST /ue-contexts/{supi}
//             &hyper::Method::POST if path.matched(paths::Forward) => Ok("SCPForward"),
// 			&hyper::Method::POST if path.matched(paths::Notify) => Ok("SCPNotify"),
//             // SMServiceDeactivation - POST /ue-contexts/{supi}
//             // &hyper::Method::POST if path.matched(paths::ID_NEGOTIATE) => Ok("ServiceNegotiate"),
//             // SendSMS - POST /ue-contexts/{supi}/sendsms
//             // &hyper::Method::POST if path.matched(paths::ID_UE_CONTEXTS_SUPI_SENDSMS) => Ok("SendSMS"),
//             _ => Err(()),
//         }
//     }
// }

#[cfg(test)]
mod test {
    use hyper::Uri;

    use super::*;
    #[test]
    fn test_reg() {
        let addr = "http://172.18.0.7:80/nscp-id/v1/initial-set/79d7d5252cf2d922013c63517b067e85c42359ad2e76c593a55ca38c9e1a81cd";
        let uri = Uri::from_static(addr);
        let addr_path = uri.path();
        let fwd_path: regex::Regex = regex::Regex::new(r"^/nscp-id/v1/initial-set/(?P<id>.+)$")
            .expect("Unable to create regex for Connection");
        // let path_params =
        // 		fwd_path
        //         .captures("http://scp1.scp.5gc.mnc099.mcc208.3gppnetwork.org/nscp-fwd/v1/nausf-auth/v1/ue-authentications")
        //         .unwrap_or_else(||
        //             panic!("Path matched RE NPDF_CONNECT_UUID in set but failed match against \"{}\"", fwd_path.as_str())
        //         );
        println!("{}", addr_path);
        let path = paths::GLOBAL_REGEX_SET.matches(addr_path);
        if path.matched(paths::ID_Initial_Set) {
            println!("Passed");
        }
        // let path_params =
        // 		fwd_path
        //         .captures("http://172.18.0.7/nscp-detect/v1/result/246363a2-1877-46d4-ae0f-284d234bd36b")
        //         .unwrap_or_else(||
        //             panic!("Path matched RE NPDF_CONNECT_UUID in set but failed match against \"{}\"", fwd_path.as_str())
        //         );

        let path_params =
				paths::REGEX_ID_INIT_SET
				.captures(&addr_path)
				.unwrap_or_else(||
					panic!("Path {} matched RE NAMF_MT_V1_UE_CONTEXTS_UECONTEXTID in set but failed match against \"{}\"", addr_path, paths::REGEX_DETECT_RESULT.as_str())
				);

        let id = match percent_encoding::percent_decode(path_params["id"].as_bytes()).decode_utf8()
        {
            Ok(id) => match id.parse::<String>() {
                Ok(id) => id,
                Err(e) => "BAD".to_owned(),
            },
            Err(_) => "BADBAD".to_owned(),
        };
    }
}
