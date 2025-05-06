use frunk::labelled::chars::L;
use futures::TryFutureExt;
use hyper::body::to_bytes;
use hyper::header::CONTENT_TYPE;
use hyper::http::{HeaderName, HeaderValue};
use hyper_openssl::HttpsConnector;
use models::{Fqdn, NfProfile, NfProfile1, NotificationData, ProblemDetails};
use nausf_openapi::client;
use nscp_api::{map_to_hash, SCPForwardResponse};
use regex::Regex;
use swagger::{AuthData, Connector, ContextBuilder, EmptyContext, Has, Push, XSpanIdString};
use tokio::task;
type ClientContext = swagger::make_context_ty!(
    ContextBuilder,
    EmptyContext,
    Option<AuthData>,
    XSpanIdString
);
use crate::context::{Log, CLIENT_CONTEXT};
use crate::scp_req_parser::scp_req_parser;
use crate::scp_rsp_parser::scp_rsp_parser;
use crate::{context, libsba, scp_prov};
use hyper::{Body, HeaderMap, Method, Request, Uri};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::str::FromStr;
use std::sync::Arc;
use swagger::{ApiError, BodyExt};

use crate::scp_prevent::{self, prevent_initial};

mod paths {
    use lazy_static::lazy_static;

    lazy_static! {
        pub static ref GLOBAL_REGEX_SET: regex::RegexSet =
            regex::RegexSet::new(vec![r"^/nnrf-nfm/v1/subscriptions$",])
                .expect("Unable to create global regex set");
    }
    pub(crate) static ID_SUBSCRIPTIONS: usize = 0;
}

pub async fn SCPForward(
    old_req: Request<Body>,
    client: SocketAddr,
) -> Result<SCPForwardResponse, ApiError> {
    // Log Before Prcessing the Incoming Request
    // let log = crate::scp_req_parser::scp_req_parser(old_req.clone());
    // Response Log Just Before Response is sent out!
    // log::info!("Here1");
    // let test = serde_json::to_string(&old_req.);
    let (parts, body) = old_req.into_parts();
    let uri = parts.uri;
    let method = parts.method;
    let mut headerSet = parts.headers;
    let path = uri.path_and_query().unwrap().to_string();
    let body = to_bytes(body).await.unwrap();
    let body: Vec<u8> = body.to_vec();
    // log::info!("Here1");
    let mut req_msg: HashMap<String, String> = HashMap::new();
    match crate::scp_req_parser::scp_req_parser(
        uri.clone(),
        method.clone(),
        headerSet.clone(),
        body.clone(),
    )
    .await
    {
        Some(mut data) => {
            let timestamp = chrono::offset::Local::now().timestamp().to_string();
            data.insert("Timestamp".to_string(), timestamp);
            data.insert("SenderIP".to_string(), client.ip().to_string());
            req_msg = data;
            // scp_prov::MSG_LIST.push(data);
        }
        None => {
            log::info!("{:?}", uri);
        }
    };

    // log::info!("ParseD INFO");
    let pathSet = paths::GLOBAL_REGEX_SET.matches(uri.path());
    let body = if pathSet.matched(paths::ID_SUBSCRIPTIONS) {
        let mut unused_elements = Vec::new();
        let param_subscription_data: Option<models::SubscriptionData> = if !body.is_empty() {
            let deserializer = &mut serde_json::Deserializer::from_slice(&*body);
            match serde_ignored::deserialize(deserializer, |path| {
                log::warn!("Ignoring unknown field in body: {}", path);
                unused_elements.push(path.to_string());
            }) {
                Ok(param_subscription_data) => param_subscription_data,
                Err(e) => None,
            }
        } else {
            None
        };
        let mut subscription = param_subscription_data.unwrap();
        let nfself = context::SCP_PARAMETERS.get().unwrap();
        let url = if nfself.nfctx.use_https {
            "https://".to_owned() + &nfself.nfctx.host + "/nscp-notify/v1/subscriptions"
        } else {
            "http://".to_owned() + &nfself.nfctx.host + "/nscp-notify/v1/subscriptions"
        };
        let sender_nf = subscription.req_nf_instance_id.unwrap();
        let sender_target = subscription.nf_status_notification_uri;
        // log::info!("Received Subscription Request from {:?}", sender_target);
        let target = subscription.subscr_cond.as_ref().unwrap().nf_type.unwrap();
        let mut ctx = context::NOTIFYMAP.write().unwrap();
        ctx.insert(target, (sender_nf, sender_target));

        subscription.nf_status_notification_uri = url;
        let body = serde_json::to_string(&subscription).expect("impossible to fail to serialize");
        body.as_bytes().to_vec()
    } else {
        body
    };
    let mode = &context::SCP_PARAMETERS.get().unwrap().mode;
    // let mut headerSet = parts.headers;
    if mode == &'C'.to_string() {
        return modelC(path, method, body, headerSet).await;
    } else if mode == &'D'.to_string() {
        let x = modelD(uri, path, method, body, &mut headerSet, req_msg).await;
        drop(headerSet);
        return x;
        // return Ok(SCPForwardResponse::InvalidServiceRequest(ProblemDetails::with_detail("Some Error Occured")));
    } else {
        return Ok(SCPForwardResponse::UnexpectedError(
            (ProblemDetails::with_detail("Wrong parameters for request")),
        ));
    }
    // get model type and match headervalue for part 3gpp sbi root or 3ggp discover parameters
    // forward the data to particular fucntuions
    // Ok(SCPForwardResponse::InvalidServiceRequest(ProblemDetails::with_detail("Some Error Occured")))
}


// Model C right now only works with single SCP instance, need the address resolution to find target SCP to support multiple SCPs
async fn modelC(
    path: String,
    method: Method,
    body: Vec<u8>,
    headerSet: HeaderMap<HeaderValue>,
) -> Result<SCPForwardResponse, ApiError> {
    /// Decode data from request
    /// Parse 3gpp-Sbi-Target-apiRoot
    /// Parse body and headers
    /// Create new request
    /// Send request to the particular NF and get reply
    /// Return body to thre response and headerMap to the requester
    //log::info!("Selected Model C");
    let target = headerSet
        .get("3gpp-sbi-target-apiroot")
        .unwrap()
        .to_str()
        .unwrap();
    let uri_str = target.to_owned() + &path;
    // log::info!("Target Path = {:?}", uri_str);
    let context: ClientContext = swagger::make_context!(
        ContextBuilder,
        EmptyContext,
        None as Option<AuthData>,
        XSpanIdString::default()
    );
    let mut request = match Request::builder()
        .method(method.clone())
        .uri(uri_str)
        .body(Body::empty())
    {
        Ok(req) => req,
        Err(e) => return Err(ApiError(format!("Unable to create request: {}", e))),
    };
    //log::info!("Selected Model C 1 {:?}", method);

    request.headers_mut().extend(headerSet.clone());

    let header = HeaderValue::from_str(
        Has::<XSpanIdString>::get(&context)
            .0
            .clone()
            .to_string()
            .as_str(),
    );
    request.headers_mut().insert(
        HeaderName::from_static("x-span-id"),
        match header {
            Ok(h) => h,
            Err(e) => {
                return Err(ApiError(format!(
                    "Unable to create X-Span ID header value: {}",
                    e
                )))
            }
        },
    );
    *request.body_mut() = Body::from(body);
    // //log::info!("Selected Model C2 {:?}", param_authentication_info);
    let mut client: hyper::Client<hyper_tls::HttpsConnector<hyper::client::HttpConnector>, _> = {
        let connector = hyper_tls::HttpsConnector::new();
        hyper::client::Client::builder()
            .http2_only(true)
            .build(connector)
        };
    let response: hyper::Response<Body> = match client.request(request).await {
        Ok(resp) => resp,
        Err(e) => {
            println!("ERROR FROM CLIENT {:?}", e);
            return Err(ApiError(format!("Some ERROR with API {}", e)));
        }
    };
    //log::info!("Selected Model C3");

    let resp_head = nscp_api::map_to_hash(response.headers());
    //log::info!("Selected Model C4");
    let status = response.status().as_u16();
    let body = response.into_body();
    let body = to_bytes(body)
        .map_err(|e| ApiError(format!("Failed to read response: {}", e)))
        .await
        .unwrap();
    // let body = String::from_utf8(body)
    //     .map_err(|e| ApiError(format!("Response was not valid UTF8: {}", e))).unwrap();
    //log::info!("Selected Model C5 Response {:?}", body);
    // println!("{:?}", nausf_openapi::scp_decoder::scp_dec_nausf_auth_v1_ue_authentications_post(status, body.as_bytes().to_vec(), nscp_api::hash_to_map(resp_head.clone())).await);
    let body: Vec<u8> = body.to_vec();
    Ok(SCPForwardResponse::ForwardSCPComplete {
        status: status,
        body: body,
        headers: resp_head,
    })
}

async fn modelD(
    uri: Uri,
    path: String,
    method: Method,
    body: Vec<u8>,
    headerSet: &mut HeaderMap<HeaderValue>,
    mut req_msg: HashMap<String, String>,
) -> Result<SCPForwardResponse, ApiError> {
    /// Decode data from request
    /// Parse body and headers
    /// Parse 3gpp-Sbi-Discovery-Headers
    /// Create and perform a discovery request
    /// Create new request with discovery results
    /// Send request to the particular NF and get reply
    /// Return body to thre response and headerMap to the requester
    let log_queue = crate::scp_prov::LOG_QUEUE.clone();
    let nfself = context::SCP_PARAMETERS.get().unwrap();
    // log::info!("Step 1");
    
    let mut discovery_results: Option<NfProfile> = None;
    // Creating the context for the incoming registration targets
    if req_msg.get("request_type").unwrap() == "register_nf" {
        // log::info!("{:?}", req_msg.get("SNSSAI"));
        let nf_profile = req_msg.get("profile").unwrap();
        let nf_profile: NfProfile1 = serde_json::from_str(&nf_profile).unwrap();
        // discovery_results
        let fqdn = nf_profile.fqdn.as_ref().unwrap().clone();
        let context: ClientContext = swagger::make_context!(
            ContextBuilder,
            EmptyContext,
            None as Option<AuthData>,
            XSpanIdString::default()
        );
        let xspan_id = &Has::<XSpanIdString>::get(&context).0;
        {
            let mut context = crate::context::GLOBAL_CONTEXT.ClientContext.write().unwrap();
            context.insert(fqdn.to_owned(), (nf_profile, xspan_id.to_string()));
        }
    }
    // GET Client at the end
    let nf_type: models::NfType = if headerSet.contains_key("3gpp-sbi-discovery-target-nf-type") {
        let nf_p = headerSet.get("3gpp-sbi-discovery-target-nf-type").unwrap();
        let x = models::NfType::from_str(nf_p.to_str().unwrap()).unwrap();
        req_msg.insert("sbi-disc-target-nf-type".to_owned(), x.to_string());
        x
    } else {
        if !headerSet.contains_key("3gpp-sbi-target-apiroot") {
            return Ok(SCPForwardResponse::ForwardSCPComplete {
                status: 404,
                body: vec![],
                headers: HashMap::new(),
            });
        }
        // else {
            // if prevent_token(&req_msg, headerSet) {
            //     return Ok(SCPForwardResponse::ForwardSCPComplete {
            //         status: 404,
            //         body: vec![],
            //         headers: HashMap::new(),
            //     })
            // }
        // }
        models::NfType::SCP
    };
    // log::info!("Step 2");
    // Should perform discovery only
    let (mut uri_str, mut prof, mut api_target): (String, String, Option<String>) =
        if nfself.use_next {
            (nfself.next_scp.clone(), "NEXTSCP".to_string(), None)
        } else if nf_type == models::NfType::NRF {
            (
                if nfself.nfctx.use_https {
                    "https://".to_owned() + &nfself.nfctx.nrf_uri + &path
                } else {
                    "http://".to_owned() + &nfself.nfctx.nrf_uri + &path
                },
                "NRF".to_string(),
                None,
            )
        } else if nf_type == models::NfType::NSSF {
            (
                if nfself.nfctx.use_https {
                    "https://".to_owned() + &nfself.nssf_uri + &path
                } else {
                    "http://".to_owned() + &nfself.nssf_uri + &path
                },
                "NSSF".to_string(),
                None,
            )
        } else if headerSet.contains_key("3gpp-sbi-discovery-target-nf-type") {
            let nf_service = headerSet.get("3gpp-sbi-discovery-target-services").unwrap();
            log::info!("Discovery Service:- {:?}", nf_service);
            log::info!("Discovery NFType:- {:?}", nf_type);
            req_msg.insert(
                "sbi-disc-target-nf-services".to_owned(),
                nf_service.to_str().unwrap().to_owned(),
            );
            let nf_service: Vec<String> =
                serde_json::from_str::<Vec<String>>(nf_service.to_str().unwrap()).unwrap();
            let target_instance_id: Option<String> = 
                if headerSet.contains_key("3gpp-sbi-discovery-target-nfinstance-id") {
                    let nf_p = headerSet.get("3gpp-sbi-discovery-target-nfinstance-id").unwrap();
                    let x = nf_p.to_str().unwrap();
                    req_msg.insert("sbi-disc-target-nfinstance-id".to_owned(), x.to_owned());
                    Some(x.to_owned())
            } else {
                    None
            };
            let nf_plmns: Option<Vec<models::PlmnId>> =
                if headerSet.contains_key("3gpp-sbi-discovery-target-plmns") {
                    let nf_p = headerSet.get("3gpp-sbi-discovery-target-plmns").unwrap();
                    let x = nf_p.to_str().unwrap();
                    req_msg.insert("sbi-disc-target-nf-plmns".to_owned(), x.to_owned());
                    Some(serde_json::from_str::<Vec<models::PlmnId>>(x).unwrap())
                } else {
                    None
                };

            let mut nf_target_fqdn = if headerSet.contains_key("3gpp-sbi-discovery-target-nf-fqdn")
            {
                let nf_p = headerSet.get("3gpp-sbi-discovery-target-nf-fqdn").unwrap();
                let x = nf_p.to_str().unwrap();
                req_msg.insert("sbi-disc-target-nf-fqdn".to_owned(), x.to_owned());
                Some(serde_json::from_str::<models::Fqdn>(x).unwrap())
            } else {
                None
            };
            let nf_slice: Option<Vec<models::Snssai>> =
            if headerSet.contains_key("3gpp-sbi-discovery-target-snssais") {
                let nf_p = headerSet.get("3gpp-sbi-discovery-target-snssais").unwrap();
                let x = nf_p.to_str().unwrap();
                req_msg.insert("sbi-disc-target-nf-snssais".to_owned(), x.to_owned());
                Some(serde_json::from_str::<Vec<models::Snssai>>(x).unwrap())
            } else {
                None
            };
            // Make a discovery here
            let (nf_profile, no_client) = crate::libsba::discovery_first_nf(
                nf_type,
                models::NfType::SCP,
                nf_service.clone(),
                nf_slice.clone(),
                nf_plmns.as_ref(),
                nf_target_fqdn.clone(),
                if target_instance_id.is_some(){
                Some(uuid::Uuid::parse_str(&target_instance_id.unwrap()).unwrap())
                } else {None}
                // request_hash.clone(),
            )
            .await
            .unwrap();
            let sender_ip = req_msg.get("SenderIP").unwrap().clone();

            let mut delegate = false;
            let fqdn = if nf_profile.scp_domains.is_some() {
                delegate = true;
                let mut dom = nf_profile.scp_domains.as_ref().unwrap()[0].clone();
                let dom_url = if nfself.nfctx.use_https {
                    "https://".to_owned() + &nfself.nfctx.host
                } else {
                    "http://".to_owned() + &nfself.nfctx.host
                };
                if dom == dom_url {
                    delegate = false;
                    dom = nf_profile
                        .fqdn
                        .clone()
                        .ok_or(ApiError(format!("No FQDN in NF profile")))?
                } else {
                    delegate = true;
                }
                dom
            } else {
                nf_profile
                    .fqdn
                    .clone()
                    .ok_or(ApiError(format!("No FQDN in NF profile")))?
            };
            let target = if &fqdn[0..4] != "http" {
                if nfself.nfctx.use_https {
                    format!("https://{}", fqdn)
                } else {
                    format!("http://{}", fqdn)
                }
            } else {
                fqdn
            };
            discovery_results = Some(nf_profile.clone());
            let uri_str = target.to_owned() + &path;
            let api = match delegate {
                true => {Some(nf_profile
                    .fqdn.as_ref().unwrap().clone())},
                false => {None}
            };
            (
                uri_str,
                serde_json::to_string(&nf_profile).unwrap(),
                api
                // nf_profile.fqdn.clone(),
            )
        } else {
            ("ApiTarget".into(), "LOCAL".into(), None)
        };
        // log::info!("Step 3");
    let api_target_disc: Option<NfProfile> = if headerSet.contains_key("3gpp-sbi-target-apiroot") {
        let fqdn = headerSet.get("3gpp-sbi-target-apiroot").unwrap().to_owned();
        let fqdn = format!("{}", fqdn.to_str().unwrap());
        let target = if &fqdn[0..4] != "http" {
            if nfself.nfctx.use_https {
                format!("https://{}", fqdn)
            } else {
                format!("http://{}", fqdn)
            }
        } else {
            fqdn
        };
        req_msg.insert("sbi-target".to_owned(), target.clone());
        let targetfqdn = {
            let re = Regex::new(r"^http://").unwrap();
            let re1 = Regex::new(r"^https://").unwrap();
            let FQDN = target.clone();
            if re.is_match(&FQDN) {
                FQDN[7..].to_string()
            } else if re1.is_match(&FQDN) {
                FQDN[8..].to_string()
            } else {
                FQDN
            }
        };
        // Use the FQDN
        // Check in current context

        let local_target = {
            let context = crate::context::GLOBAL_CONTEXT.ClientContext.read().unwrap();
            match context.get(&targetfqdn) {
                Some(t) => true,
                None => false
            }
        };
        let x = if local_target == false {
            let nf_service = headerSet.get("3gpp-sbi-discovery-target-services").unwrap();
            req_msg.insert(
                "sbi-disc-target-nf-services".to_owned(),
                nf_service.to_str().unwrap().to_owned(),
            );
            let nf_service: Vec<String> =
            serde_json::from_str::<Vec<String>>(nf_service.to_str().unwrap()).unwrap();
            let (nf_profile, no_client) = crate::libsba::discovery_first_nf(
                nf_type,
                models::NfType::SCP,
                nf_service.clone(),
                None,
                None,
                Some(Fqdn::from(targetfqdn)),
                None
                // request_hash.clone(),
            )
            .await
            .unwrap();
            // let sender_ip = req_msg.get("SenderIP").unwrap().clone();

            let ext_target = if nf_profile.scp_domains.is_some() {
                nf_profile.scp_domains.as_ref().unwrap()[0].clone()
            } else {
                nf_profile.fqdn.as_ref().unwrap().clone()
            };
            // nf_profile.
            let uri_str1 = ext_target + &path;
            uri_str = uri_str1.clone();
            prof =  "FROM_SCP".to_string();
            api_target = Some(nf_profile.fqdn.as_ref().unwrap().clone());
            Some(nf_profile)
        } else {
            // If present forward the message to the client
            // If context is not present then
            // perform a local discovery request to find the target SCP
            // Forward that request to the target SCP
            // May need to perform token request, In model D assume token is not got
            /// External SCP to Local Network Function
            let uri_str1 = target.to_owned() + &path;
            let token = if headerSet.contains_key(hyper::header::AUTHORIZATION) {
                Some(format!(
                    "{}",
                    headerSet
                        .get(hyper::header::AUTHORIZATION)
                        .unwrap()
                        .to_str()
                        .unwrap()
                ))
            } else {
                None
            };
            // Confused Producer Call
            uri_str = uri_str1.clone();
            prof =  "FROM_SCP".to_string();
            api_target = None;
            None
        };
        x
    } else {
        None
    };

    // log::info!("Step 4");

    // Location to add the PREVENTION POLICIES
    // Policy Activated when the discovery and access token is delegated to local
    if headerSet.contains_key("3gpp-sbi-discovery-target-nf-type") {
        if prevent_initial(&req_msg, discovery_results.as_ref(), api_target_disc.as_ref(), map_to_hash(&headerSet)) {
            return Ok(SCPForwardResponse::ForwardSCPComplete {
                status: 404,
                body: vec![],
                headers: HashMap::new(),
            });
        }
    }
    // Access Token Requests as required
    let token: Option<String> = 
    if nf_type != models::NfType::NRF && nf_type != models::NfType::NSSF {
        // THis is normal forward, when the discover header is not present we can consider a normal forward and assume the NF is local
        // if headerSet.contains_key("3gpp-sbi-target-apiroot") && !headerSet.contains_key("3gpp-sbi-discovery-target-nf-type")
        // {
        //     None
        // } // This is the Confused Producer Case, here accces token should be requested but, discovery for 3gpp-sbi-target is already performed 
        // else {
        if headerSet.contains_key("3gpp-sbi-discovery-target-nf-type") {
            let mut bearer = String::new();
            let nf_profile = discovery_results.as_ref().unwrap();
            let nf_slice: Option<Vec<models::Snssai>> =
            if headerSet.contains_key("3gpp-sbi-discovery-target-snssais") {
                let nf_p = headerSet.get("3gpp-sbi-discovery-target-snssais").unwrap();
                let x = nf_p.to_str().unwrap();
                req_msg.insert("sbi-disc-target-nf-snssais".to_owned(), x.to_owned());
                Some(serde_json::from_str::<Vec<models::Snssai>>(x).unwrap())
            } else {
                None
            };
            let nf_service = headerSet.get("3gpp-sbi-discovery-target-services").unwrap();
            req_msg.insert(
                "sbi-disc-target-nf-services".to_owned(),
                nf_service.to_str().unwrap().to_owned(),
            );
            let nf_service: Vec<String> =
                serde_json::from_str::<Vec<String>>(nf_service.to_str().unwrap()).unwrap();

            if  headerSet.contains_key(hyper::header::AUTHORIZATION) {
                headerSet.remove(hyper::header::AUTHORIZATION);
                let mut token_req = models::AccessTokenReq::new(
                    "jwt".into(),
                    nfself.nfctx.uuid,
                    nf_service[0].clone().into(),
                );
                token_req.requester_snssai_list = nf_slice;
                token_req.target_nf_instance_id = Some(nf_profile.nf_instance_id);
                let token_resp: nnrf_openapi::AccessTokenRequestResponse = {
                    let mut msg = nnrf_openapi::scp_encoder::scp_enc_access_token_request(
                        token_req.clone(),
                        None,
                        None,
                    )
                    .await
                    .unwrap();
                    let toke_req = if nfself.nfctx.use_https {
                        "https://".to_owned() + &nfself.nfctx.nrf_uri + msg.uri().path()
                    } else {
                        "http://".to_owned() + &nfself.nfctx.nrf_uri + msg.uri().path()
                    };
                    *msg.uri_mut() = Uri::from_str(&toke_req).unwrap();
                    let (parts, body) = msg.into_parts();
                    let (c_method, c_uri, c_headers) = (
                        parts.method.clone(),
                        parts.uri.clone(),
                        parts.headers.clone(),
                    );
                    let path = paths::GLOBAL_REGEX_SET.matches(uri.path());
                    let mut cloned_request = Request::from_parts(parts, Body::empty());
                    let body = to_bytes(body).await.unwrap();
                    let body: Vec<u8> = body.to_vec();
                    *cloned_request.body_mut() = Body::from(body.clone());
                    // *tok_req_mesg.get_mut("request_type".clne)
                    let nrf_client = libsba::nrf_client();
                    let response = nrf_client
                        .access_token_request(token_req, None, None)
                        .await.map_err(|e| ApiError(format!("SomeEroor{}",e)))?;
                    response
                };
                let token = match token_resp {
                    nnrf_openapi::AccessTokenRequestResponse::SuccessfulAccessTokenRequest {
                        body,
                        cache_control,
                        pragma,
                        accept_encoding,
                        content_encoding,
                    } => {
                        body.access_token
                    }
                    nnrf_openapi::AccessTokenRequestResponse::TemporaryRedirect {
                        body,
                        location,
                    } => todo!(),
                    nnrf_openapi::AccessTokenRequestResponse::PermanentRedirect {
                        body,
                        location,
                    } => todo!(),
                    e => {
                        return Err(ApiError(format!(
                            "Error requesting access token for nausf-auth, {:?}",
                            e
                        ))
                        .into());
                    }
                };
                bearer = format!("Bearer {}", token);
                headerSet.insert(
                    hyper::header::AUTHORIZATION,
                    hyper::header::HeaderValue::from_str(&bearer).unwrap(),
                );
            };
            Some(bearer)
        } else {
            // log::info!("Bearer From other SCP{:?}", headerSet.get(hyper::header::AUTHORIZATION).unwrap());
            Some(headerSet.get(hyper::header::AUTHORIZATION).unwrap().to_str().unwrap().to_owned())
        }
    } else {
        None
    };
    // log::info!("Step 5 {:?} {:?}", method, uri_str);
    let mut request = match Request::builder()
        .method(method.clone())
        .uri(uri_str.clone())
        .body(Body::empty())
    {
        Ok(req) => req,
        Err(e) => return Err(ApiError(format!("Unable to create request: {}", e))),
    };
    if headerSet.contains_key(hyper::header::CONTENT_TYPE) {
        request.headers_mut().insert(
            hyper::header::CONTENT_TYPE,
            headerSet.get(hyper::header::CONTENT_TYPE).unwrap().clone(),
        );
    }
    if token.is_some() {
        let mut tok = token.unwrap();
        if &tok == "\"" {
            tok = tok[1..tok.len() - 1].to_string();
        };
        // log::info!("Token {}",tok);
        request.headers_mut().insert(
            hyper::header::AUTHORIZATION,
            hyper::header::HeaderValue::from_str(&tok).unwrap(),
        );
    }
    let targetfqdn = {
        let re = Regex::new(r"^http://").unwrap();
        let re1 = Regex::new(r"^https://").unwrap();
        let FQDN = uri_str;
        if re.is_match(&FQDN) {
            FQDN[7..].to_string()
        } else if re1.is_match(&FQDN) {
            FQDN[8..].to_string()
        } else {
            FQDN
        }
    };
    // log::info!("Step 6");
    {
        let xspan_id = if prof == "NEXTSCP" || prof == "NRF" || prof == "NSSF" {
            let context: ClientContext = swagger::make_context!(
                ContextBuilder,
                EmptyContext,
                None as Option<AuthData>,
                XSpanIdString::default()
            );
            Has::<XSpanIdString>::get(&context).0.clone()
        } else {
            let mut nf_context = crate::context::GLOBAL_CONTEXT.ClientContext.read().unwrap();
            match nf_context.get(&targetfqdn) {
                Some(x) => x.1.clone(),
                None => {
                    let context: ClientContext = swagger::make_context!(
                        ContextBuilder,
                        EmptyContext,
                        None as Option<AuthData>,
                        XSpanIdString::default()
                    );
                    let xspan_id = &Has::<XSpanIdString>::get(&context).0;
                    // let mut client: hyper::Client<hyper_tls::HttpsConnector<hyper::client::HttpConnector>, _> = {
                    // let connector = hyper_tls::HttpsConnector::new();
                    // hyper::client::Client::builder()
                    //     .http2_only(true)
                    //     .build(connector)
                    // };
                    // let context = crate::context::GLOBAL_CONTEXT.ClientConnect.write().unwrap();
                    // nf_context.insert(targetfqdn.clone(), (serde_json::from_str(&prof).unwrap(), xspan_id.to_string()));
                    xspan_id.to_string()
                }
            }
        };
        let header = HeaderValue::from_str(&xspan_id);
        request.headers_mut().insert(
            HeaderName::from_static("x-span-id"),
            match header {
                Ok(h) => h,
                Err(e) => {
                    return Err(ApiError(format!(
                        "Unable to create X-Span ID header value: {}",
                        e
                    )))
                }
            },
        );
    }    use tokio::task;
    // log::info!("Step 7");
    if api_target.is_some() {
        let atarget = &api_target.unwrap();
        let t_header = HeaderValue::from_str(&atarget);
        req_msg.insert("sbi-target".to_owned(), atarget.clone());
        request.headers_mut().insert(
            HeaderName::from_static("3gpp-sbi-target-apiroot"),
            match t_header {
                Ok(h) => h,
                Err(e) => {
                    return Err(ApiError(format!(
                        "Unable to create X-Span ID header value: {}",
                        e
                    )))
                }
            },
        );
    } else {
        req_msg.insert("sbi-target".to_owned(), request.uri().host().expect("DADUMTHUS").to_string());
    }
    *request.body_mut() = Body::from(body);
    // log::info!("Selected Model D2 {:?}", request.headers());
    // let conn = request.
    // let addr = conn.remote_addr();
    // let con = crate::context::GLOBAL_CONTEXT.ClientConnect.clone();
    // let mut context = con.write().unwrap();
    // let x = &context.get(&targetfqdn).unwrap().0;
    // let rt = tokio::runtime::Runtime::new().unwrap();
    let target = request.uri().host().unwrap().to_owned();
    let data = task::spawn_blocking(move || {
        let clientcon = CLIENT_CONTEXT.read().unwrap();
        let client = if clientcon.contains_key(&target) {
            let x = clientcon.get(&target).clone().unwrap().clone();
            drop(clientcon);
            x
        } else {
            drop(clientcon);
            log::info!("Creating new client");
            let mut client: hyper::Client<hyper_tls::HttpsConnector<hyper::client::HttpConnector>, _> = {
                let connector = hyper_tls::HttpsConnector::new();
                hyper::client::Client::builder()
                    .http2_only(true)
                    .build(connector)
                };
            let ac = Arc::new(client);
            // CLIENT_CONTEXT.insert(target, ac.clone());\
            // let cc = 
            let mut x = CLIENT_CONTEXT.write().unwrap();
            x.insert(target, ac.clone());
            ac
        };
        client
    }).await.unwrap();

    
    let response: hyper::Response<Body> = match data.request(request).await 
    {
        Ok(resp) => resp,
        Err(e) => {
            println!("ERROR FROM CLIENT {:?}", e);
            return Err(ApiError(format!("Some ERROR with API {}", e)));
        }
    };
    // log::info!("Step 8");
    let status = response.status().as_u16();
    let (parts, body) = response.into_parts();
    let resp_header = parts.headers;

    let headers = nscp_api::map_to_hash(&resp_header);

    let body = to_bytes(body)
        .map_err(|e| ApiError(format!("Failed to read response: {}", e)))
        .await
        .unwrap();
    let body: Vec<u8> = body.to_vec();
    match crate::scp_rsp_parser::scp_rsp_parser(
        method,
        uri.clone(),
        status,
        body.clone(),
        resp_header.clone(),
    )
    .await
    {
        Some(mut data) => {
            let timestamp = chrono::offset::Local::now().timestamp().to_string();
            data.insert("Timestamp".to_string(), timestamp);
            log_queue.push(context::Log {
                req: req_msg,
                dis: prof,
                discovery: discovery_results,
                api_disc: api_target_disc,
                res: data,
            });
        }
        None => {}
    };
    // return Ok(SCPForwardResponse::ForwardSCPComplete {
    //     status: 404,
    //     body: vec![],
    //     headers: HashMap::new(),
    // });
    // log::info!("Step 9 {:?} {:?}", status, headers);

    Ok(SCPForwardResponse::ForwardSCPComplete {
        status,
        body,
        headers,
    })
}

pub fn SCPNotify(notif_data: NotificationData, route_binding: Option<String>) -> Request<Body> {
    // log::info!("Received a notification from NRF");
    let target = notif_data.nf_profile.as_ref().unwrap().nf_type;
    let data = context::NOTIFYMAP.read().unwrap();
    let (req_uuid, req_url) = data.get(&target).unwrap();
    let mut new_url: String = String::new();
    if route_binding.is_some() {
        let nf_inst = route_binding.unwrap();
        for (k, (id, url)) in data.iter() {
            if id.to_string() == nf_inst {
                new_url = url.to_string();
            }
        }
    } else {
        new_url = req_url.to_owned();
    };
    let nfself = context::SCP_PARAMETERS.get().unwrap();
    let url = if nfself.nfctx.use_https {
        "https://".to_owned() + &new_url
    } else {
        "http://".to_owned() + &new_url
    };
    let mut request = Request::builder()
        .method("POST")
        .uri(url)
        .body(Body::empty())
        .unwrap();
    let body = serde_json::to_string(&notif_data).unwrap();
    *request.body_mut() = Body::from(body);
    // log::info!("New Request{:?}", request);
    let header = "application/json";
    request
        .headers_mut()
        .insert(CONTENT_TYPE, HeaderValue::from_str(header).unwrap());
    request
}
