use std::sync::Arc;

use crate::context::{self, ApiTypeValue, HTTP_CLIENT, SCP_PARAMETERS};
pub mod nssf;
use context::Log;
use nscp_api::ContextWrapperExt as _;
use swagger::ApiError;
#[allow(unused_imports)]
use swagger::{AuthData, ContextBuilder, EmptyContext, Has, Push, XSpanIdString};
type ClientContext = swagger::make_context_ty!(
    ContextBuilder,
    EmptyContext,
    Option<AuthData>,
    XSpanIdString
);
use models::{NfProfile, NfType, ServiceName};
use nnrf_openapi::ContextWrapperExt;

use crate::utils::ScpError;

pub fn nrf_client() -> Arc<Box<dyn nnrf_openapi::ApiNoContext<ClientContext> + Send + Sync>> {
    let nfself = crate::context::SCP_PARAMETERS.get().unwrap();

    let base_url = nfself.nfctx.nrf_uri.clone();
    let client: Option<
        Arc<Box<dyn nnrf_openapi::ApiNoContext<ClientContext> + std::marker::Send + Sync>>,
    > = {
        let map = crate::context::HTTP_CLIENT.read().unwrap();
        let val = map.get(&base_url);
        match val {
            Some(d) => match d {
                crate::context::ApiTypeValue::NRF(data) => Some(data.clone()),
                _ => None,
            },
            None => None,
        }
    };
    if client.is_none() {
        let context: ClientContext = swagger::make_context!(
            ContextBuilder,
            EmptyContext,
            None as Option<AuthData>,
            XSpanIdString::default()
        );
        let client: Arc<
            Box<dyn nnrf_openapi::ApiNoContext<ClientContext> + std::marker::Send + Sync>,
        > = {
            // Using HTTP
            if nfself.nfctx.use_https {
                Arc::new(Box::new(
                    nnrf_openapi::Client::try_new_https(&("https://".to_owned()+&base_url))
                        .expect("Failed to create HTTPS client")
                        .with_context(context),
                ))
            } else {
                Arc::new(Box::new(
                    nnrf_openapi::Client::try_new_http(&("http://".to_owned()+&base_url))
                        .expect("Failed to create HTTP client")
                        .with_context(context),
                ))
            }
        };
        let mut map = &mut HTTP_CLIENT.write().unwrap();
        map.insert(base_url.clone(), ApiTypeValue::NRF(client.clone()));
        return client.clone();
    }
    client.unwrap()
}

pub fn scp_client(
    base_url: String,
) -> Arc<Box<dyn nscp_api::ApiNoContext<ClientContext> + Send + Sync>> {
    // let nfself = crate::context::SCP_PARAMETERS.get().unwrap();

    // let base_url = nfself.nfctx.nrf_uri.clone();
    // let client = None;
    let client: Option<Arc<Box<dyn nscp_api::ApiNoContext<ClientContext> + std::marker::Send + Sync >>>  = {
    	let map = crate::context::HTTP_CLIENT.read().unwrap();
    	let val = map.get(&base_url);
    	match val {
    		Some(d) => {
    			match d {
    				crate::context::ApiTypeValue::SCP(data) => {
    					Some(data.clone())
    				},
    				_=> {
    					None
    				}
    			}
    		},
    		None => {
    			None
    		}
    	}
    };
    if client.is_none() {
        let context: ClientContext = swagger::make_context!(
            ContextBuilder,
            EmptyContext,
            None as Option<AuthData>,
            XSpanIdString::default()
        );
        let param = SCP_PARAMETERS.get().unwrap();
        let client: Arc<Box<dyn nscp_api::ApiNoContext<ClientContext> + std::marker::Send + Sync>> = {
            // Using HTTP
            if param.nfctx.use_https {
                Arc::new(Box::new(
                    nscp_api::Client::try_new_https(&("https://".to_owned()+&base_url))
                        .expect("Failed to create HTTPS client")
                        .with_context(context),
                ))
            } else {
                Arc::new(Box::new(
                    nscp_api::Client::try_new_http(&("http://".to_owned()+&base_url))
                        .expect("Failed to create HTTP client")
                        .with_context(context),
                ))
            }
        };
        // let mut map = &mut HTTP_CLIENT.write().unwrap();
        // map.insert(base_url.clone(), ApiTypeValue::SCP(client.clone()));
        return client.clone();
    }
    client.unwrap()
}

// async fn get_context(uri: String) -> &'static ContextBuilder<std::option::Option<AuthData>, ContextBuilder<XSpanIdString, EmptyContext>> {
// 	{
// 		let map = context::CONTEXTMAP.read().unwrap();
// 		if map.contains_key(&uri) {
// 			return map.get(&uri).unwrap();
// 		}
// 	}
// 	let context: ClientContext =
// 		swagger::make_context!(ContextBuilder, EmptyContext, None as Option<AuthData>, XSpanIdString::default());
// 	let mut map = context::CONTEXTMAP.read().unwrap();
// 	map.insert(uri, context);
// 	&context
// }

pub async fn discovery_first_nf(
    target_type: NfType,
    requester_type: NfType,
    serivce_names: Vec<String>,
    target_slice: Option<Vec<models::Snssai>>,
    target_plmn_list: Option<&Vec<models::PlmnId>>,
    target_fqdn: Option<models::Fqdn>,
    target_instance_id: Option<uuid::Uuid>
    // orig_req_hash: String,
) -> Result<
    (
        NfProfile,
        Arc<Box<dyn nnrf_openapi::ApiNoContext<ClientContext> + Send + Sync>>,
    ),
    Box<dyn std::error::Error + Send + Sync>,
> {
    // let self_t = format!("{:?}", std::thread::current().id());
    let nfself = crate::context::SCP_PARAMETERS.get().unwrap();

    let c_time = chrono::offset::Local::now().timestamp();

    // let sndr: &Vec<String> = &nfself.nfctx.nssai.iter().map(|f| models::Snssai { sst: f.sst, sd: f.sd.clone() }).collect::<Vec<_>>().iter().map(|x| x.to_string()).collect::<Vec<String>>();

    let sndr_slice = match target_slice.clone() {
        Some(a) => {
            let z = a
                .iter()
                .map(|f| models::Snssai {
                    sst: f.sst,
                    sd: f.sd.clone(),
                })
                .collect::<Vec<_>>();
            z
        }
        None => {
            let c_slice = nfself
                .nfctx
                .nssai
                .iter()
                .map(|f| models::Snssai {
                    sst: f.sst,
                    sd: f.sd.clone(),
                })
                .collect::<Vec<_>>();
            c_slice
        }
    };
    let sndrx = sndr_slice.clone();
    let sndr = Some(&sndrx);
    let key_str = format!("{}", target_type);
    let key: String = format!("{:x}", md5::compute(key_str));
    let nrf_client = nrf_client();
    {
        let disc = context::DISC_CACHE.read();
        if disc.as_ref().unwrap().contains_key(&key) {
            let resvec = disc.as_ref().unwrap().get(&key).unwrap();
            for (time,result) in resvec {
                if result.validity_period.is_some() {
                    if *time as isize + result.validity_period.unwrap() > c_time as isize {
                        if target_instance_id.is_some() {
                            let tii = target_instance_id.as_ref().unwrap();
                            if result.nf_instances[0].nf_instance_id == *tii {
                                return Ok((
                                    result
                                        .nf_instances
                                        .first()
                                        .ok_or(ScpError::NfDiscoveryFailed {
                                            detail: format!("no NF instance found"),
                                            service: target_type.to_string(),
                                        })?
                                        .clone(),
                                    nrf_client,
                                ));
                            }
                        } else {
                            return Ok((
                                result
                                    .nf_instances
                                    .first()
                                    .ok_or(ScpError::NfDiscoveryFailed {
                                        detail: format!("no NF instance found"),
                                        service: target_type.to_string(),
                                    })?
                                    .clone(),
                                nrf_client,
                            ));
                        }
                    }
                }
            }
        }
    }
    // let fqdn = match param_requester_nf_instance_fqdn.as_ref() {
    // 	Some(ref x) => x.to_string(),
    // 	None => "None".to_string()};
    // let uuid = match param_requester_nf_instance_id.as_ref() {
    // 	Some(ref x) => x.to_string(),
    // 	None => "None".to_string()};
    // let sndr_slice = match target_slice.clone() {
    //     Some(ref x) => x.iter().map(|x| x.to_string()).collect::<Vec<String>>(),
    //     None => vec!["None".to_string()],
    // };

    // let sndr_plmn = match target_plmn_list.clone() {
    //     Some(ref x) => x.iter().map(|x| x.to_string()).collect::<Vec<String>>(),
    //     None => vec!["None".to_string()],
    // };
    let tar_fqdn = if target_fqdn.is_some() {
        target_fqdn.as_ref().unwrap().to_string()
    } else {
        "None".to_owned()
    };
    // let timestamp: String = chrono::offset::Local::now().timestamp().to_string();
    // let resp_msg = serde_json::json!({
    //     "request_type" : "discovery",
    //     "FQDN": "http://".to_owned() + &nfself.nfctx.host.to_string(),
    //     "UUID": nfself.nfctx.uuid.to_string(),
    //     "target_fqdn": tar_fqdn,
    //     "target_type": target_type,
    //     "requester_snssai" : sndr_slice,
    //     "target_plmn" : sndr_plmn,
    //     "Timestamp": timestamp,
    //     // "orig_req_hash": orig_req_hash,
    //     "SenderIP": "http://".to_owned() + &nfself.nfctx.host.to_string()
    // });
    // crate::scp_prov::MSG_LIST.push(crate::utils::jmap_hash(msg));
    //Add the log to Queue
    // return Some(jmap_hash(msg))
    let result = nrf_client
        .search_nf_instances(
            target_type,
            requester_type,
            None,
            Some(nfself.nfctx.uuid),
            Some(
                &serivce_names
                    .iter()
                    .map(|f| f.to_string().into())
                    .collect::<Vec<_>>(),
            ),
            None,
            target_plmn_list,
            Some(&nfself.nfctx.plmns.iter().cloned().collect::<Vec<_>>()),
            target_instance_id,
            Some(tar_fqdn),
            None,
            None,
            sndr,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None
        )
        .await?;
    // let log_queue = crate::scp_prov::LOG_QUEUE.clone();
    // let data_string = serde_json::to_string(&resp_msg).unwrap();
    // let req_hash = md5::compute(data_string);
    // let request_hash = req_hash
    //     .iter()
    //     .map(|x| format!("{:x?}", x))
    //     .collect::<Vec<String>>()
    //     .join("");
    // let mut req_log = crate::utils::jmap_hash(resp_msg);
    // req_log.insert("request_hash".to_owned(), request_hash.clone());
    match result {
        nnrf_openapi::SearchNFInstancesResponse::ExpectedResponseToAValidRequest {
            body,
            cache_control,
            e_tag,
            content_encoding,
        } => {
            let mut disc = crate::context::DISC_CACHE.write().unwrap();
            // let c_time = chrono::offset::Local::now().timestamp();
            if disc.contains_key(&key) {
                let rv = disc.get_mut(&key).unwrap();
                rv.push((c_time, body.clone()));
            } else {
                disc.insert(key, vec!((c_time, body.clone())));
            }
            // let b2 = serde_json::to_string(&body).unwrap();
            // let instances: Vec<String> = body.nf_instances.iter().map(|x| x.to_string()).collect();
            // let timestamp: String = chrono::offset::Local::now().timestamp().to_string();
            // let msg = serde_json::json!({
            //     "request_type" : "discovery",
            //     "instances": instances,
            //     "response": b2,
            //     "status_code": 200,
            //     "Timestamp": timestamp
            // });
            // let mut resp_log = crate::utils::jmap_hash(msg);
            // resp_log.insert("request_hash".to_owned(), request_hash);
            // log_queue.push(Log {
            //     req: req_log,
            //     dis: "NRF".to_string(),
            //     discovery: None,
            //     api_disc: None,
            //     res: resp_log,
            // });
            // Send log to queue
            // Some(jmap_hash(msg))
            return Ok((
                body.nf_instances
                    .first()
                    .ok_or(ScpError::NfDiscoveryFailed {
                        detail: format!("no NF instance found"),
                        service: target_type.to_string(),
                    })?
                    .clone(),
                nrf_client,
            ));
        }
        s => {
            let timestamp = chrono::offset::Local::now().timestamp().to_string();
            let msg = serde_json::json!({
                "request_type" : "discovery",
                "instances": "",
                "response": "",
                "status_code": 400,
                "Timestamp": timestamp
            });
            // let mut resp_log = crate::utils::jmap_hash(msg);
            // resp_log.insert("request_hash".to_owned(), request_hash);
            // log_queue.push(Log {
            //     req: req_log,
            //     dis: "NRF".to_string(),
            //     discovery: None,
            //     api_disc: None,
            //     res: resp_log,
            // });
            // Send log to queue
            // Some(jmap_hash(msg))
            return Err(ScpError::NfDiscoveryFailed {
                detail: format!("NF discovery failed: {:?}", s),
                service: target_type.to_string(),
            }
            .into());
        }
    }
}

pub async fn discovery_all_nfs(
    target_type: NfType,
    requester_type: NfType,
    serivce_names: Vec<&str>,
) -> Result<
    (
        Vec<NfProfile>,
        Arc<Box<dyn nnrf_openapi::ApiNoContext<ClientContext> + Send + Sync>>,
    ),
    Box<dyn std::error::Error + Send + Sync>,
> {
    let nfself = crate::context::SCP_PARAMETERS.get().unwrap();
    let nrf_client = nrf_client();
    let result = nrf_client
        .search_nf_instances(
            target_type,
            requester_type,
            None,
            None,
            Some(
                &serivce_names
                    .iter()
                    .map(|f| f.to_string().into())
                    .collect::<Vec<_>>(),
            ),
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            Some(
                &nfself
                    .nfctx
                    .nssai
                    .iter()
                    .map(|f| models::Snssai {
                        sst: f.sst,
                        sd: f.sd.clone(),
                    })
                    .collect::<Vec<_>>(),
            ),
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None
        )
        .await?;
    match result {
        nnrf_openapi::SearchNFInstancesResponse::ExpectedResponseToAValidRequest {
            body,
            cache_control,
            e_tag,
            content_encoding,
        } => {
            return Ok((body.nf_instances, nrf_client));
        }
        s => {
            return Err(ScpError::NfDiscoveryFailed {
                detail: format!("NF discovery failed: {:?}", s),
                service: target_type.to_string(),
            }
            .into());
        }
    }
}
