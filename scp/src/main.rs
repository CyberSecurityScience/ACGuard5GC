#![allow(dead_code)]
#![allow(unused)]
#![allow(non_snake_case)]
#![allow(non_upper_case_globals)]
#![allow(non_camel_case_types)]
#![allow(non_snake_case)]

use clap::{App, Arg};
use jwt_simple::prelude::Ed25519PublicKey;
use libmodels::network_function::NetworkFunctionContext;
use libsba::nrf_client;
use local_ip_address::local_ip;
use log::{debug, error, info, log_enabled, warn, Level};
use models::{NfProfile1, NfService1, NfServiceVersion};
use serde::{Deserialize, Serialize};
use tokio::runtime;
use std::collections::HashMap;
use std::fs::File;
use std::hash::RandomState;
use std::io::Write;
use std::sync::atomic::Ordering;
use std::sync::mpsc::Receiver;
use std::sync::mpsc::SyncSender;
use std::sync::{mpsc, Arc};
use std::thread;
use std::time::Duration;
use std::{
    collections::HashSet,
    net::{IpAddr, Ipv4Addr},
};
use tokio::runtime::Handle;

pub mod private_id;
pub mod scp_prevent;

#[macro_use]
extern crate lazy_static;

#[allow(unused_imports)]
use swagger::{AuthData, ContextBuilder, EmptyContext, Has, Push, XSpanIdString};

pub mod context;
use context::{ApiTypeValue, SCPParameters, HTTP_CLIENT};

use crate::context::Log;
use crate::scp_prov::ValTup;
use crate::utils::jmap_hash;

/// SBA server
pub mod server;

/// SBA client
pub mod libsba;

pub mod utils;

pub mod scp_service;

pub mod scp_req_parser;

pub mod scp_rsp_parser;

pub mod scp_prov;

#[derive(Debug, Serialize, Deserialize)]
struct SCPConfig_nf {
    pub host: String,
    pub nrf_uri: String,
    pub nssf_uri: String,
    pub name: String,
    pub allowed_nssai: Vec<models::ExtSnssai>,
    pub nssai: Vec<models::ExtSnssai>,
    pub plmns: HashSet<models::PlmnId>,
    pub allowed_plmns: HashSet<models::PlmnId>,
}

#[derive(Debug, Serialize, Deserialize)]
struct SCPConfig_scp {
    pub mode: String,
    pub next_hop: bool,
    pub next_scp: String,
    pub dumper_interval: usize,
    pub log_folder: String,
}

#[derive(Debug, Serialize, Deserialize)]
struct SCPConfig {
    pub nf: SCPConfig_nf,
    pub scp: SCPConfig_scp,
}
type ClientContext = swagger::make_context_ty!(
    ContextBuilder,
    EmptyContext,
    Option<AuthData>,
    XSpanIdString
);

async fn create_nf_heartbeat_task(
    client: Arc<Box<dyn nnrf_openapi::ApiNoContext<ClientContext> + Send + Sync>>,
    nfid: uuid::Uuid,
    timer: isize,
    dis: String,
    param: SCPParameters,
) {
    type ClientContext = swagger::make_context_ty!(
        ContextBuilder,
        EmptyContext,
        Option<AuthData>,
        XSpanIdString
    );
    use nnrf_openapi::ContextWrapperExt;
    let context: ClientContext = swagger::make_context!(
        ContextBuilder,
        EmptyContext,
        None as Option<AuthData>,
        XSpanIdString::default()
    );

    // let client : Box<dyn nnrf_openapi::ApiNoContext<ClientContext>>  = {
    // 	// Using HTTP
    // 	let client = Box::new(nnrf_openapi::Client::try_new_https(
    // 		&base_url)
    // 		.expect("Failed to create HTTP client"));
    // 		Box::new(client.with_context(context))
    // };

    // let client = HTTP_CLIENT();

    let task = Handle::current().spawn(async move {
        let mut interval = tokio::time::interval(Duration::from_secs(timer as _));

        loop {
            interval.tick().await;
            let ctime = chrono::offset::Local::now().timestamp();
            let req_msg = serde_json::json!({
                "Timestamp": ctime,
                "request_type" : "update_nf",
                "uuid": nfid.to_string(),
                "SenderIP": local_ip().unwrap(),
                "data": models::PatchItem {
                    op: models::PatchOperation::REPLACE,
                    path: "/nfStatus".into(),
                    value: Some("REGISTERED".into()),
                    from: None
                }.to_string()
               // // "hash": format!("{:x}" ,md5::compute(serde_json::to_string(&param_patch_item.clone())?))
            });
            client
                .update_nf_instance(
                    nfid,
                    &vec![models::PatchItem {
                        op: models::PatchOperation::REPLACE,
                        path: "/nfStatus".into(),
                        value: Some("REGISTERED".into()),
                        from: None,
                    }],
                    None,
                    None,
                    None,
                )
                .await;
            let msg = serde_json::json!({
                "Timestamp": ctime,
                "request_type" : "update_nf",
                // "uuid": param_nf_instance_id.to_string(),
                "status_code": 200,
            });
            let log_queue = crate::scp_prov::LOG_QUEUE.clone();
            let data_string = serde_json::to_string(&req_msg).unwrap();
            let req_hash = md5::compute(data_string);
            let request_hash = req_hash
                .iter()
                .map(|x| format!("{:x?}", x))
                .collect::<Vec<String>>()
                .join("");
            let mut req_log = crate::utils::jmap_hash(req_msg);
            req_log.insert("request_hash".to_owned(), request_hash.clone());
            let mut resp_log = crate::utils::jmap_hash(msg);
            resp_log.insert("request_hash".to_owned(), request_hash);
            log_queue.push(Log {
                req: req_log,
                dis: dis.clone(),
                discovery: None,
                api_disc: None,
                res: resp_log,
            });
        }
    });
}

async fn register_nrf(param: &SCPParameters) -> Result<(), Box<dyn std::error::Error>> {
    type ClientContext = swagger::make_context_ty!(
        ContextBuilder,
        EmptyContext,
        Option<AuthData>,
        XSpanIdString
    );
    use nnrf_openapi::ContextWrapperExt;
    let mut dis = String::new();
    let base_url = if param.use_next {
        dis = "NEXTSCP".to_owned();
        param.next_scp.clone()
    } else {
        dis = "NRF".to_owned();
        param.nfctx.nrf_uri.clone()
    };
    log::info!("Registering with {:?}", base_url);
    let context: ClientContext = swagger::make_context!(
        ContextBuilder,
        EmptyContext,
        None as Option<AuthData>,
        XSpanIdString::default()
    );
    // log::info!("Here1");
    let mut client: Arc<
        Box<
            (dyn nnrf_openapi::ApiNoContext<
                ContextBuilder<
                    std::option::Option<AuthData>, 
                    ContextBuilder<XSpanIdString, EmptyContext>,
                >,
            > + std::marker::Send
                 + Sync
                 + 'static),
        >,
    > = {
        // Using HTTP
        if param.nfctx.use_https {
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
    {
        let map = &mut HTTP_CLIENT.write().unwrap();
        map.insert(base_url.clone(), ApiTypeValue::NRF(client.clone()));
    }
    // log::info!("Here2");
    let ctime = chrono::offset::Local::now().timestamp();
    let mut profile = NfProfile1::new(
        param.nfctx.uuid,
        models::NfType::SCP,
        models::NfStatus::registered(),
    );
    profile.fqdn = Some(param.nfctx.host.clone());
    profile.s_nssais = Some(param.nfctx.nssai.clone());
    profile.allowed_nssais = Some(param.nfctx.allowed_nssai.clone());
    profile.nf_instance_name = Some(param.nfctx.name.clone());
    profile.nf_services = Some(param.nfctx.services.clone());
    profile.plmn_list = Some(param.nfctx.plmns.iter().cloned().collect::<Vec<_>>());
    profile.allowed_plmns = Some(
        param
            .nfctx
            .allowed_plmns
            .iter()
            .cloned()
            .collect::<Vec<_>>(),
    );
    let mut scp_info = models::ScpInfo::new();
    let mut ports_map: HashMap<String, i32, RandomState> = HashMap::new();
    if param.nfctx.use_https {
        ports_map.insert("https".to_owned(), 443);
    } else {
        ports_map.insert("http".to_owned(), 80);
    }
    scp_info.scp_ports = Some(ports_map);
    scp_info.address_domains = Some(vec![]);
    scp_info.ipv4_addresses = Some(vec![]);
    profile.scp_info = Some(scp_info);
    match local_ip().unwrap() {
        IpAddr::V4(ip) => profile.ipv4_addresses = Some(vec![models::Ipv4Addr(ip.to_string())]),
        IpAddr::V6(ip) => profile.ipv6_addresses = Some(vec![models::Ipv6Addr(ip.to_string())]),
    }
    // log::info!("{:?}", param_nf_profile1.s_nssais.clone());
    let slices: Vec<String> = match profile.s_nssais.clone() {
        Some(ref a) => a.iter().map(|x| serde_json::to_string(x).unwrap()).collect(),
        None => ["None".to_string()].to_vec(),
    };
    let allowed_slices: Vec<String> = match profile.allowed_nssais.clone() {
        Some(ref a) => a.iter().map(|x| serde_json::to_string(x).unwrap()).collect(),
        None => ["None".to_string()].to_vec(),
    };
    let plmns: Vec<String> = match profile.plmn_list.clone() {
        Some(ref a) => a.iter().map(|x| serde_json::to_string(x).unwrap()).collect(),
        None => ["None".to_string()].to_vec(),
    };
    let fqdn: String = match profile.fqdn {
        Some(ref a) => a.to_string(),
        None => "None".to_string(),
    };
    let nf_status: String = profile.nf_status.to_string();
    let nf_type: String = profile.nf_type.to_string();
    log::info!("Registering {:?} {:?}", fqdn, nf_status);
    let req_msg = serde_json::json!({
        "request_type" : "register_nf",
        "FQDN": fqdn,
        "profile": profile.to_string(),
        "SNSSAI": slices,
        "nf_status": nf_status,
        "nf_type": nf_type,
        "plmns": plmns,
        "UUID": profile.nf_instance_id,
        "allowed_snssai": allowed_slices,
        "SenderIP": profile.ipv4_addresses.as_ref().unwrap()[0].to_string(),
        "Timestamp": ctime,
        // "hash": format!("{:x}" ,md5::compute(serde_json::to_string(&param_nf_profile1.clone())?))
    });
    let log_queue = crate::scp_prov::LOG_QUEUE.clone();
    let data_string = serde_json::to_string(&req_msg).unwrap();
    let req_hash = md5::compute(data_string);
    let request_hash = req_hash
        .iter()
        .map(|x| format!("{:x?}", x))
        .collect::<Vec<String>>()
        .join("");
    let mut req_log = crate::utils::jmap_hash(req_msg);
    req_log.insert("request_hash".to_owned(), request_hash.clone());
    // log::info!("Here3");
    match client
        .register_nf_instance(param.nfctx.uuid, profile, None, None)
        .await?
    {
        nnrf_openapi::RegisterNFInstanceResponse::OK { body, .. }
        | nnrf_openapi::RegisterNFInstanceResponse::ExpectedResponseToAValidRequest {
            body, ..
        } => {
            let custom_info = body.custom_info.expect("Missing expected info");
            let nrf_public_key = custom_info
                .as_object()
                .unwrap()
                .get("nrf_public_key")
                .unwrap()
                .as_str()
                .unwrap();
            *context::GLOBAL_CONTEXT.NrfPublicKey.write().unwrap() =
                Some(Ed25519PublicKey::from_bytes(&hex::decode(nrf_public_key).unwrap()).unwrap());
            let msg = serde_json::json!({
                "Timestamp": ctime,
                "request_type" : "register_nf",
                "status_code": 200
            });
            let mut resp_log = crate::utils::jmap_hash(msg);
            resp_log.insert("request_hash".to_owned(), request_hash);
            log_queue.push(Log {
                req: req_log,
                dis: dis.clone(),
                discovery: None,
                api_disc: None,
                res: resp_log,
            });
            create_nf_heartbeat_task(
                client.clone(),
                param.nfctx.uuid,
                body.heart_beat_timer.unwrap(),
                dis.clone(),
                param.clone(),
            )
            .await;
            info!("SCP uuid={} registered in NRF", param.nfctx.uuid);
        }
        _ => {
            panic!(
                "[*] SCP uuid={} failed to register in NRF",
                param.nfctx.uuid
            );
            let msg = serde_json::json!({
                "Timestamp": ctime,
                "request_type" : "register_nf",
                "status_code": 400
            });
            let mut resp_log = crate::utils::jmap_hash(msg);
            resp_log.insert("request_hash".to_owned(), request_hash);
            log_queue.push(Log {
                req: req_log,
                dis,
                discovery: None,
                api_disc: None,
                res: resp_log,
            });
        }
    }
    // log::info!("Here4");
    Ok(())
}

async fn deregister_nrf(param: &SCPParameters) {
    // type ClientContext = swagger::make_context_ty!(ContextBuilder, EmptyContext, Option<AuthData>, XSpanIdString);
    // use nnrf_openapi::ContextWrapperExt;

    let mut dis = String::new();
    let base_url = if param.use_next {
        dis = "NEXTSCP".to_owned();
        param.next_scp.clone()
    } else {
        dis = "NRF".to_owned();
        param.nfctx.nrf_uri.clone()
    };
    // let context: ClientContext =
    // 	swagger::make_context!(ContextBuilder, EmptyContext, None as Option<AuthData>, XSpanIdString::default());
    let ctime = chrono::offset::Local::now().timestamp();
    let client = nrf_client();
    let req_msg = serde_json::json!({
        "Timestamp": ctime,
        "request_type" : "update_nf",
        "uuid": param.nfctx.uuid.to_string(),
        "SenderIP": local_ip().unwrap()
       // // "hash": format!("{:x}" ,md5::compute(serde_json::to_string(&param_patch_item.clone())?))
    });
    client
        .deregister_nf_instance(param.nfctx.uuid)
        .await
        .unwrap();
    info!("SCP uuid={} deregistered from NRF", param.nfctx.uuid);
    let msg = serde_json::json!({
        "Timestamp": ctime,
        "request_type" : "de_register_nf",
        "status_code": 200,
    });
    let log_queue = crate::scp_prov::LOG_QUEUE.clone();
    let data_string = serde_json::to_string(&req_msg).unwrap();
    let req_hash = md5::compute(data_string);
    let request_hash = req_hash
        .iter()
        .map(|x| format!("{:x?}", x))
        .collect::<Vec<String>>()
        .join("");
    let mut req_log = crate::utils::jmap_hash(req_msg);
    req_log.insert("request_hash".to_owned(), request_hash.clone());
    let mut resp_log = crate::utils::jmap_hash(msg);
    resp_log.insert("request_hash".to_owned(), request_hash);
    log_queue.push(Log {
        req: req_log,
        dis,
        discovery: None,
        api_disc: None,
        res: resp_log,
    });
}

#[tokio::main]
async fn main() {
    env_logger::init();

    let matches = App::new("SCP")
        .version("1.0")
        .author("Team VET5G")
        .about("SCP service")
        .arg(
            Arg::new("https")
                .long("https")
                .help("Whether to use HTTPS or not"),
        )
        .arg(
            Arg::new("port")
                .long("port")
                .default_value("80")
                .required(true)
                .help("port to listen on"),
        )
        .arg(
            Arg::new("ip")
                .long("ip")
                .default_value("0.0.0.0")
                .required(true)
                .help("IP to listen on"),
        )
        .arg(
            Arg::new("config")
                .long("config")
                .default_value("scp-config.yaml")
                .required(true)
                .help("SCP config file"),
        )
        .get_matches();

    let listen_ip = matches.value_of("ip").unwrap();
    let listen_port = matches.value_of("port").unwrap();

    let cfg_file = std::fs::File::open(matches.value_of("config").unwrap()).unwrap();
    let config: SCPConfig = serde_yaml::from_reader(cfg_file).unwrap();

    let mut comm_service_profile = NfService1::new(
        uuid::Uuid::new_v4().to_string(),
        "nscp-fwd".into(),
        vec![NfServiceVersion::new("/v1".into(), "/nscp-fwd/v1".into())],
        models::UriScheme::HTTP,
        models::NfServiceStatus::REGISTERED,
    );

    // let mut loc_service_profile = NfService1::new(
    // 	uuid::Uuid::new_v4().to_string(),
    // 	"nSCP-loc".into(),
    // 	vec![NfServiceVersion::new("/v1".into(), "/nSCP-loc/v1".into())],
    // 	models::UriScheme::HTTP,
    // 	models::NfServiceStatus::REGISTERED
    // );

    // setup SCP parameters
    let SCP_param = SCPParameters {
        nfctx: NetworkFunctionContext {
            nssai: config.nf.nssai,
            allowed_nssai: config.nf.allowed_nssai,
            plmns: config.nf.plmns,
            allowed_plmns: config.nf.allowed_plmns,
            use_https: matches.is_present("https"),
            host: config.nf.host,
            name: config.nf.name,

            nrf_uri: config.nf.nrf_uri.clone(),
            uuid: uuid::Uuid::new_v4(),
            services: vec![comm_service_profile],
            nf_startup_time: chrono::Utc::now(),
        },
        nssf_uri: config.nf.nssf_uri.clone(),
        mode: config.scp.mode,
        next_scp: config.scp.next_scp.clone(),
        use_next: config.scp.next_hop,
        dumper_interval: config.scp.dumper_interval,
        log_folder: config.scp.log_folder,
    };
    let host = SCP_param.nfctx.uuid.clone();
    println!("Using HTTPS {:?}", SCP_param.nfctx.use_https);
    // let mut offset: i64 = 0;
    let mut key: Vec<u8> = vec![];

    // let (logtx, logrx) = mpsc::channel();
    // let (logtx2, logrx2) = mpsc::channel();
    let (tx, rx) = mpsc::channel();
    tokio::spawn(async {
    	log::info!("SHOULD START SCP");
        scp_prov::graph::creator(rx).await;
    });
    // let (tx1, rx1) = mpsc::channel();
    // tokio::spawn(async {
    //     scp_prov::dump::dumper(rx1, logtx, logrx2).await;
    // });
    // let rt = runtime::
    // let scp_id = crate::scp_prov::gen_id();
    // *context::SCP_ID.write().unwrap() = scp_id.clone();
    // let mut scp_node = crate::scp_prov::Node::create(
    //     "SCP-Primary".to_string(),
    //     "FQDN".to_string(),
    //     "http://".to_owned() + &SCP_param.nfctx.host,
    //     chrono::offset::Local::now().timestamp(),
    // );
    let ctime = chrono::offset::Local::now().timestamp();
    // scp_node.dev_id.insert(
    //     "UUID".to_owned(),
    //     vec![ValTup::new(SCP_param.nfctx.uuid.to_string(), ctime)],
    // );
    let nrf_id = crate::scp_prov::gen_id();
    let mut nrf_node = crate::scp_prov::Node::create(
        "NRF".to_string(),
        "FQDN".to_string(),
        config.nf.nrf_uri.clone(),
        chrono::offset::Local::now().timestamp(),
    );
    let nssf_id = crate::scp_prov::gen_id();
    let mut nssf_node = crate::scp_prov::Node::create(
        "NSSF".to_string(),
        "FQDN".to_string(),
        config.nf.nssf_uri.clone(),
        chrono::offset::Local::now().timestamp(),
    );
    // let next_scp_id = crate::scp_prov::gen_id();
    // let mut next_scp_node = crate::scp_prov::Node::create(
    //     "SCP".to_string(),
    //     "FQDN".to_string(),
    //     config.scp.next_scp.clone(),
    //     chrono::offset::Local::now().timestamp(),
    // );
    {
        let mut temp_nlist = crate::scp_prov::NODEMAP.write().unwrap();
        // temp_nlist.insert(scp_id.clone(), scp_node);
        // if config.scp.next_hop {
        //     temp_nlist.insert(next_scp_id.clone(), next_scp_node);
        // } else {
            temp_nlist.insert(nrf_id.clone(), nrf_node);
            temp_nlist.insert(nssf_id.clone(), nssf_node);
        // }
        drop(temp_nlist);
    }
    {
        let mut temp_ret = crate::scp_prov::RETRIEVE.write().unwrap();
        // temp_ret.insert(SCP_param.nfctx.host.clone(), scp_id);
        if config.scp.next_hop {
            // temp_ret.insert(config.scp.next_scp, next_scp_id.clone());
        } else {
            temp_ret.insert(config.nf.nrf_uri, nrf_id);
            temp_ret.insert(config.nf.nssf_uri, nssf_id);
        }
        drop(temp_ret);
    }
    register_nrf(&SCP_param).await.unwrap();

    context::SCP_PARAMETERS.set(SCP_param);
    // scp_detect::fill_log_ts();
    let addr = &format!("{}:{}", listen_ip, listen_port);

    // *crate::context::ASYNC_RUNTIME.lock().unwrap() = Some(Handle::current());
    // let (sender, receiver) = crossbeam_channel::unbounded();

    // let future = thread::spawn(move || {
    //     scp_detect::private_id_looper();
    // });
    info!("SCP listening on {}...", addr);
    // tokio::spawn(async{
    // 	thread::sleep(std::time::Duration::new(120, 0));
    // 	log::info!("Now Dumping the graphs");
    // 	let mut f = File::create("graph.dot").expect("Unable to create file");
    // 	f.write_all(scp_prov::dot::dot_gen().as_bytes()).expect("Unable to write data");
    // });

    let handle = tokio::spawn(async {
        // Your asynchronous code here
        std::thread::sleep(std::time::Duration::from_secs(10500));
        let rt = context::RUNTIMES.lock().unwrap();
        let rows = rt.len();
        let cols = rt[0].len();
        
        let mut averages = vec![0; cols];
        
        for col in 0..cols {
            let sum: u128 = rt.iter().map(|row| row[col].as_nanos()).sum();
            averages[col] = sum / rows as u128;
        }
        let regicount = context::COUNTER.load(Ordering::SeqCst);
        log::info!("{:?},{:?},{:?}",rows, averages, regicount);
    });


    server::create(addr, matches.is_present("https")).await;
    
    handle.await.unwrap();

    deregister_nrf(context::SCP_PARAMETERS.get().unwrap()).await;

    let _ = tx.send(true);
    // graph.join().unwrap();
    // let _ = tx1.send(true);

    // let sender = context::DETECT_SENDER.0.clone();
    // sender.send("END".to_owned());
    // future.join();

    info!("SCP finishes running");
    std::process::exit(0);

    // for handle in protocol_thread_handles {
    //      handle.join().unwrap();
    // };
}
