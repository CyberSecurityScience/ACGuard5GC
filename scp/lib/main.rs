#![allow(dead_code)]
#![allow(unused)]
#![allow(non_snake_case)]
#![allow(non_upper_case_globals)]
#![allow(non_camel_case_types)]
#![allow(non_snake_case)]

use jwt_simple::prelude::Ed25519PublicKey;
use libmodels::network_function::NetworkFunctionContext;
use models::{NfProfile1, NfService1, NfServiceVersion};
use serde::{Serialize, Deserialize};
use tokio::runtime::Handle;
use local_ip_address::local_ip;

use std::{net::{IpAddr, Ipv4Addr}, sync::mpsc, collections::HashSet};
use std::thread;
use std::time::Duration;
use std::sync::mpsc::Sender;
use std::sync::mpsc::Receiver;
use std::string::String;

use clap::{App, Arg};
use log::{debug, error, log_enabled, info, Level, warn};

#[macro_use]
extern crate lazy_static;

#[macro_use]
extern crate concat_idents;

#[macro_use]
extern crate bitfield;

pub mod context;
use context::{AMFParameters, TimerValues};

extern crate libngap;
extern crate libnas;

/// NGAP layer, including SCTP layer
pub mod ngap;

/// NAS layer, including 5gMM and 5GSM layer
pub mod nas;

/// SBA handler layer
pub mod sba;

/// SBA server
pub mod server;

/// SBA client
pub mod libsba;

/// Common utils
pub mod utils;

// Provenance
pub mod logs;

#[derive(Debug, Serialize, Deserialize)]
struct AMFConfig_nf {
	pub host: String,
	pub nrf_uri: String,
	pub nssf_uri: String,
	pub name: String,
	pub allowed_nssai: Vec<models::ExtSnssai>,
	pub nssai: Vec<models::ExtSnssai>,
	pub plmns: HashSet<models::PlmnId>,
	pub allowed_plmns: HashSet<models::PlmnId>
}

#[derive(Debug, Serialize, Deserialize)]
struct AMFConfig_amf_ngap {
	pub timeout_seconds: u64
}

#[derive(Debug, Serialize, Deserialize)]
struct AMFConfig_amf {
	pub name: String,
	pub relative_capacity: i64,
	pub ngap: AMFConfig_amf_ngap,
	pub network_name: String,
	pub timezone: String,
	pub served_guami: Vec<libmodels::served_guami::ServedGuami>,
	pub tais: Vec<libmodels::tai::Tai>,
	pub plmns: Vec<libmodels::plmn_snssai::PlmnSnssai>,
	pub timer_values: TimerValues
}

#[derive(Debug, Serialize, Deserialize)]
struct AMFConfig {
	pub nf: AMFConfig_nf,
	pub amf: AMFConfig_amf,
	pub log_url: String
}

#[allow(unused_imports)]
use swagger::{AuthData, ContextBuilder, EmptyContext, Has, Push, XSpanIdString};

async fn create_nf_heartbeat_task(base_url: String, nfid: uuid::Uuid, timer: isize) {
	type ClientContext = swagger::make_context_ty!(ContextBuilder, EmptyContext, Option<AuthData>, XSpanIdString);
	use nnrf_openapi::ContextWrapperExt;
	let context: ClientContext =
		swagger::make_context!(ContextBuilder, EmptyContext, None as Option<AuthData>, XSpanIdString::default());

	let client : Box<dyn nnrf_openapi::ApiNoContext<ClientContext>>  = {
		// Using HTTP
		let client = Box::new(nnrf_openapi::Client::try_new_http(
			&base_url)
			.expect("Failed to create HTTP client"));
			Box::new(client.with_context(context))
	};

	let task = Handle::current().spawn(async move {
        let mut interval = tokio::time::interval(Duration::from_secs(timer as _));

        loop {
            interval.tick().await;
			
			client.update_nf_instance(
				nfid,
				&vec![
					models::PatchItem {
						op: models::PatchOperation::REPLACE,
						path: "/nfStatus".into(),
						value: Some("REGISTERED".into()),
						from: None
					}
				],
				None,
				None,
				None
			).await;
        }
    });
}

async fn register_nrf(param: &AMFParameters) -> Result<(), Box<dyn std::error::Error>> {
	type ClientContext = swagger::make_context_ty!(ContextBuilder, EmptyContext, Option<AuthData>, XSpanIdString);
	use nnrf_openapi::ContextWrapperExt;

	let base_url = param.nfctx.nrf_uri.clone();
	let context: ClientContext =
		swagger::make_context!(ContextBuilder, EmptyContext, None as Option<AuthData>, XSpanIdString::default());

	let mut client : Box<dyn nnrf_openapi::ApiNoContext<ClientContext>> = {
		// Using HTTP
		let client = Box::new(nnrf_openapi::Client::try_new_http(
			&base_url)
			.expect("Failed to create HTTP client"));
		Box::new(client.with_context(context))
	};

	let mut profile = NfProfile1::new(param.nfctx.uuid, models::NfType::AMF, models::NfStatus::registered());
	profile.fqdn = Some(param.nfctx.host.clone());
	profile.s_nssais = Some(param.nfctx.nssai.clone());
	profile.allowed_nssais = Some(param.nfctx.allowed_nssai.clone());
	profile.nf_instance_name = Some(param.nfctx.name.clone());
	profile.nf_services = Some(param.nfctx.services.clone());
	profile.plmn_list = Some(param.nfctx.plmns.iter().cloned().collect::<Vec<_>>());
	profile.allowed_plmns = Some(param.nfctx.allowed_plmns.iter().cloned().collect::<Vec<_>>());
	match local_ip().unwrap() {
		IpAddr::V4(ip) => profile.ipv4_addresses = Some(vec![models::Ipv4Addr(ip.to_string())]),
		IpAddr::V6(ip) => profile.ipv6_addresses = Some(vec![models::Ipv6Addr(ip.to_string())]),
	}

	match client.register_nf_instance(param.nfctx.uuid, profile, None, None).await? {
		nnrf_openapi::RegisterNFInstanceResponse::OK { body, .. } | nnrf_openapi::RegisterNFInstanceResponse::ExpectedResponseToAValidRequest { body, .. } =>  {
			let custom_info = body.custom_info.expect("Missing expected info");
			let nrf_public_key = custom_info.as_object().unwrap().get("nrf_public_key").unwrap().as_str().unwrap().clone();
			*context::GLOBAL_CONTEXT.NrfPublicKey.write().unwrap() = Some(Ed25519PublicKey::from_bytes(&hex::decode(nrf_public_key).unwrap()).unwrap());
			create_nf_heartbeat_task(base_url.clone(), param.nfctx.uuid, body.heart_beat_timer.unwrap()).await;
			info!("AMF uuid={} registered in NRF", param.nfctx.uuid);
		},
		_ => {
			panic!("[*] AMF uuid={} failed to register in NRF", param.nfctx.uuid);
		}
	}

	Ok(())
}

async fn deregister_nrf(param: &AMFParameters) {
	type ClientContext = swagger::make_context_ty!(ContextBuilder, EmptyContext, Option<AuthData>, XSpanIdString);
	use nnrf_openapi::ContextWrapperExt;

	let base_url = param.nfctx.nrf_uri.clone();
	let context: ClientContext =
		swagger::make_context!(ContextBuilder, EmptyContext, None as Option<AuthData>, XSpanIdString::default());

	let mut client : Box<dyn nnrf_openapi::ApiNoContext<ClientContext>> = {
		// Using HTTP
		let client = Box::new(nnrf_openapi::Client::try_new_http(
			&base_url)
			.expect("Failed to create HTTP client"));
		Box::new(client.with_context(context))
	};

	client.deregister_nf_instance(param.nfctx.uuid).await.unwrap();
	info!("AMF uuid={} deregistered from NRF", param.nfctx.uuid);
}


async fn register_nssf(param: &AMFParameters) -> Result<(), Box<dyn std::error::Error>> {
	type ClientContext = swagger::make_context_ty!(ContextBuilder, EmptyContext, Option<AuthData>, XSpanIdString);
	use nnssf_openapi::ContextWrapperExt;

	let base_url = param.NssfUri.clone();
	let context: ClientContext =
		swagger::make_context!(ContextBuilder, EmptyContext, None as Option<AuthData>, XSpanIdString::default());

	let mut client : Box<dyn nnssf_openapi::ApiNoContext<ClientContext> + Send + Sync> = {
		// Using HTTP
		let client = Box::new(nnssf_openapi::Client::try_new_http(
			&base_url)
			.expect("Failed to create HTTP client"));
		Box::new(client.with_context(context))
	};

	let nssai_availability_info = models::NssaiAvailabilityInfo {
		supported_nssai_availability_data: param.SupportedTAIList.iter().map(|tai| {
			models::SupportedNssaiAvailabilityData {
				tai: tai.to_sbi(),
				supported_snssai_list: param.nfctx.allowed_nssai.clone(),
				tai_list: None,
				tai_range_list: None
			}
		}).collect::<Vec<_>>(),
		supported_features: None,
		amf_set_id: None
	};

	match client.nssai_availability_put(param.nfctx.uuid, nssai_availability_info, None, None).await? {
		nnssf_openapi::NSSAIAvailabilityPutResponse::OK { body, accept_encoding, content_encoding } => {

		},
		nnssf_openapi::NSSAIAvailabilityPutResponse::NoContent => {

		},
		ex => {
			panic!("Failed to populate NSSF, {:?}", ex);
		}
	}

	Ok(())
}

async fn deregister_nssf(param: &AMFParameters) {
	let mut client = libsba::nssf::nssf_discovery_client();

	client.nssai_availability_delete(param.nfctx.uuid.to_string()).await;
}

/// Entry point for running AMF
#[tokio::main]
async fn main() {
    env_logger::init();

	let matches = App::new("AMF")
		.version("1.0")
		.author("Team VET5G")
		.about("AMF service")
		.arg(Arg::new("https")
			.long("https")
			.about("Whether to use HTTPS or not"))
		.arg(Arg::new("port")
			.long("port")
			.default_value("80")
			.required(true)
			.about("port to listen on"))
		.arg(Arg::new("ip")
			.long("ip")
			.default_value("0.0.0.0")
			.required(true)
			.about("IP to listen on"))
		.arg(Arg::new("config")
			.long("config")
			.default_value("amf-config.yaml")
			.required(true)
			.about("AMF config file"))
        .get_matches();

	let listen_ip = matches.value_of("ip").unwrap();
	let listen_port = matches.value_of("port").unwrap();

	let cfg_file = std::fs::File::open(matches.value_of("config").unwrap()).unwrap();
	let config: AMFConfig = serde_yaml::from_reader(cfg_file).unwrap();

	let mut comm_service_profile = NfService1::new(
		uuid::Uuid::new_v4().to_string(),
		"namf-comm".into(),
		vec![NfServiceVersion::new("/v1".into(), "/namf-comm/v1".into())],
		models::UriScheme::HTTP,
		models::NfServiceStatus::REGISTERED
	);

	let mut loc_service_profile = NfService1::new(
		uuid::Uuid::new_v4().to_string(),
		"namf-loc".into(),
		vec![NfServiceVersion::new("/v1".into(), "/namf-loc/v1".into())],
		models::UriScheme::HTTP,
		models::NfServiceStatus::REGISTERED
	);

	// setup AMF parameters
	let amf_param = AMFParameters {
		nfctx: NetworkFunctionContext {
			nssai: config.nf.nssai,
			allowed_nssai: config.nf.allowed_nssai,
			plmns: config.nf.plmns,
			allowed_plmns: config.nf.allowed_plmns,
			use_https: matches.is_present("https"),
			host: config.nf.host,
			name: config.nf.name,
			nrf_uri: config.nf.nrf_uri,
			uuid: uuid::Uuid::new_v4(),
			services: vec![comm_service_profile, loc_service_profile],
			nf_startup_time: chrono::Utc::now()
		},
		NssfUri: config.nf.nssf_uri,
		Name: config.amf.name.clone(),
		RelativeCapacity: config.amf.relative_capacity,
		ServingNetworkName: config.amf.network_name,
		ServedGuamiList: config.amf.served_guami,
		SupportedTAIList: config.amf.tais,
		SupportedPLMNList: config.amf.plmns,
		Timezone: config.amf.timezone,
		NgapTimeoutSeconds: config.amf.ngap.timeout_seconds,
		TimerValues: config.amf.timer_values
	};
	register_nrf(&amf_param).await.unwrap();
	register_nssf(&amf_param).await.unwrap();
	let host = amf_param.nfctx.uuid.clone();
	context::AMF_PARAMETERS.set(amf_param);

	let log_addr = config.log_url.to_string();
	logs::connect_socket(format!("tcp://{}", log_addr), host.to_string());

    let addr = &format!("{}:{}",
		listen_ip,
		listen_port
	);

	*crate::context::ASYNC_RUNTIME.lock().unwrap() = Some(Handle::current());

	let handle = crate::ngap::sctp::create_sctp_thread().expect("Failed to create SCTP thread");

	info!("AMF listening on {}...", addr);
    server::create(addr, matches.is_present("https")).await;

	deregister_nssf(context::AMF_PARAMETERS.get().unwrap()).await;
	deregister_nrf(context::AMF_PARAMETERS.get().unwrap()).await;

    info!("AMF finishes running");
	std::process::exit(0);

	// // Join: Wait for all threads to finish
	// for handle in protocol_thread_handles {
	// 	handle.join().unwrap();
	// };
}
