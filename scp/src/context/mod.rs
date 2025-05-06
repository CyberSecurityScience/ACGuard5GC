use jwt_simple::prelude::Ed25519PublicKey;
use models::{NfProfile, NfProfile1, NfType};
use once_cell::sync::{Lazy, OnceCell};
use std::{sync::{atomic::AtomicU32, Arc, Mutex, RwLock}, time::Duration};

// use crossbeam_channel::{Receiver, Sender};
use protocol::private_id::company::CompanyPrivateId;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use swagger::{AuthData, ContextBuilder, EmptyContext, XSpanIdString};
use tokio::runtime::Handle;
type ClientContext = swagger::make_context_ty!(
    ContextBuilder,
    EmptyContext,
    Option<AuthData>,
    XSpanIdString
);
// use swagger::{ContextBuilder, EmptyContext, AuthData, XSpanIdString};

#[derive(Clone)]
pub struct SCPParameters {
    pub nfctx: libmodels::network_function::NetworkFunctionContext,
    pub nssf_uri: String,
    pub mode: String,
    pub next_scp: String,
    pub use_next: bool,
    pub dumper_interval: usize,
    pub log_folder: String,
}
impl SCPParameters {
    // to http(s)://<self-uri>
    pub fn to_base_path(&self) -> String {
        format!(
            "{}://{}",
            if self.nfctx.use_https {
                "https"
            } else {
                "http"
            },
            self.nfctx.host
        )
    }
}

pub static SCP_PARAMETERS: OnceCell<SCPParameters> = OnceCell::new();

pub struct SCPContext {
    pub NrfPublicKey: std::sync::RwLock<Option<Ed25519PublicKey>>,
    pub ClientContext: std::sync::RwLock<HashMap<String, (NfProfile1, String)>>,
    // pub ClientConnect: std::sync::RwLock<HashMap<String, String>>,
    // pub ClientConnect: Arc<std::sync::RwLock<HashMap<String, (hyper::Client<hyper_tls::HttpsConnector<hyper::client::HttpConnector>>, String)>>>,
}

impl SCPContext {
    pub fn new() -> Self {
        Self {
            NrfPublicKey: std::sync::RwLock::new(None),
            // ClientConnect: RwLock::new(HashMap::new()),
            ClientContext: RwLock::new(HashMap::new()),
        }
    }
}
#[derive(Debug)]
pub struct Log {
    pub req: HashMap<String, String>,
    pub dis: String,
    pub discovery: Option<NfProfile>,
    pub api_disc: Option<NfProfile>,
    pub res: HashMap<String, String>,
}

pub enum ApiTypeValue {
    AUSF(Arc<Box<dyn nausf_openapi::ApiNoContext<ClientContext> + Send + Sync>>),
    AMF(Arc<Box<dyn namf_openapi::ApiNoContext<ClientContext> + Send + Sync>>),
    NRF(Arc<Box<dyn nnrf_openapi::ApiNoContext<ClientContext> + Send + Sync>>),
    NSSF(Arc<Box<dyn nnssf_openapi::ApiNoContext<ClientContext> + Send + Sync>>),
    SMSF(Arc<Box<dyn nsmsf_openapi::ApiNoContext<ClientContext> + Send + Sync>>),
    SMF(Arc<Box<dyn nsmf_openapi::ApiNoContext<ClientContext> + Send + Sync>>),
    UDM(Arc<Box<dyn nudm_openapi::ApiNoContext<ClientContext> + Send + Sync>>),
    SCP(Arc<Box<dyn nscp_api::ApiNoContext<ClientContext> + Send + Sync>>),
    // UPF(Arc<Box<dyn nupf_openapi::ApiNoContext<ClientContext> + Send + Sync>>),
}

lazy_static! {
    pub static ref GLOBAL_CONTEXT: SCPContext = SCPContext::new();
    pub static ref CLIENT_CONTEXT: Arc<RwLock<HashMap<String, Arc<hyper::Client<hyper_tls::HttpsConnector<hyper::client::HttpConnector>>>>>> =
        Arc::new(RwLock::new(HashMap::new()));
    pub static ref DISC_CACHE: std::sync::RwLock<HashMap<String, Vec<(i64, models::SearchResult)>>> =
        std::sync::RwLock::new(HashMap::new());
    // pub static ref CONTEXTMAP: std::sync::RwLock<
    //     HashMap<
    //         String,
    //         ContextBuilder<
    //             std::option::Option<AuthData>,
    //             ContextBuilder<XSpanIdString, EmptyContext>,
    //         >,
    //     >,
    // > = std::sync::RwLock::new(HashMap::new());
    pub static ref NOTIFYMAP: std::sync::RwLock<HashMap<NfType, (uuid::Uuid, String)>> =
        std::sync::RwLock::new(HashMap::new());
    // pub static ref SCP_ID: std::sync::RwLock<String> = std::sync::RwLock::new(String::new());
    pub static ref HTTP_CLIENT: RwLock<HashMap<String, ApiTypeValue>> = RwLock::new(HashMap::new());
    // pub static ref LOG_TS: RwLock<Vec<i64>> = RwLock::new(Vec::new());
    // pub static ref DETECT_SENDER: (Sender<String>, Receiver<String>) =
    //     crossbeam_channel::unbounded();
    // pub static ref PRIVATE_ID: RwLock<HashMap<String, CompanyPrivateId>> =
    //     RwLocke::nw(HashMap::new());
    // pub static ref KEY_SET: RwLock<HashMap<String, Vec<String>>> = RwLock::new(HashMap::new());
    // pub static ref RESULT_SET: RwLock<HashMap<String, (Vec<String>, Vec<String>)>> =
    //     RwLock::new(HashMap::new());
    pub static ref RUNTIMES: Mutex<Vec<Vec<Duration>>> = Mutex::new(Vec::new());
    pub static ref COUNTER: AtomicU32 = AtomicU32::new(0);
}
