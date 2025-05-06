use std::sync::Arc;

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
use nnssf_openapi::ContextWrapperExt;

use crate::{
    context::{ApiTypeValue, HTTP_CLIENT},
    utils::ScpError,
};

pub fn nssf_discovery_client(
) -> Arc<Box<dyn nnssf_openapi::ApiNoContext<ClientContext> + Send + Sync>> {
    let nfself = crate::context::SCP_PARAMETERS.get().unwrap();

    let base_url = nfself.nssf_uri.clone();
    let client: Option<
        Arc<Box<dyn nnssf_openapi::ApiNoContext<ClientContext> + std::marker::Send + Sync>>,
    > = {
        let map = crate::context::HTTP_CLIENT.read().unwrap();
        let val = map.get(&base_url);
        match val {
            Some(d) => match d {
                crate::context::ApiTypeValue::NSSF(data) => Some(data.clone()),
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
            Box<dyn nnssf_openapi::ApiNoContext<ClientContext> + std::marker::Send + Sync>,
        > = {
            // Using HTTP
            if nfself.nfctx.use_https {
                Arc::new(Box::new(
                    nnssf_openapi::Client::try_new_https(&("https://".to_owned()+&base_url))
                        .expect("Failed to create HTTPS client")
                        .with_context(context),
                ))
            } else {
                Arc::new(Box::new(
                    nnssf_openapi::Client::try_new_http(&("http://".to_owned()+&base_url))
                        .expect("Failed to create HTTP client")
                        .with_context(context),
                ))
            }
        };
        let mut map = &mut HTTP_CLIENT.write().unwrap();
        map.insert(base_url.clone(), ApiTypeValue::NSSF(client.clone()));
        return client.clone();
    }
    client.unwrap()
}
