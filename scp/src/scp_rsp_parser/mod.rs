use futures::{future, future::BoxFuture, future::FutureExt, stream, stream::TryStreamExt, Stream};
use hyper::header::{HeaderName, HeaderValue, CONTENT_TYPE};
use hyper::{Body, HeaderMap, Request, Response, StatusCode};
use log::warn;
use mime_0_2::{Mime as Mime2, SubLevel, TopLevel};
use mime_multipart::{read_multipart_body, Node, Part};
use std::collections::HashMap;
#[allow(unused_imports)]
use std::convert::{TryFrom, TryInto};
use std::error::Error;
use std::future::Future;
use std::marker::PhantomData;
use std::task::{Context, Poll};
pub use swagger::auth::Authorization;
use swagger::auth::Scopes;
use swagger::{ApiError, BodyExt, Has, RequestParser, XSpanIdString};
use url::form_urlencoded;
pub mod smf;
pub use crate::context;
use crate::utils::jmap_hash;

mod paths {
    use lazy_static::lazy_static;

    lazy_static! {
        pub static ref GLOBAL_REGEX_SET: regex::RegexSet = regex::RegexSet::new(vec![
            r"^/namf-comm/v1/ue-contexts/(?P<ueContextId>[^/?#]*)/n1-n2-messages$",
            r"^/namf-loc/v1/(?P<ueContextId>[^/?#]*)/provide-loc-info$",
            r"^/namf-mt/v1/ue-contexts/(?P<ueContextId>[^/?#]*)/ue-reachind$",
            r"^/nausf-auth/v1/ue-authentications$",
            r"^/nausf-auth/v1/ue-authentications/(?P<authCtxId>[^/?#]*)/5g-aka-confirmation$",
            r"^/oauth2/token$",
            r"^/nnrf-nfm/v1/nf-instances$",
            r"^/nnrf-nfm/v1/nf-instances/(?P<nfInstanceID>[^/?#]*)$",
            r"^/nnrf-nfm/v1/subscriptions$",
            r"^/nnrf-nfm/v1/subscriptions/(?P<subscriptionID>[^/?#]*)$",
            r"^/nnrf-disc/v1/nf-instances$",
            r"^/nnssf-nsselection/v2/network-slice-information$",
            r"^/nnssf-nssaiavailability/v1/nssai-availability/(?P<nfId>[^/?#]*)$",
            r"^/nudm-uecm/v1/(?P<ueId>[^/?#]*)/registrations/amf-3gpp-access$",
            r"^/nudm-sdm/v2/(?P<supi>[^/?#]*)/am-data$",
            r"^/nudm-ueau/v1/(?P<supi>[^/?#]*)/auth-events$",
            r"^/nudm-ueau/v1/(?P<supiOrSuci>[^/?#]*)/security-information/generate-auth-data$",
            r"^/nudm-sdm/v2/(?P<supi>[^/?#]*)/smf-select-data$",
            r"^/nudm-uecm/v1/(?P<ueId>[^/?#]*)/registrations/smsf-3gpp-access$",
            r"^/nudm-sdm/v2/(?P<supi>[^/?#]*)/sms-mng-data$",
            r"^/nudm-sdm/v2/(?P<supi>[^/?#]*)/sm-data$",
            r"^/nudm-sdm/v2/(?P<supi>[^/?#]*)/nssai$",
            r"^/nsmf-pdusession/v1/sm-contexts$",
            r"^/nsmf-pdusession/v1/sm-contexts/(?P<smContextRef>[^/?#]*)/modify$",
            r"^/nsmf-pdusession/v1/sm-contexts/(?P<smContextRef>[^/?#]*)/release$",
            r"^/nsmsf-sms/v2/ue-contexts/(?P<supi>[^/?#]*)$",
            r"^/nsmsf-sms/v2/ue-contexts/(?P<supi>[^/?#]*)/sendsms$"
        ])
        .expect("Unable to create global regex set");
    }
    pub(crate) static ID_NAMF_COMM_V1_UE_CONTEXTS_UECONTEXTID_N1_N2_MESSAGES: usize = 0;
    lazy_static! {
        pub static ref REGEX_NAMF_COMM_V1_UE_CONTEXTS_UECONTEXTID_N1_N2_MESSAGES: regex::Regex =
            regex::Regex::new(
                r"^/namf-comm/v1/ue-contexts/(?P<ueContextId>[^/?#]*)/n1-n2-messages$"
            )
            .expect(
                "Unable to create regex for NAMF_COMM_V1_UE_CONTEXTS_UECONTEXTID_N1_N2_MESSAGES"
            );
    }
    pub(crate) static ID_NAMF_LOC_V1_UECONTEXTID_PROVIDE_LOC_INFO: usize = 1;
    lazy_static! {
        pub static ref REGEX_NAMF_LOC_V1_UECONTEXTID_PROVIDE_LOC_INFO: regex::Regex =
            regex::Regex::new(r"^/namf-loc/v1/(?P<ueContextId>[^/?#]*)/provide-loc-info$")
                .expect("Unable to create regex for NAMF_LOC_V1_UECONTEXTID_PROVIDE_LOC_INFO");
    }
    pub(crate) static ID_NAMF_MT_V1_UE_CONTEXTS_UECONTEXTID_UE_REACHIND: usize = 2;
    lazy_static! {
        pub static ref REGEX_NAMF_MT_V1_UE_CONTEXTS_UECONTEXTID_UE_REACHIND: regex::Regex =
            regex::Regex::new(r"^/namf-mt/v1/ue-contexts/(?P<ueContextId>[^/?#]*)/ue-reachind$")
                .expect(
                    "Unable to create regex for NAMF_MT_V1_UE_CONTEXTS_UECONTEXTID_UE_REACHIND"
                );
    }
    pub(crate) static ID_NAUSF_AUTH_V1_UE_AUTHENTICATIONS: usize = 3;
    pub(crate) static ID_NAUSF_AUTH_V1_UE_AUTHENTICATIONS_AUTHCTXID_5G_AKA_CONFIRMATION: usize = 4;
    lazy_static! {
        pub static ref REGEX_NAUSF_AUTH_V1_UE_AUTHENTICATIONS_AUTHCTXID_5G_AKA_CONFIRMATION: regex::Regex =
            regex::Regex::new(r"^/nausf-auth/v1/ue-authentications/(?P<authCtxId>[^/?#]*)/5g-aka-confirmation$")
                .expect("Unable to create regex for NAUSF_AUTH_V1_UE_AUTHENTICATIONS_AUTHCTXID_5G_AKA_CONFIRMATION");
    }
    pub(crate) static ID_OAUTH2_TOKEN: usize = 5;
    pub(crate) static ID_NNRF_NFM_V1_NF_INSTANCES: usize = 6;
    pub(crate) static ID_NNRF_NFM_V1_NF_INSTANCES_NFINSTANCEID: usize = 7;
    lazy_static! {
        pub static ref REGEX_NNRF_NFM_V1_NF_INSTANCES_NFINSTANCEID: regex::Regex =
            regex::Regex::new(r"^/nnrf-nfm/v1/nf-instances/(?P<nfInstanceID>[^/?#]*)$")
                .expect("Unable to create regex for NNRF_NFM_V1_NF_INSTANCES_NFINSTANCEID");
    }
    pub(crate) static ID_NNRF_NFM_V1_SUBSCRIPTIONS: usize = 8;
    pub(crate) static ID_NNRF_NFM_V1_SUBSCRIPTIONS_SUBSCRIPTIONID: usize = 9;
    lazy_static! {
        pub static ref REGEX_NNRF_NFM_V1_SUBSCRIPTIONS_SUBSCRIPTIONID: regex::Regex =
            regex::Regex::new(r"^/nnrf-nfm/v1/subscriptions/(?P<subscriptionID>[^/?#]*)$")
                .expect("Unable to create regex for NNRF_NFM_V1_SUBSCRIPTIONS_SUBSCRIPTIONID");
    }
    pub(crate) static ID_NNRF_DISC_V1_NF_INSTANCES: usize = 10;
    pub(crate) static ID_NNSSF_NSSELECTION_V2_NETWORK_SLICE_INFORMATION: usize = 11;
    pub(crate) static ID_NNSSF_NSSAIAVAILABILITY_V1_NSSAI_AVAILABILITY_NFID: usize = 12;
    lazy_static! {
        pub static ref REGEX_NNSSF_NSSAIAVAILABILITY_V1_NSSAI_AVAILABILITY_NFID: regex::Regex =
            regex::Regex::new(
                r"^/nnssf-nssaiavailability/v1/nssai-availability/(?P<nfId>[^/?#]*)$"
            )
            .expect(
                "Unable to create regex for NNSSF_NSSAIAVAILABILITY_V1_NSSAI_AVAILABILITY_NFID"
            );
    }
    pub(crate) static ID_NUDM_UECM_V1_UEID_REGISTRATIONS_AMF_3GPP_ACCESS: usize = 13;
    lazy_static! {
        pub static ref REGEX_NUDM_UECM_V1_UEID_REGISTRATIONS_AMF_3GPP_ACCESS: regex::Regex =
            regex::Regex::new(r"^/nudm-uecm/v1/(?P<ueId>[^/?#]*)/registrations/amf-3gpp-access$")
                .expect(
                    "Unable to create regex for NUDM_UECM_V1_UEID_REGISTRATIONS_AMF_3GPP_ACCESS"
                );
    }
    pub(crate) static ID_NUDM_SDM_V2_SUPI_AM_DATA: usize = 14;
    lazy_static! {
        pub static ref REGEX_NUDM_SDM_V2_SUPI_AM_DATA: regex::Regex =
            regex::Regex::new(r"^/nudm-sdm/v2/(?P<supi>[^/?#]*)/am-data$")
                .expect("Unable to create regex for NUDM_SDM_V2_SUPI_AM_DATA");
    }
    pub(crate) static ID_NUDM_UEAU_V1_SUPI_AUTH_EVENTS: usize = 15;
    lazy_static! {
        pub static ref REGEX_NUDM_UEAU_V1_SUPI_AUTH_EVENTS: regex::Regex =
            regex::Regex::new(r"^/nudm-ueau/v1/(?P<supi>[^/?#]*)/auth-events$")
                .expect("Unable to create regex for NUDM_UEAU_V1_SUPI_AUTH_EVENTS");
    }
    pub(crate) static ID_NUDM_UEAU_V1_SUPIORSUCI_SECURITY_INFORMATION_GENERATE_AUTH_DATA: usize =
        16;
    lazy_static! {
        pub static ref REGEX_NUDM_UEAU_V1_SUPIORSUCI_SECURITY_INFORMATION_GENERATE_AUTH_DATA: regex::Regex =
            regex::Regex::new(r"^/nudm-ueau/v1/(?P<supiOrSuci>[^/?#]*)/security-information/generate-auth-data$")
                .expect("Unable to create regex for NUDM_UEAU_V1_SUPIORSUCI_SECURITY_INFORMATION_GENERATE_AUTH_DATA");
    }
    pub(crate) static ID_NUDM_SDM_V2_SUPI_SMF_SELECT_DATA: usize = 17;
    lazy_static! {
        pub static ref REGEX_NUDM_SDM_V2_SUPI_SMF_SELECT_DATA: regex::Regex =
            regex::Regex::new(r"^/nudm-sdm/v2/(?P<supi>[^/?#]*)/smf-select-data$")
                .expect("Unable to create regex for NUDM_SDM_V2_SUPI_SMF_SELECT_DATA");
    }
    pub(crate) static ID_NUDM_UECM_V1_UEID_REGISTRATIONS_SMSF_3GPP_ACCESS: usize = 18;
    lazy_static! {
        pub static ref REGEX_NUDM_UECM_V1_UEID_REGISTRATIONS_SMSF_3GPP_ACCESS: regex::Regex =
            regex::Regex::new(r"^/nudm-uecm/v1/(?P<ueId>[^/?#]*)/registrations/smsf-3gpp-access$")
                .expect(
                    "Unable to create regex for NUDM_UECM_V1_UEID_REGISTRATIONS_SMSF_3GPP_ACCESS"
                );
    }
    pub(crate) static ID_NUDM_SDM_V2_SUPI_SMS_MNG_DATA: usize = 19;
    lazy_static! {
        pub static ref REGEX_NUDM_SDM_V2_SUPI_SMS_MNG_DATA: regex::Regex =
            regex::Regex::new(r"^/nudm-sdm/v2/(?P<supi>[^/?#]*)/sms-mng-data$")
                .expect("Unable to create regex for NUDM_SDM_V2_SUPI_SMS_MNG_DATA");
    }
    pub(crate) static ID_NUDM_SDM_V2_SUPI_SM_DATA: usize = 20;
    lazy_static! {
        pub static ref REGEX_NUDM_SDM_V2_SUPI_SM_DATA: regex::Regex =
            regex::Regex::new(r"^/nudm-sdm/v2/(?P<supi>[^/?#]*)/sm-data$")
                .expect("Unable to create regex for NUDM_SDM_V2_SUPI_SM_DATA");
    }
    pub(crate) static ID_NUDM_SDM_V2_SUPI_NSSAI: usize = 21;
    lazy_static! {
        pub static ref REGEX_NUDM_SDM_V2_SUPI_NSSAI: regex::Regex =
            regex::Regex::new(r"^/nudm-sdm/v2/(?P<supi>[^/?#]*)/nssai$")
                .expect("Unable to create regex for NUDM_SDM_V2_SUPI_NSSAI");
    }
    pub(crate) static ID_SM_CONTEXTS: usize = 22;
    pub(crate) static ID_SM_CONTEXTS_SMCONTEXTREF_MODIFY: usize = 23;
    lazy_static! {
        pub static ref REGEX_SM_CONTEXTS_SMCONTEXTREF_MODIFY: regex::Regex = regex::Regex::new(
            r"^/nsmf-pdusession/v1/sm-contexts/(?P<smContextRef>[^/?#]*)/modify$"
        )
        .expect("Unable to create regex for SM_CONTEXTS_SMCONTEXTREF_MODIFY");
    }
    pub(crate) static ID_SM_CONTEXTS_SMCONTEXTREF_RELEASE: usize = 24;
    lazy_static! {
        pub static ref REGEX_SM_CONTEXTS_SMCONTEXTREF_RELEASE: regex::Regex = regex::Regex::new(
            r"^/nsmf-pdusession/v1/sm-contexts/(?P<smContextRef>[^/?#]*)/release$"
        )
        .expect("Unable to create regex for SM_CONTEXTS_SMCONTEXTREF_RELEASE");
    }
    pub(crate) static ID_UE_CONTEXTS_SUPI: usize = 25;
    lazy_static! {
        pub static ref REGEX_UE_CONTEXTS_SUPI: regex::Regex =
            regex::Regex::new(r"^/nsmsf-sms/v2/ue-contexts/(?P<supi>[^/?#]*)$")
                .expect("Unable to create regex for UE_CONTEXTS_SUPI");
    }
    pub(crate) static ID_UE_CONTEXTS_SUPI_SENDSMS: usize = 26;
    lazy_static! {
        pub static ref REGEX_UE_CONTEXTS_SUPI_SENDSMS: regex::Regex =
            regex::Regex::new(r"^/nsmsf-sms/v2/ue-contexts/(?P<supi>[^/?#]*)/sendsms$")
                .expect("Unable to create regex for UE_CONTEXTS_SUPI_SENDSMS");
    }
}

pub async fn scp_rsp_parser(
    method: hyper::Method,
    uri: hyper::Uri,
    status: u16,
    body: Vec<u8>,
    headers: HeaderMap,
) -> Option<HashMap<String, String>> {
    // let (request, context) = req;
    // let (parts, body) = request.into_parts();
    // let (method, uri, headers) = (parts.method, parts.uri, parts.headers);
    let path = paths::GLOBAL_REGEX_SET.matches(uri.path());
    match &method {
        // ProvideLocationInfo - POST /namf-loc/v1/{ueContextId}/provide-loc-info
        &hyper::Method::POST
            if path.matched(paths::ID_NAMF_LOC_V1_UECONTEXTID_PROVIDE_LOC_INFO) =>
        {
            let result =
                namf_openapi::scp_decoder::scp_dec_provide_location_info(status, body, headers)
                    .await;
            let (hash, x): (String, String) = match result {
                Ok(ref rsp) => match rsp {
                    namf_openapi::ProvideLocationInfoResponse::ExpectedResponseToAValidRequest(
                        body,
                    ) => {
                        let b = serde_json::to_string(&body).unwrap();
                        (format!("{:x}", md5::compute(b.clone())), b)
                    }
                    _ => ("0".to_string(), "None".to_string()),
                },
                _ => ("0".to_string(), "None".to_string()),
            };
            let msg = serde_json::json!({
                "request_type": "provide_location_info",
                "response": x,
                "status_code": status
            });
            return Some(jmap_hash(msg));
        }

        // N1N2MessageTransfer - POST /namf-comm/v1/ue-contexts/{ueContextId}/n1-n2-messages
        &hyper::Method::POST
            if path.matched(paths::ID_NAMF_COMM_V1_UE_CONTEXTS_UECONTEXTID_N1_N2_MESSAGES) =>
        {
            let msg = serde_json::json!({
                "request_type" : "n1_n2_message_transfer",
                // "supi": param_ue_context_id,
                "status_code": status
            });
            return Some(jmap_hash(msg));
        }

        // EnableUeReachability - PUT /namf-mt/v1/ue-contexts/{ueContextId}/ue-reachind
        &hyper::Method::PUT
            if path.matched(paths::ID_NAMF_MT_V1_UE_CONTEXTS_UECONTEXTID_UE_REACHIND) =>
        {
            let result =
                namf_openapi::scp_decoder::scp_dec_enable_ue_reachability(status, body, headers)
                    .await;
            let (hash, x): (String, String) = match result {
                Ok(ref rsp) => match rsp {
                    namf_openapi::EnableUeReachabilityResponse::UEHasBecomeReachableAsDesired(
                        body,
                    ) => {
                        let b = serde_json::to_string(&body).unwrap();
                        (format!("{:x}", md5::compute(b.clone())), b)
                    }
                    _ => ("0".to_string(), "None".to_string()),
                },
                _ => ("0".to_string(), "None".to_string()),
            };
            let msg = serde_json::json!({
                "request_type": "enable_ue_reachability",
                "response": x,
                "status_code": status
            });
            return Some(jmap_hash(msg));
        }

        // NausfAuthV1UeAuthenticationsAuthCtxId5gAkaConfirmationPut - PUT /nausf-auth/v1/ue-authentications/{authCtxId}/5g-aka-confirmation
        &hyper::Method::PUT
            if path.matched(
                paths::ID_NAUSF_AUTH_V1_UE_AUTHENTICATIONS_AUTHCTXID_5G_AKA_CONFIRMATION,
            ) =>
        {
            // Path parameters
            let result = nausf_openapi::scp_decoder::scp_dec_nausf_auth_v1_ue_authentications_auth_ctx_id5g_aka_confirmation_put(status, body, headers).await;
            let x: String = match result {
                    Ok(ref rsp) => match rsp {
                        nausf_openapi::NausfAuthV1UeAuthenticationsAuthCtxId5gAkaConfirmationPutResponse::RequestProcessed
                        (body)
                        => {
                            let b = serde_json::to_string(&body.clone()).unwrap();
                            b
                            // let d = format!("{:x}" , md5::compute(&b));
                            // d
                        }
                        _ => {
                            "0".to_string()
                        }
                    },
                    _ => {
                        "0".to_string()
                    }
                };
            let msg = serde_json::json!({
                "request_type" : "ctx_id5g_aka",
                // "token": jwt_token.as_ref().unwrap().clone(),
                // "auth_ctx_id": param_auth_ctx_id.clone().to_string(),
                "status_code": status,
                "response": x
            });
            return Some(jmap_hash(msg));
        }

        // NausfAuthV1UeAuthenticationsPost - POST /nausf-auth/v1/ue-authentications
        &hyper::Method::POST if path.matched(paths::ID_NAUSF_AUTH_V1_UE_AUTHENTICATIONS) => {
            let result = nausf_openapi::scp_decoder::scp_dec_nausf_auth_v1_ue_authentications_post(
                status, body, headers,
            )
            .await;

            let x: String = match result {
                    Ok(ref rsp) => match rsp {
                        nausf_openapi::NausfAuthV1UeAuthenticationsPostResponse::UEAuthenticationCtx
                            {
                                body,
                                location
                            }
                        => {
                            let b = serde_json::to_string(&body.clone()).unwrap();
                            // let d = format!("{:x}" , md5::compute(b));
                            b
                        }
                        _ => {
                            "0".to_string()
                        }
                    },
                    _ => {
                        "0".to_string()
                    }
                };
            let msg = serde_json::json!({
                "request_type" : "ue_authentications_post",
                // "ue_id": param_authentication_info.supi_or_suci.clone(),
                // "token": jwt_token.as_ref().unwrap().clone(),
                "status_code": status,
                "response": x
            });
            return Some(jmap_hash(msg));
        }

        // RemoveSubscription - DELETE /nnrf-nfm/v1/subscriptions/{subscriptionID}
        &hyper::Method::DELETE
            if path.matched(paths::ID_NNRF_NFM_V1_SUBSCRIPTIONS_SUBSCRIPTIONID) =>
        {
            let result =
                nnrf_openapi::scp_decoder::scp_dec_remove_subscription(status, body, headers).await;
            let x: &str = match result {
                    Ok(ref rsp) => match rsp {
                        nnrf_openapi::RemoveSubscriptionResponse::ExpectedResponseToASuccessfulSubscriptionRemoval
                        => {
                            "OK"
                        }
                        _ => {
                            "NO"
                        }
                    },
                    _ => {
                        "NO"
                    }
                };

            let msg = serde_json::json!({
                "request_type" : "remove_subscription",
                "status_code": status,
                // "hash": "0"
            });
            return Some(jmap_hash(msg));
        }

        // CreateSubscription - POST /nnrf-nfm/v1/subscriptions
        &hyper::Method::POST if path.matched(paths::ID_NNRF_NFM_V1_SUBSCRIPTIONS) => {
            let result =
                nnrf_openapi::scp_decoder::scp_dec_create_subscription(status, body, headers).await;
            let (hash, inst): (String, String) = match result {
                Ok(ref rsp) => match rsp {
                    nnrf_openapi::CreateSubscriptionResponse::ExpectedResponseToAValidRequest {
                        body,
                        location,
                        accept_encoding,
                        content_encoding,
                    } => {
                        let b2 = serde_json::to_string(&body).unwrap();
                        // let b3 = Body::from(b2).to_raw().unwrap();
                        // ( format!("{:x}" , md5::compute(b2)),
                        //
                        // );
                        (b2, body.subscription_id.as_ref().unwrap().to_string())
                    }
                    _ => ("0".to_string(), "None".to_string()),
                },
                _ => ("0".to_string(), "None".to_string()),
            };

            let msg = serde_json::json!({
                "request_type" : "create_subscription",
                "sub_id": inst,
                "status_code": status,
                "response": hash
            });
            return Some(jmap_hash(msg));
        }

        // SearchNFInstances - GET /nnrf-disc/v1/nf-instances
        &hyper::Method::GET if path.matched(paths::ID_NNRF_DISC_V1_NF_INSTANCES) => {
            // Header parameters
            let result =
                nnrf_openapi::scp_decoder::scp_dec_search_nf_instances(status, body, headers).await;
            let (hash, inst): (String, Vec<String>) = match result {
                Ok(ref rsp) => match rsp {
                    nnrf_openapi::SearchNFInstancesResponse::ExpectedResponseToAValidRequest {
                        body,
                        cache_control,
                        e_tag,
                        content_encoding,
                    } => {
                        let b2 = serde_json::to_string(&body).unwrap();
                        (
                            b2,
                            body.nf_instances.iter().map(|x| x.to_string()).collect(),
                        )
                    }
                    _ => ("0".to_string(), vec!["None".to_string()]),
                },
                _ => ("0".to_string(), vec!["None".to_string()]),
            };
            let msg = serde_json::json!({
                "request_type" : "discovery",
                "instances": inst,
                "response": hash,
                "status_code": status,
            });
            return Some(jmap_hash(msg));
        }

        // DeregisterNFInstance - DELETE /nnrf-nfm/v1/nf-instances/{nfInstanceID}
        &hyper::Method::DELETE if path.matched(paths::ID_NNRF_NFM_V1_NF_INSTANCES_NFINSTANCEID) => {
            let result: Result<nnrf_openapi::DeregisterNFInstanceResponse, ApiError> =
                nnrf_openapi::scp_decoder::scp_dec_deregister_nf_instance(status, body, headers)
                    .await;
            let x: &str = match result {
                    Ok(ref rsp) => match rsp {
                        nnrf_openapi::DeregisterNFInstanceResponse::ExpectedResponseToASuccessfulDeregistration
                        => {
                            "OK"
                        }
                        _ => {
                            "NO"
                        }
                    },
                    _ => {
                        "NO"
                    }
                };

            let msg = serde_json::json!({
                "request_type" : "de_register_nf",
                // "uuid": param_nf_instance_id.to_string(),
                // "hash": "0",
                "dereg": x,
                "status_code": status,
            });
            return Some(jmap_hash(msg));
        }

        // UpdateNFInstance - PATCH /nnrf-nfm/v1/nf-instances/{nfInstanceID}
        &hyper::Method::PATCH if path.matched(paths::ID_NNRF_NFM_V1_NF_INSTANCES_NFINSTANCEID) => {
            let result =
                nnrf_openapi::scp_decoder::scp_dec_update_nf_instance(status, body, headers).await;
            let x: String = match result {
                Ok(ref rsp) => match rsp {
                    nnrf_openapi::UpdateNFInstanceResponse::ExpectedResponseToAValidRequest {
                        body,
                        accept_encoding,
                        e_tag,
                        content_encoding,
                    } => {
                        let b = serde_json::to_string(&body).unwrap();
                        // format!("{:x}" , md5::compute(b))
                        b
                    }
                    _ => "0".to_string(),
                },
                _ => "0".to_string(),
            };

            let msg = serde_json::json!({
                "request_type" : "update_nf",
                // "uuid": param_nf_instance_id.to_string(),
                "response": x,
                "status_code": status,
            });
            return Some(jmap_hash(msg));
        }

        // RegisterNFInstance - PUT /nnrf-nfm/v1/nf-instances/{nfInstanceID}
        &hyper::Method::PUT if path.matched(paths::ID_NNRF_NFM_V1_NF_INSTANCES_NFINSTANCEID) => {
            // Path parameters
            let result =
                nnrf_openapi::scp_decoder::scp_dec_register_nf_instance(status, body, headers)
                    .await;
            let x: String = match result {
                Ok(ref rsp) => match rsp {
                    nnrf_openapi::RegisterNFInstanceResponse::OK {
                        body,
                        accept_encoding,
                        content_encoding,
                        e_tag,
                    } => {
                        let b = serde_json::to_string(&body).unwrap();
                        // format!("{:x}" , md5::compute(b))
                        b
                    }
                    _ => "0".to_string(),
                },
                _ => "0".to_string(),
            };
            let msg = serde_json::json!({
                "request_type" : "register_nf",
                "status_code": status,
                "response": x
            });
            return Some(jmap_hash(msg));
        }

        // AccessTokenRequest - POST /oauth2/token
        &hyper::Method::POST if path.matched(paths::ID_OAUTH2_TOKEN) => {
            let result =
                nnrf_openapi::scp_decoder::scp_dec_access_token_request(status, body, headers)
                    .await;
            let (x, a, b, c, d): (String, String, String, String, String) = match result {
                Ok(ref rsp) => match rsp {
                    nnrf_openapi::AccessTokenRequestResponse::SuccessfulAccessTokenRequest {
                        body,
                        cache_control,
                        pragma,
                        accept_encoding,
                        content_encoding,
                    } => {
                        let b = serde_json::to_string(&body).unwrap();
                        (
                            b,
                            body.access_token.to_string(),
                            body.token_type.to_string(),
                            body.expires_in.unwrap().to_string(),
                            body.scope.clone().expect("REASON").to_string(),
                        )
                    }
                    _ => (
                        "0".to_string(),
                        "None".to_string(),
                        "None".to_string(),
                        "None".to_string(),
                        "None".to_string(),
                    ),
                },
                _ => (
                    "0".to_string(),
                    "None".to_string(),
                    "None".to_string(),
                    "None".to_string(),
                    "None".to_string(),
                ),
            };
            let msg = serde_json::json! ({
                "request_type": "access_token_req",
                "token": a,
                "token_type": b,
                "expires_in": c,
                "scope": d,
                "response": x,
                "status_code": status,
            });
            return Some(jmap_hash(msg));
        }

        // NSSAIAvailabilityPut - PUT /nnssf-nssaiavailability/v1/nssai-availability/{nfId}
        &hyper::Method::PUT
            if path.matched(paths::ID_NNSSF_NSSAIAVAILABILITY_V1_NSSAI_AVAILABILITY_NFID) =>
        {
            let result =
                nnssf_openapi::scp_decoder::scp_dec_nssai_availability_put(status, body, headers)
                    .await;
            let x: String = match result {
                Ok(ref rsp) => match rsp {
                    nnssf_openapi::NSSAIAvailabilityPutResponse::OK {
                        body,
                        accept_encoding,
                        content_encoding,
                    } => {
                        let b = serde_json::to_string(&body).unwrap();
                        // format!("{:x}" , md5::compute(b))
                        b
                    }
                    _ => "0".to_string(),
                },
                _ => "0".to_string(),
            };

            let msg = serde_json::json!({
                "request_type" : "nssai_avail_put",
                "status_code": status,
                "hash": x
            });
            return Some(jmap_hash(msg));
        }

        // NSSAIAvailabilityDelete - DELETE /nnssf-nssaiavailability/v1/nssai-availability/{nfId}
        &hyper::Method::DELETE
            if path.matched(paths::ID_NNSSF_NSSAIAVAILABILITY_V1_NSSAI_AVAILABILITY_NFID) =>
        {
            let result = nnssf_openapi::scp_decoder::scp_dec_nssai_availability_delete(
                status, body, headers,
            )
            .await;
            let x: &str = match result {
                Ok(ref rsp) => match rsp {
                    nnssf_openapi::NSSAIAvailabilityDeleteResponse::NoContent => "OK",
                    _ => "NO",
                },
                _ => "NO",
            };
            let msg = serde_json::json!({
                "request_type": "nssai_avail_delete",
                "result": x,
                "status_code": status,
                // "hash": "0",
                // "nf_id": param_nf_id,
            });
            return Some(jmap_hash(msg));
        }

        // NSSelectionGet - GET /nnssf-nsselection/v2/network-slice-information
        &hyper::Method::GET
            if path.matched(paths::ID_NNSSF_NSSELECTION_V2_NETWORK_SLICE_INFORMATION) =>
        {
            let result =
                nnssf_openapi::scp_decoder::scp_dec_ns_selection_get(status, body, headers).await;
            let x: String = match result {
                Ok(ref rsp) => match rsp {
                    nnssf_openapi::NSSelectionGetResponse::OK(body) => {
                        let b = serde_json::to_string(&body).unwrap();
                        b
                        // format!("{:x}" , md5::compute(b))
                    }
                    _ => "0".to_string(),
                },
                _ => "0".to_string(),
            };

            let msg = serde_json::json!({
                "request_type" : "nssf_sel_get",
                // "nf_id": param_nf_id.to_string(),
                // "nf_type": param_nf_type.to_string(),
                "response": x,
                "status_code": status,
            });
            return Some(jmap_hash(msg));
        }

        // Call3GppRegistration - PUT /nudm-uecm/v1/{ueId}/registrations/amf-3gpp-access
        &hyper::Method::PUT
            if path.matched(paths::ID_NUDM_UECM_V1_UEID_REGISTRATIONS_AMF_3GPP_ACCESS) =>
        {
            let result =
                nudm_openapi::scp_decoder::scp_dec_call3_gpp_registration(status, body, headers)
                    .await;
            let x: String = match result {
                Ok(ref rsp) => match rsp {
                    nudm_openapi::Call3GppRegistrationResponse::OK(body) => {
                        let b = serde_json::to_string(&body).unwrap();
                        // format!("{:x}" , md5::compute(b))
                        b
                    }
                    _ => "0".to_string(),
                },
                _ => "0".to_string(),
            };
            let msg = serde_json::json!({
                "request_type": "call3_gpp_registration",
                "status_code": status,
                // "ue_id": param_ue_id,
                // "guami": param_amf3_gpp_access_registration.guami.to_string(),
                "response": x
            });
            return Some(jmap_hash(msg));
        }

        // Update3GppRegistration - PATCH /nudm-uecm/v1/{ueId}/registrations/amf-3gpp-access
        &hyper::Method::PATCH
            if path.matched(paths::ID_NUDM_UECM_V1_UEID_REGISTRATIONS_AMF_3GPP_ACCESS) =>
        {
            let result =
                nudm_openapi::scp_decoder::scp_dec_update3_gpp_registration(status, body, headers)
                    .await;
            let x: String = match result {
                    Ok(ref rsp) => match rsp {
                        nudm_openapi::Update3GppRegistrationResponse::ExpectedResponseToAValidRequest
                            (body)
                        => {
                            let b = serde_json::to_string(&body).unwrap();
                            // format!("{:x}" , md5::compute(b))
                            b
                        }
                        _ => {
                            "0".to_string()
                        }
                    },
                    _ => {
                        "0".to_string()
                    }
                };
            let msg = serde_json::json!({
                "request_type": "update3_gpp_registration",
                // "ue_id": param_ue_id,
                // "guami": param_amf3_gpp_access_registration_modification.guami.to_string(),
                "status_code": status,
                "response": x
            });
            return Some(jmap_hash(msg));
        }

        // GetAmData - GET /nudm-sdm/v2/{supi}/am-data
        &hyper::Method::GET if path.matched(paths::ID_NUDM_SDM_V2_SUPI_AM_DATA) => {
            let result =
                nudm_openapi::scp_decoder::scp_dec_get_am_data(status, body, headers).await;
            let x: String = match result {
                Ok(ref rsp) => match rsp {
                    nudm_openapi::GetAmDataResponse::ExpectedResponseToAValidRequest {
                        body,
                        cache_control,
                        e_tag,
                        last_modified,
                    } => {
                        let b = serde_json::to_string(&body).unwrap();
                        b
                        // format!("{:x}" , md5::compute(b))
                    }
                    _ => "0".to_string(),
                },
                _ => "0".to_string(),
            };
            // let plmn = match param_plmn_id {
            //     Some(ref a) => {a.to_string()},
            //     None => {"None".to_string()}
            // };
            let msg = serde_json::json!({
                "request_type": "get_am_data",
                // "ue_id": param_supi,
                // "plmn": plmn,
                "status_code": status,
                "response": x
            });
            return Some(jmap_hash(msg));
        }

        // ConfirmAuth - POST /nudm-ueau/v1/{supi}/auth-events
        &hyper::Method::POST if path.matched(paths::ID_NUDM_UEAU_V1_SUPI_AUTH_EVENTS) => {
            let result =
                nudm_openapi::scp_decoder::scp_dec_confirm_auth(status, body, headers).await;
            let x: String = match result {
                Ok(ref rsp) => match rsp {
                    nudm_openapi::ConfirmAuthResponse::ExpectedResponseToAValidRequest {
                        body,
                        location,
                    } => {
                        let b = serde_json::to_string(&body).unwrap();
                        b
                        // format!("{:x}" , md5::compute(b))
                    }
                    _ => "0".to_string(),
                },
                _ => "0".to_string(),
            };
            let msg = serde_json::json!({
                "request_type": "confirm_auth",
                // "ue_id": param_supi,
                "response": x,
                "status_code": status,
            });
            return Some(jmap_hash(msg));
        }

        // GenerateAuthData - POST /nudm-ueau/v1/{supiOrSuci}/security-information/generate-auth-data
        &hyper::Method::POST
            if path.matched(
                paths::ID_NUDM_UEAU_V1_SUPIORSUCI_SECURITY_INFORMATION_GENERATE_AUTH_DATA,
            ) =>
        {
            let result =
                nudm_openapi::scp_decoder::scp_dec_generate_auth_data(status, body, headers).await;
            let (x, supi): (String, String) = match result {
                Ok(ref rsp) => match rsp {
                    nudm_openapi::GenerateAuthDataResponse::ExpectedResponseToAValidRequest(
                        body,
                    ) => {
                        let supi = body.supi.clone().unwrap_or("None".to_owned());
                        let b = serde_json::to_string(&body).unwrap();
                        (b, supi.to_string())
                        // format!("{:x}" , md5::compute(b))
                    }
                    _ => ("0".to_string(), "None".to_string()),
                },
                _ => ("0".to_string(), "None".to_string()),
            };
            let msg = serde_json::json!({
                "request_type": "generate_auth_data",
                "supi": supi,
                "response": x,
                "status_code": status,
            });
            return Some(jmap_hash(msg));
        }

        // GetSmfSelData - GET /nudm-sdm/v2/{supi}/smf-select-data
        &hyper::Method::GET if path.matched(paths::ID_NUDM_SDM_V2_SUPI_SMF_SELECT_DATA) => {
            let result =
                nudm_openapi::scp_decoder::scp_dec_get_smf_sel_data(status, body, headers).await;
            let x: String = match result {
                Ok(ref rsp) => match rsp {
                    nudm_openapi::GetSmfSelDataResponse::ExpectedResponseToAValidRequest {
                        body,
                        cache_control,
                        e_tag,
                        last_modified,
                    } => {
                        let b = serde_json::to_string(&body).unwrap();
                        b
                        // format!("{:x}" , md5::compute(b))
                    }
                    _ => "0".to_string(),
                },
                _ => "0".to_string(),
            };
            // let plmn = match param_plmn_id {
            //     Some(ref a) => {a.to_string()},
            //     None => {"None".to_string()}
            // };
            let msg = serde_json::json!({
                "request_type": "get_smf_sel_data",
                // "ue_id": param_supi,
                // "plmn": plmn,
                "response": x,
                "status_code": status,
            });
            return Some(jmap_hash(msg));
        }

        // Get3GppSmsfRegistration - GET /nudm-uecm/v1/{ueId}/registrations/smsf-3gpp-access
        &hyper::Method::GET
            if path.matched(paths::ID_NUDM_UECM_V1_UEID_REGISTRATIONS_SMSF_3GPP_ACCESS) =>
        {
            let result = nudm_openapi::scp_decoder::scp_dec_get3_gpp_smsf_registration(
                status, body, headers,
            )
            .await;
            let x: String = match result {
                    Ok(ref rsp) => match rsp {
                        nudm_openapi::Get3GppSmsfRegistrationResponse::ExpectedResponseToAValidRequest
                        (body)
                        => {
                            let b = serde_json::to_string(&body).unwrap();
                            b
                        }
                        _ => {
                            "0".to_string()
                        }
                    },
                    _ => {
                        "0".to_string()
                    }
                };
            let msg = serde_json::json!({
                "request_type": "get_smsf_reg_data",
                "response": x,
                "status_code": status,
            });
            return Some(jmap_hash(msg));
        }

        // Call3GppSmsfDeregistration - DELETE /nudm-uecm/v1/{ueId}/registrations/smsf-3gpp-access
        &hyper::Method::DELETE
            if path.matched(paths::ID_NUDM_UECM_V1_UEID_REGISTRATIONS_SMSF_3GPP_ACCESS) =>
        {
            let result = nudm_openapi::scp_decoder::scp_dec_call3_gpp_smsf_deregistration(
                status, body, headers,
            )
            .await;
            let x: String = match result {
                    Ok(ref rsp) => match rsp {
                        nudm_openapi::Call3GppSmsfDeregistrationResponse::ExpectedResponseToAValidRequest
                        => {
                            "1".to_string()
                        }
                        _ => {
                            "0".to_string()
                        }
                    },
                    _ => {
                        "0".to_string()
                    }
                };
            let msg = serde_json::json!({
                "request_type": "get_smsf_dereg_data",
                // "response": x,
                "status_code": status,
            });
            return Some(jmap_hash(msg));
        }

        // Call3GppSmsfRegistration - PUT /nudm-uecm/v1/{ueId}/registrations/smsf-3gpp-access
        &hyper::Method::PUT
            if path.matched(paths::ID_NUDM_UECM_V1_UEID_REGISTRATIONS_SMSF_3GPP_ACCESS) =>
        {
            let result = nudm_openapi::scp_decoder::scp_dec_call3_gpp_smsf_registration(
                status, body, headers,
            )
            .await;
            let x: String = match result {
                    Ok(ref rsp) => match rsp {
                        nudm_openapi::Call3GppSmsfRegistrationResponse::ExpectedResponseToAValidRequest
                        (body)
                        => {
                            let b = serde_json::to_string(&body).unwrap();
                            b
                            // format!("{:x}" , md5::compute(b))
                        }
                        _ => {
                            "0".to_string()
                        }
                    },
                    _ => {
                        "0".to_string()
                    }
                };
            let msg = serde_json::json!({
                "request_type": "call3_gpp_smsf_registration",
                // "ue_id": param_ue_id,
                "response": x,
                "status_code": status,
            });
            return Some(jmap_hash(msg));
        }

        // GetSmsMngtData - GET /nudm-sdm/v2/{supi}/sms-mng-data
        &hyper::Method::GET if path.matched(paths::ID_NUDM_SDM_V2_SUPI_SMS_MNG_DATA) => {
            let result =
                nudm_openapi::scp_decoder::scp_dec_get_sms_mngt_data(status, body, headers).await;
            let x: String = match result {
                Ok(ref rsp) => match rsp {
                    nudm_openapi::GetSmsMngtDataResponse::ExpectedResponseToAValidRequest {
                        body,
                        cache_control,
                        e_tag,
                        last_modified,
                    } => {
                        let b = serde_json::to_string(&body).unwrap();
                        b
                        // format!("{:x}" , md5::compute(b))
                    }
                    _ => "0".to_string(),
                },
                _ => "0".to_string(),
            };
            // let plmn = match param_plmn_id {
            //     Some(ref a) => {a.to_string()},
            //     None => {"None".to_string()}
            // };
            let msg = serde_json::json!({
                "request_type": "get_sms_mngt_data",
                // "ue_id": param_supi,
                // "plmn": plmn,
                "status_code": status,
                "response": x
            });
            return Some(jmap_hash(msg));
        }

        // GetSmData - GET /nudm-sdm/v2/{supi}/sm-data
        &hyper::Method::GET if path.matched(paths::ID_NUDM_SDM_V2_SUPI_SM_DATA) => {
            let result =
                nudm_openapi::scp_decoder::scp_dec_get_sm_data(status, body, headers).await;
            let x: String = match result {
                Ok(ref rsp) => match rsp {
                    nudm_openapi::GetSmDataResponse::ExpectedResponseToAValidRequest {
                        body,
                        cache_control,
                        e_tag,
                        last_modified,
                    } => {
                        let b = serde_json::to_string(&body).unwrap();
                        b
                        // format!("{:x}" , md5::compute(b))
                    }
                    _ => "0".to_string(),
                },
                _ => "0".to_string(),
            };
            let msg = serde_json::json!({
                "request_type": "get_sm_data",
                "status_code": status,
                "response": x
            });
            return Some(jmap_hash(msg));
        }

        // GetNSSAI - GET /nudm-sdm/v2/{supi}/nssai
        &hyper::Method::GET if path.matched(paths::ID_NUDM_SDM_V2_SUPI_NSSAI) => {
            let result = nudm_openapi::scp_decoder::scp_dec_get_nssai(status, body, headers).await;
            let x: String = match result {
                Ok(ref rsp) => match rsp {
                    nudm_openapi::GetNssaiResponse::ExpectedResponseToAValidRequest {
                        body,
                        cache_control,
                        e_tag,
                        last_modified,
                    } => {
                        let b = serde_json::to_string(&body).unwrap();
                        b
                        // format!("{:x}" , md5::compute(b))
                    }
                    _ => "0".to_string(),
                },
                _ => "0".to_string(),
            };
            let msg = serde_json::json!({
                "request_type": "get_nssai",
                "status_code": status,
                "response": x
            });
            return Some(jmap_hash(msg));
        }

        // ReleaseSmContext - POST /sm-contexts/{smContextRef}/release
        &hyper::Method::POST if path.matched(paths::ID_SM_CONTEXTS_SMCONTEXTREF_RELEASE) => {
            let result = smf::scp_dec_release_sm_context(status, body, headers).await;
            let x: String = match result {
                    Ok(ref rsp) => match rsp {
                        nsmf_openapi::ReleaseSmContextResponse::SuccessfulReleaseOfAPDUSessionWithContentInTheResponse
                            (body)
                        => {
                            let b = serde_json::to_string(&body).unwrap();
                            b
                            // format!("{:x}" , md5::compute(b))
                        }
                        _ => {
                            "0".to_string()
                        }
                    },
                    _ => {
                        "0".to_string()
                    }
                };
            let msg = serde_json::json! ({
                "request_type": "release_sm_context",
                "status_code": status,
                // "context_id": param_sm_context_ref,
                "response": x
            });
            return Some(jmap_hash(msg));
        }

        // UpdateSmContext - POST /sm-contexts/{smContextRef}/modify
        &hyper::Method::POST if path.matched(paths::ID_SM_CONTEXTS_SMCONTEXTREF_MODIFY) => {
            let result = smf::scp_dec_update_sm_context(status, body, headers).await;
            let x: String = match result {
                    Ok(ref rsp) => match rsp {
                        nsmf_openapi::UpdateSmContextResponse::SuccessfulUpdateOfAnSMContextWithContentInTheResponse
                        (body)
                        => {
                            let b = serde_json::to_string(&body).unwrap();
                            format!("{:x}" , md5::compute(b))
                        }
                        _ => {
                            "0".to_string()
                        }
                    },
                    _ => {
                        "0".to_string()
                    }
                };
            let msg = serde_json::json! ({
                "request_type": "update_sm_context",
                "status_code": status,
                // "context_id": param_sm_context_ref,
                "reponse": x
            });
            return Some(jmap_hash(msg));
        }

        // PostSmContexts - POST /sm-contexts
        &hyper::Method::POST if path.matched(paths::ID_SM_CONTEXTS) => {
            let result = smf::scp_dec_post_sm_contexts(status, body, headers).await;
            let (x, location): (String, String) = match result {
                Ok(ref rsp) => match rsp {
                    nsmf_openapi::PostSmContextsResponse::SuccessfulCreationOfAnSMContext {
                        body,
                        location,
                    } => {
                        let b = serde_json::to_string(&body).unwrap();
                        (format!("{:x}", md5::compute(b)), location.to_string())
                    }
                    _ => ("0".to_string(), "None".to_string()),
                },
                _ => ("0".to_string(), "None".to_string()),
            };
            let msg = serde_json::json! ({
                "request_type": "post_sm_context",
                // "supi": param_sm_context_create_data.supi.clone(),
                // "pdu_id": param_sm_context_create_data.pdu_session_id.clone(),
                "context_id": location,
                "status_code": status,
                "response": x
            });
            return Some(jmap_hash(msg));
        }

        // SMServiceActivation - PUT /ue-contexts/{supi}
        &hyper::Method::PUT if path.matched(paths::ID_UE_CONTEXTS_SUPI) => {
            let result =
                nsmsf_openapi::scp_decoder::scp_dec_sm_service_activation(status, body, headers)
                    .await;
            let x: String = match result {
                    Ok(ref rsp) => match rsp {
                        nsmsf_openapi::SMServiceActivationResponse::UEContextForSMSIsCreatedInSMSF
                            {
                                body,
                                location,
                                e_tag
                            }
                        => {
                            let b = serde_json::to_string(&body).unwrap();
                            // format!("{:x}" , md5::compute(b))
                            b
                        }
                        _ => {
                            "0".to_string()
                        }
                    },
                    _ => {
                        "0".to_string()
                    }
                };
            let msg = serde_json::json!({
                "request_type": "sms_service_activation",
                "response": x,
                "status_code": status,
                // "ue_id": param_supi.clone(),
            });
            return Some(jmap_hash(msg));
        }

        // SMServiceDeactivation - DELETE /ue-contexts/{supi}
        &hyper::Method::DELETE if path.matched(paths::ID_UE_CONTEXTS_SUPI) => {
            let msg = serde_json::json!({
                "request_type": "sms_service_deactivation",
                "status_code": status,
            });
            return Some(jmap_hash(msg));
        }

        // SendSMS - POST /ue-contexts/{supi}/sendsms
        &hyper::Method::POST if path.matched(paths::ID_UE_CONTEXTS_SUPI_SENDSMS) => {
            let result = nsmsf_openapi::scp_decoder::scp_dec_send_sms(status, body, headers).await;
            let x: String = match result {
                Ok(ref rsp) => match rsp {
                    nsmsf_openapi::SendSMSResponse::SMSPayloadIsReceivedBySMSF(body) => {
                        let b = serde_json::to_string(&body).unwrap();
                        b
                        // format!("{:x}" , md5::compute(b))
                    }
                    _ => "0".to_string(),
                },
                _ => "0".to_string(),
            };
            let msg = serde_json::json!({
                "request_type": "send_sms_service",
                "status_code": status,
                // "ue_id": param_supi.clone(),
                "response": x
            });
            // log::info!("{:?}", msg);
            return Some(jmap_hash(msg));
        }
        _ => None,
    }
}
