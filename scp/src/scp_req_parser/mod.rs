use futures::{future, future::BoxFuture, future::FutureExt, stream, stream::TryStreamExt, Stream};
use hyper::header;
use hyper::header::{HeaderName, HeaderValue, CONTENT_TYPE};
use hyper::{Body, HeaderMap, Request, Response, StatusCode};
use hyper_0_10::header::{ContentType, Headers};
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

pub async fn scp_req_parser(
    uri: hyper::Uri,
    method: hyper::Method,
    headers: HeaderMap,
    body: Vec<u8>,
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
            // Path parameters
            let path: &str = &uri.path().to_string();
            let path_params =
					paths::REGEX_NAMF_LOC_V1_UECONTEXTID_PROVIDE_LOC_INFO
					.captures(&path)
					.unwrap_or_else(||
						panic!("Path {} matched RE NAMF_LOC_V1_UECONTEXTID_PROVIDE_LOC_INFO in set but failed match against \"{}\"", path, paths::REGEX_NAMF_LOC_V1_UECONTEXTID_PROVIDE_LOC_INFO.as_str())
					);

            let param_ue_context_id =
                match percent_encoding::percent_decode(path_params["ueContextId"].as_bytes())
                    .decode_utf8()
                {
                    Ok(param_ue_context_id) => match param_ue_context_id.parse::<String>() {
                        Ok(param_ue_context_id) => param_ue_context_id,
                        Err(e) => return None,
                    },
                    Err(_) => return None,
                };

            let jwt_token = headers
                .get("authorization")
                .map(|h| h.to_str().unwrap().strip_prefix("Bearer "))
                .flatten()
                .map(|f| f.to_string());

            // Body parameters (note that non-required body parameters will ignore garbage
            // values, rather than causing a 400 response). Produce warning header and logs for
            // any unused fields.
            let mut unused_elements = Vec::new();
            let param_request_loc_info: Option<models::RequestLocInfo> = if !body.is_empty() {
                let deserializer = &mut serde_json::Deserializer::from_slice(&*body);
                match serde_ignored::deserialize(deserializer, |path| {
                    warn!("Ignoring unknown field in body: {}", path);
                    unused_elements.push(path.to_string());
                }) {
                    Ok(param_request_loc_info) => param_request_loc_info,
                    Err(e) => return None,
                }
            } else {
                None
            };
            let param_request_loc_info = match param_request_loc_info {
                Some(param_request_loc_info) => param_request_loc_info,
                None => return None,
            };
            let oci: &str = if headers.contains_key("3gpp-Sbi-Oci") {
                headers.get("3gpp-Sbi-Oci").unwrap().to_str().unwrap()
            } else {
                "None"
            };
            let token = match jwt_token {
                Some(ref t) => t.clone(),
                None => "None".to_string(),
            };
            let msg = serde_json::json!({
                "request_type": "provide_location_info",
                "token": token,
                "supi": param_ue_context_id.clone(),
                "oci": oci,
                //// // "hash": format!("{:x}" ,md5::compute(serde_json::to_string(&param_request_loc_info)?))
            });
            return Some(jmap_hash(msg));
        }

        // N1N2MessageTransfer - POST /namf-comm/v1/ue-contexts/{ueContextId}/n1-n2-messages
        &hyper::Method::POST
            if path.matched(paths::ID_NAMF_COMM_V1_UE_CONTEXTS_UECONTEXTID_N1_N2_MESSAGES) =>
        {
            // Path parameters
            let path: &str = &uri.path().to_string();
            let path_params =
					paths::REGEX_NAMF_COMM_V1_UE_CONTEXTS_UECONTEXTID_N1_N2_MESSAGES
					.captures(&path)
					.unwrap_or_else(||
						panic!("Path {} matched RE NAMF_COMM_V1_UE_CONTEXTS_UECONTEXTID_N1_N2_MESSAGES in set but failed match against \"{}\"", path, paths::REGEX_NAMF_COMM_V1_UE_CONTEXTS_UECONTEXTID_N1_N2_MESSAGES.as_str())
					);

            let param_ue_context_id =
                match percent_encoding::percent_decode(path_params["ueContextId"].as_bytes())
                    .decode_utf8()
                {
                    Ok(param_ue_context_id) => match param_ue_context_id.parse::<String>() {
                        Ok(param_ue_context_id) => param_ue_context_id,
                        Err(e) => return None,
                    },
                    Err(_) => return None,
                };

            // Body parameters (note that non-required body parameters will ignore garbage
            // values, rather than causing a 400 response). Produce warning header and logs for
            // any unused fields.
            let mut unused_elements: Vec<String> = vec![];

            let result = if headers.get(CONTENT_TYPE).unwrap().to_str().unwrap()
                == "application/json"
            {
                let param_n1_n2_message_transfer_req_data: Option<
                    models::N1N2MessageTransferReqData,
                > = if !body.is_empty() {
                    let deserializer = &mut serde_json::Deserializer::from_slice(&*body);
                    match serde_ignored::deserialize(deserializer, |path| {
                        warn!("Ignoring unknown field in body: {}", path);
                        unused_elements.push(path.to_string());
                    }) {
                        Ok(param_n1_n2_message_transfer_req_data) => {
                            param_n1_n2_message_transfer_req_data
                        }
                        Err(e) => return None,
                    }
                } else {
                    None
                };
                let param_n1_n2_message_transfer_req_data =
                    match param_n1_n2_message_transfer_req_data {
                        Some(param_n1_n2_message_transfer_req_data) => {
                            param_n1_n2_message_transfer_req_data
                        }
                        None => return None,
                    };
                let msg = serde_json::json!({
                    "request_type" : "n1_n2_message_transfer",
                    "supi": param_ue_context_id,
                    //// // "hash": format!("{:x}" ,md5::compute(serde_json::to_string(&param_n1_n2_message_transfer_req_data)?))
                });
                return Some(jmap_hash(msg));
            } else {
                // Get multipart chunks.

                // Extract the top-level content type header.
                let content_type_mime = headers
								.get(CONTENT_TYPE)
								.ok_or("Missing content-type header".to_string())
								.and_then(|v| v.to_str().map_err(|e| format!("Couldn't read content-type header value for N1N2MessageTransfer: {}", e)))
								.and_then(|v| v.parse::<Mime2>().map_err(|_e| format!("Couldn't parse content-type header value for N1N2MessageTransfer")));

                // Insert top-level content type header into a Headers object.
                let mut multi_part_headers = Headers::new();
                match content_type_mime {
                    Ok(content_type_mime) => {
                        multi_part_headers.set(ContentType(content_type_mime));
                    }
                    Err(e) => {
                        return None;
                    }
                }

                // &*body expresses the body as a byteslice, &mut provides a
                // mutable reference to that byteslice.
                let nodes = match read_multipart_body(&mut &*body, &multi_part_headers, false) {
                    Ok(nodes) => nodes,
                    Err(e) => {
                        return None;
                    }
                };
                let mut param_n1_n2_message_transfer_req_data = None;
                let mut param_binary_data_n1_message_content_id = None;
                let mut param_binary_data_n1_message = None;
                let mut param_binary_data_n2_information_content_id = None;
                let mut param_binary_data_n2_information = None;
                let mut param_binary_mt_data_content_id = None;
                let mut param_binary_mt_data = None;

                // &*body expresses the body as a byteslice, &mut provides a
                // mutable reference to that byteslice.
                let nodes = match read_multipart_body(&mut &*body, &multi_part_headers, false) {
                    Ok(nodes) => nodes,
                    Err(e) => {
                        return None;
                    }
                };

                for node in nodes {
                    if let Node::Part(part) = node {
                        if let Some(content_type) = part.content_type().map(|x| format!("{}", x)) {
                            if content_type == "application/json"
                                && param_n1_n2_message_transfer_req_data.is_none()
                            {
                                // Extract JSON part.
                                let deserializer =
                                    &mut serde_json::Deserializer::from_slice(part.body.as_slice());
                                let json_data: models::N1N2MessageTransferReqData =
                                    match serde_ignored::deserialize(deserializer, |path| {
                                        warn!("Ignoring unknown field in JSON part: {}", path);
                                        unused_elements.push(path.to_string());
                                    }) {
                                        Ok(json_data) => json_data,
                                        Err(e) => return None,
                                    };
                                // Push JSON part to return object.
                                if let Some(ref info) = json_data.n1_message_container {
                                    param_binary_data_n1_message_content_id
                                        .get_or_insert(info.n1_message_content.content_id.clone());
                                }
                                if let Some(ref info) = json_data.n2_info_container {
                                    match info.n2_information_class {
                                        models::N2InformationClass::SM => {
                                            if let Some(ref info) = info.sm_info {
                                                if let Some(ref info) = info.n2_info_content {
                                                    param_binary_data_n2_information_content_id
                                                        .get_or_insert(
                                                            info.ngap_data.content_id.clone(),
                                                        );
                                                }
                                            }
                                        }
                                        models::N2InformationClass::NRPPA => {
                                            if let Some(ref info) = info.nrppa_info {
                                                param_binary_data_n2_information_content_id
                                                    .get_or_insert(
                                                        info.nrppa_pdu.ngap_data.content_id.clone(),
                                                    );
                                            }
                                        }
                                        models::N2InformationClass::PWS
                                        | models::N2InformationClass::PWS_BCAL
                                        | models::N2InformationClass::PWS_RF => {
                                            if let Some(ref info) = info.pws_info {
                                                param_binary_data_n2_information_content_id
                                                    .get_or_insert(
                                                        info.pws_container
                                                            .ngap_data
                                                            .content_id
                                                            .clone(),
                                                    );
                                            }
                                        }
                                        models::N2InformationClass::RAN => {
                                            if let Some(ref info) = info.ran_info {
                                                param_binary_data_n2_information_content_id
                                                    .get_or_insert(
                                                        info.n2_info_content
                                                            .ngap_data
                                                            .content_id
                                                            .clone(),
                                                    );
                                            }
                                        }
                                        models::N2InformationClass::V2X => {
                                            if let Some(ref info) = info.v2x_info {
                                                if let Some(ref info2) = info.n2_pc5_pol {
                                                    param_binary_data_n2_information_content_id
                                                        .get_or_insert(
                                                            info2.ngap_data.content_id.clone(),
                                                        );
                                                }
                                            }
                                        }
                                    };
                                }
                                if let Some(ref info) = json_data.mt_data {
                                    param_binary_mt_data_content_id
                                        .get_or_insert(info.content_id.clone());
                                }
                                param_n1_n2_message_transfer_req_data.get_or_insert(json_data);
                            }
                        }
                        if let Some(content_id) = part
                            .headers
                            .get_raw("Content-ID")
                            .map(|x| std::str::from_utf8(x[0].as_slice()).unwrap())
                        {
                            param_binary_data_n1_message_content_id.as_ref().map(|id| {
                                if id == content_id {
                                    param_binary_data_n1_message
                                        .get_or_insert(swagger::ByteArray(part.body.clone()));
                                }
                            });
                            param_binary_data_n2_information_content_id
                                .as_ref()
                                .map(|id| {
                                    if id == content_id {
                                        param_binary_data_n2_information
                                            .get_or_insert(swagger::ByteArray(part.body.clone()));
                                    }
                                });
                            param_binary_mt_data_content_id.as_ref().map(|id| {
                                if id == content_id {
                                    param_binary_mt_data
                                        .get_or_insert(swagger::ByteArray(part.body.clone()));
                                }
                            });
                        }
                    } else {
                        unimplemented!("No support for handling unexpected parts");
                        // unused_elements.push();
                    }
                }

                let param_n1_n2_message_transfer_req_data =
                    match param_n1_n2_message_transfer_req_data {
                        Some(param_n1_n2_message_transfer_req_data) => {
                            param_n1_n2_message_transfer_req_data
                        }
                        None => return None,
                    };
                let bytes = param_binary_data_n1_message.clone().map(|f| f.0).unwrap();
                let ip = if bytes.len() > 30 {
                    bytes[26..30]
                        .iter()
                        .map(|x| x.to_string())
                        .collect::<Vec<String>>()
                        .join(".")
                } else {
                    "None".to_string()
                };
                let msg = serde_json::json!({
                    "request_type" : "n1_n2_message_transfer",
                    "supi": param_ue_context_id,
                    "ip": ip,
                    //// // "hash": format!("{:x}" ,md5::compute(serde_json::to_string(&param_n1_n2_message_transfer_req_data)?))
                });
                return Some(jmap_hash(msg));
            };
        }

        // EnableUeReachability - PUT /namf-mt/v1/ue-contexts/{ueContextId}/ue-reachind
        &hyper::Method::PUT
            if path.matched(paths::ID_NAMF_MT_V1_UE_CONTEXTS_UECONTEXTID_UE_REACHIND) =>
        {
            //// CHANGE THIS OUOPUT
            // Path parameters
            let path: &str = &uri.path().to_string();
            let path_params =
					paths::REGEX_NAMF_MT_V1_UE_CONTEXTS_UECONTEXTID_UE_REACHIND
					.captures(&path)
					.unwrap_or_else(||
						panic!("Path {} matched RE NAMF_MT_V1_UE_CONTEXTS_UECONTEXTID_UE_REACHIND in set but failed match against \"{}\"", path, paths::REGEX_NAMF_MT_V1_UE_CONTEXTS_UECONTEXTID_UE_REACHIND.as_str())
					);

            let param_ue_context_id =
                match percent_encoding::percent_decode(path_params["ueContextId"].as_bytes())
                    .decode_utf8()
                {
                    Ok(param_ue_context_id) => match param_ue_context_id.parse::<String>() {
                        Ok(param_ue_context_id) => param_ue_context_id,
                        Err(e) => return None,
                    },
                    Err(_) => return None,
                };

            // Body parameters (note that non-required body parameters will ignore garbage
            // values, rather than causing a 400 response). Produce warning header and logs for
            // any unused fields.
            let mut unused_elements = Vec::new();
            let param_enable_ue_reachability_req_data: Option<models::EnableUeReachabilityReqData> =
                if !body.is_empty() {
                    let deserializer = &mut serde_json::Deserializer::from_slice(&*body);
                    match serde_ignored::deserialize(deserializer, |path| {
                        warn!("Ignoring unknown field in body: {}", path);
                        unused_elements.push(path.to_string());
                    }) {
                        Ok(param_enable_ue_reachability_req_data) => {
                            param_enable_ue_reachability_req_data
                        }
                        Err(e) => return None,
                    }
                } else {
                    None
                };
            let param_enable_ue_reachability_req_data = match param_enable_ue_reachability_req_data
            {
                Some(param_enable_ue_reachability_req_data) => {
                    param_enable_ue_reachability_req_data
                }
                None => return None,
            };
            // return Some(jmap_hash(msg))
            let msg = serde_json::json!({
                "request_type" : "enable_ue_reachability",
                "supi": param_ue_context_id,
                // "ip": ip,
                //// // "hash": format!("{:x}" ,md5::compute(serde_json::to_string(&param_n1_n2_message_transfer_req_data)?))
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
            let path: &str = &uri.path().to_string();
            let path_params =
				paths::REGEX_NAUSF_AUTH_V1_UE_AUTHENTICATIONS_AUTHCTXID_5G_AKA_CONFIRMATION
				.captures(&path)
				.unwrap_or_else(||
					panic!("Path {} matched RE NAUSF_AUTH_V1_UE_AUTHENTICATIONS_AUTHCTXID_5G_AKA_CONFIRMATION in set but failed match against \"{}\"", path, paths::REGEX_NAUSF_AUTH_V1_UE_AUTHENTICATIONS_AUTHCTXID_5G_AKA_CONFIRMATION.as_str())
				);

            let param_auth_ctx_id =
                match percent_encoding::percent_decode(path_params["authCtxId"].as_bytes())
                    .decode_utf8()
                {
                    Ok(param_auth_ctx_id) => match param_auth_ctx_id.parse::<String>() {
                        Ok(param_auth_ctx_id) => param_auth_ctx_id,
                        Err(e) => return None,
                    },
                    Err(_) => return None,
                };

            let jwt_token = headers
                .get("authorization")
                .map(|h| h.to_str().unwrap().strip_prefix("Bearer "))
                .flatten()
                .map(|f| f.to_string());

            // Body parameters (note that non-required body parameters will ignore garbage
            // values, rather than causing a 400 response). Produce warning header and logs for
            // any unused fields.
            let mut unused_elements = Vec::new();
            let param_confirmation_data: Option<models::ConfirmationData> = if !body.is_empty() {
                let deserializer = &mut serde_json::Deserializer::from_slice(&*body);
                match serde_ignored::deserialize(deserializer, |path| {
                    warn!("Ignoring unknown field in body: {}", path);
                    unused_elements.push(path.to_string());
                }) {
                    Ok(param_confirmation_data) => param_confirmation_data,
                    Err(_) => None,
                }
            } else {
                None
            };
            let msg = serde_json::json!({
                "request_type" : "ctx_id5g_aka",
                "token": jwt_token.as_ref().unwrap().clone(),
                "auth_ctx_id": param_auth_ctx_id.clone().to_string(),
                //// // "hash": format!("{:x}" ,md5::compute(serde_json::to_string(&param_confirmation_data.as_ref().unwrap())?))
            });
            return Some(jmap_hash(msg));
        }

        // NausfAuthV1UeAuthenticationsPost - POST /nausf-auth/v1/ue-authentications
        &hyper::Method::POST if path.matched(paths::ID_NAUSF_AUTH_V1_UE_AUTHENTICATIONS) => {
            // log::info!("Step 1");
            let jwt_token = headers
                .get("authorization")
                .map(|h| h.to_str().unwrap().strip_prefix("Bearer "))
                .flatten()
                .map(|f| f.to_string());
            // Body parameters (note that non-required body parameters will ignore garbage
            // values, rather than causing a 400 response). Produce warning header and logs for
            // any unused fields.
            // log::info!("Step 2");
            // 			log::info!("Step 3");
            let mut unused_elements = Vec::new();
            let param_authentication_info: Option<models::AuthenticationInfo> = if !body.is_empty()
            {
                let deserializer = &mut serde_json::Deserializer::from_slice(&*body);
                match serde_ignored::deserialize(deserializer, |path| {
                    warn!("Ignoring unknown field in body: {}", path);
                    unused_elements.push(path.to_string());
                }) {
                    Ok(param_authentication_info) => param_authentication_info,
                    Err(e) => return None,
                }
            } else {
                None
            };
            // log::info!("Step 4");
            let param_authentication_info = match param_authentication_info {
                Some(param_authentication_info) => param_authentication_info,
                None => return None,
            };
            // log::info!("Step 5");
            let msg = serde_json::json!({
                "request_type" : "ue_authentications_post",
                "supi": param_authentication_info.supi_or_suci.clone(),
                "token": jwt_token.as_ref().unwrap().clone(),
                // "hash": format!("{:x}", md5::compute(serde_json::to_string(&param_authentication_info)?))
            });
            return Some(jmap_hash(msg));
        }

        // RemoveSubscription - DELETE /nnrf-nfm/v1/subscriptions/{subscriptionID}
        &hyper::Method::DELETE
            if path.matched(paths::ID_NNRF_NFM_V1_SUBSCRIPTIONS_SUBSCRIPTIONID) =>
        {
            // Path parameters
            let path: &str = &uri.path().to_string();
            let path_params =
                    paths::REGEX_NNRF_NFM_V1_SUBSCRIPTIONS_SUBSCRIPTIONID
                    .captures(&path)
                    .unwrap_or_else(||
                        panic!("Path {} matched RE NNRF_NFM_V1_SUBSCRIPTIONS_SUBSCRIPTIONID in set but failed match against \"{}\"", path, paths::REGEX_NNRF_NFM_V1_SUBSCRIPTIONS_SUBSCRIPTIONID.as_str())
                    );

            let param_subscription_id =
                match percent_encoding::percent_decode(path_params["subscriptionID"].as_bytes())
                    .decode_utf8()
                {
                    Ok(param_subscription_id) => match param_subscription_id.parse::<String>() {
                        Ok(param_subscription_id) => param_subscription_id,
                        Err(e) => return None,
                    },
                    Err(_) => return None,
                };
            let msg = serde_json::json!({
                "request_type" : "remove_subscription",
                "subid": param_subscription_id,
               // // "hash": "0"
            });
            return Some(jmap_hash(msg));
        }

        // CreateSubscription - POST /nnrf-nfm/v1/subscriptions
        &hyper::Method::POST if path.matched(paths::ID_NNRF_NFM_V1_SUBSCRIPTIONS) => {
            // Header parameters
            let param_content_encoding = headers.get(HeaderName::from_static("content-encoding"));

            let param_content_encoding = match param_content_encoding {
                Some(v) => {
                    match nnrf_openapi::header::IntoHeaderValue::<String>::try_from((*v).clone()) {
                        Ok(result) => Some(result.0),
                        Err(err) => {
                            return None;
                        }
                    }
                }
                None => None,
            };
            let param_accept_encoding = headers.get(HeaderName::from_static("accept-encoding"));

            let param_accept_encoding = match param_accept_encoding {
                Some(v) => {
                    match nnrf_openapi::header::IntoHeaderValue::<String>::try_from((*v).clone()) {
                        Ok(result) => Some(result.0),
                        Err(err) => {
                            return None;
                        }
                    }
                }
                None => None,
            };

            // Body parameters (note that non-required body parameters will ignore garbage
            // values, rather than causing a 400 response). Produce warning header and logs for
            // any unused fields.
            let mut unused_elements = Vec::new();
            let param_subscription_data: Option<models::SubscriptionData> = if !body.is_empty() {
                let deserializer = &mut serde_json::Deserializer::from_slice(&*body);
                match serde_ignored::deserialize(deserializer, |path| {
                    warn!("Ignoring unknown field in body: {}", path);
                    unused_elements.push(path.to_string());
                }) {
                    Ok(param_subscription_data) => param_subscription_data,
                    Err(e) => return None,
                }
            } else {
                None
            };
            let param_subscription_data = match param_subscription_data {
                Some(param_subscription_data) => param_subscription_data,
                None => return None,
            };
            let req_fqdn = match &param_subscription_data.req_nf_fqdn {
                Some(ref x) => x.to_string(),
                None => "None".to_string(),
            };

            let msg = serde_json::json!({
                "request_type" : "create_subscription",
                "target_fqdn": req_fqdn.to_string(),
               // // "hash": format!("{:x}" ,md5::compute(serde_json::to_string(&param_subscription_data.clone())?))
            });
            return Some(jmap_hash(msg));
        }

        // SearchNFInstances - GET /nnrf-disc/v1/nf-instances
        &hyper::Method::GET if path.matched(paths::ID_NNRF_DISC_V1_NF_INSTANCES) => {
            // Header parameters
            let param_accept_encoding = headers.get(HeaderName::from_static("accept-encoding"));

            let param_accept_encoding = match param_accept_encoding {
                Some(v) => {
                    match nnrf_openapi::header::IntoHeaderValue::<String>::try_from((*v).clone()) {
                        Ok(result) => Some(result.0),
                        Err(err) => {
                            return None;
                        }
                    }
                }
                None => None,
            };
            let param_if_none_match = headers.get(HeaderName::from_static("if-none-match"));

            let param_if_none_match = match param_if_none_match {
                Some(v) => {
                    match nnrf_openapi::header::IntoHeaderValue::<String>::try_from((*v).clone()) {
                        Ok(result) => Some(result.0),
                        Err(err) => {
                            return None;
                        }
                    }
                }
                None => None,
            };

            // Query parameters (note that non-required or collection query parameters will ignore garbage values, rather than causing a 400 response)
            let query_params = form_urlencoded::parse(uri.query().unwrap_or_default().as_bytes())
                .collect::<Vec<_>>();
            let param_target_nf_type = query_params
                .iter()
                .filter(|e| e.0 == "target-nf-type")
                .map(|e| e.1.to_owned())
                .nth(0);
            let param_target_nf_type = match param_target_nf_type {
                Some(param_target_nf_type) => {
                    let param_target_nf_type =
                        <models::NfType as std::str::FromStr>::from_str(&param_target_nf_type);
                    match param_target_nf_type {
                        Ok(param_target_nf_type) => Some(param_target_nf_type),
                        Err(e) => return None,
                    }
                }
                None => None,
            };
            let param_target_nf_type = match param_target_nf_type {
                Some(param_target_nf_type) => param_target_nf_type,
                None => return None,
            };
            let param_requester_nf_type = query_params
                .iter()
                .filter(|e| e.0 == "requester-nf-type")
                .map(|e| e.1.to_owned())
                .nth(0);
            let param_requester_nf_type = match param_requester_nf_type {
                Some(param_requester_nf_type) => {
                    let param_requester_nf_type =
                        <models::NfType as std::str::FromStr>::from_str(&param_requester_nf_type);
                    match param_requester_nf_type {
                        Ok(param_requester_nf_type) => Some(param_requester_nf_type),
                        Err(e) => return None,
                    }
                }
                None => None,
            };
            let param_requester_nf_type = match param_requester_nf_type {
                Some(param_requester_nf_type) => param_requester_nf_type,
                None => return None,
            };
            let param_requester_nf_instance_id = query_params
                .iter()
                .filter(|e| e.0 == "requester-nf-instance-id")
                .map(|e| e.1.to_owned())
                .nth(0);
            let param_requester_nf_instance_id = match param_requester_nf_instance_id {
                Some(param_requester_nf_instance_id) => {
                    let param_requester_nf_instance_id =
                        <uuid::Uuid as std::str::FromStr>::from_str(
                            &param_requester_nf_instance_id,
                        );
                    match param_requester_nf_instance_id {
                        Ok(param_requester_nf_instance_id) => Some(param_requester_nf_instance_id),
                        Err(e) => return None,
                    }
                }
                None => None,
            };
            let param_service_names: Vec<models::ServiceName> = query_params
                .iter()
                .filter(|e| e.0 == "service-names")
                .map(|e| e.1.to_owned())
                .filter_map(|param_service_names| param_service_names.parse().ok())
                .collect::<Vec<_>>();
            let param_service_names = if !param_service_names.is_empty() {
                Some(param_service_names)
            } else {
                None
            };
            let param_requester_nf_instance_fqdn = query_params
                .iter()
                .filter(|e| e.0 == "requester-nf-instance-fqdn")
                .map(|e| e.1.to_owned())
                .nth(0);
            let param_requester_nf_instance_fqdn = match param_requester_nf_instance_fqdn {
                Some(param_requester_nf_instance_fqdn) => {
                    let param_requester_nf_instance_fqdn =
                        <String as std::str::FromStr>::from_str(&param_requester_nf_instance_fqdn);
                    match param_requester_nf_instance_fqdn {
                        Ok(param_requester_nf_instance_fqdn) => {
                            Some(param_requester_nf_instance_fqdn)
                        }
                        Err(e) => return None,
                    }
                }
                None => None,
            };
            let param_target_plmn_list = query_params
                .iter()
                .filter(|e| e.0 == "target-plmn-list")
                .map(|e| e.1.to_owned())
                .nth(0);
            let param_target_plmn_list = match param_target_plmn_list {
                Some(param_target_plmn_list) => {
                    let param_target_plmn_list =
                        serde_json::from_str::<Vec<models::PlmnId>>(&param_target_plmn_list);
                    match param_target_plmn_list {
                        Ok(param_target_plmn_list) => Some(param_target_plmn_list),
                        Err(e) => return None,
                    }
                }
                None => None,
            };
            let param_requester_plmn_list = query_params
                .iter()
                .filter(|e| e.0 == "requester-plmn-list")
                .map(|e| e.1.to_owned())
                .nth(0);
            let param_requester_plmn_list = match param_requester_plmn_list {
                Some(param_requester_plmn_list) => {
                    let param_requester_plmn_list =
                        serde_json::from_str::<Vec<models::PlmnId>>(&param_requester_plmn_list);
                    match param_requester_plmn_list {
                        Ok(param_requester_plmn_list) => Some(param_requester_plmn_list),
                        Err(e) => return None,
                    }
                }
                None => None,
            };
            let param_target_nf_instance_id = query_params
                .iter()
                .filter(|e| e.0 == "target-nf-instance-id")
                .map(|e| e.1.to_owned())
                .nth(0);
            let param_target_nf_instance_id = match param_target_nf_instance_id {
                Some(param_target_nf_instance_id) => {
                    let param_target_nf_instance_id =
                        <uuid::Uuid as std::str::FromStr>::from_str(&param_target_nf_instance_id);
                    match param_target_nf_instance_id {
                        Ok(param_target_nf_instance_id) => Some(param_target_nf_instance_id),
                        Err(e) => return None,
                    }
                }
                None => None,
            };
            let param_target_nf_fqdn = query_params
                .iter()
                .filter(|e| e.0 == "target-nf-fqdn")
                .map(|e| e.1.to_owned())
                .nth(0);
            let param_target_nf_fqdn = match param_target_nf_fqdn {
                Some(param_target_nf_fqdn) => {
                    let param_target_nf_fqdn =
                        <String as std::str::FromStr>::from_str(&param_target_nf_fqdn);
                    match param_target_nf_fqdn {
                        Ok(param_target_nf_fqdn) => Some(param_target_nf_fqdn),
                        Err(e) => return None,
                    }
                }
                None => None,
            };
            let param_hnrf_uri = query_params
                .iter()
                .filter(|e| e.0 == "hnrf-uri")
                .map(|e| e.1.to_owned())
                .nth(0);
            let param_hnrf_uri = match param_hnrf_uri {
                Some(param_hnrf_uri) => {
                    let param_hnrf_uri = <String as std::str::FromStr>::from_str(&param_hnrf_uri);
                    match param_hnrf_uri {
                        Ok(param_hnrf_uri) => Some(param_hnrf_uri),
                        Err(e) => return None,
                    }
                }
                None => None,
            };
            let param_snssais = query_params
                .iter()
                .filter(|e| e.0 == "snssais")
                .map(|e| e.1.to_owned())
                .nth(0);
            let param_snssais = match param_snssais {
                Some(param_snssais) => {
                    let param_snssais = serde_json::from_str::<Vec<models::Snssai>>(&param_snssais);
                    match param_snssais {
                        Ok(param_snssais) => Some(param_snssais),
                        Err(e) => return None,
                    }
                }
                None => None,
            };
            let param_requester_snssais = query_params
                .iter()
                .filter(|e| e.0 == "requester-snssais")
                .map(|e| e.1.to_owned())
                .nth(0);
            let param_requester_snssais = match param_requester_snssais {
                Some(param_requester_snssais) => {
                    let param_requester_snssais =
                        serde_json::from_str::<Vec<models::Snssai>>(&param_requester_snssais);
                    match param_requester_snssais {
                        Ok(param_requester_snssais) => Some(param_requester_snssais),
                        Err(e) => return None,
                    }
                }
                None => None,
            };
            let param_plmn_specific_snssai_list = query_params
                .iter()
                .filter(|e| e.0 == "plmn-specific-snssai-list")
                .map(|e| e.1.to_owned())
                .nth(0);
            let param_plmn_specific_snssai_list = match param_plmn_specific_snssai_list {
                Some(param_plmn_specific_snssai_list) => {
                    let param_plmn_specific_snssai_list =
                        serde_json::from_str::<Vec<models::PlmnSnssai>>(
                            &param_plmn_specific_snssai_list,
                        );
                    match param_plmn_specific_snssai_list {
                        Ok(param_plmn_specific_snssai_list) => {
                            Some(param_plmn_specific_snssai_list)
                        }
                        Err(e) => return None,
                    }
                }
                None => None,
            };
            let param_requester_plmn_specific_snssai_list = query_params
                .iter()
                .filter(|e| e.0 == "requester-plmn-specific-snssai-list")
                .map(|e| e.1.to_owned())
                .nth(0);
            let param_requester_plmn_specific_snssai_list =
                match param_requester_plmn_specific_snssai_list {
                    Some(param_requester_plmn_specific_snssai_list) => {
                        let param_requester_plmn_specific_snssai_list =
                            serde_json::from_str::<Vec<models::PlmnSnssai>>(
                                &param_requester_plmn_specific_snssai_list,
                            );
                        match param_requester_plmn_specific_snssai_list {
                            Ok(param_requester_plmn_specific_snssai_list) => {
                                Some(param_requester_plmn_specific_snssai_list)
                            }
                            Err(e) => return None,
                        }
                    }
                    None => None,
                };
            let param_dnn = query_params
                .iter()
                .filter(|e| e.0 == "dnn")
                .map(|e| e.1.to_owned())
                .nth(0);
            let param_dnn = match param_dnn {
                Some(param_dnn) => {
                    let param_dnn = <String as std::str::FromStr>::from_str(&param_dnn);
                    match param_dnn {
                        Ok(param_dnn) => Some(param_dnn),
                        Err(e) => return None,
                    }
                }
                None => None,
            };
            let param_nsi_list: Vec<String> = query_params
                .iter()
                .filter(|e| e.0 == "nsi-list")
                .map(|e| e.1.to_owned())
                .filter_map(|param_nsi_list| param_nsi_list.parse().ok())
                .collect::<Vec<_>>();
            let param_nsi_list = if !param_nsi_list.is_empty() {
                Some(param_nsi_list)
            } else {
                None
            };
            let param_smf_serving_area = query_params
                .iter()
                .filter(|e| e.0 == "smf-serving-area")
                .map(|e| e.1.to_owned())
                .nth(0);
            let param_smf_serving_area = match param_smf_serving_area {
                Some(param_smf_serving_area) => {
                    let param_smf_serving_area =
                        <String as std::str::FromStr>::from_str(&param_smf_serving_area);
                    match param_smf_serving_area {
                        Ok(param_smf_serving_area) => Some(param_smf_serving_area),
                        Err(e) => return None,
                    }
                }
                None => None,
            };
            let param_tai = query_params
                .iter()
                .filter(|e| e.0 == "tai")
                .map(|e| e.1.to_owned())
                .nth(0);
            let param_tai = match param_tai {
                Some(param_tai) => {
                    let param_tai = serde_json::from_str::<models::Tai>(&param_tai);
                    match param_tai {
                        Ok(param_tai) => Some(param_tai),
                        Err(e) => return None,
                    }
                }
                None => None,
            };
            let param_amf_region_id = query_params
                .iter()
                .filter(|e| e.0 == "amf-region-id")
                .map(|e| e.1.to_owned())
                .nth(0);
            let param_amf_region_id = match param_amf_region_id {
                Some(param_amf_region_id) => {
                    let param_amf_region_id =
                        <String as std::str::FromStr>::from_str(&param_amf_region_id);
                    match param_amf_region_id {
                        Ok(param_amf_region_id) => Some(param_amf_region_id),
                        Err(e) => return None,
                    }
                }
                None => None,
            };
            let param_amf_set_id = query_params
                .iter()
                .filter(|e| e.0 == "amf-set-id")
                .map(|e| e.1.to_owned())
                .nth(0);
            let param_amf_set_id = match param_amf_set_id {
                Some(param_amf_set_id) => {
                    let param_amf_set_id =
                        <String as std::str::FromStr>::from_str(&param_amf_set_id);
                    match param_amf_set_id {
                        Ok(param_amf_set_id) => Some(param_amf_set_id),
                        Err(e) => return None,
                    }
                }
                None => None,
            };
            let param_guami = query_params
                .iter()
                .filter(|e| e.0 == "guami")
                .map(|e| e.1.to_owned())
                .nth(0);
            let param_guami = match param_guami {
                Some(param_guami) => {
                    let param_guami = serde_json::from_str::<models::Guami>(&param_guami);
                    match param_guami {
                        Ok(param_guami) => Some(param_guami),
                        Err(e) => return None,
                    }
                }
                None => None,
            };
            let param_supi = query_params
                .iter()
                .filter(|e| e.0 == "supi")
                .map(|e| e.1.to_owned())
                .nth(0);
            let param_supi = match param_supi {
                Some(param_supi) => {
                    let param_supi = <String as std::str::FromStr>::from_str(&param_supi);
                    match param_supi {
                        Ok(param_supi) => Some(param_supi),
                        Err(e) => return None,
                    }
                }
                None => None,
            };
            let param_ue_ipv4_address = query_params
                .iter()
                .filter(|e| e.0 == "ue-ipv4-address")
                .map(|e| e.1.to_owned())
                .nth(0);
            let param_ue_ipv4_address = match param_ue_ipv4_address {
                Some(param_ue_ipv4_address) => {
                    let param_ue_ipv4_address =
                        <String as std::str::FromStr>::from_str(&param_ue_ipv4_address);
                    match param_ue_ipv4_address {
                        Ok(param_ue_ipv4_address) => Some(param_ue_ipv4_address),
                        Err(e) => return None,
                    }
                }
                None => None,
            };
            let param_ip_domain = query_params
                .iter()
                .filter(|e| e.0 == "ip-domain")
                .map(|e| e.1.to_owned())
                .nth(0);
            let param_ip_domain = match param_ip_domain {
                Some(param_ip_domain) => {
                    let param_ip_domain = <String as std::str::FromStr>::from_str(&param_ip_domain);
                    match param_ip_domain {
                        Ok(param_ip_domain) => Some(param_ip_domain),
                        Err(e) => return None,
                    }
                }
                None => None,
            };
            let param_ue_ipv6_prefix = query_params
                .iter()
                .filter(|e| e.0 == "ue-ipv6-prefix")
                .map(|e| e.1.to_owned())
                .nth(0);
            let param_ue_ipv6_prefix = match param_ue_ipv6_prefix {
                Some(param_ue_ipv6_prefix) => {
                    let param_ue_ipv6_prefix =
                        <String as std::str::FromStr>::from_str(&param_ue_ipv6_prefix);
                    match param_ue_ipv6_prefix {
                        Ok(param_ue_ipv6_prefix) => Some(param_ue_ipv6_prefix),
                        Err(e) => return None,
                    }
                }
                None => None,
            };
            let param_pgw_ind = query_params
                .iter()
                .filter(|e| e.0 == "pgw-ind")
                .map(|e| e.1.to_owned())
                .nth(0);
            let param_pgw_ind = match param_pgw_ind {
                Some(param_pgw_ind) => {
                    let param_pgw_ind = <bool as std::str::FromStr>::from_str(&param_pgw_ind);
                    match param_pgw_ind {
                        Ok(param_pgw_ind) => Some(param_pgw_ind),
                        Err(e) => return None,
                    }
                }
                None => None,
            };
            let param_pgw = query_params
                .iter()
                .filter(|e| e.0 == "pgw")
                .map(|e| e.1.to_owned())
                .nth(0);
            let param_pgw = match param_pgw {
                Some(param_pgw) => {
                    let param_pgw = <String as std::str::FromStr>::from_str(&param_pgw);
                    match param_pgw {
                        Ok(param_pgw) => Some(param_pgw),
                        Err(e) => return None,
                    }
                }
                None => None,
            };
            let param_gpsi = query_params
                .iter()
                .filter(|e| e.0 == "gpsi")
                .map(|e| e.1.to_owned())
                .nth(0);
            let param_gpsi = match param_gpsi {
                Some(param_gpsi) => {
                    let param_gpsi = <String as std::str::FromStr>::from_str(&param_gpsi);
                    match param_gpsi {
                        Ok(param_gpsi) => Some(param_gpsi),
                        Err(e) => return None,
                    }
                }
                None => None,
            };
            let param_external_group_identity = query_params
                .iter()
                .filter(|e| e.0 == "external-group-identity")
                .map(|e| e.1.to_owned())
                .nth(0);
            let param_external_group_identity = match param_external_group_identity {
                Some(param_external_group_identity) => {
                    let param_external_group_identity =
                        <String as std::str::FromStr>::from_str(&param_external_group_identity);
                    match param_external_group_identity {
                        Ok(param_external_group_identity) => Some(param_external_group_identity),
                        Err(e) => return None,
                    }
                }
                None => None,
            };
            let param_internal_group_identity = query_params
                .iter()
                .filter(|e| e.0 == "internal-group-identity")
                .map(|e| e.1.to_owned())
                .nth(0);
            let param_internal_group_identity = match param_internal_group_identity {
                Some(param_internal_group_identity) => {
                    let param_internal_group_identity =
                        <String as std::str::FromStr>::from_str(&param_internal_group_identity);
                    match param_internal_group_identity {
                        Ok(param_internal_group_identity) => Some(param_internal_group_identity),
                        Err(e) => return None,
                    }
                }
                None => None,
            };
            let param_pfd_data = query_params
                .iter()
                .filter(|e| e.0 == "pfd-data")
                .map(|e| e.1.to_owned())
                .nth(0);
            let param_pfd_data = match param_pfd_data {
                Some(param_pfd_data) => {
                    let param_pfd_data = serde_json::from_str::<models::PfdData>(&param_pfd_data);
                    match param_pfd_data {
                        Ok(param_pfd_data) => Some(param_pfd_data),
                        Err(e) => return None,
                    }
                }
                None => None,
            };
            let param_data_set = query_params
                .iter()
                .filter(|e| e.0 == "data-set")
                .map(|e| e.1.to_owned())
                .nth(0);
            let param_data_set = match param_data_set {
                Some(param_data_set) => {
                    let param_data_set =
                        <models::DataSetId as std::str::FromStr>::from_str(&param_data_set);
                    match param_data_set {
                        Ok(param_data_set) => Some(param_data_set),
                        Err(e) => return None,
                    }
                }
                None => None,
            };
            let param_routing_indicator = query_params
                .iter()
                .filter(|e| e.0 == "routing-indicator")
                .map(|e| e.1.to_owned())
                .nth(0);
            let param_routing_indicator = match param_routing_indicator {
                Some(param_routing_indicator) => {
                    let param_routing_indicator =
                        <String as std::str::FromStr>::from_str(&param_routing_indicator);
                    match param_routing_indicator {
                        Ok(param_routing_indicator) => Some(param_routing_indicator),
                        Err(e) => return None,
                    }
                }
                None => None,
            };
            let param_group_id_list: Vec<models::NfGroupId> = query_params
                .iter()
                .filter(|e| e.0 == "group-id-list")
                .map(|e| e.1.to_owned())
                .filter_map(|param_group_id_list| param_group_id_list.parse().ok())
                .collect::<Vec<_>>();
            let param_group_id_list = if !param_group_id_list.is_empty() {
                Some(param_group_id_list)
            } else {
                None
            };
            let param_dnai_list: Vec<models::Dnai> = query_params
                .iter()
                .filter(|e| e.0 == "dnai-list")
                .map(|e| e.1.to_owned())
                .filter_map(|param_dnai_list| param_dnai_list.parse().ok())
                .collect::<Vec<_>>();
            let param_dnai_list = if !param_dnai_list.is_empty() {
                Some(param_dnai_list)
            } else {
                None
            };
            let param_pdu_session_types: Vec<models::PduSessionType> = query_params
                .iter()
                .filter(|e| e.0 == "pdu-session-types")
                .map(|e| e.1.to_owned())
                .filter_map(|param_pdu_session_types| param_pdu_session_types.parse().ok())
                .collect::<Vec<_>>();
            let param_pdu_session_types = if !param_pdu_session_types.is_empty() {
                Some(param_pdu_session_types)
            } else {
                None
            };
            let param_event_id_list: Vec<models::EventId> = query_params
                .iter()
                .filter(|e| e.0 == "event-id-list")
                .map(|e| e.1.to_owned())
                .filter_map(|param_event_id_list| param_event_id_list.parse().ok())
                .collect::<Vec<_>>();
            let param_event_id_list = if !param_event_id_list.is_empty() {
                Some(param_event_id_list)
            } else {
                None
            };
            let param_nwdaf_event_list: Vec<models::NwdafEvent> = query_params
                .iter()
                .filter(|e| e.0 == "nwdaf-event-list")
                .map(|e| e.1.to_owned())
                .filter_map(|param_nwdaf_event_list| param_nwdaf_event_list.parse().ok())
                .collect::<Vec<_>>();
            let param_nwdaf_event_list = if !param_nwdaf_event_list.is_empty() {
                Some(param_nwdaf_event_list)
            } else {
                None
            };
            let param_supported_features = query_params
                .iter()
                .filter(|e| e.0 == "supported-features")
                .map(|e| e.1.to_owned())
                .nth(0);
            let param_supported_features = match param_supported_features {
                Some(param_supported_features) => {
                    let param_supported_features =
                        <String as std::str::FromStr>::from_str(&param_supported_features);
                    match param_supported_features {
                        Ok(param_supported_features) => Some(param_supported_features),
                        Err(e) => return None,
                    }
                }
                None => None,
            };
            let param_upf_iwk_eps_ind = query_params
                .iter()
                .filter(|e| e.0 == "upf-iwk-eps-ind")
                .map(|e| e.1.to_owned())
                .nth(0);
            let param_upf_iwk_eps_ind = match param_upf_iwk_eps_ind {
                Some(param_upf_iwk_eps_ind) => {
                    let param_upf_iwk_eps_ind =
                        <bool as std::str::FromStr>::from_str(&param_upf_iwk_eps_ind);
                    match param_upf_iwk_eps_ind {
                        Ok(param_upf_iwk_eps_ind) => Some(param_upf_iwk_eps_ind),
                        Err(e) => return None,
                    }
                }
                None => None,
            };
            let param_chf_supported_plmn = query_params
                .iter()
                .filter(|e| e.0 == "chf-supported-plmn")
                .map(|e| e.1.to_owned())
                .nth(0);
            let param_chf_supported_plmn = match param_chf_supported_plmn {
                Some(param_chf_supported_plmn) => {
                    let param_chf_supported_plmn =
                        serde_json::from_str::<models::PlmnId>(&param_chf_supported_plmn);
                    match param_chf_supported_plmn {
                        Ok(param_chf_supported_plmn) => Some(param_chf_supported_plmn),
                        Err(e) => return None,
                    }
                }
                None => None,
            };
            let param_preferred_locality = query_params
                .iter()
                .filter(|e| e.0 == "preferred-locality")
                .map(|e| e.1.to_owned())
                .nth(0);
            let param_preferred_locality = match param_preferred_locality {
                Some(param_preferred_locality) => {
                    let param_preferred_locality =
                        <String as std::str::FromStr>::from_str(&param_preferred_locality);
                    match param_preferred_locality {
                        Ok(param_preferred_locality) => Some(param_preferred_locality),
                        Err(e) => return None,
                    }
                }
                None => None,
            };
            let param_access_type = query_params
                .iter()
                .filter(|e| e.0 == "access-type")
                .map(|e| e.1.to_owned())
                .nth(0);
            let param_access_type = match param_access_type {
                Some(param_access_type) => {
                    let param_access_type =
                        <models::AccessType as std::str::FromStr>::from_str(&param_access_type);
                    match param_access_type {
                        Ok(param_access_type) => Some(param_access_type),
                        Err(e) => return None,
                    }
                }
                None => None,
            };
            let param_limit = query_params
                .iter()
                .filter(|e| e.0 == "limit")
                .map(|e| e.1.to_owned())
                .nth(0);
            let param_limit = match param_limit {
                Some(param_limit) => {
                    let param_limit = <i32 as std::str::FromStr>::from_str(&param_limit);
                    match param_limit {
                        Ok(param_limit) => Some(param_limit),
                        Err(e) => return None,
                    }
                }
                None => None,
            };
            let param_required_features: Vec<models::SupportedFeatures> = query_params
                .iter()
                .filter(|e| e.0 == "required-features")
                .map(|e| e.1.to_owned())
                .filter_map(|param_required_features| param_required_features.parse().ok())
                .collect::<Vec<_>>();
            let param_required_features = if !param_required_features.is_empty() {
                Some(param_required_features)
            } else {
                None
            };
            let param_complex_query = query_params
                .iter()
                .filter(|e| e.0 == "complex-query")
                .map(|e| e.1.to_owned())
                .nth(0);
            let param_complex_query = match param_complex_query {
                Some(param_complex_query) => {
                    let param_complex_query =
                        serde_json::from_str::<models::ComplexQuery>(&param_complex_query);
                    match param_complex_query {
                        Ok(param_complex_query) => Some(param_complex_query),
                        Err(e) => return None,
                    }
                }
                None => None,
            };
            let param_max_payload_size = query_params
                .iter()
                .filter(|e| e.0 == "max-payload-size")
                .map(|e| e.1.to_owned())
                .nth(0);
            let param_max_payload_size = match param_max_payload_size {
                Some(param_max_payload_size) => {
                    let param_max_payload_size =
                        <i32 as std::str::FromStr>::from_str(&param_max_payload_size);
                    match param_max_payload_size {
                        Ok(param_max_payload_size) => Some(param_max_payload_size),
                        Err(e) => return None,
                    }
                }
                None => None,
            };
            let param_max_payload_size_ext = query_params
                .iter()
                .filter(|e| e.0 == "max-payload-size-ext")
                .map(|e| e.1.to_owned())
                .nth(0);
            let param_max_payload_size_ext = match param_max_payload_size_ext {
                Some(param_max_payload_size_ext) => {
                    let param_max_payload_size_ext =
                        <i32 as std::str::FromStr>::from_str(&param_max_payload_size_ext);
                    match param_max_payload_size_ext {
                        Ok(param_max_payload_size_ext) => Some(param_max_payload_size_ext),
                        Err(e) => return None,
                    }
                }
                None => None,
            };
            let param_atsss_capability = query_params
                .iter()
                .filter(|e| e.0 == "atsss-capability")
                .map(|e| e.1.to_owned())
                .nth(0);
            let param_atsss_capability = match param_atsss_capability {
                Some(param_atsss_capability) => {
                    let param_atsss_capability =
                        serde_json::from_str::<models::AtsssCapability>(&param_atsss_capability);
                    match param_atsss_capability {
                        Ok(param_atsss_capability) => Some(param_atsss_capability),
                        Err(e) => return None,
                    }
                }
                None => None,
            };
            let param_upf_ue_ip_addr_ind = query_params
                .iter()
                .filter(|e| e.0 == "upf-ue-ip-addr-ind")
                .map(|e| e.1.to_owned())
                .nth(0);
            let param_upf_ue_ip_addr_ind = match param_upf_ue_ip_addr_ind {
                Some(param_upf_ue_ip_addr_ind) => {
                    let param_upf_ue_ip_addr_ind =
                        <bool as std::str::FromStr>::from_str(&param_upf_ue_ip_addr_ind);
                    match param_upf_ue_ip_addr_ind {
                        Ok(param_upf_ue_ip_addr_ind) => Some(param_upf_ue_ip_addr_ind),
                        Err(e) => return None,
                    }
                }
                None => None,
            };
            let param_client_type = query_params
                .iter()
                .filter(|e| e.0 == "client-type")
                .map(|e| e.1.to_owned())
                .nth(0);
            let param_client_type = match param_client_type {
                Some(param_client_type) => {
                    let param_client_type =
                        serde_json::from_str::<models::ExternalClientType>(&param_client_type);
                    match param_client_type {
                        Ok(param_client_type) => Some(param_client_type),
                        Err(e) => return None,
                    }
                }
                None => None,
            };
            let param_lmf_id = query_params
                .iter()
                .filter(|e| e.0 == "lmf-id")
                .map(|e| e.1.to_owned())
                .nth(0);
            let param_lmf_id = match param_lmf_id {
                Some(param_lmf_id) => {
                    let param_lmf_id = serde_json::from_str::<String>(&param_lmf_id);
                    match param_lmf_id {
                        Ok(param_lmf_id) => Some(param_lmf_id),
                        Err(e) => return None,
                    }
                }
                None => None,
            };
            let param_an_node_type = query_params
                .iter()
                .filter(|e| e.0 == "an-node-type")
                .map(|e| e.1.to_owned())
                .nth(0);
            let param_an_node_type = match param_an_node_type {
                Some(param_an_node_type) => {
                    let param_an_node_type =
                        serde_json::from_str::<models::AnNodeType>(&param_an_node_type);
                    match param_an_node_type {
                        Ok(param_an_node_type) => Some(param_an_node_type),
                        Err(e) => return None,
                    }
                }
                None => None,
            };
            let param_rat_type = query_params
                .iter()
                .filter(|e| e.0 == "rat-type")
                .map(|e| e.1.to_owned())
                .nth(0);
            let param_rat_type = match param_rat_type {
                Some(param_rat_type) => {
                    let param_rat_type = serde_json::from_str::<models::RatType>(&param_rat_type);
                    match param_rat_type {
                        Ok(param_rat_type) => Some(param_rat_type),
                        Err(e) => return None,
                    }
                }
                None => None,
            };
            let param_preferred_tai = query_params
                .iter()
                .filter(|e| e.0 == "preferred-tai")
                .map(|e| e.1.to_owned())
                .nth(0);
            let param_preferred_tai = match param_preferred_tai {
                Some(param_preferred_tai) => {
                    let param_preferred_tai =
                        serde_json::from_str::<models::Tai>(&param_preferred_tai);
                    match param_preferred_tai {
                        Ok(param_preferred_tai) => Some(param_preferred_tai),
                        Err(e) => return None,
                    }
                }
                None => None,
            };
            let param_preferred_nf_instances: Vec<models::NfInstanceId> = query_params
                .iter()
                .filter(|e| e.0 == "preferred-nf-instances")
                .map(|e| e.1.to_owned())
                .filter_map(|param_preferred_nf_instances| {
                    param_preferred_nf_instances.parse().ok()
                })
                .collect::<Vec<_>>();
            let param_preferred_nf_instances = if !param_preferred_nf_instances.is_empty() {
                Some(param_preferred_nf_instances)
            } else {
                None
            };
            let param_target_snpn = query_params
                .iter()
                .filter(|e| e.0 == "target-snpn")
                .map(|e| e.1.to_owned())
                .nth(0);
            let param_target_snpn = match param_target_snpn {
                Some(param_target_snpn) => {
                    let param_target_snpn =
                        serde_json::from_str::<models::PlmnIdNid>(&param_target_snpn);
                    match param_target_snpn {
                        Ok(param_target_snpn) => Some(param_target_snpn),
                        Err(e) => return None,
                    }
                }
                None => None,
            };
            let param_requester_snpn_list = query_params
                .iter()
                .filter(|e| e.0 == "requester-snpn-list")
                .map(|e| e.1.to_owned())
                .nth(0);
            let param_requester_snpn_list = match param_requester_snpn_list {
                Some(param_requester_snpn_list) => {
                    let param_requester_snpn_list =
                        serde_json::from_str::<Vec<models::PlmnIdNid>>(&param_requester_snpn_list);
                    match param_requester_snpn_list {
                        Ok(param_requester_snpn_list) => Some(param_requester_snpn_list),
                        Err(e) => return None,
                    }
                }
                None => None,
            };
            let param_af_ee_data = query_params
                .iter()
                .filter(|e| e.0 == "af-ee-data")
                .map(|e| e.1.to_owned())
                .nth(0);
            let param_af_ee_data = match param_af_ee_data {
                Some(param_af_ee_data) => {
                    let param_af_ee_data =
                        serde_json::from_str::<models::AfEventExposureData>(&param_af_ee_data);
                    match param_af_ee_data {
                        Ok(param_af_ee_data) => Some(param_af_ee_data),
                        Err(e) => return None,
                    }
                }
                None => None,
            };
            let param_w_agf_info = query_params
                .iter()
                .filter(|e| e.0 == "w-agf-info")
                .map(|e| e.1.to_owned())
                .nth(0);
            let param_w_agf_info = match param_w_agf_info {
                Some(param_w_agf_info) => {
                    let param_w_agf_info =
                        serde_json::from_str::<models::WAgfInfo1>(&param_w_agf_info);
                    match param_w_agf_info {
                        Ok(param_w_agf_info) => Some(param_w_agf_info),
                        Err(e) => return None,
                    }
                }
                None => None,
            };
            let param_tngf_info = query_params
                .iter()
                .filter(|e| e.0 == "tngf-info")
                .map(|e| e.1.to_owned())
                .nth(0);
            let param_tngf_info = match param_tngf_info {
                Some(param_tngf_info) => {
                    let param_tngf_info =
                        serde_json::from_str::<models::TngfInfo1>(&param_tngf_info);
                    match param_tngf_info {
                        Ok(param_tngf_info) => Some(param_tngf_info),
                        Err(e) => return None,
                    }
                }
                None => None,
            };
            let param_twif_info = query_params
                .iter()
                .filter(|e| e.0 == "twif-info")
                .map(|e| e.1.to_owned())
                .nth(0);
            let param_twif_info = match param_twif_info {
                Some(param_twif_info) => {
                    let param_twif_info =
                        serde_json::from_str::<models::TwifInfo1>(&param_twif_info);
                    match param_twif_info {
                        Ok(param_twif_info) => Some(param_twif_info),
                        Err(e) => return None,
                    }
                }
                None => None,
            };
            let param_target_nf_set_id = query_params
                .iter()
                .filter(|e| e.0 == "target-nf-set-id")
                .map(|e| e.1.to_owned())
                .nth(0);
            let param_target_nf_set_id = match param_target_nf_set_id {
                Some(param_target_nf_set_id) => {
                    let param_target_nf_set_id =
                        <String as std::str::FromStr>::from_str(&param_target_nf_set_id);
                    match param_target_nf_set_id {
                        Ok(param_target_nf_set_id) => Some(param_target_nf_set_id),
                        Err(e) => return None,
                    }
                }
                None => None,
            };
            let param_target_nf_service_set_id = query_params
                .iter()
                .filter(|e| e.0 == "target-nf-service-set-id")
                .map(|e| e.1.to_owned())
                .nth(0);
            let param_target_nf_service_set_id = match param_target_nf_service_set_id {
                Some(param_target_nf_service_set_id) => {
                    let param_target_nf_service_set_id =
                        <String as std::str::FromStr>::from_str(&param_target_nf_service_set_id);
                    match param_target_nf_service_set_id {
                        Ok(param_target_nf_service_set_id) => Some(param_target_nf_service_set_id),
                        Err(e) => return None,
                    }
                }
                None => None,
            };
            let param_nef_id = query_params
                .iter()
                .filter(|e| e.0 == "nef-id")
                .map(|e| e.1.to_owned())
                .nth(0);
            let param_nef_id = match param_nef_id {
                Some(param_nef_id) => {
                    let param_nef_id = <String as std::str::FromStr>::from_str(&param_nef_id);
                    match param_nef_id {
                        Ok(param_nef_id) => Some(param_nef_id),
                        Err(e) => return None,
                    }
                }
                None => None,
            };
            let param_notification_type = query_params
                .iter()
                .filter(|e| e.0 == "notification-type")
                .map(|e| e.1.to_owned())
                .nth(0);
            let param_notification_type = match param_notification_type {
                Some(param_notification_type) => {
                    let param_notification_type =
                        <models::NotificationType as std::str::FromStr>::from_str(
                            &param_notification_type,
                        );
                    match param_notification_type {
                        Ok(param_notification_type) => Some(param_notification_type),
                        Err(e) => return None,
                    }
                }
                None => None,
            };
            let param_n1_msg_class = query_params
                .iter()
                .filter(|e| e.0 == "n1-msg-class")
                .map(|e| e.1.to_owned())
                .nth(0);
            let param_n1_msg_class = match param_n1_msg_class {
                Some(param_n1_msg_class) => {
                    let param_n1_msg_class =
                        <models::N1MessageClass as std::str::FromStr>::from_str(
                            &param_n1_msg_class,
                        );
                    match param_n1_msg_class {
                        Ok(param_n1_msg_class) => Some(param_n1_msg_class),
                        Err(e) => return None,
                    }
                }
                None => None,
            };
            let param_n2_info_class = query_params
                .iter()
                .filter(|e| e.0 == "n2-info-class")
                .map(|e| e.1.to_owned())
                .nth(0);
            let param_n2_info_class = match param_n2_info_class {
                Some(param_n2_info_class) => {
                    let param_n2_info_class =
                        <models::N2InformationClass as std::str::FromStr>::from_str(
                            &param_n2_info_class,
                        );
                    match param_n2_info_class {
                        Ok(param_n2_info_class) => Some(param_n2_info_class),
                        Err(e) => return None,
                    }
                }
                None => None,
            };
            let param_serving_scope: Vec<String> = query_params
                .iter()
                .filter(|e| e.0 == "serving-scope")
                .map(|e| e.1.to_owned())
                .filter_map(|param_serving_scope| param_serving_scope.parse().ok())
                .collect::<Vec<_>>();
            let param_serving_scope = if !param_serving_scope.is_empty() {
                Some(param_serving_scope)
            } else {
                None
            };
            let param_imsi = query_params
                .iter()
                .filter(|e| e.0 == "imsi")
                .map(|e| e.1.to_owned())
                .nth(0);
            let param_imsi = match param_imsi {
                Some(param_imsi) => {
                    let param_imsi = <String as std::str::FromStr>::from_str(&param_imsi);
                    match param_imsi {
                        Ok(param_imsi) => Some(param_imsi),
                        Err(e) => return None,
                    }
                }
                None => None,
            };
            let param_ims_private_identity = query_params
                .iter()
                .filter(|e| e.0 == "ims-private-identity")
                .map(|e| e.1.to_owned())
                .nth(0);
            let param_ims_private_identity = match param_ims_private_identity {
                Some(param_ims_private_identity) => {
                    let param_ims_private_identity =
                        <String as std::str::FromStr>::from_str(&param_ims_private_identity);
                    match param_ims_private_identity {
                        Ok(param_ims_private_identity) => Some(param_ims_private_identity),
                        Err(e) => return None,
                    }
                }
                None => None,
            };
            let param_ims_public_identity = query_params
                .iter()
                .filter(|e| e.0 == "ims-public-identity")
                .map(|e| e.1.to_owned())
                .nth(0);
            let param_ims_public_identity = match param_ims_public_identity {
                Some(param_ims_public_identity) => {
                    let param_ims_public_identity =
                        <String as std::str::FromStr>::from_str(&param_ims_public_identity);
                    match param_ims_public_identity {
                        Ok(param_ims_public_identity) => Some(param_ims_public_identity),
                        Err(e) => return None,
                    }
                }
                None => None,
            };
            let param_msisdn = query_params
                .iter()
                .filter(|e| e.0 == "msisdn")
                .map(|e| e.1.to_owned())
                .nth(0);
            let param_msisdn = match param_msisdn {
                Some(param_msisdn) => {
                    let param_msisdn = <String as std::str::FromStr>::from_str(&param_msisdn);
                    match param_msisdn {
                        Ok(param_msisdn) => Some(param_msisdn),
                        Err(e) => return None,
                    }
                }
                None => None,
            };
            let param_preferred_api_versions = query_params
                .iter()
                .filter(|e| e.0 == "preferred-api-versions")
                .map(|e| e.1.to_owned())
                .nth(0);
            let param_preferred_api_versions = match param_preferred_api_versions {
                Some(param_preferred_api_versions) => {
                    let param_preferred_api_versions =
                        serde_json::from_str::<std::collections::HashMap<String, String>>(
                            &param_preferred_api_versions,
                        );
                    match param_preferred_api_versions {
                        Ok(param_preferred_api_versions) => Some(param_preferred_api_versions),
                        Err(e) => return None,
                    }
                }
                None => None,
            };
            let param_v2x_support_ind = query_params
                .iter()
                .filter(|e| e.0 == "v2x-support-ind")
                .map(|e| e.1.to_owned())
                .nth(0);
            let param_v2x_support_ind = match param_v2x_support_ind {
                Some(param_v2x_support_ind) => {
                    let param_v2x_support_ind =
                        <bool as std::str::FromStr>::from_str(&param_v2x_support_ind);
                    match param_v2x_support_ind {
                        Ok(param_v2x_support_ind) => Some(param_v2x_support_ind),
                        Err(e) => return None,
                    }
                }
                None => None,
            };
            let param_redundant_gtpu = query_params
                .iter()
                .filter(|e| e.0 == "redundant-gtpu")
                .map(|e| e.1.to_owned())
                .nth(0);
            let param_redundant_gtpu = match param_redundant_gtpu {
                Some(param_redundant_gtpu) => {
                    let param_redundant_gtpu =
                        <bool as std::str::FromStr>::from_str(&param_redundant_gtpu);
                    match param_redundant_gtpu {
                        Ok(param_redundant_gtpu) => Some(param_redundant_gtpu),
                        Err(e) => return None,
                    }
                }
                None => None,
            };
            let param_redundant_transport = query_params
                .iter()
                .filter(|e| e.0 == "redundant-transport")
                .map(|e| e.1.to_owned())
                .nth(0);
            let param_redundant_transport = match param_redundant_transport {
                Some(param_redundant_transport) => {
                    let param_redundant_transport =
                        <bool as std::str::FromStr>::from_str(&param_redundant_transport);
                    match param_redundant_transport {
                        Ok(param_redundant_transport) => Some(param_redundant_transport),
                        Err(e) => return None,
                    }
                }
                None => None,
            };
            let param_ipups = query_params
                .iter()
                .filter(|e| e.0 == "ipups")
                .map(|e| e.1.to_owned())
                .nth(0);
            let param_ipups = match param_ipups {
                Some(param_ipups) => {
                    let param_ipups = <bool as std::str::FromStr>::from_str(&param_ipups);
                    match param_ipups {
                        Ok(param_ipups) => Some(param_ipups),
                        Err(e) => return None,
                    }
                }
                None => None,
            };
            let param_scp_domain_list: Vec<String> = query_params
                .iter()
                .filter(|e| e.0 == "scp-domain-list")
                .map(|e| e.1.to_owned())
                .filter_map(|param_scp_domain_list| param_scp_domain_list.parse().ok())
                .collect::<Vec<_>>();
            let param_scp_domain_list = if !param_scp_domain_list.is_empty() {
                Some(param_scp_domain_list)
            } else {
                None
            };
            let param_address_domain = query_params
                .iter()
                .filter(|e| e.0 == "address-domain")
                .map(|e| e.1.to_owned())
                .nth(0);
            let param_address_domain = match param_address_domain {
                Some(param_address_domain) => {
                    let param_address_domain =
                        <String as std::str::FromStr>::from_str(&param_address_domain);
                    match param_address_domain {
                        Ok(param_address_domain) => Some(param_address_domain),
                        Err(e) => return None,
                    }
                }
                None => None,
            };
            let param_ipv4_addr = query_params
                .iter()
                .filter(|e| e.0 == "ipv4-addr")
                .map(|e| e.1.to_owned())
                .nth(0);
            let param_ipv4_addr = match param_ipv4_addr {
                Some(param_ipv4_addr) => {
                    let param_ipv4_addr = <String as std::str::FromStr>::from_str(&param_ipv4_addr);
                    match param_ipv4_addr {
                        Ok(param_ipv4_addr) => Some(param_ipv4_addr),
                        Err(e) => return None,
                    }
                }
                None => None,
            };
            let param_ipv6_prefix = query_params
                .iter()
                .filter(|e| e.0 == "ipv6-prefix")
                .map(|e| e.1.to_owned())
                .nth(0);
            let param_ipv6_prefix = match param_ipv6_prefix {
                Some(param_ipv6_prefix) => {
                    let param_ipv6_prefix =
                        <String as std::str::FromStr>::from_str(&param_ipv6_prefix);
                    match param_ipv6_prefix {
                        Ok(param_ipv6_prefix) => Some(param_ipv6_prefix),
                        Err(e) => return None,
                    }
                }
                None => None,
            };
            let param_served_nf_set_id = query_params
                .iter()
                .filter(|e| e.0 == "served-nf-set-id")
                .map(|e| e.1.to_owned())
                .nth(0);
            let param_served_nf_set_id = match param_served_nf_set_id {
                Some(param_served_nf_set_id) => {
                    let param_served_nf_set_id =
                        <String as std::str::FromStr>::from_str(&param_served_nf_set_id);
                    match param_served_nf_set_id {
                        Ok(param_served_nf_set_id) => Some(param_served_nf_set_id),
                        Err(e) => return None,
                    }
                }
                None => None,
            };
            let param_remote_plmn_id = query_params
                .iter()
                .filter(|e| e.0 == "remote-plmn-id")
                .map(|e| e.1.to_owned())
                .nth(0);
            let param_remote_plmn_id = match param_remote_plmn_id {
                Some(param_remote_plmn_id) => {
                    let param_remote_plmn_id =
                        serde_json::from_str::<models::PlmnId>(&param_remote_plmn_id);
                    match param_remote_plmn_id {
                        Ok(param_remote_plmn_id) => Some(param_remote_plmn_id),
                        Err(e) => return None,
                    }
                }
                None => None,
            };
            let param_data_forwarding = query_params
                .iter()
                .filter(|e| e.0 == "data-forwarding")
                .map(|e| e.1.to_owned())
                .nth(0);
            let param_data_forwarding = match param_data_forwarding {
                Some(param_data_forwarding) => {
                    let param_data_forwarding =
                        <bool as std::str::FromStr>::from_str(&param_data_forwarding);
                    match param_data_forwarding {
                        Ok(param_data_forwarding) => Some(param_data_forwarding),
                        Err(e) => return None,
                    }
                }
                None => None,
            };
            let param_preferred_full_plmn = query_params
                .iter()
                .filter(|e| e.0 == "preferred-full-plmn")
                .map(|e| e.1.to_owned())
                .nth(0);
            let param_preferred_full_plmn = match param_preferred_full_plmn {
                Some(param_preferred_full_plmn) => {
                    let param_preferred_full_plmn =
                        <bool as std::str::FromStr>::from_str(&param_preferred_full_plmn);
                    match param_preferred_full_plmn {
                        Ok(param_preferred_full_plmn) => Some(param_preferred_full_plmn),
                        Err(e) => return None,
                    }
                }
                None => None,
            };
            let param_requester_features = query_params
                .iter()
                .filter(|e| e.0 == "requester-features")
                .map(|e| e.1.to_owned())
                .nth(0);
            let param_requester_features = match param_requester_features {
                Some(param_requester_features) => {
                    let param_requester_features =
                        <String as std::str::FromStr>::from_str(&param_requester_features);
                    match param_requester_features {
                        Ok(param_requester_features) => Some(param_requester_features),
                        Err(e) => return None,
                    }
                }
                None => None,
            };
            let param_realm_id = query_params
                .iter()
                .filter(|e| e.0 == "realm-id")
                .map(|e| e.1.to_owned())
                .nth(0);
            let param_realm_id = match param_realm_id {
                Some(param_realm_id) => {
                    let param_realm_id = <String as std::str::FromStr>::from_str(&param_realm_id);
                    match param_realm_id {
                        Ok(param_realm_id) => Some(param_realm_id),
                        Err(e) => return None,
                    }
                }
                None => None,
            };
            let param_storage_id = query_params
                .iter()
                .filter(|e| e.0 == "storage-id")
                .map(|e| e.1.to_owned())
                .nth(0);
            let param_storage_id = match param_storage_id {
                Some(param_storage_id) => {
                    let param_storage_id =
                        <String as std::str::FromStr>::from_str(&param_storage_id);
                    match param_storage_id {
                        Ok(param_storage_id) => Some(param_storage_id),
                        Err(e) => return None,
                    }
                }
                None => None,
            };
            let param_vsmf_support_ind = query_params
                .iter()
                .filter(|e| e.0 == "vsmf-support-ind")
                .map(|e| e.1.to_owned())
                .nth(0);
            let param_vsmf_support_ind = match param_vsmf_support_ind {
                Some(param_vsmf_support_ind) => {
                    let param_vsmf_support_ind =
                        <bool as std::str::FromStr>::from_str(&param_vsmf_support_ind);
                    match param_vsmf_support_ind {
                        Ok(param_vsmf_support_ind) => Some(param_vsmf_support_ind),
                        Err(e) => return None,
                    }
                }
                None => None,
            };

            let fqdn = match param_requester_nf_instance_fqdn.as_ref() {
                Some(ref x) => x.to_string(),
                None => "None".to_string(),
            };
            let uuid = match param_requester_nf_instance_id.as_ref() {
                Some(ref x) => x.to_string(),
                None => "None".to_string(),
            };
            let sndr = match param_requester_snssais.clone() {
                Some(ref x) => x.iter().map(|x| serde_json::to_string(x).unwrap()).collect::<Vec<String>>(),
                None => vec!["None".to_string()],
            };
            let sndr_plmn = match param_target_plmn_list.clone() {
                Some(ref x) => x.iter().map(|x| serde_json::to_string(x).unwrap()).collect::<Vec<String>>(),
                None => vec!["None".to_string()],
            };
            let msg = serde_json::json!({
                "request_type" : "discovery",
                "FQDN": fqdn,
                "uuid": uuid,
                "target_type": param_target_nf_type,
                "target_plmn": sndr_plmn,
                "requester_snssai" :sndr,
               // // "hash": "0"
            });
            return Some(jmap_hash(msg));
        }

        // DeregisterNFInstance - DELETE /nnrf-nfm/v1/nf-instances/{nfInstanceID}
        &hyper::Method::DELETE if path.matched(paths::ID_NNRF_NFM_V1_NF_INSTANCES_NFINSTANCEID) => {
            // Path parameters
            let path: &str = &uri.path().to_string();
            let path_params =
                    paths::REGEX_NNRF_NFM_V1_NF_INSTANCES_NFINSTANCEID
                    .captures(&path)
                    .unwrap_or_else(||
                        panic!("Path {} matched RE NNRF_NFM_V1_NF_INSTANCES_NFINSTANCEID in set but failed match against \"{}\"", path, paths::REGEX_NNRF_NFM_V1_NF_INSTANCES_NFINSTANCEID.as_str())
                    );

            let param_nf_instance_id =
                match percent_encoding::percent_decode(path_params["nfInstanceID"].as_bytes())
                    .decode_utf8()
                {
                    Ok(param_nf_instance_id) => match param_nf_instance_id.parse::<uuid::Uuid>() {
                        Ok(param_nf_instance_id) => param_nf_instance_id,
                        Err(e) => return None,
                    },
                    Err(_) => return None,
                };
            let msg = serde_json::json!({
                "request_type" : "de_register_nf",
                "uuid": param_nf_instance_id.to_string(),
               // // "hash": "0",
            });
            return Some(jmap_hash(msg));
        }

        // UpdateNFInstance - PATCH /nnrf-nfm/v1/nf-instances/{nfInstanceID}
        &hyper::Method::PATCH if path.matched(paths::ID_NNRF_NFM_V1_NF_INSTANCES_NFINSTANCEID) => {
            // Path parameters
            let path: &str = &uri.path().to_string();
            let path_params =
                    paths::REGEX_NNRF_NFM_V1_NF_INSTANCES_NFINSTANCEID
                    .captures(&path)
                    .unwrap_or_else(||
                        panic!("Path {} matched RE NNRF_NFM_V1_NF_INSTANCES_NFINSTANCEID in set but failed match against \"{}\"", path, paths::REGEX_NNRF_NFM_V1_NF_INSTANCES_NFINSTANCEID.as_str())
                    );

            let param_nf_instance_id =
                match percent_encoding::percent_decode(path_params["nfInstanceID"].as_bytes())
                    .decode_utf8()
                {
                    Ok(param_nf_instance_id) => match param_nf_instance_id.parse::<uuid::Uuid>() {
                        Ok(param_nf_instance_id) => param_nf_instance_id,
                        Err(e) => return None,
                    },
                    Err(_) => return None,
                };

            // Header parameters
            let param_content_encoding = headers.get(HeaderName::from_static("content-encoding"));

            let param_content_encoding = match param_content_encoding {
                Some(v) => {
                    match nnrf_openapi::header::IntoHeaderValue::<String>::try_from((*v).clone()) {
                        Ok(result) => Some(result.0),
                        Err(err) => {
                            return None;
                        }
                    }
                }
                None => None,
            };
            let param_accept_encoding = headers.get(HeaderName::from_static("accept-encoding"));

            let param_accept_encoding = match param_accept_encoding {
                Some(v) => {
                    match nnrf_openapi::header::IntoHeaderValue::<String>::try_from((*v).clone()) {
                        Ok(result) => Some(result.0),
                        Err(err) => {
                            return None;
                        }
                    }
                }
                None => None,
            };
            let param_if_match = headers.get(HeaderName::from_static("if-match"));

            let param_if_match = match param_if_match {
                Some(v) => {
                    match nnrf_openapi::header::IntoHeaderValue::<String>::try_from((*v).clone()) {
                        Ok(result) => Some(result.0),
                        Err(err) => {
                            return None;
                        }
                    }
                }
                None => None,
            };

            // Body parameters (note that non-required body parameters will ignore garbage
            // values, rather than causing a 400 response). Produce warning header and logs for
            // any unused fields.
            let mut unused_elements = Vec::new();
            let param_patch_item: Option<Vec<models::PatchItem>> = if !body.is_empty() {
                let deserializer = &mut serde_json::Deserializer::from_slice(&*body);
                match serde_ignored::deserialize(deserializer, |path| {
                    warn!("Ignoring unknown field in body: {}", path);
                    unused_elements.push(path.to_string());
                }) {
                    Ok(param_patch_item) => param_patch_item,
                    Err(e) => return None,
                }
            } else {
                None
            };
            let param_patch_item = match param_patch_item {
                Some(param_patch_item) => param_patch_item,
                None => return None,
            };
            let msg = serde_json::json!({
                "request_type" : "update_nf",
                "uuid": param_nf_instance_id.to_string(),
               // // "hash": format!("{:x}" ,md5::compute(serde_json::to_string(&param_patch_item.clone())?))
            });
            return Some(jmap_hash(msg));
        }

        // RegisterNFInstance - PUT /nnrf-nfm/v1/nf-instances/{nfInstanceID}
        &hyper::Method::PUT if path.matched(paths::ID_NNRF_NFM_V1_NF_INSTANCES_NFINSTANCEID) => {
            // Path parameters

            let path: &str = &uri.path().to_string();
            let path_params =
					paths::REGEX_NNRF_NFM_V1_NF_INSTANCES_NFINSTANCEID
					.captures(&path)
					.unwrap_or_else(||
						panic!("Path {} matched RE NNRF_NFM_V1_NF_INSTANCES_NFINSTANCEID in set but failed match against \"{}\"", path, paths::REGEX_NNRF_NFM_V1_NF_INSTANCES_NFINSTANCEID.as_str())
					);

            let param_nf_instance_id =
                match percent_encoding::percent_decode(path_params["nfInstanceID"].as_bytes())
                    .decode_utf8()
                {
                    Ok(param_nf_instance_id) => match param_nf_instance_id.parse::<uuid::Uuid>() {
                        Ok(param_nf_instance_id) => param_nf_instance_id,
                        Err(e) => return None,
                    },
                    Err(_) => return None,
                };

            // Header parameters
            let param_content_encoding = headers.get(HeaderName::from_static("content-encoding"));

            let param_content_encoding = match param_content_encoding {
                Some(v) => {
                    match nnrf_openapi::header::IntoHeaderValue::<String>::try_from((*v).clone()) {
                        Ok(result) => Some(result.0),
                        Err(err) => {
                            return None;
                        }
                    }
                }
                None => None,
            };
            let param_accept_encoding = headers.get(HeaderName::from_static("accept-encoding"));

            let param_accept_encoding = match param_accept_encoding {
                Some(v) => {
                    match nnrf_openapi::header::IntoHeaderValue::<String>::try_from((*v).clone()) {
                        Ok(result) => Some(result.0),
                        Err(err) => {
                            return None;
                        }
                    }
                }
                None => None,
            };

            // Body parameters (note that non-required body parameters will ignore garbage
            // values, rather than causing a 400 response). Produce warning header and logs for
            // any unused fields.
            let mut unused_elements = Vec::new();
            let param_nf_profile1: Option<models::NfProfile1> = if !body.is_empty() {
                let deserializer = &mut serde_json::Deserializer::from_slice(&*body);
                match serde_ignored::deserialize(deserializer, |path| {
                    warn!("Ignoring unknown field in body: {}", path);
                    unused_elements.push(path.to_string());
                }) {
                    Ok(param_nf_profile1) => param_nf_profile1,
                    Err(e) => return None,
                }
            } else {
                None
            };
            let param_nf_profile1 = match param_nf_profile1 {
                Some(param_nf_profile1) => param_nf_profile1,
                None => return None,
            };
            // log::info!("{:?}", param_nf_profile1.s_nssais.clone());
            let slices: Vec<String> = match param_nf_profile1.s_nssais.clone() {
                Some(ref a) => a.iter().map(|x| serde_json::to_string(x).unwrap()).collect(),
                None => ["None".to_string()].to_vec(),
            };
            let allowed_slices: Vec<String> = match param_nf_profile1.allowed_nssais.clone() {
                Some(ref a) => a.iter().map(|x| serde_json::to_string(x).unwrap()).collect(),
                None => ["None".to_string()].to_vec(),
            };
            let plmns: Vec<String> = match param_nf_profile1.plmn_list.clone() {
                Some(ref a) => a.iter().map(|x| serde_json::to_string(x).unwrap()).collect(),
                None => ["None".to_string()].to_vec(),
            };
            let fqdn: String = match param_nf_profile1.fqdn {
                Some(ref a) => a.to_string(),
                None => "None".to_string(),
            };
            let nf_status: String = param_nf_profile1.nf_status.to_string();
            let nf_type: String = param_nf_profile1.nf_type.to_string();

            let msg = serde_json::json!({
                "request_type" : "register_nf",
                "FQDN": fqdn,
                "UUID": param_nf_instance_id.to_string(),
                "SNSSAI": slices,
                "allowed_snssai": allowed_slices,
                "nf_status": nf_status,
                "nf_type": nf_type,
                "plmns": plmns,
                "profile": serde_json::to_string(&param_nf_profile1).unwrap()
                // "hash": format!("{:x}" ,md5::compute(serde_json::to_string(&param_nf_profile1.clone())?))
            });
            // log::info!("Here {:?}", msg);
            return Some(jmap_hash(msg));
        }

        // AccessTokenRequest - POST /oauth2/token
        &hyper::Method::POST if path.matched(paths::ID_OAUTH2_TOKEN) => {
            // Header parameters
            let param_content_encoding = headers.get(HeaderName::from_static("content-encoding"));

            let param_content_encoding = match param_content_encoding {
                Some(v) => {
                    match nnrf_openapi::header::IntoHeaderValue::<String>::try_from((*v).clone()) {
                        Ok(result) => Some(result.0),
                        Err(err) => {
                            return None;
                        }
                    }
                }
                None => None,
            };
            let param_accept_encoding = headers.get(HeaderName::from_static("accept-encoding"));

            let param_accept_encoding = match param_accept_encoding {
                Some(v) => {
                    match nnrf_openapi::header::IntoHeaderValue::<String>::try_from((*v).clone()) {
                        Ok(result) => Some(result.0),
                        Err(err) => {
                            return None;
                        }
                    }
                }
                None => None,
            };

            // Body parameters (note that non-required body parameters will ignore garbage
            // values, rather than causing a 400 response). Produce warning header and logs for
            // any unused fields.
            let mut unused_elements = Vec::new();
            // #[cfg(feature = "logs")]
            // let hash = format!("{:x}", md5::compute(body.clone()));
            let param_access_token_req: Option<models::AccessTokenReq> = if !body.is_empty() {
                let deserializer = &mut serde_json::Deserializer::from_slice(&*body);
                match serde_ignored::deserialize(deserializer, |path| {
                    warn!("Ignoring unknown field in body: {}", path);
                    unused_elements.push(path.to_string());
                }) {
                    Ok(param_access_token_req) => param_access_token_req,
                    Err(e) => return None,
                }
            } else {
                None
            };
            let param_access_token_req = match param_access_token_req {
                Some(param_access_token_req) => param_access_token_req,
                None => return None,
            };

            let sndr = match &param_access_token_req.requester_snssai_list {
                Some(ref x) => x.iter().map(|x| serde_json::to_string(x).unwrap()).collect::<Vec<String>>(),
                None => vec!["None".to_string()],
            };
            let targ = match &param_access_token_req.target_snssai_list {
                Some(ref x) => x.iter().map(|x| serde_json::to_string(x).unwrap()).collect::<Vec<String>>(),
                None => vec!["None".to_string()],
            };
            let send_type = match &param_access_token_req.nf_type {
                Some(ref x) => x.to_string(),
                None => "None".to_string(),
            };
            let send_fqdn = match &param_access_token_req.requester_fqdn {
                Some(ref x) => x.to_string(),
                None => "None".to_string(),
            };
            let tar_type = match &param_access_token_req.target_nf_type {
                Some(ref x) => x.to_string(),
                None => "None".to_string(),
            };
            let tar_id = match &param_access_token_req.target_nf_instance_id {
                Some(ref x) => x.to_string(),
                None => "None".to_string(),
            };

            let msg = serde_json::json! ({
                "request_type": "access_token_request",
                "sender_id": &param_access_token_req.nf_instance_id.to_string(),
                "sender_fqdn": send_fqdn,
                "target_type": tar_type,
                "target_id": tar_id,
                "sender_snssai": sndr,
                "target_snssai": targ,
               // // "hash": format!("{:x}" ,md5::compute(serde_json::to_string(&param_access_token_req.clone())?))
            });
            return Some(jmap_hash(msg));
        }

        // NSSAIAvailabilityPut - PUT /nnssf-nssaiavailability/v1/nssai-availability/{nfId}
        &hyper::Method::PUT
            if path.matched(paths::ID_NNSSF_NSSAIAVAILABILITY_V1_NSSAI_AVAILABILITY_NFID) =>
        {
            // Path parameters
            let path: &str = &uri.path().to_string();
            let path_params =
                    paths::REGEX_NNSSF_NSSAIAVAILABILITY_V1_NSSAI_AVAILABILITY_NFID
                    .captures(&path)
                    .unwrap_or_else(||
                        panic!("Path {} matched RE NNSSF_NSSAIAVAILABILITY_V1_NSSAI_AVAILABILITY_NFID in set but failed match against \"{}\"", path, paths::REGEX_NNSSF_NSSAIAVAILABILITY_V1_NSSAI_AVAILABILITY_NFID.as_str())
                    );

            let param_nf_id = match percent_encoding::percent_decode(path_params["nfId"].as_bytes())
                .decode_utf8()
            {
                Ok(param_nf_id) => match param_nf_id.parse::<uuid::Uuid>() {
                    Ok(param_nf_id) => param_nf_id,
                    Err(e) => return None,
                },
                Err(_) => return None,
            };

            // Header parameters
            let param_content_encoding = headers.get(HeaderName::from_static("content-encoding"));

            let param_content_encoding = match param_content_encoding {
                Some(v) => {
                    match nnssf_openapi::header::IntoHeaderValue::<String>::try_from((*v).clone()) {
                        Ok(result) => Some(result.0),
                        Err(err) => {
                            return None;
                        }
                    }
                }
                None => None,
            };
            let param_accept_encoding = headers.get(HeaderName::from_static("accept-encoding"));

            let param_accept_encoding = match param_accept_encoding {
                Some(v) => {
                    match nnssf_openapi::header::IntoHeaderValue::<String>::try_from((*v).clone()) {
                        Ok(result) => Some(result.0),
                        Err(err) => {
                            return None;
                        }
                    }
                }
                None => None,
            };

            // Body parameters (note that non-required body parameters will ignore garbage
            // values, rather than causing a 400 response). Produce warning header and logs for
            // any unused fields.
            let mut unused_elements = Vec::new();
            let param_nssai_availability_info: Option<models::NssaiAvailabilityInfo> =
                if !body.is_empty() {
                    let deserializer = &mut serde_json::Deserializer::from_slice(&*body);
                    match serde_ignored::deserialize(deserializer, |path| {
                        warn!("Ignoring unknown field in body: {}", path);
                        unused_elements.push(path.to_string());
                    }) {
                        Ok(param_nssai_availability_info) => param_nssai_availability_info,
                        Err(e) => return None,
                    }
                } else {
                    None
                };
            let param_nssai_availability_info = match param_nssai_availability_info {
                Some(param_nssai_availability_info) => param_nssai_availability_info,
                None => return None,
            };

            let msg = serde_json::json!({
                "request_type" : "nssai_avail_put",
                "nf_id": param_nf_id.to_string(),
               // // "hash": format!("{:x}" ,md5::compute(serde_json::to_string(&param_nssai_availability_info.clone())?))
            });
            return Some(jmap_hash(msg));
        }

        // NSSAIAvailabilityDelete - DELETE /nnssf-nssaiavailability/v1/nssai-availability/{nfId}
        &hyper::Method::DELETE
            if path.matched(paths::ID_NNSSF_NSSAIAVAILABILITY_V1_NSSAI_AVAILABILITY_NFID) =>
        {
            // Path parameters
            let path: &str = &uri.path().to_string();
            let path_params =
					paths::REGEX_NNSSF_NSSAIAVAILABILITY_V1_NSSAI_AVAILABILITY_NFID
					.captures(&path)
					.unwrap_or_else(||
						panic!("Path {} matched RE NNSSF_NSSAIAVAILABILITY_V1_NSSAI_AVAILABILITY_NFID in set but failed match against \"{}\"", path, paths::REGEX_NNSSF_NSSAIAVAILABILITY_V1_NSSAI_AVAILABILITY_NFID.as_str())
					);

            let param_nf_id = match percent_encoding::percent_decode(path_params["nfId"].as_bytes())
                .decode_utf8()
            {
                Ok(param_nf_id) => match param_nf_id.parse::<String>() {
                    Ok(param_nf_id) => param_nf_id,
                    Err(e) => return None,
                },
                Err(_) => return None,
            };
            let msg = serde_json::json!({
                "request_type": "nssai_avail_delete",
                "nf_id": param_nf_id.clone(),
                // "hash": "0"
            });
            None
        }

        // NSSelectionGet - GET /nnssf-nsselection/v2/network-slice-information
        &hyper::Method::GET
            if path.matched(paths::ID_NNSSF_NSSELECTION_V2_NETWORK_SLICE_INFORMATION) =>
        {
            // Query parameters (note that non-required or collection query parameters will ignore garbage values, rather than causing a 400 response)
            let query_params = form_urlencoded::parse(uri.query().unwrap_or_default().as_bytes())
                .collect::<Vec<_>>();
            let param_nf_type = query_params
                .iter()
                .filter(|e| e.0 == "nf-type")
                .map(|e| e.1.to_owned())
                .nth(0);
            let param_nf_type = match param_nf_type {
                Some(param_nf_type) => {
                    let param_nf_type =
                        <models::NfType as std::str::FromStr>::from_str(&param_nf_type);
                    match param_nf_type {
                        Ok(param_nf_type) => Some(param_nf_type),
                        Err(e) => return None,
                    }
                }
                None => None,
            };
            let param_nf_type = match param_nf_type {
                Some(param_nf_type) => param_nf_type,
                None => return None,
            };
            let param_nf_id = query_params
                .iter()
                .filter(|e| e.0 == "nf-id")
                .map(|e| e.1.to_owned())
                .nth(0);
            let param_nf_id = match param_nf_id {
                Some(param_nf_id) => {
                    let param_nf_id = <uuid::Uuid as std::str::FromStr>::from_str(&param_nf_id);
                    match param_nf_id {
                        Ok(param_nf_id) => Some(param_nf_id),
                        Err(e) => return None,
                    }
                }
                None => None,
            };
            let param_nf_id = match param_nf_id {
                Some(param_nf_id) => param_nf_id,
                None => return None,
            };
            let param_slice_info_request_for_registration = query_params
                .iter()
                .filter(|e| e.0 == "slice-info-request-for-registration")
                .map(|e| e.1.to_owned())
                .nth(0);
            let param_slice_info_request_for_registration =
                match param_slice_info_request_for_registration {
                    Some(param_slice_info_request_for_registration) => {
                        let param_slice_info_request_for_registration =
                            serde_json::from_str::<models::SliceInfoForRegistration>(
                                &param_slice_info_request_for_registration,
                            );
                        match param_slice_info_request_for_registration {
                            Ok(param_slice_info_request_for_registration) => {
                                Some(param_slice_info_request_for_registration)
                            }
                            Err(e) => return None,
                        }
                    }
                    None => None,
                };
            let param_slice_info_request_for_pdu_session = query_params
                .iter()
                .filter(|e| e.0 == "slice-info-request-for-pdu-session")
                .map(|e| e.1.to_owned())
                .nth(0);
            let param_slice_info_request_for_pdu_session =
                match param_slice_info_request_for_pdu_session {
                    Some(param_slice_info_request_for_pdu_session) => {
                        let param_slice_info_request_for_pdu_session =
                            serde_json::from_str::<models::SliceInfoForPduSession>(
                                &param_slice_info_request_for_pdu_session,
                            );
                        match param_slice_info_request_for_pdu_session {
                            Ok(param_slice_info_request_for_pdu_session) => {
                                Some(param_slice_info_request_for_pdu_session)
                            }
                            Err(e) => return None,
                        }
                    }
                    None => None,
                };
            let param_slice_info_request_for_ue_cu = query_params
                .iter()
                .filter(|e| e.0 == "slice-info-request-for-ue-cu")
                .map(|e| e.1.to_owned())
                .nth(0);
            let param_slice_info_request_for_ue_cu = match param_slice_info_request_for_ue_cu {
                Some(param_slice_info_request_for_ue_cu) => {
                    let param_slice_info_request_for_ue_cu =
                        serde_json::from_str::<models::SliceInfoForUeConfigurationUpdate>(
                            &param_slice_info_request_for_ue_cu,
                        );
                    match param_slice_info_request_for_ue_cu {
                        Ok(param_slice_info_request_for_ue_cu) => {
                            Some(param_slice_info_request_for_ue_cu)
                        }
                        Err(e) => return None,
                    }
                }
                None => None,
            };
            let param_home_plmn_id = query_params
                .iter()
                .filter(|e| e.0 == "home-plmn-id")
                .map(|e| e.1.to_owned())
                .nth(0);
            let param_home_plmn_id = match param_home_plmn_id {
                Some(param_home_plmn_id) => {
                    let param_home_plmn_id =
                        serde_json::from_str::<models::PlmnId>(&param_home_plmn_id);
                    match param_home_plmn_id {
                        Ok(param_home_plmn_id) => Some(param_home_plmn_id),
                        Err(e) => return None,
                    }
                }
                None => None,
            };
            let param_tai = query_params
                .iter()
                .filter(|e| e.0 == "tai")
                .map(|e| e.1.to_owned())
                .nth(0);
            let param_tai = match param_tai {
                Some(param_tai) => {
                    let param_tai = serde_json::from_str::<models::Tai>(&param_tai);
                    match param_tai {
                        Ok(param_tai) => Some(param_tai),
                        Err(e) => return None,
                    }
                }
                None => None,
            };
            let param_supported_features = query_params
                .iter()
                .filter(|e| e.0 == "supported-features")
                .map(|e| e.1.to_owned())
                .nth(0);
            let param_supported_features = match param_supported_features {
                Some(param_supported_features) => {
                    let param_supported_features =
                        <String as std::str::FromStr>::from_str(&param_supported_features);
                    match param_supported_features {
                        Ok(param_supported_features) => Some(param_supported_features),
                        Err(e) => return None,
                    }
                }
                None => None,
            };
            let msg = serde_json::json!({
                "request_type" : "nssf_sel_get",
                "nf_id": param_nf_id.to_string(),
                "nf_type": param_nf_type.to_string(),
               // // "hash": "0"
            });
            None
        }

        // Call3GppRegistration - PUT /nudm-uecm/v1/{ueId}/registrations/amf-3gpp-access
        &hyper::Method::PUT
            if path.matched(paths::ID_NUDM_UECM_V1_UEID_REGISTRATIONS_AMF_3GPP_ACCESS) =>
        {
            /*{
                let authorization = match (&context as &dyn Has<Option<Authorization>>).get() {
                    &Some(ref authorization) => authorization,
                    &None => return None,
                };

                // Authorization
                if let Scopes::Some(ref scopes) = authorization.scopes {
                    let required_scopes: std::collections::BTreeSet<String> = vec![
                        "nudm-sdm".to_string(), // Access to the nudm-sdm API
                    ].into_iter().collect();

                    if !required_scopes.is_subset(scopes) {
                        let missing_scopes = required_scopes.difference(scopes);
                        return None;
                    }
                }
            }*/

            // Path parameters
            let path: &str = &uri.path().to_string();
            let path_params =
                    paths::REGEX_NUDM_UECM_V1_UEID_REGISTRATIONS_AMF_3GPP_ACCESS
                    .captures(&path)
                    .unwrap_or_else(||
                        panic!("Path {} matched RE NUDM_UECM_V1_UEID_REGISTRATIONS_AMF_3GPP_ACCESS in set but failed match against \"{}\"", path, paths::REGEX_NUDM_UECM_V1_UEID_REGISTRATIONS_AMF_3GPP_ACCESS.as_str())
                    );

            let param_ue_id = match percent_encoding::percent_decode(path_params["ueId"].as_bytes())
                .decode_utf8()
            {
                Ok(param_ue_id) => match param_ue_id.parse::<String>() {
                    Ok(param_ue_id) => param_ue_id,
                    Err(e) => return None,
                },
                Err(_) => return None,
            };

            // Body parameters (note that non-required body parameters will ignore garbage
            // values, rather than causing a 400 response). Produce warning header and logs for
            // any unused fields.
            let mut unused_elements = Vec::new();
            let param_amf3_gpp_access_registration: Option<models::Amf3GppAccessRegistration> =
                if !body.is_empty() {
                    let deserializer = &mut serde_json::Deserializer::from_slice(&*body);
                    match serde_ignored::deserialize(deserializer, |path| {
                        warn!("Ignoring unknown field in body: {}", path);
                        unused_elements.push(path.to_string());
                    }) {
                        Ok(param_amf3_gpp_access_registration) => {
                            param_amf3_gpp_access_registration
                        }
                        Err(e) => return None,
                    }
                } else {
                    None
                };
            let param_amf3_gpp_access_registration = match param_amf3_gpp_access_registration {
                Some(param_amf3_gpp_access_registration) => param_amf3_gpp_access_registration,
                None => return None,
            };
            let msg = serde_json::json!({
                "request_type": "call3_gpp_registration",
                "supi": param_ue_id,
                "guami": param_amf3_gpp_access_registration.guami.to_string(),
               // // "hash": format!("{:x}", md5::compute(body))
            });
            return Some(jmap_hash(msg));
        }

        // Update3GppRegistration - PATCH /nudm-uecm/v1/{ueId}/registrations/amf-3gpp-access
        &hyper::Method::PATCH
            if path.matched(paths::ID_NUDM_UECM_V1_UEID_REGISTRATIONS_AMF_3GPP_ACCESS) =>
        {
            /*{
                let authorization = match (&context as &dyn Has<Option<Authorization>>).get() {
                    &Some(ref authorization) => authorization,
                    &None => return None,
                };

                // Authorization
                if let Scopes::Some(ref scopes) = authorization.scopes {
                    let required_scopes: std::collections::BTreeSet<String> = vec![
                        "nudm-sdm".to_string(), // Access to the nudm-sdm API
                    ].into_iter().collect();

                    if !required_scopes.is_subset(scopes) {
                        let missing_scopes = required_scopes.difference(scopes);
                        return None;
                    }
                }
            }*/

            // Path parameters
            let path: &str = &uri.path().to_string();
            let path_params =
                    paths::REGEX_NUDM_UECM_V1_UEID_REGISTRATIONS_AMF_3GPP_ACCESS
                    .captures(&path)
                    .unwrap_or_else(||
                        panic!("Path {} matched RE NUDM_UECM_V1_UEID_REGISTRATIONS_AMF_3GPP_ACCESS in set but failed match against \"{}\"", path, paths::REGEX_NUDM_UECM_V1_UEID_REGISTRATIONS_AMF_3GPP_ACCESS.as_str())
                    );

            let param_ue_id = match percent_encoding::percent_decode(path_params["ueId"].as_bytes())
                .decode_utf8()
            {
                Ok(param_ue_id) => match param_ue_id.parse::<String>() {
                    Ok(param_ue_id) => param_ue_id,
                    Err(e) => return None,
                },
                Err(_) => return None,
            };

            // Query parameters (note that non-required or collection query parameters will ignore garbage values, rather than causing a 400 response)
            let query_params = form_urlencoded::parse(uri.query().unwrap_or_default().as_bytes())
                .collect::<Vec<_>>();
            let param_supported_features = query_params
                .iter()
                .filter(|e| e.0 == "supported-features")
                .map(|e| e.1.to_owned())
                .nth(0);
            let param_supported_features = match param_supported_features {
                Some(param_supported_features) => {
                    let param_supported_features =
                        <String as std::str::FromStr>::from_str(&param_supported_features);
                    match param_supported_features {
                        Ok(param_supported_features) => Some(param_supported_features),
                        Err(e) => return None,
                    }
                }
                None => None,
            };

            // Body parameters (note that non-required body parameters will ignore garbage
            // values, rather than causing a 400 response). Produce warning header and logs for
            // any unused fields.
            let mut unused_elements = Vec::new();
            let param_amf3_gpp_access_registration_modification: Option<
                models::Amf3GppAccessRegistrationModification,
            > = if !body.is_empty() {
                let deserializer = &mut serde_json::Deserializer::from_slice(&*body);
                match serde_ignored::deserialize(deserializer, |path| {
                    warn!("Ignoring unknown field in body: {}", path);
                    unused_elements.push(path.to_string());
                }) {
                    Ok(param_amf3_gpp_access_registration_modification) => {
                        param_amf3_gpp_access_registration_modification
                    }
                    Err(e) => return None,
                }
            } else {
                None
            };
            let param_amf3_gpp_access_registration_modification =
                match param_amf3_gpp_access_registration_modification {
                    Some(param_amf3_gpp_access_registration_modification) => {
                        param_amf3_gpp_access_registration_modification
                    }
                    None => return None,
                };
            let msg = serde_json::json!({
                "request_type": "update3_gpp_registration",
                "supi": param_ue_id,
                "guami": param_amf3_gpp_access_registration_modification.guami.to_string(),
               // // "hash": format!("{:x}", md5::compute(serde_json::to_string(&param_amf3_gpp_access_registration_modification)?))
            });
            return Some(jmap_hash(msg));
        }

        // GetAmData - GET /nudm-sdm/v2/{supi}/am-data
        &hyper::Method::GET if path.matched(paths::ID_NUDM_SDM_V2_SUPI_AM_DATA) => {
            /*{
                let authorization = match (&context as &dyn Has<Option<Authorization>>).get() {
                    &Some(ref authorization) => authorization,
                    &None => return None,
                };

                // Authorization
                if let Scopes::Some(ref scopes) = authorization.scopes {
                    let required_scopes: std::collections::BTreeSet<String> = vec![
                        "nudm-sdm".to_string(), // Access to the nudm-sdm API
                    ].into_iter().collect();

                    if !required_scopes.is_subset(scopes) {
                        let missing_scopes = required_scopes.difference(scopes);
                        return None;
                    }
                }
            }*/

            // Path parameters
            let path: &str = &uri.path().to_string();
            let path_params =
					paths::REGEX_NUDM_SDM_V2_SUPI_AM_DATA
					.captures(&path)
					.unwrap_or_else(||
						panic!("Path {} matched RE NUDM_SDM_V2_SUPI_AM_DATA in set but failed match against \"{}\"", path, paths::REGEX_NUDM_SDM_V2_SUPI_AM_DATA.as_str())
					);

            let param_supi = match percent_encoding::percent_decode(path_params["supi"].as_bytes())
                .decode_utf8()
            {
                Ok(param_supi) => match param_supi.parse::<String>() {
                    Ok(param_supi) => param_supi,
                    Err(e) => return None,
                },
                Err(_) => return None,
            };

            // Header parameters
            let param_if_none_match = headers.get(HeaderName::from_static("if-none-match"));

            let param_if_none_match = match param_if_none_match {
                Some(v) => {
                    match nudm_openapi::header::IntoHeaderValue::<String>::try_from((*v).clone()) {
                        Ok(result) => Some(result.0),
                        Err(err) => {
                            return None;
                        }
                    }
                }
                None => None,
            };
            let param_if_modified_since = headers.get(HeaderName::from_static("if-modified-since"));

            let param_if_modified_since = match param_if_modified_since {
                Some(v) => {
                    match nudm_openapi::header::IntoHeaderValue::<String>::try_from((*v).clone()) {
                        Ok(result) => Some(result.0),
                        Err(err) => {
                            return None;
                        }
                    }
                }
                None => None,
            };

            // Query parameters (note that non-required or collection query parameters will ignore garbage values, rather than causing a 400 response)
            let query_params = form_urlencoded::parse(uri.query().unwrap_or_default().as_bytes())
                .collect::<Vec<_>>();
            let param_supported_features = query_params
                .iter()
                .filter(|e| e.0 == "supported-features")
                .map(|e| e.1.to_owned())
                .nth(0);
            let param_supported_features = match param_supported_features {
                Some(param_supported_features) => {
                    let param_supported_features =
                        <String as std::str::FromStr>::from_str(&param_supported_features);
                    match param_supported_features {
                        Ok(param_supported_features) => Some(param_supported_features),
                        Err(e) => return None,
                    }
                }
                None => None,
            };
            let param_plmn_id = query_params
                .iter()
                .filter(|e| e.0 == "plmn-id")
                .map(|e| e.1.to_owned())
                .nth(0);
            let param_plmn_id = match param_plmn_id {
                Some(param_plmn_id) => {
                    let param_plmn_id = serde_json::from_str::<models::PlmnId>(&param_plmn_id);
                    match param_plmn_id {
                        Ok(param_plmn_id) => Some(param_plmn_id),
                        Err(e) => return None,
                    }
                }
                None => None,
            };
            let plmn = match param_plmn_id {
                Some(ref a) => a.to_string(),
                None => "None".to_string(),
            };
            let msg = serde_json::json!({
                "request_type": "get_am_data",
                "supi": param_supi,
                "plmn": plmn,
                // "hash": "0"
            });
            return Some(jmap_hash(msg));
        }

        // ConfirmAuth - POST /nudm-ueau/v1/{supi}/auth-events
        &hyper::Method::POST if path.matched(paths::ID_NUDM_UEAU_V1_SUPI_AUTH_EVENTS) => {
            /*{
                let authorization = match (&context as &dyn Has<Option<Authorization>>).get() {
                    &Some(ref authorization) => authorization,
                    &None => return None,
                };

                // Authorization
                if let Scopes::Some(ref scopes) = authorization.scopes {
                    let required_scopes: std::collections::BTreeSet<String> = vec![
                        "nudm-sdm".to_string(), // Access to the nudm-sdm API
                    ].into_iter().collect();

                    if !required_scopes.is_subset(scopes) {
                        let missing_scopes = required_scopes.difference(scopes);
                        return None;
                    }
                }
            }*/

            // Path parameters
            let path: &str = &uri.path().to_string();
            let path_params =
                    paths::REGEX_NUDM_UEAU_V1_SUPI_AUTH_EVENTS
                    .captures(&path)
                    .unwrap_or_else(||
                        panic!("Path {} matched RE NUDM_UEAU_V1_SUPI_AUTH_EVENTS in set but failed match against \"{}\"", path, paths::REGEX_NUDM_UEAU_V1_SUPI_AUTH_EVENTS.as_str())
                    );

            let param_supi = match percent_encoding::percent_decode(path_params["supi"].as_bytes())
                .decode_utf8()
            {
                Ok(param_supi) => match param_supi.parse::<String>() {
                    Ok(param_supi) => param_supi,
                    Err(e) => return None,
                },
                Err(_) => return None,
            };

            // Body parameters (note that non-required body parameters will ignore garbage
            // values, rather than causing a 400 response). Produce warning header and logs for
            // any unused fields.
            let mut unused_elements = Vec::new();
            let param_auth_event: Option<models::AuthEvent> = if !body.is_empty() {
                let deserializer = &mut serde_json::Deserializer::from_slice(&*body);
                match serde_ignored::deserialize(deserializer, |path| {
                    warn!("Ignoring unknown field in body: {}", path);
                    unused_elements.push(path.to_string());
                }) {
                    Ok(param_auth_event) => param_auth_event,
                    Err(e) => return None,
                }
            } else {
                None
            };
            let param_auth_event = match param_auth_event {
                Some(param_auth_event) => param_auth_event,
                None => return None,
            };
            let msg = serde_json::json!({
                "request_type": "confirm_auth",
                "supi": param_supi,
               // // "hash": format!("{:x}", md5::compute(serde_json::to_string(&param_auth_event)?))
            });
            return Some(jmap_hash(msg));
        }

        // GenerateAuthData - POST /nudm-ueau/v1/{supiOrSuci}/security-information/generate-auth-data
        &hyper::Method::POST
            if path.matched(
                paths::ID_NUDM_UEAU_V1_SUPIORSUCI_SECURITY_INFORMATION_GENERATE_AUTH_DATA,
            ) =>
        {
            /*{
                let authorization = match (&context as &dyn Has<Option<Authorization>>).get() {
                    &Some(ref authorization) => authorization,
                    &None => return None,
                };

                // Authorization
                if let Scopes::Some(ref scopes) = authorization.scopes {
                    let required_scopes: std::collections::BTreeSet<String> = vec![
                        "nudm-sdm".to_string(), // Access to the nudm-sdm API
                    ].into_iter().collect();

                    if !required_scopes.is_subset(scopes) {
                        let missing_scopes = required_scopes.difference(scopes);
                        return None;
                    }
                }
            }*/

            // Path parameters
            let path: &str = &uri.path().to_string();
            let path_params =
                    paths::REGEX_NUDM_UEAU_V1_SUPIORSUCI_SECURITY_INFORMATION_GENERATE_AUTH_DATA
                    .captures(&path)
                    .unwrap_or_else(||
                        panic!("Path {} matched RE NUDM_UEAU_V1_SUPIORSUCI_SECURITY_INFORMATION_GENERATE_AUTH_DATA in set but failed match against \"{}\"", path, paths::REGEX_NUDM_UEAU_V1_SUPIORSUCI_SECURITY_INFORMATION_GENERATE_AUTH_DATA.as_str())
                    );

            let param_supi_or_suci =
                match percent_encoding::percent_decode(path_params["supiOrSuci"].as_bytes())
                    .decode_utf8()
                {
                    Ok(param_supi_or_suci) => match param_supi_or_suci.parse::<String>() {
                        Ok(param_supi_or_suci) => param_supi_or_suci,
                        Err(e) => return None,
                    },
                    Err(_) => return None,
                };

            // Body parameters (note that non-required body parameters will ignore garbage
            // values, rather than causing a 400 response). Produce warning header and logs for
            // any unused fields.
            let mut unused_elements = Vec::new();
            let param_authentication_info_request: Option<models::AuthenticationInfoRequest> =
                if !body.is_empty() {
                    let deserializer = &mut serde_json::Deserializer::from_slice(&*body);
                    match serde_ignored::deserialize(deserializer, |path| {
                        warn!("Ignoring unknown field in body: {}", path);
                        unused_elements.push(path.to_string());
                    }) {
                        Ok(param_authentication_info_request) => param_authentication_info_request,
                        Err(e) => return None,
                    }
                } else {
                    None
                };
            let param_authentication_info_request = match param_authentication_info_request {
                Some(param_authentication_info_request) => param_authentication_info_request,
                None => return None,
            };

            let msg = serde_json::json!({
                "request_type": "generate_auth_data",
                "supi": param_supi_or_suci,
               // // "hash": format!("{:x}", md5::compute(serde_json::to_string(&param_authentication_info_request)?))
            });
            return Some(jmap_hash(msg));
        }

        // GetSmfSelData - GET /nudm-sdm/v2/{supi}/smf-select-data
        &hyper::Method::GET if path.matched(paths::ID_NUDM_SDM_V2_SUPI_SMF_SELECT_DATA) => {
            /*{
                let authorization = match (&context as &dyn Has<Option<Authorization>>).get() {
                    &Some(ref authorization) => authorization,
                    &None => return Ok(Response::builder()
                                            .status(StatusCode::FORBIDDEN)
                                            .body(Body::from("Unauthenticated"))
                                            .expect("Unable to create Authentication Forbidden response")),
                };

                // Authorization
                if let Scopes::Some(ref scopes) = authorization.scopes {
                    let required_scopes: std::collections::BTreeSet<String> = vec![
                        "nudm-sdm".to_string(), // Access to the nudm-sdm API
                    ].into_iter().collect();

                    if !required_scopes.is_subset(scopes) {
                        let missing_scopes = required_scopes.difference(scopes);
                        return Ok(Response::builder()
                            .status(StatusCode::FORBIDDEN)
                            .body(Body::from(missing_scopes.fold(
                                "Insufficient authorization, missing scopes".to_string(),
                                |s, scope| format!("{} {}", s, scope))
                            ))
                            .expect("Unable to create Authentication Insufficient response")
                        );
                    }
                }
            }*/

            // Path parameters
            let path: &str = &uri.path().to_string();
            let path_params =
                    paths::REGEX_NUDM_SDM_V2_SUPI_SMF_SELECT_DATA
                    .captures(&path)
                    .unwrap_or_else(||
                        panic!("Path {} matched RE NUDM_SDM_V2_SUPI_SMF_SELECT_DATA in set but failed match against \"{}\"", path, paths::REGEX_NUDM_SDM_V2_SUPI_SMF_SELECT_DATA.as_str())
                    );

            let param_supi = match percent_encoding::percent_decode(path_params["supi"].as_bytes())
                .decode_utf8()
            {
                Ok(param_supi) => match param_supi.parse::<String>() {
                    Ok(param_supi) => param_supi,
                    Err(e) => return None,
                },
                Err(_) => return None,
            };

            // Header parameters
            let param_if_none_match = headers.get(HeaderName::from_static("if-none-match"));

            let param_if_none_match = match param_if_none_match {
                Some(v) => {
                    match nudm_openapi::header::IntoHeaderValue::<String>::try_from((*v).clone()) {
                        Ok(result) => Some(result.0),
                        Err(err) => {
                            return None;
                        }
                    }
                }
                None => None,
            };
            let param_if_modified_since = headers.get(HeaderName::from_static("if-modified-since"));

            let param_if_modified_since = match param_if_modified_since {
                Some(v) => {
                    match nudm_openapi::header::IntoHeaderValue::<String>::try_from((*v).clone()) {
                        Ok(result) => Some(result.0),
                        Err(err) => {
                            return None;
                        }
                    }
                }
                None => None,
            };

            // Query parameters (note that non-required or collection query parameters will ignore garbage values, rather than causing a 400 response)
            let query_params = form_urlencoded::parse(uri.query().unwrap_or_default().as_bytes())
                .collect::<Vec<_>>();
            let param_supported_features = query_params
                .iter()
                .filter(|e| e.0 == "supported-features")
                .map(|e| e.1.to_owned())
                .nth(0);
            let param_supported_features = match param_supported_features {
                Some(param_supported_features) => {
                    let param_supported_features =
                        <String as std::str::FromStr>::from_str(&param_supported_features);
                    match param_supported_features {
                        Ok(param_supported_features) => Some(param_supported_features),
                        Err(e) => return None,
                    }
                }
                None => None,
            };
            let param_plmn_id = query_params
                .iter()
                .filter(|e| e.0 == "plmn-id")
                .map(|e| e.1.to_owned())
                .nth(0);
            let param_plmn_id = match param_plmn_id {
                Some(param_plmn_id) => {
                    let param_plmn_id = serde_json::from_str::<models::PlmnId>(&param_plmn_id);
                    match param_plmn_id {
                        Ok(param_plmn_id) => Some(param_plmn_id),
                        Err(e) => return None,
                    }
                }
                None => None,
            };
            let plmn = match param_plmn_id {
                Some(ref a) => a.to_string(),
                None => "None".to_string(),
            };
            let msg = serde_json::json!({
                "request_type": "get_smf_sel_data",
                "supi": param_supi,
                "plmn": plmn,
               // // "hash": "0"
            });
            return Some(jmap_hash(msg));
        }

        // Get3GppSmsfRegistration - GET /nudm-uecm/v1/{ueId}/registrations/smsf-3gpp-access
        &hyper::Method::GET
            if path.matched(paths::ID_NUDM_UECM_V1_UEID_REGISTRATIONS_SMSF_3GPP_ACCESS) =>
        {
            /// CHANGE THIS OUTPUT
            /*{
                let authorization = match (&context as &dyn Has<Option<Authorization>>).get() {
                    &Some(ref authorization) => authorization,
                    &None => return Ok(Response::builder()
                                            .status(StatusCode::FORBIDDEN)
                                            .body(Body::from("Unauthenticated"))
                                            .expect("Unable to create Authentication Forbidden response")),
                };

                // Authorization
                if let Scopes::Some(ref scopes) = authorization.scopes {
                    let required_scopes: std::collections::BTreeSet<String> = vec![
                        "nudm-sdm".to_string(), // Access to the nudm-sdm API
                    ].into_iter().collect();

                    if !required_scopes.is_subset(scopes) {
                        let missing_scopes = required_scopes.difference(scopes);
                        return Ok(Response::builder()
                            .status(StatusCode::FORBIDDEN)
                            .body(Body::from(missing_scopes.fold(
                                "Insufficient authorization, missing scopes".to_string(),
                                |s, scope| format!("{} {}", s, scope))
                            ))
                            .expect("Unable to create Authentication Insufficient response")
                        );
                    }
                }
            }*/
            // Path parameters
            let path: &str = &uri.path().to_string();
            let path_params =
                    paths::REGEX_NUDM_UECM_V1_UEID_REGISTRATIONS_SMSF_3GPP_ACCESS
                    .captures(&path)
                    .unwrap_or_else(||
                        panic!("Path {} matched RE NUDM_UECM_V1_UEID_REGISTRATIONS_SMSF_3GPP_ACCESS in set but failed match against \"{}\"", path, paths::REGEX_NUDM_UECM_V1_UEID_REGISTRATIONS_SMSF_3GPP_ACCESS.as_str())
                    );

            let param_ue_id = match percent_encoding::percent_decode(path_params["ueId"].as_bytes())
                .decode_utf8()
            {
                Ok(param_ue_id) => match param_ue_id.parse::<String>() {
                    Ok(param_ue_id) => param_ue_id,
                    Err(e) => return None,
                },
                Err(_) => return None,
            };

            // Query parameters (note that non-required or collection query parameters will ignore garbage values, rather than causing a 400 response)
            let query_params = form_urlencoded::parse(uri.query().unwrap_or_default().as_bytes())
                .collect::<Vec<_>>();
            let param_supported_features = query_params
                .iter()
                .filter(|e| e.0 == "supported-features")
                .map(|e| e.1.to_owned())
                .nth(0);
            let param_supported_features = match param_supported_features {
                Some(param_supported_features) => {
                    let param_supported_features =
                        <String as std::str::FromStr>::from_str(&param_supported_features);
                    match param_supported_features {
                        Ok(param_supported_features) => Some(param_supported_features),
                        Err(e) => return None,
                    }
                }
                None => None,
            };
            // return Some(jmap_hash(msg))
            let msg = serde_json::json!({
                "request_type": "get_smsf_registration",
                "supi": param_ue_id,
            // "guami": param_amf3_gpp_access_registration.guami.to_string(),
            // "hash": format!("{:x}", md5::compute(body))
            });
            return Some(jmap_hash(msg));
        }

        // Call3GppSmsfDeregistration - DELETE /nudm-uecm/v1/{ueId}/registrations/smsf-3gpp-access
        &hyper::Method::DELETE
            if path.matched(paths::ID_NUDM_UECM_V1_UEID_REGISTRATIONS_SMSF_3GPP_ACCESS) =>
        {
            /// CHANGE THIS OPUTPUT
            /*{
                let authorization = match (&context as &dyn Has<Option<Authorization>>).get() {
                    &Some(ref authorization) => authorization,
                    &None => return Ok(Response::builder()
                                            .status(StatusCode::FORBIDDEN)
                                            .body(Body::from("Unauthenticated"))
                                            .expect("Unable to create Authentication Forbidden response")),
                };

                // Authorization
                if let Scopes::Some(ref scopes) = authorization.scopes {
                    let required_scopes: std::collections::BTreeSet<String> = vec![
                        "nudm-sdm".to_string(), // Access to the nudm-sdm API
                    ].into_iter().collect();

                    if !required_scopes.is_subset(scopes) {
                        let missing_scopes = required_scopes.difference(scopes);
                        return Ok(Response::builder()
                            .status(StatusCode::FORBIDDEN)
                            .body(Body::from(missing_scopes.fold(
                                "Insufficient authorization, missing scopes".to_string(),
                                |s, scope| format!("{} {}", s, scope))
                            ))
                            .expect("Unable to create Authentication Insufficient response")
                        );
                    }
                }
            }*/
            // Path parameters
            let path: &str = &uri.path().to_string();
            let path_params =
                    paths::REGEX_NUDM_UECM_V1_UEID_REGISTRATIONS_SMSF_3GPP_ACCESS
                    .captures(&path)
                    .unwrap_or_else(||
                        panic!("Path {} matched RE NUDM_UECM_V1_UEID_REGISTRATIONS_SMSF_3GPP_ACCESS in set but failed match against \"{}\"", path, paths::REGEX_NUDM_UECM_V1_UEID_REGISTRATIONS_SMSF_3GPP_ACCESS.as_str())
                    );

            let param_ue_id = match percent_encoding::percent_decode(path_params["ueId"].as_bytes())
                .decode_utf8()
            {
                Ok(param_ue_id) => match param_ue_id.parse::<String>() {
                    Ok(param_ue_id) => param_ue_id,
                    Err(e) => return None,
                },
                Err(_) => return None,
            };

            // Query parameters (note that non-required or collection query parameters will ignore garbage values, rather than causing a 400 response)
            let query_params = form_urlencoded::parse(uri.query().unwrap_or_default().as_bytes())
                .collect::<Vec<_>>();
            let param_smsf_set_id = query_params
                .iter()
                .filter(|e| e.0 == "smsf-set-id")
                .map(|e| e.1.to_owned())
                .nth(0);
            let param_smsf_set_id = match param_smsf_set_id {
                Some(param_smsf_set_id) => {
                    let param_smsf_set_id =
                        <String as std::str::FromStr>::from_str(&param_smsf_set_id);
                    match param_smsf_set_id {
                        Ok(param_smsf_set_id) => Some(param_smsf_set_id),
                        Err(e) => return None,
                    }
                }
                None => None,
            };
            let msg = serde_json::json!({
                "request_type": "get_smsf_dereg_data",
                "supi": param_ue_id,
                "smsf_set_id": param_smsf_set_id.unwrap_or("None".to_owned())
               // // "hash": format!("{:x}", md5::compute(serde_json::to_string(&param_smsf_registration)?))
            });
            return Some(jmap_hash(msg));
        }

        // Call3GppSmsfRegistration - PUT /nudm-uecm/v1/{ueId}/registrations/smsf-3gpp-access
        &hyper::Method::PUT
            if path.matched(paths::ID_NUDM_UECM_V1_UEID_REGISTRATIONS_SMSF_3GPP_ACCESS) =>
        {
            /*{
                let authorization = match (&context as &dyn Has<Option<Authorization>>).get() {
                    &Some(ref authorization) => authorization,
                    &None => return Ok(Response::builder()
                                            .status(StatusCode::FORBIDDEN)
                                            .body(Body::from("Unauthenticated"))
                                            .expect("Unable to create Authentication Forbidden response")),
                };

                // Authorization
                if let Scopes::Some(ref scopes) = authorization.scopes {
                    let required_scopes: std::collections::BTreeSet<String> = vec![
                        "nudm-sdm".to_string(), // Access to the nudm-sdm API
                    ].into_iter().collect();

                    if !required_scopes.is_subset(scopes) {
                        let missing_scopes = required_scopes.difference(scopes);
                        return Ok(Response::builder()
                            .status(StatusCode::FORBIDDEN)
                            .body(Body::from(missing_scopes.fold(
                                "Insufficient authorization, missing scopes".to_string(),
                                |s, scope| format!("{} {}", s, scope))
                            ))
                            .expect("Unable to create Authentication Insufficient response")
                        );
                    }
                }
            }*/

            // Path parameters
            let path: &str = &uri.path().to_string();
            let path_params =
                    paths::REGEX_NUDM_UECM_V1_UEID_REGISTRATIONS_SMSF_3GPP_ACCESS
                    .captures(&path)
                    .unwrap_or_else(||
                        panic!("Path {} matched RE NUDM_UECM_V1_UEID_REGISTRATIONS_SMSF_3GPP_ACCESS in set but failed match against \"{}\"", path, paths::REGEX_NUDM_UECM_V1_UEID_REGISTRATIONS_SMSF_3GPP_ACCESS.as_str())
                    );

            let param_ue_id = match percent_encoding::percent_decode(path_params["ueId"].as_bytes())
                .decode_utf8()
            {
                Ok(param_ue_id) => match param_ue_id.parse::<String>() {
                    Ok(param_ue_id) => param_ue_id,
                    Err(e) => return None,
                },
                Err(_) => return None,
            };

            // Body parameters (note that non-required body parameters will ignore garbage
            // values, rather than causing a 400 response). Produce warning header and logs for
            // any unused fields.
            let mut unused_elements = Vec::new();
            let param_smsf_registration: Option<models::SmsfRegistration> = if !body.is_empty() {
                let deserializer = &mut serde_json::Deserializer::from_slice(&*body);
                match serde_ignored::deserialize(deserializer, |path| {
                    warn!("Ignoring unknown field in body: {}", path);
                    unused_elements.push(path.to_string());
                }) {
                    Ok(param_smsf_registration) => param_smsf_registration,
                    Err(e) => return None,
                }
            } else {
                None
            };
            let param_smsf_registration = match param_smsf_registration {
                Some(param_smsf_registration) => param_smsf_registration,
                None => return None,
            };
            let msg = serde_json::json!({
                "request_type": "call3_gpp_smsf_registration",
                "supi": param_ue_id,
               // // "hash": format!("{:x}", md5::compute(serde_json::to_string(&param_smsf_registration)?))
            });
            return Some(jmap_hash(msg));
        }

        // GetSmsMngtData - GET /nudm-sdm/v2/{supi}/sms-mng-data
        &hyper::Method::GET if path.matched(paths::ID_NUDM_SDM_V2_SUPI_SMS_MNG_DATA) => {
            /*{
                let authorization = match (&context as &dyn Has<Option<Authorization>>).get() {
                    &Some(ref authorization) => authorization,
                    &None => return None,
                };

                // Authorization
                if let Scopes::Some(ref scopes) = authorization.scopes {
                    let required_scopes: std::collections::BTreeSet<String> = vec![
                        "nudm-sdm".to_string(), // Access to the nudm-sdm API
                    ].into_iter().collect();

                    if !required_scopes.is_subset(scopes) {
                        let missing_scopes = required_scopes.difference(scopes);
                        return None;
                    }
                }
            }*/

            // Path parameters
            let path: &str = &uri.path().to_string();
            let path_params =
                    paths::REGEX_NUDM_SDM_V2_SUPI_SMS_MNG_DATA
                    .captures(&path)
                    .unwrap_or_else(||
                        panic!("Path {} matched RE NUDM_SDM_V2_SUPI_SMS_MNG_DATA in set but failed match against \"{}\"", path, paths::REGEX_NUDM_SDM_V2_SUPI_SMS_MNG_DATA.as_str())
                    );

            let param_supi = match percent_encoding::percent_decode(path_params["supi"].as_bytes())
                .decode_utf8()
            {
                Ok(param_supi) => match param_supi.parse::<String>() {
                    Ok(param_supi) => param_supi,
                    Err(e) => return None,
                },
                Err(_) => return None,
            };

            // Header parameters
            let param_if_none_match = headers.get(HeaderName::from_static("if-none-match"));

            let param_if_none_match = match param_if_none_match {
                Some(v) => {
                    match nudm_openapi::header::IntoHeaderValue::<String>::try_from((*v).clone()) {
                        Ok(result) => Some(result.0),
                        Err(err) => {
                            return None;
                        }
                    }
                }
                None => None,
            };
            let param_if_modified_since = headers.get(HeaderName::from_static("if-modified-since"));

            let param_if_modified_since = match param_if_modified_since {
                Some(v) => {
                    match nudm_openapi::header::IntoHeaderValue::<String>::try_from((*v).clone()) {
                        Ok(result) => Some(result.0),
                        Err(err) => {
                            return None;
                        }
                    }
                }
                None => None,
            };

            // Query parameters (note that non-required or collection query parameters will ignore garbage values, rather than causing a 400 response)
            let query_params = form_urlencoded::parse(uri.query().unwrap_or_default().as_bytes())
                .collect::<Vec<_>>();
            let param_supported_features = query_params
                .iter()
                .filter(|e| e.0 == "supported-features")
                .map(|e| e.1.to_owned())
                .nth(0);
            let param_supported_features = match param_supported_features {
                Some(param_supported_features) => {
                    let param_supported_features =
                        <String as std::str::FromStr>::from_str(&param_supported_features);
                    match param_supported_features {
                        Ok(param_supported_features) => Some(param_supported_features),
                        Err(e) => return None,
                    }
                }
                None => None,
            };
            let param_plmn_id = query_params
                .iter()
                .filter(|e| e.0 == "plmn-id")
                .map(|e| e.1.to_owned())
                .nth(0);
            let param_plmn_id = match param_plmn_id {
                Some(param_plmn_id) => {
                    let param_plmn_id = serde_json::from_str::<models::PlmnId>(&param_plmn_id);
                    match param_plmn_id {
                        Ok(param_plmn_id) => Some(param_plmn_id),
                        Err(e) => return None,
                    }
                }
                None => None,
            };
            let plmn = match param_plmn_id {
                Some(ref a) => a.to_string(),
                None => "None".to_string(),
            };
            let msg = serde_json::json!({
                "request_type": "get_sms_mngt_data",
                "supi": param_supi,
                "plmn": plmn,
               // // "hash": "0"
            });
            return Some(jmap_hash(msg));
        }

        // GetSmData - GET /nudm-sdm/v2/{supi}/sm-data
        &hyper::Method::GET if path.matched(paths::ID_NUDM_SDM_V2_SUPI_SM_DATA) => {
            /*{
                let authorization = match (&context as &dyn Has<Option<Authorization>>).get() {
                    &Some(ref authorization) => authorization,
                    &None => return None,
                };

                // Authorization
                if let Scopes::Some(ref scopes) = authorization.scopes {
                    let required_scopes: std::collections::BTreeSet<String> = vec![
                        "nudm-sdm".to_string(), // Access to the nudm-sdm API
                    ].into_iter().collect();

                    if !required_scopes.is_subset(scopes) {
                        let missing_scopes = required_scopes.difference(scopes);
                        return None;
                    }
                }
            }*/

            // Path parameters
            let path: &str = &uri.path().to_string();
            let path_params =
                    paths::REGEX_NUDM_SDM_V2_SUPI_SM_DATA
                    .captures(&path)
                    .unwrap_or_else(||
                        panic!("Path {} matched RE NUDM_SDM_V2_SUPI_SM_DATA in set but failed match against \"{}\"", path, paths::REGEX_NUDM_SDM_V2_SUPI_SM_DATA.as_str())
                    );

            let param_supi = match percent_encoding::percent_decode(path_params["supi"].as_bytes())
                .decode_utf8()
            {
                Ok(param_supi) => match param_supi.parse::<String>() {
                    Ok(param_supi) => param_supi,
                    Err(e) => return None,
                },
                Err(_) => return None,
            };

            // Header parameters
            let param_if_none_match = headers.get(HeaderName::from_static("if-none-match"));

            let param_if_none_match = match param_if_none_match {
                Some(v) => {
                    match nudm_openapi::header::IntoHeaderValue::<String>::try_from((*v).clone()) {
                        Ok(result) => Some(result.0),
                        Err(err) => {
                            return None;
                        }
                    }
                }
                None => None,
            };
            let param_if_modified_since = headers.get(HeaderName::from_static("if-modified-since"));

            let param_if_modified_since = match param_if_modified_since {
                Some(v) => {
                    match nudm_openapi::header::IntoHeaderValue::<String>::try_from((*v).clone()) {
                        Ok(result) => Some(result.0),
                        Err(err) => {
                            return None;
                        }
                    }
                }
                None => None,
            };

            // Query parameters (note that non-required or collection query parameters will ignore garbage values, rather than causing a 400 response)
            let query_params = form_urlencoded::parse(uri.query().unwrap_or_default().as_bytes())
                .collect::<Vec<_>>();
            let param_supported_features = query_params
                .iter()
                .filter(|e| e.0 == "supported-features")
                .map(|e| e.1.to_owned())
                .nth(0);
            let param_supported_features = match param_supported_features {
                Some(param_supported_features) => {
                    let param_supported_features =
                        <String as std::str::FromStr>::from_str(&param_supported_features);
                    match param_supported_features {
                        Ok(param_supported_features) => Some(param_supported_features),
                        Err(e) => return None,
                    }
                }
                None => None,
            };
            let param_single_nssai = query_params
                .iter()
                .filter(|e| e.0 == "single-nssai")
                .map(|e| e.1.to_owned())
                .nth(0);
            let param_single_nssai = match param_single_nssai {
                Some(param_single_nssai) => {
                    let param_single_nssai =
                        serde_json::from_str::<models::Snssai>(&param_single_nssai);
                    match param_single_nssai {
                        Ok(param_single_nssai) => Some(param_single_nssai),
                        Err(e) => return None,
                    }
                }
                None => None,
            };
            let param_dnn = query_params
                .iter()
                .filter(|e| e.0 == "dnn")
                .map(|e| e.1.to_owned())
                .nth(0);
            let param_dnn = match param_dnn {
                Some(param_dnn) => {
                    let param_dnn = <String as std::str::FromStr>::from_str(&param_dnn);
                    match param_dnn {
                        Ok(param_dnn) => Some(param_dnn),
                        Err(e) => return None,
                    }
                }
                None => None,
            };
            let param_plmn_id = query_params
                .iter()
                .filter(|e| e.0 == "plmn-id")
                .map(|e| e.1.to_owned())
                .nth(0);
            let param_plmn_id = match param_plmn_id {
                Some(param_plmn_id) => {
                    let param_plmn_id = serde_json::from_str::<models::PlmnId>(&param_plmn_id);
                    match param_plmn_id {
                        Ok(param_plmn_id) => Some(param_plmn_id),
                        Err(e) => return None,
                    }
                }
                None => None,
            };

            let plmn = match param_plmn_id {
                Some(ref a) => a.to_string(),
                None => "None".to_string(),
            };
            let msg = serde_json::json!({
                "request_type": "get_sm_data",
                "supi": param_supi,
                "plmn": plmn,
               // // "hash": "0"
            });
            return Some(jmap_hash(msg));
        }

        // GetNSSAI - GET /nudm-sdm/v2/{supi}/nssai
        &hyper::Method::GET if path.matched(paths::ID_NUDM_SDM_V2_SUPI_NSSAI) => {
            /// CHANGE THIS OUL:UT
            /*{
                let authorization = match (&context as &dyn Has<Option<Authorization>>).get() {
                    &Some(ref authorization) => authorization,
                    &None => return Ok(Response::builder()
                                            .status(StatusCode::FORBIDDEN)
                                            .body(Body::from("Unauthenticated"))
                                            .expect("Unable to create Authentication Forbidden response")),
                };

                // Authorization
                if let Scopes::Some(ref scopes) = authorization.scopes {
                    let required_scopes: std::collections::BTreeSet<String> = vec![
                        "nudm-sdm".to_string(), // Access to the nudm-sdm API
                    ].into_iter().collect();

                    if !required_scopes.is_subset(scopes) {
                        let missing_scopes = required_scopes.difference(scopes);
                        return Ok(Response::builder()
                            .status(StatusCode::FORBIDDEN)
                            .body(Body::from(missing_scopes.fold(
                                "Insufficient authorization, missing scopes".to_string(),
                                |s, scope| format!("{} {}", s, scope))
                            ))
                            .expect("Unable to create Authentication Insufficient response")
                        );
                    }
                }
            }*/
            // Path parameters
            let path: &str = &uri.path().to_string();
            let path_params =
                    paths::REGEX_NUDM_SDM_V2_SUPI_NSSAI
                    .captures(&path)
                    .unwrap_or_else(||
                        panic!("Path {} matched RE NUDM_SDM_V2_SUPI_NSSAI in set but failed match against \"{}\"", path, paths::REGEX_NUDM_SDM_V2_SUPI_NSSAI.as_str())
                    );

            let param_supi = match percent_encoding::percent_decode(path_params["supi"].as_bytes())
                .decode_utf8()
            {
                Ok(param_supi) => match param_supi.parse::<String>() {
                    Ok(param_supi) => param_supi,
                    Err(e) => return None,
                },
                Err(_) => return None,
            };

            // Header parameters
            let param_if_none_match = headers.get(HeaderName::from_static("if-none-match"));

            let param_if_none_match = match param_if_none_match {
                Some(v) => {
                    match nudm_openapi::header::IntoHeaderValue::<String>::try_from((*v).clone()) {
                        Ok(result) => Some(result.0),
                        Err(err) => {
                            return None;
                        }
                    }
                }
                None => None,
            };
            let param_if_modified_since = headers.get(HeaderName::from_static("if-modified-since"));

            let param_if_modified_since = match param_if_modified_since {
                Some(v) => {
                    match nudm_openapi::header::IntoHeaderValue::<String>::try_from((*v).clone()) {
                        Ok(result) => Some(result.0),
                        Err(err) => {
                            return None;
                        }
                    }
                }
                None => None,
            };

            // Query parameters (note that non-required or collection query parameters will ignore garbage values, rather than causing a 400 response)
            let query_params = form_urlencoded::parse(uri.query().unwrap_or_default().as_bytes())
                .collect::<Vec<_>>();
            let param_supported_features = query_params
                .iter()
                .filter(|e| e.0 == "supported-features")
                .map(|e| e.1.to_owned())
                .nth(0);
            let param_supported_features = match param_supported_features {
                Some(param_supported_features) => {
                    let param_supported_features =
                        <String as std::str::FromStr>::from_str(&param_supported_features);
                    match param_supported_features {
                        Ok(param_supported_features) => Some(param_supported_features),
                        Err(e) => return None,
                    }
                }
                None => None,
            };
            let param_plmn_id = query_params
                .iter()
                .filter(|e| e.0 == "plmn-id")
                .map(|e| e.1.to_owned())
                .nth(0);
            let param_plmn_id = match param_plmn_id {
                Some(param_plmn_id) => {
                    let param_plmn_id = serde_json::from_str::<models::PlmnId>(&param_plmn_id);
                    match param_plmn_id {
                        Ok(param_plmn_id) => Some(param_plmn_id),
                        Err(e) => return None,
                    }
                }
                None => None,
            };
            let msg = serde_json::json!({
                "request_type": "get_nssai",
                "supi": param_supi,
                // "plmn": plmn,
               // // "hash": "0"
            });
            return Some(jmap_hash(msg));
        }

        // ReleaseSmContext - POST /sm-contexts/{smContextRef}/release
        &hyper::Method::POST if path.matched(paths::ID_SM_CONTEXTS_SMCONTEXTREF_RELEASE) => {
            /*{
                let authorization = match (&context as &dyn Has<Option<Authorization>>).get() {
                    &Some(ref authorization) => authorization,
                    &None => return Ok(Response::builder()
                                            .status(StatusCode::FORBIDDEN)
                                            .body(Body::from("Unauthenticated"))
                                            .expect("Unable to create Authentication Forbidden response")),
                };

                // Authorization
                if let Scopes::Some(ref scopes) = authorization.scopes {
                    let required_scopes: std::collections::BTreeSet<String> = vec![
                        "nsmf-pdusession".to_string(), // Access to the nsmf-pdusession API
                    ].into_iter().collect();

                    if !required_scopes.is_subset(scopes) {
                        let missing_scopes = required_scopes.difference(scopes);
                        return Ok(Response::builder()
                            .status(StatusCode::FORBIDDEN)
                            .body(Body::from(missing_scopes.fold(
                                "Insufficient authorization, missing scopes".to_string(),
                                |s, scope| format!("{} {}", s, scope))
                            ))
                            .expect("Unable to create Authentication Insufficient response")
                        );
                    }
                }
            }*/

            // Path parameters
            let path: &str = &uri.path().to_string();
            let path_params =
					paths::REGEX_SM_CONTEXTS_SMCONTEXTREF_RELEASE
					.captures(&path)
					.unwrap_or_else(||
						panic!("Path {} matched RE SM_CONTEXTS_SMCONTEXTREF_RELEASE in set but failed match against \"{}\"", path, paths::REGEX_SM_CONTEXTS_SMCONTEXTREF_RELEASE.as_str())
					);

            let param_sm_context_ref =
                match percent_encoding::percent_decode(path_params["smContextRef"].as_bytes())
                    .decode_utf8()
                {
                    Ok(param_sm_context_ref) => match param_sm_context_ref.parse::<String>() {
                        Ok(param_sm_context_ref) => param_sm_context_ref,
                        Err(e) => return None,
                    },
                    Err(_) => return None,
                };

            // Body parameters (note that non-required body parameters will ignore garbage
            // values, rather than causing a 400 response). Produce warning header and logs for
            // any unused fields.
            let mut unused_elements: Vec<String> = vec![];

            let result = if headers.get(CONTENT_TYPE).unwrap().to_str().unwrap()
                == "application/json"
            {
                let param_sm_context_release_data: Option<models::SmContextReleaseData> =
                    if !body.is_empty() {
                        let deserializer = &mut serde_json::Deserializer::from_slice(&*body);
                        match serde_ignored::deserialize(deserializer, |path| {
                            warn!("Ignoring unknown field in body: {}", path);
                            unused_elements.push(path.to_string());
                        }) {
                            Ok(param_sm_context_release_data) => param_sm_context_release_data,
                            Err(e) => return None,
                        }
                    } else {
                        None
                    };

                let param_sm_context_release_data = match param_sm_context_release_data {
                    Some(param_sm_context_release_data) => param_sm_context_release_data,
                    None => return None,
                };
                let msg = serde_json::json! ({
                    "request_type": "release_sm_context",
                    "context_id": param_sm_context_ref,
                    // "hash": format!("{:x}", md5::compute(serde_json::to_string(&param_sm_context_release_data)?))
                });
                return Some(jmap_hash(msg));
            } else {
                // Get multipart chunks.

                // Extract the top-level content type header.
                let content_type_mime = headers
                    .get(CONTENT_TYPE)
                    .ok_or("Missing content-type header".to_string())
                    .and_then(|v| {
                        v.to_str().map_err(|e| {
                            format!(
                                "Couldn't read content-type header value for ReleaseSmContext: {}",
                                e
                            )
                        })
                    })
                    .and_then(|v| {
                        v.parse::<Mime2>().map_err(|_e| {
                            format!("Couldn't parse content-type header value for ReleaseSmContext")
                        })
                    });

                // Insert top-level content type header into a Headers object.
                let mut multi_part_headers = Headers::new();
                match content_type_mime {
                    Ok(content_type_mime) => {
                        multi_part_headers.set(ContentType(content_type_mime));
                    }
                    Err(e) => {
                        return None;
                    }
                }

                let mut param_sm_context_release_data = None;
                let mut param_binary_data_n2_sm_information_content_id = None;
                let mut param_binary_data_n2_sm_information = None;

                // &*body expresses the body as a byteslice, &mut provides a
                // mutable reference to that byteslice.
                let nodes = match read_multipart_body(&mut &*body, &multi_part_headers, false) {
                    Ok(nodes) => nodes,
                    Err(e) => {
                        return None;
                    }
                };

                for node in nodes {
                    if let Node::Part(part) = node {
                        if let Some(content_type) = part.content_type().map(|x| format!("{}", x)) {
                            if content_type == "application/json"
                                && param_sm_context_release_data.is_none()
                            {
                                // Extract JSON part.
                                let deserializer =
                                    &mut serde_json::Deserializer::from_slice(part.body.as_slice());
                                let json_data: models::SmContextReleaseData =
                                    match serde_ignored::deserialize(deserializer, |path| {
                                        warn!("Ignoring unknown field in JSON part: {}", path);
                                        unused_elements.push(path.to_string());
                                    }) {
                                        Ok(json_data) => json_data,
                                        Err(e) => return None,
                                    };
                                // Push JSON part to return object.
                                if let Some(ref info) = json_data.n2_sm_info {
                                    param_binary_data_n2_sm_information_content_id
                                        .get_or_insert(info.content_id.clone());
                                }
                                param_sm_context_release_data.get_or_insert(json_data);
                            }
                        }
                        if let Some(content_id) = part
                            .headers
                            .get_raw("Content-ID")
                            .map(|x| std::str::from_utf8(x[0].as_slice()).unwrap())
                        {
                            param_binary_data_n2_sm_information_content_id
                                .as_ref()
                                .map(|id| {
                                    if id == content_id {
                                        param_binary_data_n2_sm_information
                                            .get_or_insert(swagger::ByteArray(part.body.clone()));
                                    }
                                });
                        }
                    } else {
                        unimplemented!("No support for handling unexpected parts");
                        // unused_elements.push();
                    }
                }

                let param_sm_context_release_data = match param_sm_context_release_data {
                    Some(param_sm_context_release_data) => param_sm_context_release_data,
                    None => return None,
                };
                let msg = serde_json::json! ({
                    "request_type": "release_sm_context",
                    "context_id": param_sm_context_ref,
                    // "hash": format!("{:x}", md5::compute(serde_json::to_string(&param_sm_context_release_data)?))
                });
                return Some(jmap_hash(msg));
            };
        }

        // UpdateSmContext - POST /sm-contexts/{smContextRef}/modify
        &hyper::Method::POST if path.matched(paths::ID_SM_CONTEXTS_SMCONTEXTREF_MODIFY) => {
            /*{
                let authorization = match (&context as &dyn Has<Option<Authorization>>).get() {
                    &Some(ref authorization) => authorization,
                    &None => return Ok(Response::builder()
                                            .status(StatusCode::FORBIDDEN)
                                            .body(Body::from("Unauthenticated"))
                                            .expect("Unable to create Authentication Forbidden response")),
                };

                // Authorization
                if let Scopes::Some(ref scopes) = authorization.scopes {
                    let required_scopes: std::collections::BTreeSet<String> = vec![
                        "nsmf-pdusession".to_string(), // Access to the nsmf-pdusession API
                    ].into_iter().collect();

                    if !required_scopes.is_subset(scopes) {
                        let missing_scopes = required_scopes.difference(scopes);
                        return Ok(Response::builder()
                            .status(StatusCode::FORBIDDEN)
                            .body(Body::from(missing_scopes.fold(
                                "Insufficient authorization, missing scopes".to_string(),
                                |s, scope| format!("{} {}", s, scope))
                            ))
                            .expect("Unable to create Authentication Insufficient response")
                        );
                    }
                }
            }*/

            // Path parameters
            let path: &str = &uri.path().to_string();
            let path_params =
					paths::REGEX_SM_CONTEXTS_SMCONTEXTREF_MODIFY
					.captures(&path)
					.unwrap_or_else(||
						panic!("Path {} matched RE SM_CONTEXTS_SMCONTEXTREF_MODIFY in set but failed match against \"{}\"", path, paths::REGEX_SM_CONTEXTS_SMCONTEXTREF_MODIFY.as_str())
					);

            let param_sm_context_ref =
                match percent_encoding::percent_decode(path_params["smContextRef"].as_bytes())
                    .decode_utf8()
                {
                    Ok(param_sm_context_ref) => match param_sm_context_ref.parse::<String>() {
                        Ok(param_sm_context_ref) => param_sm_context_ref,
                        Err(e) => return None,
                    },
                    Err(_) => return None,
                };

            // Body parameters (note that non-required body parameters will ignore garbage
            // values, rather than causing a 400 response). Produce warning header and logs for
            // any unused fields.
            let mut unused_elements: Vec<String> = vec![];

            let result = if headers.get(CONTENT_TYPE).unwrap().to_str().unwrap()
                == "application/json"
            {
                let param_sm_context_update_data: Option<models::SmContextUpdateData> =
                    if !body.is_empty() {
                        let deserializer = &mut serde_json::Deserializer::from_slice(&*body);
                        match serde_ignored::deserialize(deserializer, |path| {
                            warn!("Ignoring unknown field in body: {}", path);
                            unused_elements.push(path.to_string());
                        }) {
                            Ok(param_sm_context_update_data) => param_sm_context_update_data,
                            Err(e) => return None,
                        }
                    } else {
                        None
                    };
                let param_sm_context_update_data = match param_sm_context_update_data {
                    Some(param_sm_context_update_data) => param_sm_context_update_data,
                    None => return None,
                };
                let msg = serde_json::json! ({
                    "request_type": "update_sm_context",
                    "context_id": param_sm_context_ref,
                    // "hash": format!("{:x}", md5::compute(serde_json::to_string(&param_sm_context_update_data)?))
                });
                return Some(jmap_hash(msg));
            } else {
                // Get multipart chunks.

                // Extract the top-level content type header.
                let content_type_mime = headers
                    .get(CONTENT_TYPE)
                    .ok_or("Missing content-type header".to_string())
                    .and_then(|v| {
                        v.to_str().map_err(|e| {
                            format!(
                                "Couldn't read content-type header value for UpdateSmContext: {}",
                                e
                            )
                        })
                    })
                    .and_then(|v| {
                        v.parse::<Mime2>().map_err(|_e| {
                            format!("Couldn't parse content-type header value for UpdateSmContext")
                        })
                    });

                // Insert top-level content type header into a Headers object.
                let mut multi_part_headers = Headers::new();
                match content_type_mime {
                    Ok(content_type_mime) => {
                        multi_part_headers.set(ContentType(content_type_mime));
                    }
                    Err(e) => {
                        return None;
                    }
                }

                let mut param_sm_context_update_data = None;
                let mut param_binary_data_n1_sm_message_content_id = None;
                let mut param_binary_data_n1_sm_message = None;
                let mut param_binary_data_n2_sm_information_content_id = None;
                let mut param_binary_data_n2_sm_information = None;
                let mut param_binary_data_n2_sm_information_ext1_content_id = None;
                let mut param_binary_data_n2_sm_information_ext1 = None;

                // &*body expresses the body as a byteslice, &mut provides a
                // mutable reference to that byteslice.
                let nodes = match read_multipart_body(&mut &*body, &multi_part_headers, false) {
                    Ok(nodes) => nodes,
                    Err(e) => {
                        return None;
                    }
                };

                for node in nodes {
                    if let Node::Part(part) = node {
                        if let Some(content_type) = part.content_type().map(|x| format!("{}", x)) {
                            if content_type == "application/json"
                                && param_sm_context_update_data.is_none()
                            {
                                // Extract JSON part.
                                let deserializer =
                                    &mut serde_json::Deserializer::from_slice(part.body.as_slice());
                                let json_data: models::SmContextUpdateData =
                                    match serde_ignored::deserialize(deserializer, |path| {
                                        warn!("Ignoring unknown field in JSON part: {}", path);
                                        unused_elements.push(path.to_string());
                                    }) {
                                        Ok(json_data) => json_data,
                                        Err(e) => return None,
                                    };
                                // Push JSON part to return object.
                                if let Some(ref info) = json_data.n1_sm_msg {
                                    param_binary_data_n1_sm_message_content_id
                                        .get_or_insert(info.content_id.clone());
                                }
                                if let Some(ref info) = json_data.n2_sm_info {
                                    param_binary_data_n2_sm_information_content_id
                                        .get_or_insert(info.content_id.clone());
                                }
                                if let Some(ref info) = json_data.n2_sm_info_ext1 {
                                    param_binary_data_n2_sm_information_ext1_content_id
                                        .get_or_insert(info.content_id.clone());
                                }
                                param_sm_context_update_data.get_or_insert(json_data);
                            }
                        }
                        if let Some(content_id) = part
                            .headers
                            .get_raw("Content-ID")
                            .map(|x| std::str::from_utf8(x[0].as_slice()).unwrap())
                        {
                            param_binary_data_n1_sm_message_content_id
                                .as_ref()
                                .map(|id| {
                                    if id == content_id {
                                        param_binary_data_n1_sm_message
                                            .get_or_insert(swagger::ByteArray(part.body.clone()));
                                    }
                                });
                            param_binary_data_n2_sm_information_content_id
                                .as_ref()
                                .map(|id| {
                                    if id == content_id {
                                        param_binary_data_n2_sm_information
                                            .get_or_insert(swagger::ByteArray(part.body.clone()));
                                    }
                                });
                            param_binary_data_n2_sm_information_ext1_content_id
                                .as_ref()
                                .map(|id| {
                                    if id == content_id {
                                        param_binary_data_n2_sm_information_ext1
                                            .get_or_insert(swagger::ByteArray(part.body.clone()));
                                    }
                                });
                        }
                    } else {
                        unimplemented!("No support for handling unexpected parts");
                        // unused_elements.push();
                    }
                }
                let param_sm_context_update_data = match param_sm_context_update_data {
                    Some(param_sm_context_update_data) => param_sm_context_update_data,
                    None => return None,
                };
                let msg = serde_json::json! ({
                    "request_type": "update_sm_context",
                    "context_id": param_sm_context_ref,
                    // "hash": format!("{:x}", md5::compute(serde_json::to_string(&param_sm_context_update_data)?))
                });
                return Some(jmap_hash(msg));
            };
        }

        // PostSmContexts - POST /sm-contexts
        &hyper::Method::POST if path.matched(paths::ID_SM_CONTEXTS) => {
            /*{
                let authorization = match (&context as &dyn Has<Option<Authorization>>).get() {
                    &Some(ref authorization) => authorization,
                    &None => return Ok(Response::builder()
                                            .status(StatusCode::FORBIDDEN)
                                            .body(Body::from("Unauthenticated"))
                                            .expect("Unable to create Authentication Forbidden response")),
                };
                // Authorization
                if let Scopes::Some(ref scopes) = authorization.scopes {
                    let required_scopes: std::collections::BTreeSet<String> = vec![
                        "nsmf-pdusession".to_string(), // Access to the nsmf-pdusession API
                    ].into_iter().collect();

                    if !required_scopes.is_subset(scopes) {
                        let missing_scopes = required_scopes.difference(scopes);
                        return Ok(Response::builder()
                            .status(StatusCode::FORBIDDEN)
                            .body(Body::from(missing_scopes.fold(
                                "Insufficient authorization, missing scopes".to_string(),
                                |s, scope| format!("{} {}", s, scope))
                            ))
                            .expect("Unable to create Authentication Insufficient response")
                        );
                    }
                }
            }*/
            // Body parameters (note that non-required body parameters will ignore garbage
            // values, rather than causing a 400 response). Produce warning header and logs for
            // any unused fields.
            let mut unused_elements: Vec<String> = vec![];

            // Get multipart chunks.

            // Extract the top-level content type header.
            let content_type_mime = headers
                .get(CONTENT_TYPE)
                .ok_or("Missing content-type header".to_string())
                .and_then(|v| {
                    v.to_str().map_err(|e| {
                        format!(
                            "Couldn't read content-type header value for PostSmContexts: {}",
                            e
                        )
                    })
                })
                .and_then(|v| {
                    v.parse::<Mime2>().map_err(|_e| {
                        format!("Couldn't parse content-type header value for PostSmContexts")
                    })
                });
            // Insert top-level content type header into a Headers object.
            let mut multi_part_headers = Headers::new();
            match content_type_mime {
                Ok(content_type_mime) => {
                    multi_part_headers.set(ContentType(content_type_mime));
                }
                Err(e) => {
                    return None;
                }
            }
            // &*body expresses the body as a byteslice, &mut provides a
            // mutable reference to that byteslice.
            let nodes = match read_multipart_body(&mut &*body, &multi_part_headers, false) {
                Ok(nodes) => nodes,
                Err(e) => {
                    return None;
                }
            };
            let mut param_sm_context_create_data = None;
            let mut param_binary_data_n1_sm_message_content_id = None;
            let mut param_binary_data_n1_sm_message = None;
            let mut param_binary_data_n2_sm_information_content_id = None;
            let mut param_binary_data_n2_sm_information = None;
            let mut param_binary_data_n2_sm_information_ext1_content_id = None;
            let mut param_binary_data_n2_sm_information_ext1 = None;

            for node in nodes {
                if let Node::Part(part) = node {
                    if let Some(content_type) = part.content_type().map(|x| format!("{}", x)) {
                        if content_type == "application/json"
                            && param_sm_context_create_data.is_none()
                        {
                            // Extract JSON part.
                            let deserializer =
                                &mut serde_json::Deserializer::from_slice(part.body.as_slice());
                            let json_data: models::SmContextCreateData =
                                match serde_ignored::deserialize(deserializer, |path| {
                                    warn!("Ignoring unknown field in JSON part: {}", path);
                                    unused_elements.push(path.to_string());
                                }) {
                                    Ok(json_data) => json_data,
                                    Err(e) => return None,
                                };
                            // Push JSON part to return object.
                            if let Some(ref info) = json_data.n1_sm_msg {
                                param_binary_data_n1_sm_message_content_id
                                    .get_or_insert(info.content_id.clone());
                            }
                            if let Some(ref info) = json_data.n2_sm_info {
                                param_binary_data_n2_sm_information_content_id
                                    .get_or_insert(info.content_id.clone());
                            }
                            if let Some(ref info) = json_data.n2_sm_info_ext1 {
                                param_binary_data_n2_sm_information_ext1_content_id
                                    .get_or_insert(info.content_id.clone());
                            }
                            param_sm_context_create_data.get_or_insert(json_data);
                        }
                    }
                    if let Some(content_id) = part
                        .headers
                        .get_raw("Content-ID")
                        .map(|x| std::str::from_utf8(x[0].as_slice()).unwrap())
                    {
                        param_binary_data_n1_sm_message_content_id
                            .as_ref()
                            .map(|id| {
                                if id == content_id {
                                    param_binary_data_n1_sm_message
                                        .get_or_insert(swagger::ByteArray(part.body.clone()));
                                }
                            });
                        param_binary_data_n2_sm_information_content_id
                            .as_ref()
                            .map(|id| {
                                if id == content_id {
                                    param_binary_data_n2_sm_information
                                        .get_or_insert(swagger::ByteArray(part.body.clone()));
                                }
                            });
                        param_binary_data_n2_sm_information_ext1_content_id
                            .as_ref()
                            .map(|id| {
                                if id == content_id {
                                    param_binary_data_n2_sm_information_ext1
                                        .get_or_insert(swagger::ByteArray(part.body.clone()));
                                }
                            });
                    }
                } else {
                    unimplemented!("No support for handling unexpected parts");
                    // unused_elements.push();
                }
            }
            // Check that the required multipart chunks are present.
            let param_sm_context_create_data = match param_sm_context_create_data {
                Some(param_sm_context_create_data) => param_sm_context_create_data,
                None => return None,
            };
            let msg = serde_json::json! ({
                "request_type": "post_sm_context",
                "supi": param_sm_context_create_data.supi.clone(),
                "pdu_id": param_sm_context_create_data.pdu_session_id.clone(),
                // "hash": format!("{:x}", md5::compute(serde_json::to_string(&param_sm_context_create_data)?))
            });
            return Some(jmap_hash(msg));
        }

        // SMServiceActivation - PUT /ue-contexts/{supi}
        &hyper::Method::PUT if path.matched(paths::ID_UE_CONTEXTS_SUPI) => {
            // Path parameters
            let path: &str = &uri.path().to_string();
            let path_params =
                    paths::REGEX_UE_CONTEXTS_SUPI
                    .captures(&path)
                    .unwrap_or_else(||
                        panic!("Path {} matched RE UE_CONTEXTS_SUPI in set but failed match against \"{}\"", path, paths::REGEX_UE_CONTEXTS_SUPI.as_str())
                    );

            let param_supi = match percent_encoding::percent_decode(path_params["supi"].as_bytes())
                .decode_utf8()
            {
                Ok(param_supi) => match param_supi.parse::<String>() {
                    Ok(param_supi) => param_supi,
                    Err(e) => return None,
                },
                Err(_) => return None,
            };

            // Body parameters (note that non-required body parameters will ignore garbage
            // values, rather than causing a 400 response). Produce warning header and logs for
            // any unused fields.
            let mut unused_elements = Vec::new();
            let param_ue_sms_context_data: Option<models::UeSmsContextData> = if !body.is_empty() {
                let deserializer = &mut serde_json::Deserializer::from_slice(&*body);
                match serde_ignored::deserialize(deserializer, |path| {
                    warn!("Ignoring unknown field in body: {}", path);
                    unused_elements.push(path.to_string());
                }) {
                    Ok(param_ue_sms_context_data) => param_ue_sms_context_data,
                    Err(e) => return None,
                }
            } else {
                None
            };
            let param_ue_sms_context_data = match param_ue_sms_context_data {
                Some(param_ue_sms_context_data) => param_ue_sms_context_data,
                None => return None,
            };

            let msg = serde_json::json!({
                "request_type": "sms_service_activation",
                "supi": param_supi.clone(),
               // // "hash": format!("{:x}", md5::compute(serde_json::to_string(&param_ue_sms_context_data)?))
            });
            return Some(jmap_hash(msg));
        }

        // SMServiceDeactivation - DELETE /ue-contexts/{supi}
        &hyper::Method::DELETE if path.matched(paths::ID_UE_CONTEXTS_SUPI) => {
            // Path parameters
            let path: &str = &uri.path().to_string();
            let path_params =
                    paths::REGEX_UE_CONTEXTS_SUPI
                    .captures(&path)
                    .unwrap_or_else(||
                        panic!("Path {} matched RE UE_CONTEXTS_SUPI in set but failed match against \"{}\"", path, paths::REGEX_UE_CONTEXTS_SUPI.as_str())
                    );

            let param_supi = match percent_encoding::percent_decode(path_params["supi"].as_bytes())
                .decode_utf8()
            {
                Ok(param_supi) => match param_supi.parse::<String>() {
                    Ok(param_supi) => param_supi,
                    Err(e) => return None,
                },
                Err(_) => return None,
            };

            // Header parameters
            let param_if_match = headers.get(HeaderName::from_static("if-match"));

            let param_if_match = match param_if_match {
                Some(v) => {
                    match nsmsf_openapi::header::IntoHeaderValue::<String>::try_from((*v).clone()) {
                        Ok(result) => Some(result.0),
                        Err(err) => {
                            return None;
                        }
                    }
                }
                None => None,
            };

            let msg = serde_json::json!({
                "request_type": "sms_service_deactivation",
                "supi": param_supi.clone(),
               // // "hash": "0"
            });
            return Some(jmap_hash(msg));
        }

        // SendSMS - POST /ue-contexts/{supi}/sendsms
        &hyper::Method::POST if path.matched(paths::ID_UE_CONTEXTS_SUPI_SENDSMS) => {
            // Path parameters
            let path: &str = &uri.path().to_string();
            let path_params =
                    paths::REGEX_UE_CONTEXTS_SUPI_SENDSMS
                    .captures(&path)
                    .unwrap_or_else(||
                        panic!("Path {} matched RE UE_CONTEXTS_SUPI_SENDSMS in set but failed match against \"{}\"", path, paths::REGEX_UE_CONTEXTS_SUPI_SENDSMS.as_str())
                    );

            let param_supi = match percent_encoding::percent_decode(path_params["supi"].as_bytes())
                .decode_utf8()
            {
                Ok(param_supi) => match param_supi.parse::<String>() {
                    Ok(param_supi) => param_supi,
                    Err(e) => return None,
                },
                Err(_) => return None,
            };

            // Body parameters (note that non-required body parameters will ignore garbage
            // values, rather than causing a 400 response). Produce warning header and logs for
            // any unused fields.
            let mut unused_elements: Vec<String> = vec![];
            let bodyhash = format!("{:x}", md5::compute(&body));
            // Get multipart chunks.

            // Extract the top-level content type header.
            let content_type_mime = headers
                .get(CONTENT_TYPE)
                .ok_or("Missing content-type header".to_string())
                .and_then(|v| {
                    v.to_str().map_err(|e| {
                        format!("Couldn't read content-type header value for SendSMS: {}", e)
                    })
                })
                .and_then(|v| {
                    v.parse::<Mime2>().map_err(|_e| {
                        format!("Couldn't parse content-type header value for SendSMS")
                    })
                });

            // Insert top-level content type header into a Headers object.
            let mut multi_part_headers = Headers::new();
            match content_type_mime {
                Ok(content_type_mime) => {
                    multi_part_headers.set(ContentType(content_type_mime));
                }
                Err(e) => {
                    return None;
                }
            }

            // &*body expresses the body as a byteslice, &mut provides a
            // mutable reference to that byteslice.
            // let nodes = match read_multipart_body(&mut &*body, &multi_part_headers, false) {
            //     Ok(nodes) => nodes,
            //     Err(e) => {
            //         return None;
            //     }
            // };

            // let mut param_json_data = None;
            // let mut param_binary_payload = None;

            // for node in nodes {
            //     if let Node::Part(part) = node {
            //         let content_type = part.content_type().map(|x| format!("{}", x));
            //         match content_type.as_ref().map(|x| x.as_str()) {
            //             Some("application/json") if param_json_data.is_none() => {
            //                 // Extract JSON part.
            //                 let deserializer =
            //                     &mut serde_json::Deserializer::from_slice(part.body.as_slice());
            //                 let json_data: models::SmsRecordData =
            //                     match serde_ignored::deserialize(deserializer, |path| {
            //                         warn!("Ignoring unknown field in JSON part: {}", path);
            //                         unused_elements.push(path.to_string());
            //                     }) {
            //                         Ok(json_data) => json_data,
            //                         Err(e) => return None,
            //                     };
            //                 // Push JSON part to return object.
            //                 param_json_data.get_or_insert(json_data);
            //             }
            //             Some("application/vnd.3gpp.sms") if param_binary_payload.is_none() => {
            //                 param_binary_payload.get_or_insert(swagger::ByteArray(part.body));
            //             }
            //             Some(content_type) => {
            //                 warn!("Ignoring unexpected content type: {}", content_type);
            //                 unused_elements.push(content_type.to_string());
            //             }
            //             None => {
            //                 warn!("Missing content type");
            //             }
            //         }
            //     } else {
            //         unimplemented!("No support for handling unexpected parts");
            //         // unused_elements.push();
            //     }
            // }

            // Check that the required multipart chunks are present.

            let msg = serde_json::json!({
                "request_type": "send_sms_service",
                "supi": param_supi.clone(),
               // // "hash": bodyhash
            });
            return Some(jmap_hash(msg));
        }

        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;
    use hyper::Uri;
    use super::*;

    #[test]
    fn test_sndsms() {
        let uri = "https://scp1.scp.5gc.mnc099.mcc208.3gppnetwork.org/nsmsf-sms/v2/ue-contexts/imsi-2089900007494/sendsms";
        let uri = Uri::from_str(uri).unwrap();
        let path = paths::GLOBAL_REGEX_SET.matches(uri.path());
        println!("{:?}", path);
    }
}