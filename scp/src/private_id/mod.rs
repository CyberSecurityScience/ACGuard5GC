use crate::libsba;
use crypto::spoint::ByteBuffer;
use futures::TryFutureExt;
use hyper::body::to_bytes;
use hyper::header::HeaderValue;
use hyper::header::CONTENT_TYPE;
use hyper::service::Service;
use hyper::{Body, Request, Uri};
use log::info;
use nscp_api::{
    SCPIDFinalSetRequest, SCPIDFinalSetResponse, SCPIDInitSetRequest, SCPIDInitSetResponse,
};
use protocol::private_id::partner;
use protocol::private_id::partner::PartnerPrivateId;
use protocol::private_id::traits::*;
use std::collections::HashMap;
use std::convert::Infallible;
use std::str::FromStr;
use std::sync::{Arc, RwLock};
use std::thread;
use swagger::{ApiError, BodyExt, Connector};
mod client;

pub fn private_id_simple_client(
    local_data: HashMap<String, Vec<String>>,
    u_company: HashMap<String, Vec<ByteBuffer>>
) -> Result<Vec<HashMap<String, Vec<ByteBuffer>>>, Box<dyn std::error::Error>> {
    let partner_protocol = PartnerPrivateId::new();
    partner_protocol.load_data(local_data).unwrap();
    partner_protocol.gen_permute_pattern().unwrap();
    let u_partner = partner_protocol.permute_hash_to_bytes().unwrap();
    let e_company = partner_protocol.encrypt_permute(u_company);
    Ok(vec![u_partner, e_company])
}

// pub async fn private_id_client(
//     id: String,
//     data: HashMap<String, Vec<String>>,
//     fqdn: String,
// ) -> Result<(), Box<dyn std::error::Error>> {
//     // 1. Create partner protocol instance

//     let partner_protocol = PartnerPrivateId::new();
//     partner_protocol.load_data(data).unwrap();
//     partner_protocol.gen_permute_pattern().unwrap();
//     let u_partner = partner_protocol.permute_hash_to_bytes().unwrap();
//     let connector = Connector::builder().build();
//     let mut scp_client = hyper::client::Client::builder()
//         .http2_only(true)
//         .build(connector);

//     let mut u_company: HashMap<String, Vec<ByteBuffer>> = Default::default();
//     let mut uri = format!("http://{}/nscp-id/v1/initial-set/{}", fqdn, id);

//     let uri = match Uri::from_str(&uri) {
//         Ok(uri) => uri,
//         Err(err) => return Err(Box::new(ApiError(format!("Unable to build URI: {}", err)))),
//     };

//     let mut request = match Request::builder()
//         .method("GET")
//         .uri(uri)
//         .body(Body::empty())
//     {
//         Ok(req) => req,
//         Err(e) => {
//             return Err(Box::new(ApiError(format!(
//                 "Unable to create request: {}",
//                 e
//             ))))
//         }
//     };
//     let resp = scp_client.request(request).await.unwrap();
//     match resp.status().as_u16() {
//         200 => {
//             let body = resp.into_body();
//             let body = to_bytes(body)
//                 .await?;
//             let body: Vec<u8> = body.to_vec();
//             let body = std::str::from_utf8(&body)
//                 .map_err(|e| ApiError(format!("Response was not valid UTF8: {}", e)))?;
//             let body = serde_json::from_str::<HashMap<String, Vec<ByteBuffer>>>(body)?;
//             // Ok(
//             //     SCPIDInitSetResponse::SCPIDInitSetComplete { uc: body }
//             // )
//             u_company.extend(body.into_iter());
//         }
//         _ => return Err(Box::new(ApiError(format!("Response is BAD ")))),
//     };

//     let e_company = partner_protocol.encrypt_permute(u_company);
//     let final_data: SCPIDFinalSetRequest = SCPIDFinalSetRequest {
//         e_c: e_company,
//         u_p: u_partner,
//     };

//     // let mut client_service = self.client_service.clone();
//     let mut uri = format!("http://{}/nscp-id/v1/final-set/{}", fqdn, id);

//     let uri = match Uri::from_str(&uri) {
//         Ok(uri) => uri,
//         Err(err) => return Err(Box::new(ApiError(format!("Unable to build URI: {}", err)))),
//     };

//     let mut request = match Request::builder()
//         .method("PUT")
//         .uri(uri)
//         .body(Body::empty())
//     {
//         Ok(req) => req,
//         Err(e) => {
//             return Err(Box::new(ApiError(format!(
//                 "Unable to create request: {}",
//                 e
//             ))))
//         }
//     };

//     let body = serde_json::to_string(&final_data).expect("impossible to fail to serialize");
//     *request.body_mut() = Body::from(body);

//     let header = "application/json";
//     request.headers_mut().insert(
//         CONTENT_TYPE,
//         match HeaderValue::from_str(header) {
//             Ok(h) => h,
//             Err(e) => {
//                 return Err(Box::new(ApiError(format!(
//                     "Unable to create header: {} - {}",
//                     header, e
//                 ))))
//             }
//         },
//     );

//     let resp = scp_client.request(request).await.unwrap();
//     match resp.status().as_u16() {
//         200 => {
//         }
//         _ => {
//             log::info!("ERROR GETTING UC");
//         }
//     }

//     Ok(())
// }
