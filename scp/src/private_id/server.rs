// #![deny(warnings)]
#![warn(rust_2018_idioms)]

use std::sync::{Arc, RwLock};
use super::rpc_server;
use bytes::Bytes;
use futures::task::UnsafeFutureObj;
// use http_body_util::{BodyExt, Empty};
use hyper::body::{Body};
use hyper::{client, Client};
// ::{self, HttpConnector};
use hyper::service::Service;
use hyper::Uri;
use crate::client::HttpConnector;
use hyper::{body::Buf, Request};
use serde::{Serialize, Deserialize};
use swagger::{ApiError, AuthData, BodyExt, Connector, DropContextService, Has, XSpanIdString, ContextBuilder, EmptyContext, Push};
use priv_id_server::start_rpc_server;
type ClientContext = swagger::make_context_ty!(ContextBuilder, EmptyContext, Option<AuthData>, XSpanIdString);

type Result<T> = std::result::Result<T, Box<dyn std::error::Error + Send + Sync>>;

/// DREQ is assist request
/// after assist request is sent from this server to client then actual server is started but it should utilize the http/2 

use std::str::FromStr;
use std::sync::atomic::AtomicBool;
use std::sync::atomic::Ordering;
use std::thread;
use std::time;

use clap::App;
use clap::Arg;
use clap::ArgGroup;
// use common::s3_path::S3Path;
use log::info;

use rpc::connect::create_server::create_server;
use rpc::proto::gen_private_id::private_id_server;

// pub async fn server(port: u32) -> Result<(), Box<dyn std::error::Error>> {
//     protocol: CompanyPrivateId::new(),
//     self.protocol
//             .load_data(&self.input_path, self.input_with_headers);
//     // Send U Company
//     self.protocol
//             .get_permuted_keys()

//     // Receive U partner
//     self.protocol
//             .set_encrypted_partner_keys(read_from_stream(&mut strm).await?)

//     // Receive E Company
//     self.protocol
//     .set_encrypted_company("e_company".to_string(), read_from_stream(&mut strm).await?)
// }
