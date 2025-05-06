use crate::context;
// use crate::context::SCP_ID;
// use array_tool::vec::Times;
// use json::object::Object;
// use crate::log_handler::cmp_obj;
use super::gen_id;
use super::RETRIEVE;
use super::{Node, ValTup, NRF_KEY};
use super::{NODEMAP};
use crate::context::Log;
use crate::server;
use chrono::{DateTime, FixedOffset};
use models::AccessAndMobilitySubscriptionData;
use models::Nssai;
use core::panic;
use models::ExtSnssai;
use models::NfProfile;
use models::PlmnId;
use models::Snssai;
use serde_json::Value;
use std::collections::BTreeMap;
use std::collections::{HashMap, HashSet, VecDeque};
use std::fmt;
use std::fs::File;
use std::io;
use std::io::stderr;
use std::io::Write;
use std::str::FromStr;
use std::sync::mpsc;
use std::sync::mpsc::{Receiver, Sender};
use std::sync::Arc;
use std::sync::Mutex;
use std::thread::sleep;
use std::time::Duration;

// fn main() {
//   let mut rng = thread_rng();
//   let random_bytes: [u8; 32] = rng.gen();
//   let random_hex_string = encode(random_bytes);

//   println!("Random 32 bit hex string: {}", random_hex_string);
// }

pub fn add(obj: Log) {
    // log::info!("\n\n{:?}\n\n", obj.req);
    let nfself = context::SCP_PARAMETERS.get().unwrap();
    let dis_profile = &obj.discovery;
    let api_profile= &obj.api_disc;
    // let req = obj.req;
    // let resp = obj.res;
    let mut target: Option<String> = None;
    // Parse Discovery Data
    let discovery_results = match obj.dis.as_str() {
        "NRF" => {
            let mut prod: HashMap<String, String> = HashMap::new();
            prod.insert("Type".to_string(), models::NfType::NRF.to_string());
            prod.insert("FQDN".to_string(), nfself.nfctx.nrf_uri.clone());
            prod
        }
        "NSSF" => {
            let mut prod: HashMap<String, String> = HashMap::new();
            prod.insert("Type".to_string(), models::NfType::NSSF.to_string());
            prod.insert("FQDN".to_string(), nfself.nssf_uri.clone());
            prod
        }
        "NEXTSCP" => {
            let mut prod: HashMap<String, String> = HashMap::new();
            prod.insert("Type".to_string(), models::NfType::SCP.to_string());
            prod.insert("FQDN".to_string(), nfself.next_scp.clone());
            prod
        }
        _ => {
            let mut prod: HashMap<String, String> = HashMap::new();
            // prod.insert("Type".to_string(), models::NfType::SCP.to_string());
            prod.insert(
                "FQDN".to_string(),
                obj.req.get("sbi-target").unwrap().to_string(),
            );
            // target = Some(req.get("sbi-target").unwrap().to_string());
            prod
        }
        // _ => {
        //     let mut prod: HashMap<String, String> = HashMap::new();
        //     // prod.insert("Type".to_string(), models::NfType::SCP.to_string());
        //     prod.insert(
        //         "FQDN".to_string(),
        //         req.get("sbi-target").unwrap().to_string(),
        //     );
        //     // target = Some(req.get("sbi-target").unwrap().to_string());

        //     prod
        // }
        // _ => { // Parsing Local NF
        //     let nfprofile: models::NfProfile1 = serde_json::from_str(&obj.dis).unwrap();
        //     // println!("{:?}", nfprofile);
        //     let dom = nfprofile.scp_domains.as_ref();
        //     let mut prod: HashMap<String, String> = HashMap::new();
        //     match dom {
        //         Some(dom) => {
        //             if dom[0] != "http://".to_owned() + &nfself.nfctx.host {
        //                 // let prod = if nfprofile.scp_domains.is_some() {
        //                 // Some(nfprofile.scp_domains.as_ref().unwrap()[0].clone())
        //                 prod.insert("Type".to_string(), models::NfType::SCP.to_string());
        //                 prod.insert("FQDN".to_string(), dom[0].clone());
        //                 target = Some(dom[0].clone());
        //                 // prod
        //             } else {
        //                 // log::info!("{:?}", nfprofile.ipv4_addresses.as_ref().unwrap()[0].to_string());
        //                 // let mut prod: HashMap<String, String> = HashMap::new();
        //                 prod.insert("Type".to_string(), nfprofile.nf_type.to_string());
        //                 prod.insert(
        //                     "FQDN".to_string(),
        //                     nfprofile.fqdn.unwrap_or("None".to_string()),
        //                 );
        //                 prod.insert("UUID".to_string(), nfprofile.nf_instance_id.to_string());
        //                 prod.insert(
        //                     "IP".to_string(),
        //                     nfprofile.ipv4_addresses.as_ref().unwrap()[0].to_string(),
        //                 );
        //                 prod.insert(
        //                     "SNSSAI".to_string(),
        //                     serde_json::to_string(&nfprofile.s_nssais.unwrap()).unwrap(),
        //                 );
        //                 prod.insert(
        //                     "ALLOWED_SNSSAI".to_string(),
        //                     serde_json::to_string(&nfprofile.allowed_nssais.unwrap()).unwrap(),
        //                 );
        //                 prod.insert(
        //                     "PLMN".to_string(),
        //                     serde_json::to_string(&nfprofile.plmn_list.unwrap()).unwrap(),
        //                 );
        //                 target = Some(dom[0].clone());
        //                 // target = Some(nfprofile)
        //                 // prod
        //             };
        //         }
        //         None => {
        //             log::warn!(
        //                 "NF Function running without SCP {:?}",
        //                 nfprofile.nf_type.to_string()
        //             );
        //             prod.insert("Type".to_string(), nfprofile.nf_type.to_string());
        //             prod.insert(
        //                 "FQDN".to_string(),
        //                 nfprofile
        //                     .fqdn
        //                     .as_ref()
        //                     .unwrap_or(&"None".to_string())
        //                     .to_owned(),
        //             );
        //             prod.insert("UUID".to_string(), nfprofile.nf_instance_id.to_string());
        //             prod.insert(
        //                 "IP".to_string(),
        //                 nfprofile.ipv4_addresses.as_ref().unwrap()[0].to_string(),
        //             );
        //             prod.insert(
        //                 "SNSSAI".to_string(),
        //                 serde_json::to_string(&nfprofile.s_nssais.unwrap()).unwrap(),
        //             );
        //             prod.insert(
        //                 "PLMN".to_string(),
        //                 serde_json::to_string(&nfprofile.plmn_list.unwrap()).unwrap(),
        //             );
        //             target = Some(nfprofile.fqdn.unwrap_or("None".to_string()));
        //         }
        //     }
        //     prod
        // }
    };
    // log::info!("Graph Step 1");
    // Check for external NF/SCP contacting external SCP NF  using sender ip and disc
    // log::info!("SenderIP {:?} \n {:?}", req, resp);
    let r = RETRIEVE.read().unwrap(); 
    let sender_nf_id = if 
        r.contains_key(obj.req.get("SenderIP").unwrap())
    {
        let x = r.get(obj.req.get("SenderIP").unwrap()).unwrap().clone();
        drop(r);
        x
    } else {
        drop(r);
        let id = if obj.req.get("request_type").unwrap() == "register_nf" {
            // println!("{:?}", req);
            let new_id = crate::scp_prov::gen_id();
            let mut tempN = Node::create(
                obj.req.get("nf_type").unwrap().to_owned(),
                "UUID".to_string(),
                obj.req.get("UUID").unwrap().to_owned(),
                obj.req.get("Timestamp").unwrap().parse::<i64>().unwrap(),
            );
            let time = obj.req["Timestamp"].parse::<i64>().unwrap();
            if obj.req.contains_key("FQDN") {
                tempN.dev_id.insert(
                    "FQDN".to_string(),
                    vec![ValTup::new(
                        obj.req["FQDN"].to_string(),
                        time,
                    )],
                );
            }
            if obj.req.contains_key("SNSSAI") {
                let mut val_vec: Vec<ValTup> = vec![];
                let data: Vec<ExtSnssai> =
                    serde_json::from_str::<Vec<String>>(obj.req.get("SNSSAI").unwrap())
                        .unwrap()
                        .iter()
                        .map(|x| serde_json::from_str(x).unwrap())
                        .collect();
                for x in data {
                    val_vec.push(ValTup::new(serde_json::to_string(&x).unwrap(), time));
                }
                tempN.dev_id.insert("SNSSAI".to_string(), val_vec);
            }
            if obj.req.contains_key("allowed_snssai") {
                let mut val_vec: Vec<ValTup> = vec![];
                let data: Vec<ExtSnssai> =
                    serde_json::from_str::<Vec<String>>(obj.req.get("allowed_snssai").unwrap())
                        .unwrap()
                        .iter()
                        .map(|x| serde_json::from_str(x).unwrap())
                        .collect();
                for x in data {
                    val_vec.push(ValTup::new(serde_json::to_string(&x).unwrap(), time));
                }
                tempN.dev_id.insert("allowed_snssai".to_string(), val_vec);
            }
            if obj.req.contains_key("plmns") {
                let mut val_vec: Vec<ValTup> = vec![];
                // log::info!("{:?}", req.get("plmns").unwrap());
                let data: Vec<PlmnId> =
                    serde_json::from_str::<Vec<String>>(obj.req.get("plmns").unwrap())
                        .unwrap()
                        .iter()
                        .map(|x| serde_json::from_str(x).unwrap())
                        .collect();
                for x in data {
                    val_vec.push(ValTup::new(serde_json::to_string(&x).unwrap(), time));
                }
                tempN.dev_id.insert("plmns".to_string(), val_vec);
            }
            tempN.dev_id.insert(
                "IP".to_string(),
                vec![ValTup::new(obj.req["SenderIP"].to_string(), time)],
            );
            // println!("Reg Node {:?}", tempN);
            {
                let mut temp_nlist = NODEMAP.write().unwrap();
                temp_nlist.insert(new_id.clone(), tempN);
                drop(temp_nlist);
            }
            {
                let mut temp_ret = RETRIEVE.write().unwrap();
                temp_ret.insert(
                    obj.req.get("FQDN").unwrap().to_string(),
                    new_id.clone(),
                );
                temp_ret.insert(obj.req.get("SenderIP").unwrap().to_string(), new_id.clone());
                drop(temp_ret);
            }
            new_id
        } else {
            // log::info!("SCP - {} ", req.get("SenderIP").unwrap());
            let new_id = gen_id();
            let mut tempN = Node::create(
                "SCP".to_string(),
                "IP".to_string(),
                obj.req.get("SenderIP").unwrap().to_string(),
                obj.req.get("Timestamp").unwrap().parse::<i64>().unwrap(),
            );
            {
                let mut temp_nlist = NODEMAP.write().unwrap();
                temp_nlist.insert(new_id.clone(), tempN);
                drop(temp_nlist);
            }
            {
                let mut temp_ret = RETRIEVE.write().unwrap();
                temp_ret.insert(obj.req.get("SenderIP").unwrap().to_string(), new_id.clone());
                drop(temp_ret);
            }
            new_id
        };
        id
    };


    if dis_profile.is_some() {
        let profile = dis_profile.as_ref().unwrap();
        let r = RETRIEVE.read().unwrap(); 
        if !r.contains_key(profile.fqdn.as_ref().unwrap()) {
            drop(r);
            let new_id = gen_id();
            let time = obj.req.get("Timestamp").unwrap().parse::<i64>().unwrap();
            let mut tempN = Node::create(
                profile.nf_type.to_string(),
                "FQDN".to_string(),
                profile.fqdn.as_ref().unwrap().clone(),
                time
            );
            tempN.dev_id.insert("Type".to_owned(), vec![ValTup::new(profile.nf_type.to_string(), time)]);
            tempN.dev_id.insert("UUID".to_owned(), vec![ValTup::new(profile.nf_instance_id.to_string(), time)]);
            let mut val_vec: Vec<ValTup> = vec![];
            for x in profile.s_nssais.as_ref().unwrap() {
                val_vec.push(ValTup::new(serde_json::to_string(&x).unwrap(), time));
            }
            tempN.dev_id.insert("SNSSAI".to_owned(), val_vec);
            let mut val_vec: Vec<ValTup> = vec![];
            for x in profile.plmn_list.as_ref().unwrap() {
                val_vec.push(ValTup::new(serde_json::to_string(&x).unwrap(), time));
            }
            // tempN.dev_id.insert("ALLOWED_SNSSAI".to_owned(), vec![ValTup::new(profile.allowed_.to_string(), time)]);
            tempN.dev_id.insert("PLMN".to_owned(), val_vec);
            let mut val_vec: Vec<ValTup> = vec![];
            for x in profile.ipv4_addresses.as_ref().unwrap() {
                val_vec.push(ValTup::new(serde_json::to_string(&x).unwrap(), time));
            }
            tempN.dev_id.insert("IP".to_owned(), val_vec);
            {
                let mut temp_nlist = NODEMAP.write().unwrap();
                temp_nlist.insert(new_id.clone(), tempN);
                drop(temp_nlist);
            }
            {
                let mut temp_ret = RETRIEVE.write().unwrap();
                temp_ret.insert(profile.fqdn.as_ref().unwrap().clone(), new_id.clone());
                temp_ret.insert(profile.ipv4_addresses.as_ref().unwrap()[0].clone().to_string(), new_id.clone());
                drop(temp_ret);
            }
        }
        // new_id
    }

    if api_profile.is_some() {
        let profile = api_profile.as_ref().unwrap();
        let r = RETRIEVE.read().unwrap(); 
        if !r.contains_key(profile.fqdn.as_ref().unwrap()) {
            drop(r);
            let new_id = gen_id();
            let time = obj.req.get("Timestamp").unwrap().parse::<i64>().unwrap();
            let mut tempN = Node::create(
                profile.nf_type.to_string(),
                "FQDN".to_string(),
                profile.fqdn.as_ref().unwrap().clone(),
                time
            );
            tempN.dev_id.insert("Type".to_owned(), vec![ValTup::new(profile.nf_type.to_string(), time)]);
            tempN.dev_id.insert("UUID".to_owned(), vec![ValTup::new(profile.nf_instance_id.to_string(), time)]);
            let mut val_vec: Vec<ValTup> = vec![];
            for x in profile.s_nssais.as_ref().unwrap() {
                val_vec.push(ValTup::new(serde_json::to_string(&x).unwrap(), time));
            }
            tempN.dev_id.insert("SNSSAI".to_owned(), val_vec);
            let mut val_vec: Vec<ValTup> = vec![];
            for x in profile.plmn_list.as_ref().unwrap() {
                val_vec.push(ValTup::new(serde_json::to_string(&x).unwrap(), time));
            }
            // tempN.dev_id.insert("ALLOWED_SNSSAI".to_owned(), vec![ValTup::new(profile.allowed_.to_string(), time)]);
            tempN.dev_id.insert("PLMN".to_owned(), val_vec);
            let mut val_vec: Vec<ValTup> = vec![];
            for x in profile.ipv4_addresses.as_ref().unwrap() {
                val_vec.push(ValTup::new(serde_json::to_string(&x).unwrap(), time));
            }
            tempN.dev_id.insert("IP".to_owned(), val_vec);
            {
                let mut temp_nlist = NODEMAP.write().unwrap();
                temp_nlist.insert(new_id.clone(), tempN);
                drop(temp_nlist);
            } {
                let mut temp_ret = RETRIEVE.write().unwrap();
                temp_ret.insert(profile.fqdn.as_ref().unwrap().clone(), new_id.clone());
                temp_ret.insert(profile.ipv4_addresses.as_ref().unwrap()[0].clone().to_string(), new_id.clone());
                drop(temp_ret);
            }
            // new_id
        }
    }
    let r = RETRIEVE.read().unwrap(); 
    let receiver_id = if r.contains_key(discovery_results.get("FQDN").unwrap())
    {
        let x = r.get(discovery_results.get("FQDN").unwrap()).unwrap().clone();
        drop(r);
        x
    }
    else
    {
        drop(r);
        log::info!("Going into rare area");
        let new_id = gen_id();
        let mut tempN = Node::create(
            "SCP".to_string(),
            "FQDN".to_string(),
            discovery_results.get("FQDN").unwrap().to_string(),
            obj.req.get("Timestamp").unwrap().parse::<i64>().unwrap(),
        );
        {
            let mut temp_nlist = NODEMAP.write().unwrap();
            temp_nlist.insert(new_id.clone(), tempN);
            drop(temp_nlist); }{
            let mut temp_ret = RETRIEVE.write().unwrap();
            temp_ret.insert(discovery_results.get("FQDN").unwrap().to_string(), new_id.clone());
            drop(temp_ret);
        }
        new_id
    };
    // log::info!("Graph Step 2");
    // let mut req_edge_obj = Edge::create(
    //     req["Timestamp"].parse::<i64>().unwrap(),
    //     req["request_type"].to_string(),
    //     HashMap::new(),
    //     req["request_hash"].to_string(),
    //     "request".to_owned(),
    // );
    // req_edge_obj.request_data.extend(req.clone());
    // // log::info!("{:?}", resp);
    // let mut rsp_edge_obj = Edge::create(
    //     resp["Timestamp"].parse::<i64>().unwrap(),
    //     resp["request_type"].to_string(),
    //     HashMap::new(),
    //     req["request_hash"].to_string(),
    //     "response".to_owned(),
    // );
    // rsp_edge_obj.request_data.extend(resp.clone());
    // let scp_id = SCP_ID.read().unwrap().clone();
    // if sender_nf_id == scp_id {
        // let sender_id = SCP_ID.read().unwrap().clone();
        // let receiver_id = RETRIEVE.read().unwrap().get(discovery_results.get("FQDN").unwrap()).unwrap().to_owned();
        // log::info!("Req Type {:?}", resp["request_type"].to_string());
        // let mut temp_elist = EDGEMAP.write().unwrap();
        // match temp_elist.get_mut(&sender_nf_id) {
        //     Some(innerlist) => match innerlist.get_mut(&receiver_nf_id) {
        //         Some(vec) => {
        //             vec.push(req_edge_obj.clone());
        //         }
        //         None => {
        //             innerlist.insert(receiver_nf_id.clone(), vec![req_edge_obj.clone()]);
        //         }
        //     },
        //     None => {
        //         let mut temp: HashMap<String, Vec<Edge>> = HashMap::new();
        //         temp.insert(receiver_nf_id.clone(), vec![req_edge_obj.clone()]);
        //         temp_elist.insert(sender_nf_id.clone(), temp);
        //     }
        // };
        // // Receiver to SCP
        // match temp_elist.get_mut(&receiver_nf_id) {
        //     Some(innerlist) => match innerlist.get_mut(&sender_nf_id.clone()) {
        //         Some(vec) => {
        //             vec.push(rsp_edge_obj.clone());
        //         }
        //         None => {
        //             innerlist.insert(sender_nf_id.clone(), vec![rsp_edge_obj.clone()]);
        //         }
        //     },
        //     None => {
        //         let mut temp: HashMap<String, Vec<Edge>> = HashMap::new();
        //         temp.insert(sender_nf_id.clone(), vec![rsp_edge_obj.clone()]);
        //         temp_elist.insert(receiver_nf_id, temp);
        //     }
        // };
    // } else {
        // log::info!("Req Type {:?}", resp["request_type"].to_string());
        // let edge_c = req_edge_obj.clone();
        // let sender_id = RETRIEVE.read().unwrap().get(req.get("SenderIP").unwrap()).unwrap().to_owned();
        // let receiver_id = if scp_domain.is_some() {
        //     RETRIEVE.read().unwrap().get(&scp_domain.as_ref().unwrap().clone()).unwrap().to_owned()
        // } else {
        //     RETRIEVE.read().unwrap().get(discovery_results.get("FQDN").unwrap()).unwrap().to_owned()
        // };
        // log::info!("Sender ID {:?}", sender_id);
        // let scp_id = SCP_ID.read().unwrap().clone();
        // let mut temp_elist = EDGEMAP.write().unwrap();
        // // Sender to SCP
        // match temp_elist.get_mut(&sender_nf_id) {
        //     Some(innerlist) => match innerlist.get_mut(&scp_id) {
        //         Some(vec) => {
        //             vec.push(req_edge_obj.clone());
        //         }
        //         None => {
        //             innerlist.insert(scp_id.clone(), vec![req_edge_obj.clone()]);
        //         }
        //     },
        //     None => {
        //         let mut temp: HashMap<String, Vec<Edge>> = HashMap::new();
        //         temp.insert(scp_id.clone(), vec![req_edge_obj.clone()]);
        //         temp_elist.insert(sender_nf_id.clone(), temp);
        //     }
        // };
        // // SCP to Receiver
        // match temp_elist.get_mut(&scp_id) {
        //     Some(innerlist) => match innerlist.get_mut(&receiver_nf_id) {
        //         Some(vec) => {
        //             vec.push(req_edge_obj);
        //         }
        //         None => {
        //             innerlist.insert(receiver_nf_id.clone(), vec![req_edge_obj]);
        //         }
        //     },
        //     None => {
        //         let mut temp: HashMap<String, Vec<Edge>> = HashMap::new();
        //         temp.insert(receiver_nf_id.clone(), vec![req_edge_obj]);
        //         temp_elist.insert(scp_id.clone(), temp);
        //     }
        // };
        // // Receiver to SCP
        // match temp_elist.get_mut(&receiver_nf_id) {
        //     Some(innerlist) => match innerlist.get_mut(&scp_id.clone()) {
        //         Some(vec) => {
        //             vec.push(rsp_edge_obj.clone());
        //         }
        //         None => {
        //             innerlist.insert(scp_id.clone(), vec![rsp_edge_obj.clone()]);
        //         }
        //     },
        //     None => {
        //         let mut temp: HashMap<String, Vec<Edge>> = HashMap::new();
        //         temp.insert(scp_id.clone(), vec![rsp_edge_obj.clone()]);
        //         temp_elist.insert(receiver_nf_id, temp);
        //     }
        // };
        // // SCP to Sender
        // match temp_elist.get_mut(&scp_id.clone()) {
        //     Some(innerlist) => match innerlist.get_mut(&sender_nf_id) {
        //         Some(vec) => {
        //             vec.push(rsp_edge_obj);
        //         }
        //         None => {
        //             innerlist.insert(sender_nf_id.clone(), vec![rsp_edge_obj]);
        //         }
        //     },
        //     None => {
        //         let mut temp: HashMap<String, Vec<Edge>> = HashMap::new();
        //         temp.insert(sender_nf_id.clone(), vec![rsp_edge_obj]);
        //         temp_elist.insert(scp_id, temp);
        //     }
        // };
    // }
    let req_node = {
        let x = NODEMAP.read().unwrap();
        let xx = x.get(&sender_nf_id).unwrap();
        xx.clone()
    };
    let target_node = {
        let x = NODEMAP.read().unwrap();
        let xx = x.get(&receiver_id).unwrap();
        xx.clone()
    };
    // log::info!("Graph Step 3");
    // if req_node.dev_name == "AMF" && req.get("request_type").unwrap() == "ue_authentications_post" {
    //     let suciosupi = req.get("ue_id").unwrap();
    //     let idtype = if suciosupi[0..4].to_string() == "suci" {
    //         "suci"
    //     } else {
    //         "supi"
    //     };
    //     let new_id = gen_id();
    //     let mut tempN = Node::create(
    //         "UE".to_string(),
    //         idtype.to_string(),
    //         suciosupi.to_string(),
    //         req.get("Timestamp").unwrap().parse::<i64>().unwrap()
    //     );
    //     if idtype == "suci" {
    //         let time = req["Timestamp"].parse::<i64>().unwrap();
    //         tempN.dev_id.insert(idtype.to_string(), vec![ValTup::new(suciosupi.to_string(), time)]);
    //     }
    //     let mut temp_nlist = NODEMAP.write().unwrap();
    //     temp_nlist.insert(new_id.clone(), tempN);
    //     drop(temp_nlist);
    //     let mut temp_ret = RETRIEVE.write().unwrap();
    //     temp_ret.insert(suciosupi.to_string(), new_id);
    //     drop(temp_ret);
    // }

    if req_node.dev_name == "AMF" && obj.req.get("request_type").unwrap() == "get_am_data" {
        // let resp_data = serde_json::from_str::<HashMap<String, String>>(req.get("response").unwrap()).unwrap();
        // println!("REQ DATA {:?}", req);
        // let suciosupi = req.get("supi").unwrap();
        // let req_idtype = if suciosupi[0..4].to_string() == "suci" {
        //     "suci"
        // } else {
        //     "supi"
        // };

        // println!("RESP DATA {:?}", resp);
        let supi = obj.req.get("supi").unwrap();
        // if supi != "None" && idtype != "supi" {
        // let new_id = gen_id();
        // let mut tempN = Node::create(
        //     "UE".to_string(),
        //     "supi".to_string(),
        //     supi.to_string(),
        //     req.get("Timestamp").unwrap().parse::<i64>().unwrap()
        // );
        let r = RETRIEVE.read().unwrap(); 
        if !r.contains_key(supi) {
            drop(r);
            let time = obj.req.get("Timestamp").unwrap().parse::<i64>().unwrap();
            let id = gen_id();
            let mut tempN = Node::create(
                "UE".to_string(),
                "SUPI".to_string(),
                supi.to_string(),
                time
            );
            let resp = obj.res.get("response").unwrap();
            let data:AccessAndMobilitySubscriptionData = serde_json::from_str(resp).unwrap();
            let nssai: Nssai = data.nssai.unwrap().take().unwrap();
            let mut val_vec: Vec<ValTup> = vec![];
            for x in nssai.default_single_nssais {
                val_vec.push(ValTup::new(serde_json::to_string(&x).unwrap(), time));
            }
            tempN.dev_id.insert("allowed_snssai".to_string(), val_vec);
            tempN.dev_id.insert("amf_slices".to_string(), req_node.dev_id.get("SNSSAI").unwrap().to_vec());
            // if req_idtype == "suci" {
            //     tempN.dev_id.insert(
            //         "suci".to_string(),
            //         vec![ValTup::new(
            //             suciosupi.to_string(),
            //             req.get("Timestamp").unwrap().parse::<i64>().unwrap(),
            //         )],
            //     );
            // };
            {
                let mut temp_nlist = NODEMAP.write().unwrap();
                temp_nlist.insert(id.clone(), tempN);
                drop(temp_nlist);
                } {
                let mut temp_ret = RETRIEVE.write().unwrap();
                temp_ret.insert(supi.to_string(), id.clone());
                drop(temp_ret);
            }
        }
        // let mut temp_nlist = NODEMAP.write().unwrap();
        // let mut node = temp_nlist.get_mut(&id).unwrap();
        // let time = req["Timestamp"].parse::<i64>().unwrap();
        // node.dev_id.insert("supi".to_string(), vec![ValTup::new(supi.to_string(), time)]);

        // temp_nlist.insert(new_id.clone(), tempN);
        // drop(temp_nlist);
        // let mut temp_ret = RETRIEVE.write().unwrap();
        // temp_ret.insert(supi.to_string(), id.to_string());
        // drop(temp_ret);
        // }
    }


    // if req_node.dev_name == "AUSF" && req.get("request_type").unwrap() == "generate_auth_data" {
    //     // let resp_data = serde_json::from_str::<HashMap<String, String>>(req.get("response").unwrap()).unwrap();
    //     // println!("REQ DATA {:?}", req);
    //     let suciosupi = req.get("supi").unwrap();
    //     let req_idtype = if suciosupi[0..4].to_string() == "suci" {
    //         "suci"
    //     } else {
    //         "supi"
    //     };

    //     // println!("RESP DATA {:?}", resp);
    //     let supi = resp.get("supi").unwrap();
    //     // if supi != "None" && idtype != "supi" {
    //     // let new_id = gen_id();
    //     // let mut tempN = Node::create(
    //     //     "UE".to_string(),
    //     //     "supi".to_string(),
    //     //     supi.to_string(),
    //     //     req.get("Timestamp").unwrap().parse::<i64>().unwrap()
    //     // );
    //     let id = gen_id();
    //     let mut tempN = Node::create(
    //         "UE".to_string(),
    //         "supi".to_string(),
    //         supi.to_string(),
    //         req.get("Timestamp").unwrap().parse::<i64>().unwrap(),
    //     );
    //     if req_idtype == "suci" {
    //         tempN.dev_id.insert(
    //             "suci".to_string(),
    //             vec![ValTup::new(
    //                 suciosupi.to_string(),
    //                 req.get("Timestamp").unwrap().parse::<i64>().unwrap(),
    //             )],
    //         );
    //     };
    //     let mut temp_nlist = NODEMAP.write().unwrap();
    //     temp_nlist.insert(id.clone(), tempN);
    //     drop(temp_nlist);
    //     let mut temp_ret = RETRIEVE.write().unwrap();
    //     temp_ret.insert(supi.to_string(), id.clone());
    //     drop(temp_ret);
    //     // let mut temp_nlist = NODEMAP.write().unwrap();
    //     // let mut node = temp_nlist.get_mut(&id).unwrap();
    //     // let time = req["Timestamp"].parse::<i64>().unwrap();
    //     // node.dev_id.insert("supi".to_string(), vec![ValTup::new(supi.to_string(), time)]);

    //     // temp_nlist.insert(new_id.clone(), tempN);
    //     // drop(temp_nlist);
    //     // let mut temp_ret = RETRIEVE.write().unwrap();
    //     // temp_ret.insert(supi.to_string(), id.to_string());
    //     // drop(temp_ret);
    //     // }
    // }
    // // log::info!("Graph Step 4");
    // // This part should be found by algorithm
    // if req_node.dev_name == "SMF" && req.get("request_type").unwrap() == "n1_n2_message_transfer" {
    //     let mut nodes = NODEMAP.write().unwrap();
    //     let mut ret = RETRIEVE.write().unwrap();
    //     let supi = req.get("supi").unwrap();
    //     // log::info!("SUPI {:?}\n {:?}", supi, ret);
    //     let id = match ret.get(supi) {
    //         Some(x) => x.to_owned(),
    //         None => {
    //             let id = gen_id();
    //             let mut nodes = NODEMAP.write().unwrap();
    //             let mut tempN = Node::create(
    //                 "UE".to_string(),
    //                 "supi".to_string(),
    //                 supi.to_string(),
    //                 req.get("Timestamp").unwrap().parse::<i64>().unwrap(),
    //             );
    //             nodes.insert(id.clone(), tempN);
    //             ret.insert(supi.to_string(), id.clone());
    //             id
    //         }
    //     };
    //     let mut nodes = NODEMAP.write().unwrap();
    //     let node = nodes.get_mut(&id).unwrap();
    //     let time = req["Timestamp"].parse::<i64>().unwrap();
    //     node.dev_id.insert(
    //         "ip".to_string(),
    //         vec![ValTup::new(req.get("ip").unwrap().to_string(), time)],
    //     );
    // }
    // // log::info!("Graph Step 5");
    // // println!("{:?}", req);
    // if req_node.dev_name == "AMF" && req.get("request_type").unwrap() == "post_sm_context" {
    //     // println!("{:?}", req);

    //     let mut ret = RETRIEVE.write().unwrap();
    //     let supi = req.get("supi").unwrap();
    //     // log::info!("SUPI {:?}\n {:?}", supi, ret);
    //     let id = match ret.get(supi) {
    //         Some(x) => x.to_owned(),
    //         None => {
    //             let id = gen_id();
    //             let mut nodes = NODEMAP.write().unwrap();
    //             let mut tempN = Node::create(
    //                 "UE".to_string(),
    //                 "supi".to_string(),
    //                 supi.to_string(),
    //                 req.get("Timestamp").unwrap().parse::<i64>().unwrap(),
    //             );
    //             nodes.insert(id.clone(), tempN);
    //             ret.insert(supi.to_string(), id.clone());
    //             id
    //         }
    //     };
    //     let mut nodes = NODEMAP.write().unwrap();
    //     let node = nodes.get_mut(&id).unwrap();
    //     let time = req["Timestamp"].parse::<i64>().unwrap();
    //     node.dev_id.insert(
    //         "pdu_id".to_string(),
    //         vec![ValTup::new(req.get("pdu_id").unwrap().to_string(), time)],
    //     );
    //     node.dev_id.insert(
    //         "context_id".to_string(),
    //         vec![ValTup::new(
    //             resp.get("context_id").unwrap().to_string(),
    //             time,
    //         )],
    //     );
    // }
    // log::info!("Graph Step 6");
    drop(obj);
}

pub async fn creator(rx: Receiver<bool>) {
    let mut st: u64 = 1;
    let mut sf = 0;
    let msg_list = super::LOG_QUEUE.clone();
    // let mut rlogr: VecDeque<Vec<serde_json::Value>> = VecDeque::new();
    // let mut count = 0;
    // log::info!("Creator Started");
    loop {
        if msg_list.is_empty() {
            // log::info!("Creator Sleeping");
            sleep(Duration::new(st, 0));
            continue;
        }
        match rx.try_recv() {
            Ok(a) => {
                break;
            }
            Err(e) => {}
        }
        // match rx2.try_recv() {
        //     Ok(a) => {
        //         tx.send(true);
        //         rx2.recv();
        //     }
        //     Err(_) => {}
        // }
        // log::info!("Add {:?}", count);
        let data = msg_list.pop().unwrap();
        // std::thread::spawn(||{
        add(data);
        // });
    }
}
