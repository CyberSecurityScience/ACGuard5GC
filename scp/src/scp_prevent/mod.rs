use std::{collections::HashMap, time::{Duration, Instant}};
use array_tool::vec::Intersect;
use frunk::coproduct::CoproductSubsetter;
use futures::executor;
use hyper::{header::{self, HeaderName, HeaderValue}, HeaderMap};
use hyper_0_10::client::request;
use models::{ExtSnssai, NfProfile};
use crate::{context, scp_prov::{api_call::request_assistance, NODEMAP, RETRIEVE}};

lazy_static! {
    static ref EP: HashMap<String, Vec<String>> = {
        let mut map = HashMap::new();
        // Add entries to the map
        map.insert("provide_location_info".to_owned(), vec![]);
        map.insert("n1_n2_message_transfer".to_owned(), vec!["AMF".to_owned(), "SMF".to_owned(), "SMSF".to_owned()]);
        map.insert("enable_ue_reachability".to_owned(), vec!["value3".to_owned()]);
        map.insert("ctx_id5g_aka".to_owned(), vec!["AMF".to_owned()]);
        map.insert("ue_authentications_post".to_owned(), vec!["AMF".to_owned()]);
        map.insert("remove_subscription".to_owned(), vec![]);
        map.insert("create_subscription".to_owned(), vec![]);
        map.insert("discovery".to_owned(), vec![]);
        map.insert("de_register_nf".to_owned(), vec![]);
        map.insert("update_nf".to_owned(), vec![]);
        map.insert("register_nf".to_owned(), vec![]);
        map.insert("access_token_request".to_owned(), vec![]);
        map.insert("nssai_avail_put".to_owned(), vec![]);
        map.insert("nssai_avail_delete".to_owned(), vec![]);
        map.insert("nssf_sel_get".to_owned(), vec![]);
        map.insert("call3_gpp_registration".to_owned(), vec!["AMF".to_owned()]);
        map.insert("update3_gpp_registration".to_owned(), vec!["AMF".to_owned()]);
        map.insert("get_am_data".to_owned(), vec!["AMF".to_owned()]);
        map.insert("confirm_auth".to_owned(), vec!["AUSF".to_owned()]);
        map.insert("generate_auth_data".to_owned(), vec!["AUSF".to_owned()]);
        map.insert("get_smf_sel_data".to_owned(), vec!["AMF".to_owned()]);
        map.insert("get_smsf_registration".to_owned(), vec!["SMSF".to_owned()]);
        map.insert("get_smsf_dereg_data".to_owned(), vec!["SMSF".to_owned()]);
        map.insert("call3_gpp_smsf_registration".to_owned(), vec!["SMSF".to_owned()]);
        map.insert("get_sms_mngt_data".to_owned(), vec!["SMSF".to_owned()]);
        map.insert("get_sm_data".to_owned(), vec!["SMF".to_owned()]);
        map.insert("get_nssai".to_owned(), vec!["AMF".to_owned()]);
        map.insert("release_sm_context".to_owned(), vec!["AMF".to_owned()]);
        map.insert("update_sm_context".to_owned(), vec!["AMF".to_owned()]);
        map.insert("post_sm_context".to_owned(), vec!["AMF".to_owned()]);
        map.insert("sms_service_activation".to_owned(), vec!["AMF".to_owned()]);
        map.insert("sms_service_deactivation".to_owned(), vec!["AMF".to_owned()]);
        map.insert("send_sms_service".to_owned(), vec!["AMF".to_owned()]);
        map.insert("key2".to_owned(), vec!["value3".to_owned()]);
        map
    };
    static ref UE_EP: Vec<String> = vec![
        "provide_location_info".to_owned(),
        "enable_ue_reachability".to_owned(),
    ];
}

fn is_subset(x: &Vec<ExtSnssai>, y: &Vec<ExtSnssai>) -> bool {
    let mut found = true;
    for xv in x {
        let mut test = false;
        for yv in y {
            if yv.sst == xv.sst && yv.sd == xv.sd  {
                test = true
            }
        }
        found = found & test;
    }
    found
}

// P1_P7
pub fn prevent_initial(req_msg: &HashMap<String, String>, dis: Option<&NfProfile>, api_dis: Option<&NfProfile>, headerset: HashMap<String, String>) -> bool {
    let mut res = false;
    let mut data: Vec<Duration>= vec![];
    let start = Instant::now();
    res = p1(&headerset);
    data.push(start.elapsed());
    
    let start = Instant::now();
    res = res | p2(req_msg, &headerset);
    data.push(start.elapsed());
    
    let start = Instant::now();
    res = res | p3(req_msg, &headerset);
    data.push(start.elapsed());
    
    let start = Instant::now();
    res = res | p4(req_msg, api_dis, dis, &headerset);
    data.push(start.elapsed());
    
    let start = Instant::now();
    res = res | p5(req_msg, api_dis, dis, &headerset);
    data.push(start.elapsed());
    
    let start = Instant::now();
    res = res | p6(req_msg);
    data.push(start.elapsed());
    
    let start = Instant::now();
    res = res | p7(req_msg, &headerset);
    data.push(start.elapsed());
    let mut runs = context::RUNTIMES.lock().unwrap();
    runs.push(data);
    if res { println!("---------------------- Complete Policy {:?}", res);}
    res
}

// SenderSlice != Null when target is != NRF
pub fn p1(headerset: &HashMap<String, String>) -> bool {
    let target_nf = headerset.get("3gpp-sbi-discovery-target-nf-type").unwrap();
    if !headerset.contains_key("3gpp-sbi-discovery-requester-snssais") && target_nf != "NRF" && target_nf != "NSSF" {
        log::info!("Detected Polciy 1");
        return true;
    }
    false
}

// SenderSlice should be subset of sneder's Slices
pub fn p2(req_msg: &HashMap<String, String>, headerset: &HashMap<String, String>) -> bool {
    let target_nf = headerset.get("3gpp-sbi-discovery-target-nf-type").unwrap();
    if target_nf == "NRF" || target_nf == "NSSF" {
        return false;
    }
    let senderIP = req_msg.get("SenderIP").unwrap();
    // println!("Sender IP: {}", senderIP);
    // println!("Request Type: {}", req_msg.get("request_type").unwrap());
    let sender_snssai = {
        let ID = {
                let r = RETRIEVE.read().unwrap();
                let x = if r.contains_key(senderIP)
                {
                    r.get(senderIP).unwrap().clone()
                }
                else {
                    return false
                };
            x
        };
        let Nodes = NODEMAP.read().unwrap();
        let node = Nodes.get(&ID).unwrap();
        // println!("{:?}", node);
        let snssai = node.dev_id.get("SNSSAI").unwrap();
        let snssaiset: Vec<ExtSnssai> = snssai.iter().map(|x| serde_json::from_str::<ExtSnssai>(&x.value).unwrap()).collect();
        snssaiset
    };
    // log::info!("{:?}", headerset);
    let sender_slices = headerset.get("3gpp-sbi-discovery-requester-snssais").unwrap();
    let sender_slices = serde_json::from_str::<Vec<ExtSnssai>>(&sender_slices).unwrap();
    if !is_subset(&sender_slices, &sender_snssai) {
        log::info!("Detected Polciy 2");
        return true;
    }
    false
}

// If OCI header Present should be subset of sender's Slices
pub fn p3(req_msg: &HashMap<String, String>, headerset: &HashMap<String, String>) -> bool {
    let target_nf = headerset.get("3gpp-sbi-discovery-target-nf-type").unwrap();
    if target_nf == "NRF" || target_nf == "NSSF" {
        return false;
    }
    let senderIP = req_msg.get("SenderIP").unwrap();
    let sender_snssai = {
        let ID = {
            let r = RETRIEVE.read().unwrap();
            let x = if r.contains_key(senderIP)
                {
                    r.get(senderIP).unwrap().clone()
                }
                else {
                    return false
                };
            x
        };
        let Nodes = NODEMAP.read().unwrap();
        let node = Nodes.get(&ID).unwrap();
        let snssai = node.dev_id.get("SNSSAI").unwrap();
        let snssaiset: Vec<ExtSnssai> = snssai.iter().map(|x| serde_json::from_str::<ExtSnssai>(&x.value).unwrap()).collect();
        snssaiset
    };
    if headerset.contains_key("3gpp-Sbi-Oci") {
        let oci = headerset.get("3gpp-Sbi-Oci").unwrap();
        let mut slice2_data: HashMap<String, String> = HashMap::new();
        let temp_data = oci.split(";").collect::<Vec<&str>>(); // get slice info from header map
        for x in temp_data {
            let (k, v) = x.split_once("=").unwrap();
            slice2_data.insert(k.to_string(),v.to_string());
        }
        let oci_slices = serde_json::from_str::<Vec<ExtSnssai>>(slice2_data.get("snssai").unwrap()).unwrap();
        if !is_subset(&oci_slices, &sender_snssai) {
            log::info!("Detected Polciy 3");
            return true;
        }
    }
    false
}

// If UE id present in request, UE slices should be present in subset of sender's Slices
pub fn p4(req_msg: &HashMap<String, String>, api_dis: Option<&NfProfile>, dis: Option<&NfProfile>, headerset: &HashMap<String, String>) -> bool {
    let target_nf = headerset.get("3gpp-sbi-discovery-target-nf-type").unwrap();
    if target_nf == "NRF" || target_nf == "NSSF" {
        return false;
    }
    let senderIP = req_msg.get("SenderIP").unwrap();
    let sender_snssai = {
        let ID = {
            let r = RETRIEVE.read().unwrap();
            let x = if r.contains_key(senderIP)
                {
                    r.get(senderIP).unwrap().clone()
                }
                else {
                    return false
                };
            x
        };
        let Nodes = NODEMAP.read().unwrap();
        let node = Nodes.get(&ID).unwrap();
        let snssai = node.dev_id.get("SNSSAI").unwrap();
        let snssaiset: Vec<ExtSnssai> = snssai.iter().map(|x| serde_json::from_str::<ExtSnssai>(&x.value).unwrap()).collect();
        snssaiset
    };
    let request = req_msg.get("request_type").unwrap();
    if req_msg.contains_key("supi") && UE_EP.contains(request) {
        let supi = req_msg.get("supi").unwrap();
        let r = RETRIEVE.read().unwrap();
        if r.contains_key(supi)
        {
            let id = r.get(supi).unwrap().clone();
            drop(r);
            let Nodes = NODEMAP.read().unwrap();
            let node = Nodes.get(&id).unwrap();
            let snssai = node.dev_id.get("allowed_snssai").unwrap();
            let snssaiset: Vec<ExtSnssai> = snssai.iter().map(|x| serde_json::from_str::<ExtSnssai>(&x.value).unwrap()).collect();
            if sender_snssai.intersect(snssaiset).len() == 0 {
                log::info!("Detected Polciy 4");
                return true;
            }
        }
        else {
            drop(r);
            // log::info!("NOT HERE 1 {:?} {:?}", senderIP, supi );
            let scp_id = if api_dis.is_some() {
                api_dis.as_ref().unwrap().scp_domains.as_ref().unwrap()[0].clone()
            } else {
                dis.as_ref().unwrap().scp_domains.as_ref().unwrap()[0].clone()
            };
            if !executor::block_on(async {
                // Blocking code here
                request_assistance(senderIP.to_string(), sender_snssai.iter().map(|x| x.to_string()).collect(), scp_id, supi.to_string()).await
            }) {
                log::info!("Detected Polciy 4");
                return true;
            }
            //Perform the Private set intersection with 
            // 1. APItarget Discover's SCP else Discovery's SCP 
        }
    }
    false
}

// API target present then Target's slices should be present in the subset of sender's Slices
pub fn p5(req_msg: &HashMap<String, String>, api_dis: Option<&NfProfile>, dis: Option<&NfProfile>, headerset: &HashMap<String, String>) -> bool {
    let target_nf = headerset.get("3gpp-sbi-discovery-target-nf-type").unwrap();
    if target_nf == "NRF" || target_nf == "NSSF" {
        return false;
    }
    let senderIP = req_msg.get("SenderIP").unwrap();
    let sender_snssai = {
        let ID = {
            let r = RETRIEVE.read().unwrap();
            let x = if r.contains_key(senderIP)
            {
                r.get(senderIP).unwrap().clone()
            }
            else {
                return false
            };
            x
        };
        let Nodes = NODEMAP.read().unwrap();
        let node = Nodes.get(&ID).unwrap();
        let snssai = node.dev_id.get("SNSSAI").unwrap();
        let snssaiset: Vec<ExtSnssai> = snssai.iter().map(|x| serde_json::from_str::<ExtSnssai>(&x.value).unwrap()).collect();
        snssaiset
    };
    if headerset.contains_key("3gpp-sbi-target-apiroot") {
        let apiroot = req_msg.get("3gpp-sbi-target-apiroot").unwrap();
        let r = RETRIEVE.read().unwrap();
        if r.contains_key(apiroot)
        {
            let id = r.get(apiroot).unwrap().clone();
            drop(r);
            let Nodes = NODEMAP.read().unwrap();
            let node = Nodes.get(&id).unwrap();
            let snssai = node.dev_id.get("allowed_snssai").unwrap();
            let snssaiset: Vec<ExtSnssai> = snssai.iter().map(|x| serde_json::from_str::<ExtSnssai>(&x.value).unwrap()).collect();
            if sender_snssai.intersect(snssaiset).len() == 0 {
                log::info!("Detected Polciy 5");

                return true;
            }
        }
        else {
            drop(r);
            // log::info!("NOT HERE 2 {:?} {:?}", senderIP, apiroot );
            let scp_id = if api_dis.is_some() {
                api_dis.as_ref().unwrap().scp_domains.as_ref().unwrap()[0].clone()
            } else {
                dis.as_ref().unwrap().scp_domains.as_ref().unwrap()[0].clone()
            };
            if !executor::block_on(async {
                // Blocking code here
                request_assistance(senderIP.to_string(), sender_snssai.iter().map(|x| x.to_string()).collect(), scp_id, apiroot.to_string()).await
            }) {
                log::info!("Detected Polciy 5");

                return true;
            }
            //Perform the Private set intersection with 
            // 1. APItarget Discover's SCP else Discovery's SCP 
        }
    }
    false
}

// Endpoint set should be part of the end points need to create this 
pub fn p6(req_msg: &HashMap<String, String>) -> bool {
    let senderIP = req_msg.get("SenderIP").unwrap();
    let ID = {
        let r = RETRIEVE.read().unwrap();
        let x = if r.contains_key(senderIP)
        {
            r.get(senderIP).unwrap().clone()
        }
        else {
            return false
        };
        x
    };
    let Nodes = NODEMAP.read().unwrap();
    let node = Nodes.get(&ID).unwrap();
    let name: String = node.dev_name.clone();
    let req_type = req_msg.get("request_type").unwrap();
    match EP.get(req_type) {
        Some(x) => {
            if x.len() > 0 {
                if !x.contains(&name) {
                    log::info!("Detected Polciy 6");

                    return true
                }
            }
        },
        None => {}
    }
    false
}

// UpdateNF / Register should have OAM codes
pub fn p7(req_msg: &HashMap<String, String>, headerset: &HashMap<String, String>) -> bool {
    let target_nf = headerset.get("3gpp-sbi-discovery-target-nf-type").unwrap();
    if target_nf  == "NRF" {
        if req_msg.get("request_type").unwrap() == "update_nf" {
            if req_msg.contains_key("OAM_MAC") {
                let mac = req_msg.get("OAM_MAC").unwrap();
                if mac == "XXXXX" {
                    log::info!("Detected Polciy 7");

                    return true;
                }
            }
        }
    }
    false
}

// pub fn prevent_token(req_msg: &HashMap<String, String>, hm: &HeaderMap<HeaderValue>) -> bool {
//     // Token
//     if req_msg.contains_key("Token") {
//         if !hm.contains_key(hyper::header::AUTHORIZATION) {
//             return true
//         }
//     }
//     false
// }
// fn is_subset_in_order(x: &[String], y: &[String]) -> bool {
//     if x.len() > y.len() {
//         return false;
//     }
    
//     x.iter().zip(y.iter()).all(|(a, b)| a == b)
// }
// pub fn prevent_stage2(set1: Vec<String>, set2: Vec<String>) -> bool {
//     // Privacy in Private set intersection
//     is_subset_in_order(&set1, &set2)
// }

#[cfg(test)]
mod t {
    use models::NfStatus;
    use crate::utils::jmap_hash;

    use super::*;
    #[test]
    pub fn test_status() {
        let nfs: NfStatus = NfStatus::registered();
        println!("{:?}", nfs);
        let nf_status: String = nfs.to_string();
        println!("{:}", nf_status);
    }
    #[test]
    pub fn test1() {
        let y1 = ExtSnssai{sst: 1, sd: Some("000001".to_owned()), sd_ranges: None, wildcard_sd: None};
        let y2 = ExtSnssai{sst: 2, sd: Some("000002".to_owned()), sd_ranges: None, wildcard_sd: None};
        let y3 = ExtSnssai{sst: 3, sd: Some("000003".to_owned()), sd_ranges: None, wildcard_sd: None};
        let vecext = Some(vec![y1, y2, y3]);
        let slices: Vec<String> = match vecext {
            Some(ref a) => a.iter().map(|x| serde_json::to_string(x).unwrap()).collect(),
            None => ["None".to_string()].to_vec(),
        };
        let msg = serde_json::json!({
            "request_type" : "register_nf",
            // "FQDN": fqdn,
            // "UUID": param_nf_instance_id.to_string(),
            "SNSSAI": slices,
            // "allowed_snssai": allowed_slices,
            // "nf_status": nf_status,
            // "nf_type": nf_type,
            // "plmns": plmns,
            // "profile": serde_json::to_string(&param_nf_profile1).unwrap()
            // "hash": format!("{:x}" ,md5::compute(serde_json::to_string(&param_nf_profile1.clone())?))
        });
        // log::info!("Here {:?}", msg);
        let data = jmap_hash(msg);
        let x123 = "[\"sst,1,sd,000001\"]";
        let data: Vec<ExtSnssai> =
                    serde_json::from_str::<Vec<String>>(x123)
                        .unwrap()
                        .iter()
                        .map(|x| serde_json::from_str(x).unwrap())
                        .collect();
        // let x = serde_json::to_string(&y1).unwrap();
        // let y: ExtSnssai = serde_json::from_str(&x).unwrap();
        println!("{:?}", data);
    }
}
