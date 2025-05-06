use common::timer;
use models::ProblemDetails;
use nscp_api::{
    SCPDetectAssistRequest, SCPDetectAssistResponse, SCPDetectInitRequest, SCPDetectInitResponse,
    SCPDetectResultResponse, SCPIDFinalSetRequest, SCPIDFinalSetResponse, SCPIDInitSetRequest,
    SCPIDInitSetResponse,
};
use protocol::private_id::{company::CompanyPrivateId, traits::CompanyPrivateIdProtocol};
use regex::Regex;
use std::{collections::HashMap, error::Error, sync::atomic::Ordering, thread};

use crate::{
    context, libsba, scp_prov::{NODEMAP, RETRIEVE}};
//     scp_detect::{self, assist_with_id},
// };
use nscp_api::AssistType;
// use super::detection;

pub async fn scp_detect_init(
    data: SCPDetectInitRequest,
) -> Result<SCPDetectInitResponse, Box<dyn Error>> {
    log::info!("Received a detection Init");
    if data.start_time == 1 {
        let nodes = NODEMAP.read().unwrap();
        log::info!("{:?}", nodes.len());
    }
    if data.end_time == 1 {
        let nodes = RETRIEVE.read().unwrap();
        log::info!("{:?}", nodes.len());
    }
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
    // let move_id = unique_id.clone();
    // match data.algo_name.as_str() {
    //     "confused_producer" => {
    //         tokio::spawn(async move {
    //             // log::info!("Inside thread");
    //             // scp_detect::confused_producer::detect_confused_attacker(move_id).await;
    //             // scp_detect::confused_producer::detect_confused_attacker(
    //             //     move_id,
    //             //     data.start_time.clone(),
    //             //     data.end_time.clone(),
    //             // )
    //             // .await;
    //         });
    //     }
    //     _ => todo!(),
    // }
    Ok(SCPDetectInitResponse::SCPDetectInitComplete { id: 1.to_string() })
}

pub async fn scp_detect_assist(
    data: SCPDetectAssistRequest,
) -> Result<SCPDetectAssistResponse, Box<dyn Error>> {
    log::info!("Received a detection Assist");
    Ok(provide_assistance(data))
}

// pub async fn scp_detect_result(id: String) -> Result<SCPDetectResultResponse, Box<dyn Error>> {
//     log::info!("Received a detection Result");
//     let key_len = {
//         let x = context::KEY_SET.read().unwrap();
//         if x.contains_key(&id) {
//             x.get(&id).unwrap().len()
//         } else {
//             return Ok(SCPDetectResultResponse::SCPDetectResultAccepted(
//                 ProblemDetails::with_detail("Still Processing"),
//             ));
//         }
//     };
//     // log::info!("Key Len {:?}", key_len);
//     let resultset = context::RESULT_SET.read().unwrap();
//     match resultset.get(&id) {
//         Some(a) => {
//             // log::info!("A len {:?}", a);
//             if a.0.len() == key_len {
//                 Ok(SCPDetectResultResponse::SCPDetectResultComplete {
//                     attackers: a.1.clone(),
//                 })
//             } else {
//                 Ok(SCPDetectResultResponse::SCPDetectResultAccepted(
//                     ProblemDetails::with_detail("Still Processing"),
//                 ))
//             }
//         }
//         None => Ok(SCPDetectResultResponse::BadRequest(
//             ProblemDetails::with_detail("Non Existent Key"),
//         )),
//     }
// }

// pub async fn scp_id_init_set(id: String) -> Result<SCPIDInitSetResponse, Box<dyn Error>> {
//     log::info!("Received a Private ID Init");
//     let t = timer::Timer::new_silent("Private ID Step 1");
//     let mut map: std::sync::RwLockWriteGuard<
//         std::collections::HashMap<String, protocol::private_id::company::CompanyPrivateId>,
//     > = context::PRIVATE_ID.write().unwrap();
//     match map.get_mut(&id) {
//         Some(protocol) => {
//             log::info!("{}", t.elapsed_str(Some("Private ID Step 1")));
//             Ok(SCPIDInitSetResponse::SCPIDInitSetComplete {
//                 uc: protocol.get_permuted_keys().unwrap(),
//             })
//         }
//         None => Ok(SCPIDInitSetResponse::InternalServerError(
//             ProblemDetails::with_detail("ERROR in MAP"),
//         )),
//     }
// }

// pub async fn scp_id_final_set(
//     id: String,
//     data: SCPIDFinalSetRequest,
// ) -> Result<SCPIDFinalSetResponse, Box<dyn Error>> {
//     log::info!("Received a Private ID Final");
//     let t = timer::Timer::new_silent("Private ID Step 2");
//     let mut map = context::PRIVATE_ID.write().unwrap();
//     match map.get_mut(&id) {
//         Some(protocol) => {
//             match protocol.set_encrypted_partner_keys(data.u_p) {
//                 Ok(()) => { /* log::info!("UP Set in {}", id); */ }
//                 Err(_) => {
//                     return Ok(SCPIDFinalSetResponse::InternalServerError(
//                         ProblemDetails::with_detail("ERROR UP"),
//                     ));
//                 }
//             }
//             match protocol.set_encrypted_company(data.e_c) {
//                 Ok(()) => { /*log::info!("EC Set in {}", id);*/ }
//                 Err(_) => {
//                     return Ok(SCPIDFinalSetResponse::InternalServerError(
//                         ProblemDetails::with_detail("ERROR EC"),
//                     ));
//                 }
//             }
//             let attackers = protocol.calculate_set_diff().unwrap();
//             let res_id = protocol.get_p_key();
//             {
//                 let mut resset = context::RESULT_SET.write().unwrap();
//                 if resset.contains_key(&res_id) {
//                     let con = resset.get_mut(&res_id).unwrap();
//                     con.0.push(id);
//                     con.1.extend(attackers);
//                 } else {
//                     resset.insert(res_id, (vec![id], attackers));
//                 }
//             }
//             protocol.set_ready(true);
//             log::info!("{}", t.elapsed_str(Some("Private ID Step 2")));
//             Ok(SCPIDFinalSetResponse::SCPIDFinalSetComplete(()))
//         }
//         None => Ok(SCPIDFinalSetResponse::InternalServerError(
//             ProblemDetails::with_detail("ERROR in MAP"),
//         )),
//     }
// }

pub fn provide_assistance(req: SCPDetectAssistRequest) -> SCPDetectAssistResponse {
    let uni_id = req.id;
    // let nf_ids = vec![req.nf_ids]; /* HashMap */
    let id = req.nf_ids;
    let mut collected_data: HashMap<String, Vec<String>> = HashMap::new();
    // let log_ts = context::LOG_TS.read().unwrap();
    // let ctx = context::SCP_PARAMETERS.get().unwrap();
    // let base = ctx.log_folder.clone();
    let nodes = crate::scp_prov::NODEMAP.read().unwrap();
    for (k, y) in nodes.iter() {
        // log::info!("Node: {:?}", y);
        let check_val: String = if y.dev_id.contains_key("FQDN") {
            let re = Regex::new(r"^http://").unwrap();
            let re1 = Regex::new(r"^https://").unwrap();
            let FQDN = y.dev_id.get("FQDN").unwrap();
            if re.is_match(&FQDN[0].value) {
                FQDN[0].value[7..].to_string()
            } else if re1.is_match(&FQDN[0].value) {
                FQDN[0].value[8..].to_string()
            } else {
                FQDN[0].value.clone()
            }
        } else if y.dev_id.contains_key("SUPI") {
            let re = Regex::new(r"^imsi://").unwrap();
            let SUPI = y.dev_id.get("SUPI").unwrap();
            if re.is_match(&SUPI[0].value) {
                SUPI[0].value[7..].to_string()
            } else {
                SUPI[0].value.clone()
            }
        } else {
            continue;
            // "Blank".to_string()
        };
        // log::info!("Inner Checking {:?}", check_val);
        if check_val == id {
            // let ext_snssai = serde_json::from_str::<Vec<ExtSnssai>>
            // (&y.dev_id.get("allowed_snssai").unwrap()[0].value).unwrap();
            let slices = &y.dev_id.get("allowed_snssai").unwrap();
            // log::info!("ID {:?}", id);
            // log::info!("SLICE COLLECTED {:?}", slices);
            let mut p_snssai: Vec<String> = vec![];
            for vtup in slices.iter() {
                if vtup.start_time < 0 /* Time From NFIDS*/
                && (vtup.end_time == 0 || vtup.end_time >  0 /* Time From NFIDS*/)
                {
                    p_snssai.push(vtup.value.clone());
                }
            }
            collected_data.insert(id.clone(), p_snssai);
            break;
        }
    }
    // let og_data = collected_data.get(&id).unwrap().clone();
    let result = crate::private_id::private_id_simple_client(collected_data, req.u_company).unwrap();
    // let datastring: Vec<String> = result[1].get(&id).unwrap().iter().map(|bb| bb.to_string()).collect();
    // if prevent_stage2(og_data, datastring) {
    //     return SCPDetectAssistResponse::UnableToCreate(ProblemDetails::with_detail("Unknown"));
    // }
    SCPDetectAssistResponse::SCPIDAssistComplete {
        data: result
    }
    // log::info!("Terminating the Client");
    //log::info!("{}", t.elapsed_str(Some("Confused Producer Assist Stage")));
}

pub async fn request_assistance(
    sender_id: String,
    sender_nf_slices: Vec<String>,
    target_scp: String,
    target_id: String,
    // ue_id: Option<String>,
) -> bool {
    log::info!("HERER:wq");
    let mut u_company: HashMap<String, Vec<String>> = HashMap::new();
    u_company.insert(sender_id.clone(), sender_nf_slices.clone());
    // let mut target_id = String::new();
    // let mut target_scp = String::new();
    let self_fqdn = crate::context::SCP_PARAMETERS
        .get()
        .unwrap()
        .nfctx
        .host
        .clone();
    // let mut target_node: Vec<String> = vec;

    let mut process_data: HashMap<String, HashMap<String, Vec<String>>> = HashMap::new();
    process_data.insert(sender_id, u_company.clone());
    let unique_id = crate::scp_prov::gen_id();
    let mut protocol: CompanyPrivateId = CompanyPrivateId::new();
    protocol.set_p_key(unique_id.clone());
    protocol.load_data(u_company);
    protocol.load_dataset(process_data);

    let actual_u_p = protocol.get_permuted_keys().unwrap();
    let scp_client = libsba::scp_client(target_scp);
    let data: SCPDetectAssistRequest = SCPDetectAssistRequest {
        id: unique_id,
        fqdn: self_fqdn.clone(),
        req_type: AssistType::SLICE_IDS,
        nf_ids: target_id,
        u_company: actual_u_p,
        interval: None,
        start_time: 0,
        end_time: 0,
    };
    let res = scp_client.scp_detect_assist(data).await.unwrap();
    context::COUNTER.fetch_add(1, Ordering::SeqCst);

    match res {
        SCPDetectAssistResponse::SCPIDAssistComplete { mut data } => {
            protocol.set_encrypted_partner_keys(data.remove(0));
            protocol.set_encrypted_company(data.remove(0));
            let attackers = protocol.calculate_set_diff().unwrap();
            protocol.set_ready(true);
            if attackers.len() == 0 {
                return true;
            } else {
                return false;
            }
        }
        _ => {
            return true;
        }
    }
}

#[cfg(test)]
mod t {
    use super::*;

    #[test]
    pub fn test1() {
        let x: SCPDetectInitRequest = SCPDetectInitRequest {
            algo_name: "confused_producer".to_owned(),
            start_time: 1718653403,
            end_time: 1718653403,
        };
        println!("{}", serde_json::to_string(&x).unwrap());
    }
}
