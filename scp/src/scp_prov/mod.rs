use crossbeam_queue::SegQueue;
use mona::Transpose;
use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::{Arc, Mutex, RwLock};

use crate::context::Log;

use hex::encode;
use rand::{thread_rng, Rng};

pub mod api_call;
// pub mod detection;
// pub mod dump;
pub mod graph;
// pub mod dot;

lazy_static! {
    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    pub static ref NODEMAP: RwLock<HashMap<String, Node>> = RwLock::new(HashMap::new());
    // #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    // pub static ref EDGEMAP: RwLock<HashMap<String, HashMap<String, Vec<Edge>>>> = RwLock::new(HashMap::new());
    // pub static ref TRANSPOSE: RwLock<bool> = RwLock::new(false);
    pub static ref RETRIEVE: RwLock<HashMap<String, String>> = RwLock::new(HashMap::new());

    pub static ref LOG_QUEUE: Arc<SegQueue<Log>> = Arc::new(SegQueue::new());
    pub static ref NRF_KEY: RwLock<String> = RwLock::new(String::new());
    pub static ref LOG_TS: RwLock<Vec<i64>> = RwLock::new(Vec::new());

}

// pub fn get_transpose() -> bool {
//     *TRANSPOSE.read().unwrap()
// }

// pub fn set_transpose() {
//     if get_transpose() == false {
//         let mut emap = EDGEMAP.write().unwrap();
//         *TRANSPOSE.write().unwrap() = true;
//         *emap = emap.clone().transpose();
//     }
// }

// pub fn unset_transpose() {
//     if get_transpose() == true {
//         let mut emap = EDGEMAP.write().unwrap();
//         *TRANSPOSE.write().unwrap() = false;
//         *emap = emap.clone().transpose();
//     }
// }

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ValTup {
    pub value: String,
    pub start_time: i64,
    pub end_time: i64,
}

impl ValTup {
    pub fn new(value: String, start_time: i64) -> ValTup {
        ValTup {
            value,
            start_time,
            end_time: 0,
        }
    }
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct Node {
    pub dev_name: String,                     // or type i.e AMF,SMF,UE etc
    pub dev_id: HashMap<String, Vec<ValTup>>, // uuid or ran_ue in case of UE
    pub dev_ts: i64,
}

impl Node {
    pub fn create(dev_name: String, id_name: String, dev_id: String, time: i64) -> Node {
        let mut th: HashMap<String, Vec<ValTup>> = HashMap::new();
        th.insert(id_name, vec![ValTup::new(dev_id, time)]);
        Node {
            dev_name,
            dev_id: th,
            dev_ts: time, // timestamp
        }
    }
    pub fn empty() -> Node {
        Node {
            dev_name: "".to_string(),
            dev_id: HashMap::new(),
            dev_ts: 0, // timestamp
        }
    }
}

// #[derive(Debug, Clone, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
// pub struct Edge {
//     pub timestamp: i64,
//     pub request_type: String,
//     pub request_data: HashMap<String, String>,
//     pub request_hash: String,
//     pub service_dir: String,
// }
// let edges_path = format!(
//     "{:}/edges_{:}.json",
//     base,
//     ctime - nfself.dumper_interval as i64
// );
// impl Edge {
//     pub fn create(
//         timestamp: i64,
//         request_type: String,
//         request_data: HashMap<String, String>,
//         request_hash: String,
//         service_dir: String,
//     ) -> Edge {
//         Edge {
//             timestamp,
//             request_type,
//             request_data,
//             request_hash,
//             service_dir,
//         }
//     }
//     pub fn cmpe(&self, edge_obj: &Edge) -> bool {
//         if self.request_data == edge_obj.request_data {
//             // self.verify = true;
//             return true;
//         } else {
//             return false;
//         }
//     }
// }

pub fn gen_id() -> String {
    let mut rng = thread_rng();
    let random_bytes: [u8; 32] = rng.gen();
    let mut new_id = encode(random_bytes);
    let ret = NODEMAP.read().unwrap();
    if ret.contains_key(&new_id) {
        while ret.contains_key(&new_id) {
            let random_bytes: [u8; 32] = rng.gen();
            let mut new_id = encode(random_bytes);
        }
    }
    new_id
}
