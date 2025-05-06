use std::{
    collections::HashMap,
    error::Error,
    fmt,
    ops::{AddAssign, BitAndAssign, Shl, ShlAssign},
    str::FromStr,
};

use num::{Bounded, Integer};

pub struct PtrWrapper<T: Clone + Copy> {
    // https://internals.rust-lang.org/t/shouldnt-pointers-be-send-sync-or/8818
    pub v: Option<T>,
}
impl<T: Clone + Copy> PtrWrapper<T> {
    pub fn new() -> Self {
        Self { v: None }
    }
    pub fn as_ref(&self) -> Option<&T> {
        self.v.as_ref()
    }
    pub fn as_deref(self) -> Option<T>
    where
        T: Sized + Copy,
    {
        self.v
    }
}
unsafe impl<T: Clone + Copy> std::marker::Send for PtrWrapper<T> {}

#[derive(Debug, Clone)]
pub enum ScpError {
    Unspecified { detail: String },
    TooManyIDs { detail: String },
    SameRequestOngoing { detail: String, procedure_id: i64 },
    RequestTimeout { detail: String },
    NfDiscoveryFailed { detail: String, service: String },
    Unimplemented { function: String },
    SBIUnexpectedError { detail: String },
    DiscardMessage,
}

impl fmt::Display for ScpError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            ScpError::Unspecified { detail } => write!(f, "ScpError: {}", detail),
            ScpError::TooManyIDs { detail } => write!(f, "ScpError: {}", detail),
            ScpError::SameRequestOngoing {
                detail,
                procedure_id,
            } => write!(f, "ScpError: {}, procedure = {}", detail, procedure_id),
            ScpError::RequestTimeout { detail } => write!(f, "ScpError: {}", detail),
            ScpError::NfDiscoveryFailed { detail, service } => {
                write!(f, "ScpError: NF dis: {}: {}", service, detail)
            }
            ScpError::Unimplemented { function } => {
                write!(f, "ScpError: {} is not implemented", function)
            }
            ScpError::SBIUnexpectedError { detail } => write!(f, "ScpError: {}", detail),
            ScpError::DiscardMessage => {
                write!(f, "ScpError: Discard due to failed integrity check")
            }
        }
    }
}

impl Error for ScpError {
    fn description(&self) -> &str {
        match self {
            ScpError::Unspecified { detail } => detail,
            ScpError::TooManyIDs { detail } => detail,
            ScpError::SameRequestOngoing {
                detail,
                procedure_id,
            } => detail,
            ScpError::RequestTimeout { detail } => detail,
            ScpError::NfDiscoveryFailed { detail, service } => detail, //format!("ScpError: NF dis: {}: {}", service, detail),
            ScpError::Unimplemented { function } => function, //format!("{} is not implemented", function),
            ScpError::SBIUnexpectedError { detail } => detail,
            ScpError::DiscardMessage => "Discard due to failed integrity check",
        }
    }
}

impl ScpError {
    pub fn boxed(self) -> Box<ScpError> {
        Box::new(self)
    }
    pub fn sbi(msg: &str) -> Self {
        ScpError::SBIUnexpectedError {
            detail: msg.to_string(),
        }
    }
}

#[derive(Debug, Clone)]
pub struct IDAllocator<
    T: Copy
        + Integer
        + AddAssign
        + Bounded
        + Shl
        + BitAndAssign
        + PartialEq
        + ShlAssign
        + fmt::Display,
> {
    pub counter: T,
    pub freed: Vec<T>,
    pub freed_unusable: Vec<T>,
    pub transaction: bool,
    pub forbidden_bit: Option<T>,
    pub max_val: Option<T>,
}
impl<
        T: Copy
            + Integer
            + AddAssign
            + Bounded
            + Shl
            + BitAndAssign
            + PartialEq
            + ShlAssign
            + fmt::Display,
    > IDAllocator<T>
{
    pub fn reset(&mut self) {
        self.counter = T::one();
        self.freed = Vec::new();
        self.freed_unusable = Vec::new();
        self.transaction = false;
    }
    pub fn new() -> IDAllocator<T> {
        Self {
            counter: T::one(),
            freed: Vec::new(),
            freed_unusable: Vec::new(),
            transaction: false,
            forbidden_bit: None,
            max_val: None,
        }
    }
    pub fn new_with_maxval(maxval: T) -> IDAllocator<T> {
        Self {
            counter: T::one(),
            freed: Vec::new(),
            freed_unusable: Vec::new(),
            transaction: false,
            forbidden_bit: None,
            max_val: Some(maxval),
        }
    }
    pub fn new_with_forbidden_bit(bitpos: T) -> IDAllocator<T> {
        Self {
            counter: T::one(),
            freed: Vec::new(),
            freed_unusable: Vec::new(),
            transaction: false,
            forbidden_bit: Some(bitpos),
            max_val: None,
        }
    }
    pub fn new_with_counter(counter: T) -> IDAllocator<T> {
        Self {
            counter: counter,
            freed: Vec::new(),
            freed_unusable: Vec::new(),
            transaction: false,
            forbidden_bit: None,
            max_val: None,
        }
    }
    pub fn allocate(&mut self) -> Result<T, ScpError> {
        if let Some(id) = self.freed.pop() {
            return Ok(id);
        }
        let ret = self.counter;
        if let Some(maxval) = self.max_val {
            if ret == maxval {
                return Err(ScpError::TooManyIDs {
                    detail: format!("Allocating ID {}/{}", ret, maxval),
                });
            }
        }
        if ret == T::max_value() {
            return Err(ScpError::TooManyIDs {
                detail: format!("Allocating ID {}/{}", ret, T::max_value()),
            });
        }
        self.counter += T::one();
        if let Some(fb) = self.forbidden_bit {
            let mut cmp = self.counter;
            let mut mask = T::one();
            mask <<= fb;
            cmp &= mask;
            if cmp != T::zero() {
                self.counter += mask; // skip this range
            }
        }
        Ok(ret)
    }
    pub fn free(&mut self, id: T) {
        if self.transaction {
            self.freed_unusable.push(id);
        } else {
            self.freed.push(id);
        }
    }
    pub fn transaction_begin(&mut self) {
        self.transaction = true;
    }
    pub fn transaction_commit(&mut self) {
        self.transaction = false;
        self.freed.append(&mut self.freed_unusable);
    }
}

pub fn jmap_hash(map: serde_json::Value) -> HashMap<String, String> {
    let mut hashMap: HashMap<String, String> = HashMap::new();
    for (k, y) in map.as_object().unwrap() {
        // log::info!("{:?}, {:?}", k, y);
        if y.is_array() {
            let data = y.as_array().unwrap();
            let data: Vec<String> = data
                .iter()
                .map(|x| x.as_str().unwrap().to_owned())
                .collect();
            let str_data = serde_json::to_string(&data).unwrap();
            // let newdata: Vec<models::ExtSnssai> = data.iter().map(|x| models::ExtSnssai::from_str(x).unwrap()).collect();
            hashMap.insert(k.to_owned(), str_data);
        } else if y.is_number() {
            let data = y.as_u64().unwrap();
            hashMap.insert(k.to_owned(), data.to_string());
        } else {
            hashMap.insert(k.to_owned(), y.as_str().unwrap().to_owned());
        }
    }
    hashMap
}
