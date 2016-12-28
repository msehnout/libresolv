//! Resource record data structures
//!
//!

use std::net::Ipv4Addr;

#[derive(Debug,PartialEq)]
pub enum Rdata {
    A(Ipv4Addr),
    Generic(Vec<u8>),
}

#[derive(Debug)]
pub struct ResRec {
    pub name: String,
    pub qtype: u16,
    pub class: u16,
    pub ttl: u32,
    pub rdata: Rdata,
}

#[derive(Debug)]
pub struct ResRecBuilder {
    name: Option<String>,
    pub qtype: u16,
    class: u16,
    ttl: u32,
    rdata: Option<Rdata>,
}

impl ResRecBuilder {
    pub fn no_name(qtype: u16, class: u16, ttl: u32) -> ResRecBuilder {
        ResRecBuilder {
            name: None,
            qtype: qtype,
            class: class,
            ttl: ttl,
            rdata: None,
        }
    }

    pub fn set_name(mut self, name: String) -> ResRecBuilder {
        self.name = Some(name);
        self
    }

    pub fn set_rdata(mut self, rdata: Rdata) -> ResRecBuilder {
        self.rdata = Some(rdata);
        self
    }

    pub fn finish(self) -> ResRec {
        ResRec {
            name: self.name.unwrap_or("".to_string()),
            qtype: self.qtype,
            class: self.class,
            ttl: self.ttl,
            rdata: self.rdata.unwrap_or(Rdata::Generic(vec![])),
        }
    }
}
