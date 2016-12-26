//! Resource record data structures
//!
//!

use std::net::Ipv4Addr;

#[derive(Debug)]
pub enum Rdata {
    A(Ipv4Addr),
    Generic(Vec<u8>),
}
