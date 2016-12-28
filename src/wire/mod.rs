//! From&To wire

use std;
use message::{Header, Message};

pub mod msg;

#[cfg(test)]
mod test;


/// Represents the ability to be converted into
/// series of bytes
pub trait ToWire {
    // TODO: co takle tam dat argument &[u8] a vracet chybu nedostatecna delka bufferu ??
    fn to_wire(&self) -> Vec<u8>;
}

// TODO: tady bude asi potřeba vytvořit vlastní chybovy typ a vracet ho nějak..
pub trait FromWire
    where Self: std::marker::Sized
{
    fn from_wire(&[u8]) -> Option<Self>;
}

impl FromWire for Header {
    fn from_wire(input: &[u8]) -> Option<Self> {
        Some(msg::parse_dns_header(input).unwrap().1)
    }
}

impl FromWire for Message {
    fn from_wire(input: &[u8]) -> Option<Self> {
        Some(msg::parse_dns_message(input).unwrap().1)
    }
}

