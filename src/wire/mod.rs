//! From&To wire

use std;
use std::slice;
use message::{Header, Message, Question, QuestionBuilder};

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

impl ToWire for u16 {
    fn to_wire(&self) -> Vec<u8> {
        unsafe { slice::from_raw_parts((&self.to_be() as *const u16) as *const u8, 2) }.to_vec()
    }
}

impl FromWire for Header {
    fn from_wire(input: &[u8]) -> Option<Self> {
        Some(msg::parse_dns_header(input).unwrap().1)
    }
}

impl ToWire for Header {
    fn to_wire(&self) -> Vec<u8> {
        let mut buffer: Vec<u8> = vec![0u8; 12];
        let id_slice: &[u8] = &self.id.to_wire();
        for (i, byte) in id_slice.into_iter().enumerate() {
            buffer[i] = *byte;
        }
        if self.response == true {
            buffer[2] |= 0b1000_0000;
        }
        let opcode = (self.opcode & 0x0F) << 3;
        buffer[2] |= opcode;
        if self.rd == true {
            buffer[2] |= 0b0000_0001;
        }
        let qdcount_slice: &[u8] = &self.qdcount.to_wire();
        for (i, byte) in qdcount_slice.into_iter().enumerate() {
            buffer[4 + i] = *byte;
        }
        buffer
    }
}

impl ToWire for Message {
    fn to_wire(&self) -> Vec<u8> {
        let mut buffer = self.header.to_wire();
        for i in 0..self.question.len() {
            let labels: Vec<&str> = self.question[i].name.split_terminator('.').collect();
            for label in labels {
                let len = label.len() as u8;
                buffer.push(len);
                buffer.extend(label.as_bytes().iter().cloned());
            }
            buffer.push(0);
            // Type
            buffer.extend((self.question[i].qtype as u16).to_wire());
            // Class
            buffer.extend((self.question[i].class as u16).to_wire());
        }
        buffer
    }
}

impl FromWire for Message {
    fn from_wire(input: &[u8]) -> Option<Self> {
        Some(msg::parse_dns_message(input).unwrap().1)
    }
}

