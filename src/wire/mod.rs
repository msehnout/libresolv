//! From&To wire

use std;
use nom::be_u16;
use super::message::*;

/// Represents the ability to be converted into
/// series of bytes
pub trait ToWire {
    // TODO: co takle tam dat argument &[u8] a vracet chybu nedostatecna delka bufferu ??
    fn to_wire(&self) -> Vec<u8>;
}

pub trait FromWire
where Self: std::marker::Sized
{
    fn from_wire(&[u8]) -> Option<Self>;
}

impl Header {
named!(parse_dns_header<Header>, do_parse!(
        id: be_u16 >>
        third_byte: bits!(tuple!(take_bits!(u8,1), take_bits!(u8,4), take_bits!(u8,1),
                                 take_bits!(u8,1), take_bits!(u8,1))) >>
        fourth_byte: bits!(tuple!(take_bits!(u8,1), take_bits!(u8,3), take_bits!(u8,4))) >>
        qdcount: be_u16 >>
        ancount: be_u16 >>
        nscount: be_u16 >>
        arcount: be_u16 >>
        (Header {
            id: id,
            response: third_byte.0 == 1,
            opcode: third_byte.1,
            aa: third_byte.2 == 1,
            tc: third_byte.3 == 1,
            rd: third_byte.4 == 1,
            ra: fourth_byte.0 == 1,
            z:  fourth_byte.1,
            // TODO: replace with tag of four zeros.. not true any more, read newer RFCs!
            rcode: fourth_byte.2,
            qdcount: qdcount,
            ancount: ancount,
            nscount: nscount,
            arcount: arcount,
        })));
}

impl FromWire for Header {
    fn from_wire(input: &[u8]) -> Option<Self> {
        Some(Header::parse_dns_header(input).unwrap().1)
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn print_parse_dns() {
        let test = vec![0xc9, 0xba, 0x01, 0x20, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x07,
        0x65, 0x78, 0x61, 0x6d, 0x70, 0x6c, 0x65, 0x03, 0x63, 0x6f, 0x6d, 0x00, 0x00,
        0x01, 0x00, 0x01, 0x00, 0x00, 0x29, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];

        println!("{:?}", Header::parse_dns_header(&test));

    }
}
