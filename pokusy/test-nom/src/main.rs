#![allow(non_snake_case)]

#[macro_use]
extern crate nom;

use nom::be_u8;
use std::str;

/*
The compression scheme allows a domain name in a message to be
represented as either:
   - a sequence of labels ending in a zero octet
   - a pointer
   - a sequence of labels ending with a pointer
*/

/// Each label is either a length byte followed by that number of bytes or a pointer to prior
/// occurrence of the same label
#[derive(Debug)]
pub enum DnsNameLabel {
    Label(String),
    Pointer(u16),
}
named!(parse_dns_name_label<&str>, map_res!(length_bytes!(be_u8), str::from_utf8));
named!(parse_dns_name_label2<DnsNameLabel>, map_res!(
        length_bytes!(be_u8),
        |s: &[u8]| {
            match String::from_utf8(s.to_owned()) {
                Ok(s) => Ok(DnsNameLabel::Label(s)),
                Err(e) => Err(e)
            }
        }
        ));

named!(parse_dns_name_pointer<(u16, u16)>, bits!(pair!(tag_bits!(u16, 2, 0x03), take_bits!(u16, 14))));
named!(parse_dns_name_pointer2<DnsNameLabel>, map_res!(
        bits!(pair!(tag_bits!(u16, 2, 0x03), take_bits!(u16, 14))),
        |(_, p)| -> Result<_, ()> {Ok(DnsNameLabel::Pointer(p))}
        ));

named!(parse_dns_name_unit<DnsNameLabel>, alt!(parse_dns_name_pointer2 | parse_dns_name_label2));
//, take_bits!(u16, 14)
named!(pub parse_dns_name<Vec<&str> >, do_parse!(
        ret: many_till!(map_res!(length_bytes!(be_u8), str::from_utf8), tag!("\0")) >>
        (ret.0)
        ));

named!(pub parse_dns_name2< Vec<&str> >, 
    terminated!(
        flat_map!(
            is_not!("\x00"),
            many0!(parse_dns_name_label)
        ),
        tag!("\x00")
    )
);


fn main() {
    let bytes = b"\x0512345";
    println!("{:?}", parse_dns_name(bytes));
    let bytes = b"\x05_____\x04____\x03___\x00";
    println!("{:?}", parse_dns_name(bytes));
    let bytes = b"\x05_____\x04____\x03___\x00";
    println!("{:?}", parse_dns_name2(bytes));
    let bytes = b"\xc0\x01_____\x04____\x03___\x00";
    println!("{:?}", parse_dns_name_pointer(bytes));
    let bytes = b"\x05\x01_____\x04____\x03___\x00";
    println!("{:?}", parse_dns_name_pointer(bytes));
    let bytes = b"\xc0\x03_____\x04____\x03___\x00";
    println!("{:?}", parse_dns_name_unit(bytes));
    let bytes = b"\x0afunguje_to\x04____\x03___\x00";
    println!("{:?}", parse_dns_name_unit(bytes));
}