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

named!(parse_dns_name_label<&str>, map_res!(length_bytes!(be_u8), str::from_utf8));
named!(parse_dns_name_pointer<(u16, u16)>, bits!(pair!(tag_bits!(u16, 2, 0x03), take_bits!(u16, 14))));
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
}
