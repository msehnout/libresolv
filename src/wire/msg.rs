use std;
use std::str::from_utf8;
use nom::{be_u8, be_u16};
use ::message::Header;

/// Each label is either a length byte followed by that number of bytes or a pointer to prior
/// occurrence of the same label. From RFC:
///
/// ```txt
/// The compression scheme allows a domain name in a message to be
/// represented as either:
///    - a sequence of labels ending in a zero octet
///    - a pointer
///    - a sequence of labels ending with a pointer
/// ```

#[derive(Debug)]
pub enum DnsNameLabel {
    Label(String),
    Pointer(u16),
}

named!(pub parse_dns_header<Header>, do_parse!(
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

named!(pub parse_dns_name_label<DnsNameLabel>, map_res!(
        length_bytes!(be_u8),
        |s: &[u8]| {
            match String::from_utf8(s.to_owned()) {
                Ok(s) => Ok(DnsNameLabel::Label(s)),
                Err(e) => Err(e)
            }
        }
        ));

named!(pub parse_dns_name_pointer<DnsNameLabel>, map_res!(
        bits!(pair!(tag_bits!(u16, 2, 0x03), take_bits!(u16, 14))),
        |(_, p)| -> Result<_, ()> {Ok(DnsNameLabel::Pointer(p))}
        ));

named!(pub parse_dns_name_unit<DnsNameLabel>, alt!(parse_dns_name_pointer | parse_dns_name_label));

// //, take_bits!(u16, 14)
// named!(pub parse_dns_name<Vec<&str> >, do_parse!(
//         ret: many_till!(map_res!(length_bytes!(be_u8), str::from_utf8), tag!("\0")) >>
//         (ret.0)
//         ));
// 
// named!(pub parse_dns_name2< Vec<&str> >,
//     terminated!(
//         flat_map!(
//             is_not!("\x00"),
//             many0!(parse_dns_name_label)
//         ),
//         tag!("\x00")
//     )
// );
// 
// // POZOR na ty >> v typu
// // named!(pub parse_dns_name_inner<Vec<&str> >, many0!(map_res!(length_bytes!(be_u8), from_utf8)));
// 
// // Alternativa:
// // + DEJ tam ten terminated!
// // named!(pub parse_dns_name< Vec<&str> >,
// //         flat_map!(
// //             is_not!("\x00"),
// //             many0!(map_res!(length_bytes!(be_u8), str::from_utf8))
// //         )
// //     );
// 
// // named!(pub parse_dns_name<Vec<&str> >, do_parse!(
// //         ret: many_till!(map_res!(length_bytes!(be_u8), from_utf8), tag!("\0")) >>
// //         (ret.0)
// //         ));
// 
// #[derive(Debug)]
// pub struct DnsQuery {
//     header: Header,
//     names: Vec<String>,
// }
// 
// 
// 
// #[derive(Debug)]
// pub struct DnsQuery2 {
//     header: Header,
//     names: Vec<Vec<DnsNameLabel>>,
// }
// 
// named!(pub parse_dns_query<DnsQuery>, do_parse!(
//         header: parse_dns_header >>
//         names: count!(parse_dns_name, header.qdcount as usize) >>
//         ( DnsQuery {
//             header: header,
//             names: names.into_iter().map(|name| String::from(name.join("."))).collect(),
//         })));
// 
// named!(pub parse_dns_query2<DnsQuery2>, do_parse!(
//         header: parse_dns_header >>
//         names: count!(parse_dns_name, header.qdcount as usize) >>
//         ( DnsQuery2 {
//             header: header,
//             names: names.into_iter().map(|name| name.into_iter().map(|label| DnsNameLabel::Label(String::from(label))).collect()).collect(),
//         })));
