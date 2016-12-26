use std;
use std::convert::From;
use std::net::Ipv4Addr;
use std::str::from_utf8;

use nom::{be_u8, be_u16, be_u32};

use message::Header;
use rr::Rdata;

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
#[derive(Debug, PartialEq)]
pub enum NameUnit {
    Label(String),
    Pointer(u16),
    End,
}

// TODO: toto pujde do message::mod.rs
#[derive(Debug)]
pub struct Message {
    pub header: Header,
    pub queries: Vec<Question>, //TODO: rename as question
    pub answer: Vec<ResRec>,
    pub authority: Vec<ResRec>,
    pub additional: Vec<ResRec>,
}

// TODO: toto pujde do message::mod.rs
#[derive(Debug)]
pub struct Question {
    pub name: Vec<NameUnit>,
    pub qtype: u16,
    pub class: u16,
}

// TODO: toto pujde do rr.rs
#[derive(Debug)]
pub struct ResRec {
    pub name: Vec<NameUnit>,
    pub qtype: u16,
    pub class: u16,
    pub ttl: u32,
    pub rdata: Rdata,
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

named!(pub parse_dns_name_label<NameUnit>, map_res!(
        length_bytes!(be_u8),
        |s: &[u8]| {
            match String::from_utf8(s.to_owned()) {
                Ok(s) => Ok(NameUnit::Label(s)),
                Err(e) => Err(e)
            }
        }
        ));

named!(pub parse_dns_name_pointer<NameUnit>, map!(
        bits!(pair!(tag_bits!(u16, 2, 0x03), take_bits!(u16, 14))),
        |(_, p)| {NameUnit::Pointer(p)}
        ));

named!(pub parse_dns_name_unit<NameUnit>, alt!(parse_dns_name_pointer | parse_dns_name_label));

named!(pub parse_dns_name_bottom<NameUnit>, alt!(
        map!(tag!("\0"), |_| {NameUnit::End})
        | parse_dns_name_pointer));

named!(pub parse_dns_name<Vec<NameUnit> >, map!(
        many_till!(parse_dns_name_label, parse_dns_name_bottom),
        |(mut v, b): (Vec<NameUnit>, NameUnit)| {
            v.push(b);
            return v;
        }
        ));

named!(pub parse_dns_question<Question>, do_parse!(
        name: parse_dns_name >>
        qtype: be_u16 >>
        class: be_u16 >>
        ( Question {
            name: name,
            qtype: qtype,
            class: class,
        })));

named!(pub parse_dns_rr<ResRec>, do_parse!(
        name: parse_dns_name >>
        qtype: be_u16 >>
        class: be_u16 >>
        ttl: be_u32 >>
        rdata: length_bytes!(be_u16) >>
        // rdata: switch!(qtype,
        //     1 => map!(be_u32, |a| {Rdata::A(Ipv4Addr::from(a))})
        //     | _ => map!(length_bytes!(be_u16), |s| {Rdata::Generic(s.to_owned())})
        // ) >>
        ( ResRec {
            name: name,
            qtype: qtype,
            class: class,
            ttl: ttl,
            // TODO: switch based on qtype enum
            // rdata: rdata,
            //rdata: Rdata::Generic(rdata.to_owned()),
            rdata: {
                match qtype {
                    1 => {
                        let mut addr = [0u8; 4];
                        for i in 0..4 {
                            addr[i] = rdata[i];
                        }
                        Rdata::A(Ipv4Addr::from(addr))
                    }
                    _ => Rdata::Generic(rdata.to_owned()),
                }
            }
        })));

named!(pub parse_dns_message<Message>, do_parse!(
        header: parse_dns_header >>
        questions: count!(parse_dns_question, header.qdcount as usize) >>
        answer: count!(parse_dns_rr, header.ancount as usize) >>
        authority: count!(parse_dns_rr, header.nscount as usize) >>
        additional: count!(parse_dns_rr, header.arcount as usize) >>
        ( Message {
            header: header,
            queries: questions,
            answer: answer,
            authority: authority,
            additional: additional,
        })));


