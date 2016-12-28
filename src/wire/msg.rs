use std;
use std::convert::From;
use std::net::Ipv4Addr;
use std::str::from_utf8;

use nom::{be_u8, be_u16, be_u32, IResult};

use error::Error;
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
    pub question: Vec<Question>,
    pub answer: Vec<ResRec>,
    pub authority: Vec<ResRec>,
    pub additional: Vec<ResRec>,
}

// TODO: toto pujde do message::mod.rs
#[derive(Debug)]
pub struct Question {
    pub name: String,
    pub qtype: u16,
    pub class: u16,
}

#[derive(Debug)]
pub struct QuestionBuilder {
    name: Option<String>,
    qtype: u16,
    class: u16,
}

impl QuestionBuilder {
    pub fn no_name(qtype: u16, class: u16) -> QuestionBuilder {
        QuestionBuilder {
            name: None,
            qtype: qtype,
            class: class,
        }
    }

    pub fn set_name(mut self, name: String) -> QuestionBuilder {
        self.name = Some(name);
        self
    }

    pub fn finish(mut self) -> Question {
        Question {
            name: self.name.unwrap_or("".to_string()),
            qtype: self.qtype,
            class: self.class,
        }
    }
}

// TODO: toto pujde do rr.rs
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
    qtype: u16,
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

    pub fn finnish(self) -> ResRec {
        ResRec {
            name: self.name.unwrap_or("".to_string()),
            qtype: self.qtype,
            class: self.class,
            ttl: self.ttl,
            rdata: self.rdata.unwrap_or(Rdata::Generic(vec![])),
        }
    }
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

named!(pub parse_dns_question<(QuestionBuilder, Vec<NameUnit>)>, do_parse!(
        name: parse_dns_name >>
        qtype: be_u16 >>
        class: be_u16 >>
        ( (QuestionBuilder::no_name(qtype, class), name)
        )));

pub fn parse_dns_rr(input: &[u8]) -> IResult<&[u8], (ResRecBuilder, Vec<NameUnit>, &[u8])> {
    do_parse!(input,
    name: parse_dns_name >>
    qtype: be_u16 >>
    class: be_u16 >>
    ttl: be_u32 >>
    rdata: length_bytes!(be_u16) >>
    ( ResRecBuilder::no_name(qtype, class, ttl), name, rdata ))
}

pub fn parse_dns_message(input: &[u8]) -> IResult<&[u8], Message> {
    let (rest, header) = try_parse!(input, parse_dns_header);
    let (rest, questions) = try_parse!(rest, count!(parse_dns_question, header.qdcount as usize));
    let (rest, answers) = try_parse!(rest, count!(parse_dns_rr, header.ancount as usize));
    let (rest, authority_list) = try_parse!(rest, count!(parse_dns_rr, header.nscount as usize));
    let (rest, additional_list) = try_parse!(rest, count!(parse_dns_rr, header.arcount as usize));

    // Ted potrebuju predelat vsechny name unit na string

    // Potom rdata na neco

    IResult::Done(&rest[..], Message {
        header: header,
        question: vec![],
        answer: vec![],
        authority: vec![],
        additional: vec![]
    })
}

