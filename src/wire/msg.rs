use std::net::Ipv4Addr;

use nom::{be_u8, be_u16, be_u32, IResult};

use message::{Header, Message, Question, QuestionBuilder};
use rr::{Rdata, ResRec, ResRecBuilder};

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

impl NameUnit {
    fn is_pointer(&self) -> bool {
        if let &NameUnit::Pointer(_) = self {
            true
        } else {
            false
        }
    }

    fn get_pointer_value(&self) -> Option<u16> {
        if let &NameUnit::Pointer(p) = self {
            Some(p)
        } else {
            None
        }
    }

    fn unwrap<'a>(&'a self) -> Option<&'a str> {
        if let &NameUnit::Label(ref s) = self {
            Some(&s)
        } else {
            None
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

pub fn decompress_name(input: &[u8], mut name: Vec<NameUnit>) -> String {
    if name.iter().all(|unit| !unit.is_pointer()) {
        let mut str_builder = String::new();
        for i in name {
            if let Some(s) = i.unwrap() {
                str_builder.push_str(s);
                str_builder.push('.');
            }
        }
        str_builder
    } else {
        let p = name.pop().unwrap().get_pointer_value().unwrap() as usize;
        let (_,mut n) = parse_dns_name(&input[p..]).unwrap();
        name.append(&mut n);
        decompress_name(input, name)
    }
}

fn parse_rdata(t: u16, i: &[u8]) -> Rdata {
    match t {
        1 => {
            let mut addr = [0u8; 4];
            addr.copy_from_slice(&i[0..4]);
            Rdata::A(Ipv4Addr::from(addr))
        }
        _ => {Rdata::Generic(i.to_owned())}
    }
}

pub fn parse_dns_message(input: &[u8]) -> IResult<&[u8], Message> {
    let (rest, header) = try_parse!(input, parse_dns_header);
    let (rest, questions) = try_parse!(rest, count!(parse_dns_question, header.qdcount as usize));
    let (rest, answers) = try_parse!(rest, count!(parse_dns_rr, header.ancount as usize));
    let (rest, authority_list) = try_parse!(rest, count!(parse_dns_rr, header.nscount as usize));
    let (rest, additional_list) = try_parse!(rest, count!(parse_dns_rr, header.arcount as usize));

    // Ted potrebuju predelat vsechny name unit na string
    let questions: Vec<Question> = questions.into_iter().map(|(builder, vec_units)| {
        builder.set_name(decompress_name(&input, vec_units)).finish()
    }).collect();

    let answers: Vec<ResRec> = answers.into_iter().map(|(builder, vec_units, rdata)| {
        let qtype = builder.qtype;
        builder.set_name(decompress_name(&input, vec_units))
                .set_rdata(parse_rdata(qtype, rdata))
                .finish()
    }).collect();
    // Potom rdata na neco

    IResult::Done(&rest[..], Message {
        header: header,
        question: questions,
        answer: answers,
        authority: vec![],
        additional: vec![]
    })
}

