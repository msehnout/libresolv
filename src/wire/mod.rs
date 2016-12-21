//! From&To wire

use std;
use std::str::from_utf8;
use nom::{be_u8, be_u16};
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


// POZOR na ty >> v typu
// named!(pub parse_dns_name_inner<Vec<&str> >, many0!(map_res!(length_bytes!(be_u8), from_utf8)));

// Alternativa:
// named!(pub parse_dns_name< Vec<&str> >,
//         flat_map!(
//             is_not!("\x00"),
//             many0!(map_res!(length_bytes!(be_u8), str::from_utf8))
//         )
//     );

named!(pub parse_dns_name<Vec<&str> >, do_parse!(
        ret: many_till!(map_res!(length_bytes!(be_u8), from_utf8), alt!(tag!("\0") | tag_bits!(u8, 2, 0xc0))) >>
        (ret.0)
        ));

#[derive(Debug)]
pub struct DnsQuery {
    header: Header,
    names: Vec<String>,
}


/// Each label is either a length byte followed by that number of bytes or a pointer to prior
/// occurrence of the same label
#[derive(Debug)]
pub enum DnsNameLabel {
    Label { idx: u16, label: String},
    Pointer(u16),
}

#[derive(Debug)]
pub struct DnsQuery2 {
    header: Header,
    names: Vec<Vec<DnsNameLabel>>,
}

named!(pub parse_dns_query<DnsQuery>, do_parse!(
        header: parse_dns_header >>
        names: count!(parse_dns_name, header.qdcount as usize) >>
        ( DnsQuery {
            header: header,
            names: names.into_iter().map(|name| String::from(name.join("."))).collect(),
        })));

named!(pub parse_dns_query2<DnsQuery2>, do_parse!(
        header: parse_dns_header >>
        names: count!(parse_dns_name, header.qdcount as usize) >>
        ( DnsQuery2 {
            header: header,
            names: names.into_iter().map(|name| name.into_iter().map(|label| DnsNameLabel::Label{idx: 0, label: String::from(label)}).collect()).collect(),
        })));

impl FromWire for Header {
    fn from_wire(input: &[u8]) -> Option<Self> {
        Some(parse_dns_header(input).unwrap().1)
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn print_parse_dns_header() {
        let test = vec![0xc9, 0xba, 0x01, 0x20, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x07,
        0x65, 0x78, 0x61, 0x6d, 0x70, 0x6c, 0x65, 0x03, 0x63, 0x6f, 0x6d, 0x00, 0x00,
        0x01, 0x00, 0x01, 0x00, 0x00, 0x29, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];

        println!("{:?}", parse_dns_header(&test));

    }

    #[test]
    fn parse_name_simple() {
        let name = "test.example.com.";
        let mut buffer = Vec::new();
        let labels: Vec<&str> = name.split_terminator('.').collect();
        for label in labels {
            let len = label.len() as u8;
            buffer.push(len);
            buffer.extend(label.as_bytes().iter().cloned());
        }
        buffer.push(0);

        // TODO: Parse the name in wire format
        let labels: Vec<&str> = parse_dns_name(&buffer[..]).unwrap().1;
        // POZOR: na konci je prazdny label
        let result = labels.join(".");
        assert_eq!(result, "test.example.com")
    }

    #[test]
    fn parse_name_2() {
        let name = "test.example.com.";
        let mut buffer = Vec::new();
        let labels: Vec<&str> = name.split_terminator('.').collect();
        for label in labels {
            let len = label.len() as u8;
            buffer.push(len);
            buffer.extend(label.as_bytes().iter().cloned());
        }
        buffer.push(0);
        buffer.push(5);
        buffer.extend(b"abcde");
        buffer.push(0);

        let labels = parse_dns_name(&buffer[..]).unwrap().1;
        let result = labels.join(".");
        assert_eq!(result, "test.example.com")
    }

    #[test]
    fn parse_query() {
        let input = vec![0x48, 0xe0, 0x01, 0x20, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
        0x03, 0x6e, 0x69, 0x63, 0x02, 0x63, 0x7a, 0x00, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x29,
        0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
        let q = parse_dns_query(&input[..]).unwrap().1;
        println!("{:?}", q);
        assert_eq!(q.names[0], "nic.cz")
    }

    #[test]
    fn parse_query2() {
        let input = vec![0x48, 0xe0, 0x01, 0x20, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
        0x03, 0x6e, 0x69, 0x63, 0x02, 0x63, 0x7a, 0x00, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x29,
        0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
        let q = parse_dns_query2(&input[..]).unwrap();
        println!("{:?}", q);
        //assert_eq!(q.names[0], "nic.cz")
    }
}
