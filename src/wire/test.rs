use std::net::Ipv4Addr;
use std::str::FromStr;

use super::msg;
use message::Header;
use rr::Rdata;

#[test]
fn test_parse_dns_header() {
    let test = vec![0xc9, 0xba, 0x01, 0x20, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x07,
    0x65, 0x78, 0x61, 0x6d, 0x70, 0x6c, 0x65, 0x03, 0x63, 0x6f, 0x6d, 0x00, 0x00,
    0x01, 0x00, 0x01, 0x00, 0x00, 0x29, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];

    let test: Header = msg::parse_dns_header(&test).unwrap().1;
    // TODO: test all parameters
    assert_eq!(test.id, 0xc9ba);
    assert_eq!(test.response, false);
    assert_eq!(test.tc, false);
    assert_eq!(test.rd, true);
    assert_eq!(test.qdcount, 1);
    assert_eq!(test.ancount, 0);
    assert_eq!(test.nscount, 0);
    assert_eq!(test.arcount, 1);

}

#[test]
fn test_parse_dns_name_label() {
    let input = b"\x05abcde";
    let output = msg::parse_dns_name_label(&input[..]).unwrap().1;
    assert_eq!(output, msg::NameUnit::Label("abcde".to_string()));
}

#[test]
fn test_parse_dns_name_pointer() {
    let input = b"\xc0\x0c";
    let output = msg::parse_dns_name_pointer(&input[..]).unwrap().1;
    assert_eq!(output, msg::NameUnit::Pointer(0x0c));
}

#[test]
fn test_parse_dns_name_unit() {
    let input = b"\xf2\x35";
    let output = msg::parse_dns_name_unit(&input[..]).unwrap().1;
    assert_eq!(output, msg::NameUnit::Pointer(0x3235));
    let input = b"\x08abcde123";
    let output = msg::parse_dns_name_unit(&input[..]).unwrap().1;
    assert_eq!(output, msg::NameUnit::Label("abcde123".to_string()));
}

#[test]
fn test_parse_dns_name_bottom() {
    let input = b"\x00\xf2\x35";
    let output = msg::parse_dns_name_bottom(&input[..]).unwrap().1;
    assert_eq!(output, msg::NameUnit::End);
    let input = b"\xf2\x35";
    let output = msg::parse_dns_name_unit(&input[..]).unwrap().1;
    assert_eq!(output, msg::NameUnit::Pointer(0x3235));
}

#[test]
fn test_parse_dns_name() {
    let input = b"\x05abcde\x04abcd\x03abc\x00";
    let output = msg::parse_dns_name(&input[..]).unwrap().1;
    assert_eq!(output, vec![
    msg::NameUnit::Label(String::from("abcde")),
    msg::NameUnit::Label(String::from("abcd")),
    msg::NameUnit::Label(String::from("abc")),
    msg::NameUnit::End,
    ]);
    let input = b"\x05abcde\xc0\x01";
    let output = msg::parse_dns_name(&input[..]).unwrap().1;
    assert_eq!(output, vec![
    msg::NameUnit::Label(String::from("abcde")),
    msg::NameUnit::Pointer(1),
    ]);
}

#[test]
fn test_parse_query() {
    let input = vec![0x48, 0xe0, 0x01, 0x20, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
    0x03, 0x6e, 0x69, 0x63, 0x02, 0x63, 0x7a, 0x00, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x29,
    0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
    let q = msg::parse_dns_message(&input[..]).unwrap().1;
    // println!("{:?}", q);
    assert_eq!(q.queries[0].name, vec![
    msg::NameUnit::Label(String::from("nic")),
    msg::NameUnit::Label(String::from("cz")),
    msg::NameUnit::End,
    ]);
}

#[test]
fn test_parse_dns_rr_a_address() {
    let input = vec![0xc9, 0xba, 0x81, 0xa0, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00,
    0x01, 0x07, 0x65, 0x78, 0x61, 0x6d, 0x70, 0x6c, 0x65, 0x03, 0x63, 0x6f, 0x6d, 0x00,
    0x00, 0x01, 0x00, 0x01, 0xc0, 0x0c, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x18, 0x5c,
    0x00, 0x04, 0x5d, 0xb8, 0xd8, 0x22, 0x00, 0x00, 0x29, 0x02, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00];
    // From wireshark: example.com: type A, class IN, addr 93.184.216.34
    let ref output = msg::parse_dns_message(&input[..]).unwrap().1.answer[0];
    //println!("{:?}", output);
    assert_eq!(output.rdata, Rdata::A(Ipv4Addr::from_str("93.184.216.34").unwrap()));
}
